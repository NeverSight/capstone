/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>

struct move_family {
	x86_insn legacy_id, vector_id;
	uint8_t prefix, load, store;
};

static const struct move_family families[] = {
	{ X86_INS_MOVUPS, X86_INS_VMOVUPS, 0, 0x10, 0x11 },
	{ X86_INS_MOVUPD, X86_INS_VMOVUPD, 1, 0x10, 0x11 },
	{ X86_INS_MOVAPS, X86_INS_VMOVAPS, 0, 0x28, 0x29 },
	{ X86_INS_MOVAPD, X86_INS_VMOVAPD, 1, 0x28, 0x29 },
	{ X86_INS_MOVDQA, X86_INS_VMOVDQA, 1, 0x6f, 0x7f },
	{ X86_INS_MOVDQU, X86_INS_VMOVDQU, 2, 0x6f, 0x7f },
};

static bool check_encoding(csh h, cs_insn *insn,
			   const struct move_family *family, unsigned bits,
			   unsigned encoding, unsigned ll, bool att, bool store,
			   bool memory, unsigned mask)
{
	uint8_t bytes[6], *end = bytes;
	if (encoding == 0) {
		if (family->prefix)
			*end++ = family->prefix == 1 ? 0x66 : 0xf3;
		*end++ = 0x0f;
	} else if (encoding == 1 || encoding == 2) {
		*end++ = encoding == 1 ? 0xc5 : 0xc4;
		if (encoding == 2)
			*end++ = 0xe1;
		*end++ = (encoding == 1 ? 0xf8 : 0x78) | (ll << 2) |
			 family->prefix;
	} else {
		*end++ = 0x62;
		*end++ = 0xf1;
		*end++ = 0x7c | (family->prefix << 7) | family->prefix;
		*end++ = 8 | (ll << 5) | (mask ? 3 : 0) |
			 (mask == 2 ? 0x80 : 0);
	}
	*end++ = store ? family->store : family->load;
	*end++ = memory ? 0x10 : 0xd3;
	const uint8_t *cursor = bytes;
	size_t left = end - bytes;
	uint64_t pc = 0x1000;
	if (!cs_disasm_iter(h, &cursor, &left, &pc, insn) || left ||
	    insn->id != (encoding ? family->vector_id : family->legacy_id))
		return false;
	const cs_x86 *x = &insn->detail->x86;
	if (encoding == 3 && (!cs_insn_group(h, insn, X86_GRP_AVX512) ||
			      cs_insn_group(h, insn, X86_GRP_VLX) != (ll < 2)))
		return false;
	if (x->op_count != 2 + (mask != 0))
		return false;
	const x86_reg first = ll == 2 ? X86_REG_ZMM0 :
			      ll == 1 ? X86_REG_YMM0 :
					X86_REG_XMM0;
	const x86_reg base = bits == 64 ? X86_REG_RAX : X86_REG_EAX;
	const bool mem_dst = memory && store, mem_src = memory && !store;
	const cs_x86_op *dst =
		&x->operands[att ? (mask ? 1 : x->op_count - 1) : 0];
	const cs_x86_op *src = &x->operands[att ? 0 : x->op_count - 1];
	if (dst->type != (mem_dst ? X86_OP_MEM : X86_OP_REG) ||
	    src->type != (mem_src ? X86_OP_MEM : X86_OP_REG))
		return false;
	if ((mem_dst ? dst->mem.base != base :
		       dst->reg != first + (store ? 3 : 2)) ||
	    (mem_src ? src->mem.base != base :
		       src->reg != first + (store ? 2 : 3)))
		return false;
	if (mask) {
		const cs_x86_op *k = &x->operands[att ? 2 : 1];
		if (k->type != X86_OP_REG || k->reg != X86_REG_K3 ||
		    k->access != CS_AC_READ)
			return false;
	}
	return dst->access == (mask == 1 && !mem_dst ? CS_AC_READ_WRITE :
						       CS_AC_WRITE) &&
	       src->access == CS_AC_READ && dst->size == (16u << ll) &&
	       src->size == (16u << ll);
}

static bool check_family(csh handle, cs_insn *insn, const struct move_family *f,
			 unsigned bits, bool att)
{
	for (unsigned encoding = 0; encoding <= (f->load == 0x6f ? 2u : 3u);
	     ++encoding) {
		const unsigned widths = encoding == 0 ? 1 :
					encoding == 3 ? 3 :
							2;
		for (unsigned ll = 0; ll < widths; ++ll) {
			for (unsigned form = 0; form < 4; ++form) {
				const bool store = form & 1, memory = form & 2;
				const unsigned masks = encoding != 3   ? 1 :
						       store && memory ? 2 :
									 3;
				for (unsigned mask = 0; mask < masks; ++mask) {
					if (!check_encoding(handle, insn, f,
							    bits, encoding, ll,
							    att, store, memory,
							    mask)) {
						fprintf(stderr,
							"packed move mismatch, id %u bits %u encoding %u LL %u AT&T %d form %u mask %u\n",
							f->vector_id, bits,
							encoding, ll, att, form,
							mask);
						return false;
					}
				}
			}
		}
	}
	return true;
}

int main(void)
{
	for (unsigned bits = 32; bits <= 64; bits += 32) {
		csh handle;
		if (cs_open(CS_ARCH_X86, bits == 32 ? CS_MODE_32 : CS_MODE_64,
			    &handle) ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON))
			return 1;
		cs_insn *insn = cs_malloc(handle);
		if (!insn)
			return 1;
		bool ok = true;
		for (unsigned att = 0; att < 2 && ok; ++att) {
			cs_err err = cs_option(handle, CS_OPT_SYNTAX,
					       att ? CS_OPT_SYNTAX_ATT :
						     CS_OPT_SYNTAX_INTEL);
			if (att && err == CS_ERR_X86_ATT)
				continue;
			ok = err == CS_ERR_OK;
			for (unsigned n = 0;
			     ok && n < sizeof(families) / sizeof(families[0]);
			     ++n)
				ok = check_family(handle, insn, &families[n],
						  bits, att);
		}
		cs_free(insn, 1);
		cs_close(&handle);
		if (!ok)
			return 1;
	}
	return 0;
}

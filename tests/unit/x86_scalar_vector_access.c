/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>

static bool check_move(csh handle, unsigned bits, unsigned encoding, bool fp64,
		       bool store, bool registers, unsigned mask, bool att)
{
	uint8_t bytes[8], *end = bytes;
	const uint8_t flags = (registers ? 0x70 : 0x78) | (2 + fp64);
	if (encoding == 2) {
		*end++ = 0x62;
		*end++ = 0xf1;
		*end++ = flags | 4 | (fp64 ? 0x80 : 0);
		*end++ = 8 | (mask ? 3 : 0) | (mask == 2 ? 0x80 : 0);
	} else if (encoding == 1) {
		*end++ = 0xc4;
		*end++ = 0xe1;
		*end++ = flags;
	} else {
		*end++ = 0xc5;
		*end++ = flags | 0x80;
	}
	*end++ = store ? 0x11 : 0x10;
	*end++ = registers ? 0xd4 : 0x14;
	if (!registers && bits != 16)
		*end++ = 0x88;

	cs_insn *insn = NULL;
	if (cs_disasm(handle, bytes, end - bytes, 0x1000, 1, &insn) != 1)
		return false;
	const cs_x86 *x = &insn->detail->x86;
	const unsigned count = 2 + registers + (mask != 0);
	const unsigned dst = att ? count - 1 - (mask != 0) : 0;
	bool ok = insn->size == end - bytes &&
		  insn->id == (fp64 ? X86_INS_VMOVSD : X86_INS_VMOVSS) &&
		  x->op_count == count && !x->eflags &&
		  cs_insn_group(handle, insn,
				encoding == 2 ? X86_GRP_AVX512 : X86_GRP_AVX);
	for (unsigned i = 0; i < x->op_count && ok; ++i) {
		const cs_x86_op *op = &x->operands[i];
		const bool memory = !registers && i == (store ? dst :
							att   ? 0 :
								count - 1);
		const bool predicate = mask && i == (att ? count - 1 : 1);
		const bool merge = mask == 1 && !memory;
		const cs_ac_type access =
			i == dst ? (merge ? CS_AC_READ_WRITE : CS_AC_WRITE) :
				   CS_AC_READ;
		ok = op->type == (memory ? X86_OP_MEM : X86_OP_REG) &&
		     op->access == access &&
		     op->size == (memory    ? (fp64 ? 8 : 4) :
				  predicate ? 1 :
					      16);
		if (predicate)
			ok = ok && op->reg == X86_REG_K3;
	}
	if (!ok)
		fprintf(stderr, "%s %s (mode %u, encoding %u, mask %u)\n",
			insn->mnemonic, insn->op_str, bits, encoding, mask);
	cs_free(insn, 1);
	return ok;
}

int main(void)
{
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	for (unsigned mode = 0; mode < 3; ++mode) {
		csh handle;
		if (cs_open(CS_ARCH_X86, modes[mode], &handle))
			return 1;
		bool ok = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) ==
			  CS_ERR_OK;
		for (unsigned att = 0; ok && att < 2; ++att) {
			cs_err err = cs_option(handle, CS_OPT_SYNTAX,
					       att ? CS_OPT_SYNTAX_ATT :
						     CS_OPT_SYNTAX_INTEL);
			if (att && err == CS_ERR_X86_ATT)
				continue;
			ok = err == CS_ERR_OK;
			for (unsigned enc = 0; ok && enc < 3; ++enc)
				for (unsigned form = 0; ok && form < 8;
				     ++form) {
					bool store = (form & 2) != 0;
					bool regs = (form & 4) != 0;
					unsigned masks = enc != 2	? 1 :
							 store && !regs ? 2 :
									  3;
					for (unsigned mask = 0;
					     ok && mask < masks; ++mask)
						ok = check_move(handle,
								16u << mode,
								enc, form & 1,
								store, regs,
								mask, att);
				}
		}
		cs_close(&handle);
		if (!ok)
			return 1;
	}
	return 0;
}

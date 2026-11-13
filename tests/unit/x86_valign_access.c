/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>

static bool contains(const cs_regs regs, uint8_t count, x86_reg reg)
{
	for (unsigned i = 0; i < count; ++i)
		if (regs[i] == reg)
			return true;
	return false;
}

static bool check(cs_insn *insn, csh handle, unsigned ll, bool qword,
		  unsigned mask, unsigned memory)
{
	/* VALIGND/Q dst2 {k3}{z}, src6, src3 or [ax], 0xa5. */
	uint8_t bytes[] = { 0x62,
			    0xf3,
			    (uint8_t)(0x4d | (qword << 7)),
			    (uint8_t)((ll << 5) | 8 | (mask ? 3 : 0) |
				      (mask == 2 ? 0x80 : 0) |
				      (memory == 2 ? 16 : 0)),
			    3,
			    (uint8_t)(memory ? 0x10 : 0xd3),
			    0xa5 };
	const uint8_t *code = bytes;
	size_t size = sizeof(bytes);
	uint64_t address = 0x1000;
	if (!cs_disasm_iter(handle, &code, &size, &address, insn) || size ||
	    insn->id != (qword ? X86_INS_VALIGNQ : X86_INS_VALIGND))
		return false;
	const cs_x86 *x = &insn->detail->x86;
	const x86_reg starts[] = { X86_REG_XMM0, X86_REG_YMM0, X86_REG_ZMM0 };
	const x86_reg dst = (x86_reg)(starts[ll] + 2),
		      src = (x86_reg)(starts[ll] + 6);
	const x86_reg rm =
		memory ? (x->addr_size == 8 ? X86_REG_RAX : X86_REG_EAX) :
			 (x86_reg)(starts[ll] + 3);
	if (x->op_count != 4 + (mask != 0) ||
	    !cs_insn_group(handle, insn, X86_GRP_AVX512) ||
	    cs_insn_group(handle, insn, X86_GRP_VLX) != (ll < 2))
		return false;
	unsigned seen = 0;
	for (unsigned i = 0; i < x->op_count; ++i) {
		const cs_x86_op *op = &x->operands[i];
		if (op->type == X86_OP_REG && op->reg == dst &&
		    op->access == (mask == 1 ? CS_AC_READ_WRITE : CS_AC_WRITE))
			seen |= 1;
		else if (op->type == X86_OP_REG && op->reg == src &&
			 op->access == CS_AC_READ)
			seen |= 2;
		else if ((memory ?
				  op->type == X86_OP_MEM && op->mem.base == rm :
				  op->type == X86_OP_REG && op->reg == rm) &&
			 op->access == CS_AC_READ)
			seen |= 4;
		else if (op->type == X86_OP_IMM && op->imm == 0xa5 &&
			 !op->access)
			seen |= 8;
		else if (mask && op->type == X86_OP_REG &&
			 op->reg == X86_REG_K3 && op->access == CS_AC_READ)
			seen |= 16;
		else
			return false;
	}
	cs_regs reads, writes;
	uint8_t nr, nw;
	return seen == (mask ? 31u : 15u) &&
	       cs_regs_access(handle, insn, reads, &nr, writes, &nw) ==
		       CS_ERR_OK &&
	       contains(reads, nr, src) && contains(reads, nr, rm) &&
	       contains(reads, nr, dst) == (mask == 1) &&
	       contains(reads, nr, X86_REG_K3) == (mask != 0) &&
	       nr == 2 + (mask != 0) + (mask == 1) && nw == 1 &&
	       writes[0] == dst;
}

int main(void)
{
	for (unsigned wide = 0; wide < 2; ++wide) {
		csh handle;
		if (cs_open(CS_ARCH_X86, wide ? CS_MODE_64 : CS_MODE_32,
			    &handle) ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON))
			return 1;
		cs_insn *insn = cs_malloc(handle);
		if (!insn)
			return 1;
		for (unsigned att = 0; att < 2; ++att) {
			cs_err e = cs_option(handle, CS_OPT_SYNTAX,
					     att ? CS_OPT_SYNTAX_ATT :
						   CS_OPT_SYNTAX_INTEL);
			if (att && e == CS_ERR_X86_ATT)
				continue;
			if (e)
				return 1;
			for (unsigned ll = 0; ll < 3; ++ll)
				for (unsigned w = 0; w < 2; ++w)
					for (unsigned mask = 0; mask < 3;
					     ++mask)
						for (unsigned mem = 0; mem < 3;
						     ++mem)
							if (!check(insn, handle,
								   ll, w, mask,
								   mem)) {
								fprintf(stderr,
									"VALIGN access mismatch: mode %u, AT&T %u, LL %u, W %u, mask %u, memory %u\n",
									wide ? 64 :
									       32,
									att, ll,
									w, mask,
									mem);
								return 1;
							}
		}
		cs_free(insn, 1);
		cs_close(&handle);
	}
	return 0;
}

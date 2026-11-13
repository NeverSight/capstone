/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>

static bool has_register(const cs_regs regs, uint8_t count, x86_reg reg)
{
	for (unsigned i = 0; i < count; i++)
		if (regs[i] == reg)
			return true;
	return false;
}

static bool check_move(csh handle, cs_insn *insn, unsigned bits, unsigned pp,
		       unsigned w, unsigned ll, bool reverse, bool memory,
		       unsigned mask)
{
	static const x86_insn ids[3][2] = {
		{ X86_INS_VMOVDQA32, X86_INS_VMOVDQA64 },
		{ X86_INS_VMOVDQU32, X86_INS_VMOVDQU64 },
		{ X86_INS_VMOVDQU8, X86_INS_VMOVDQU16 }
	};
	static const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0,
					 X86_REG_ZMM0 };
	const uint8_t bytes[] = { 0x62,
				  0xf1,
				  (uint8_t)(0x7c | pp | w << 7),
				  (uint8_t)(8 | ll << 5 | (mask ? 3 : 0) |
					    (mask == 2 ? 0x80 : 0)),
				  (uint8_t)(reverse ? 0x7f : 0x6f),
				  (uint8_t)(memory ? 0x10 : 0xd3) };
	const uint8_t *cursor = bytes;
	size_t left = sizeof(bytes);
	uint64_t address = 0x1000;
	if (!cs_disasm_iter(handle, &cursor, &left, &address, insn) || left ||
	    insn->id != ids[pp - 1][w])
		return false;
	const cs_x86 *x = &insn->detail->x86;
	const bool store = memory && reverse;
	const x86_reg base = bits == 64 ? X86_REG_RAX : X86_REG_EAX;
	const x86_reg dst = memory && reverse ?
				    base :
				    (x86_reg)(bases[ll] + (reverse ? 3 : 2));
	const x86_reg src = memory && !reverse ?
				    base :
				    (x86_reg)(bases[ll] + (reverse ? 2 : 3));
	const bool merge_reg = mask == 1 && !store;
	if (x->op_count != 2 + (mask != 0) ||
	    !cs_insn_group(handle, insn,
			   pp == 3 ? X86_GRP_BWI : X86_GRP_AVX512) ||
	    cs_insn_group(handle, insn, X86_GRP_VLX) != (ll < 2))
		return false;
	unsigned seen = 0;
	for (unsigned i = 0; i < x->op_count; i++) {
		const cs_x86_op *op = &x->operands[i];
		const bool mem = op->type == X86_OP_MEM;
		if (!mem && op->type != X86_OP_REG)
			return false;
		const x86_reg reg = mem ? op->mem.base : op->reg;
		if (reg == dst && mem == store &&
		    op->access == (merge_reg ? CS_AC_READ_WRITE : CS_AC_WRITE))
			seen |= 1;
		else if (reg == src && mem == (memory && !reverse) &&
			 op->access == CS_AC_READ)
			seen |= 2;
		else if (!mem && mask && reg == X86_REG_K3 &&
			 op->access == CS_AC_READ)
			seen |= 4;
		else
			return false;
	}
	cs_regs reads, writes;
	uint8_t nr, nw;
	return seen == (mask ? 7u : 3u) &&
	       cs_regs_access(handle, insn, reads, &nr, writes, &nw) ==
		       CS_ERR_OK &&
	       has_register(reads, nr, src) &&
	       has_register(reads, nr, dst) == (merge_reg || store) &&
	       has_register(reads, nr, X86_REG_K3) == (mask != 0) &&
	       nr == 1 + merge_reg + store + (mask != 0) && nw == !store &&
	       (!nw || writes[0] == dst);
}

int main(void)
{
	for (unsigned bits = 32; bits <= 64; bits += 32) {
		csh handle;
		if (cs_open(CS_ARCH_X86, bits == 32 ? CS_MODE_32 : CS_MODE_64,
			    &handle) != CS_ERR_OK ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
			return 1;
		cs_insn *insn = cs_malloc(handle);
		if (!insn)
			return 1;
		for (unsigned att = 0; att < 2; att++) {
			cs_err err = cs_option(handle, CS_OPT_SYNTAX,
					       att ? CS_OPT_SYNTAX_ATT :
						     CS_OPT_SYNTAX_INTEL);
			if (att && err == CS_ERR_X86_ATT)
				continue;
			if (err)
				return 1;
			for (unsigned pp = 1; pp <= 3; pp++)
				for (unsigned w = 0; w < 2; w++)
					for (unsigned ll = 0; ll < 3; ll++)
						for (unsigned rev = 0; rev < 2;
						     rev++)
							for (unsigned mem = 0;
							     mem < 2; mem++)
								for (unsigned mask =
									     0;
								     mask <
								     (rev && mem ?
									      2u :
									      3u);
								     mask++)
									if (!check_move(
										    handle,
										    insn,
										    bits,
										    pp,
										    w,
										    ll,
										    rev,
										    mem,
										    mask)) {
										fprintf(stderr,
											"EVEX move access mismatch: %u-bit AT&T %u pp %u W %u LL %u reverse %u memory %u mask %u (%s %s)\n",
											bits,
											att,
											pp,
											w,
											ll,
											rev,
											mem,
											mask,
											insn->mnemonic,
											insn->op_str);
										for (unsigned i =
											     0;
										     i <
										     insn->detail
											     ->x86
											     .op_count;
										     i++) {
											const cs_x86_op *op =
												&insn->detail
													 ->x86
													 .operands[i];
											fprintf(stderr,
												"operand %u type %u access %u\n",
												i,
												(unsigned)op
													->type,
												(unsigned)op
													->access);
										}
										return 1;
									}
		}
		cs_free(insn, 1);
		cs_close(&handle);
	}
	return 0;
}

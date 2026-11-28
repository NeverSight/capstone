/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>

static bool decode(csh handle, cs_insn *insn, cs_mode mode, uint32_t word,
		   uint64_t address)
{
	uint8_t bytes[4];
	for (unsigned i = 0; i < 4; ++i)
		bytes[mode == CS_MODE_BIG_ENDIAN ? 3 - i : i] =
			(uint8_t)(word >> (8 * i));
	const uint8_t *code = bytes;
	size_t size = sizeof(bytes);
	return cs_disasm_iter(handle, &code, &size, &address, insn) && !size;
}

static bool reg_operand(const cs_alpha_op *op, unsigned reg, cs_ac_type access)
{
	return op->type == ALPHA_OP_REG && op->reg == reg &&
	       op->access == access;
}

static bool check_transfer(csh handle, cs_insn *insn, cs_mode mode,
			   uint32_t word, uint64_t pc, unsigned id, int64_t imm,
			   bool indirect)
{
	unsigned ra = ALPHA_REG_R0 + ((word >> 21) & 31);
	unsigned rb = ALPHA_REG_R0 + ((word >> 16) & 31);
	bool diet = cs_support(CS_SUPPORT_DIET);
	cs_ac_type read = diet ? CS_AC_INVALID : CS_AC_READ;
	cs_ac_type write = diet ? CS_AC_INVALID : CS_AC_WRITE;
	if (!decode(handle, insn, mode, word, pc) || insn->id != id)
		return false;
	const cs_alpha *alpha = &insn->detail->alpha;
	const cs_alpha_op *target = &alpha->operands[indirect ? 2 : 1];
	if (alpha->op_count != (indirect ? 3 : 2) ||
	    !reg_operand(&alpha->operands[0], ra, write) ||
	    (indirect && !reg_operand(&alpha->operands[1], rb, read)) ||
	    target->type != ALPHA_OP_IMM || target->imm != imm ||
	    target->access != read || insn->detail->regs_read_count ||
	    insn->detail->regs_write_count)
		return false;
	if (diet)
		return true;
	cs_regs reads, writes;
	uint8_t nread, nwrite;
	return cs_regs_access(handle, insn, reads, &nread, writes, &nwrite) ==
		       CS_ERR_OK &&
	       nread == (unsigned)indirect && (!nread || reads[0] == rb) &&
	       nwrite == (ra != ALPHA_REG_R31) && (!nwrite || writes[0] == ra);
}

static bool check_mode(csh handle, cs_insn *insn, cs_mode mode)
{
	static const unsigned jump_ids[] = { ALPHA_INS_JMP, ALPHA_INS_JSR,
					     ALPHA_INS_RET,
					     ALPHA_INS_JSR_COROUTINE };
	static const int32_t disps[] = { -1048576, -1, 0, 1, 1048575 };
	static const uint64_t pcs[] = { 0, UINT64_C(0x120001004),
					UINT64_MAX - 3 };
	static const uint32_t hints[] = { 0, 1, 0x3fff };
	uint32_t word = 0;
	for (unsigned ra = 0; ra < 32; ++ra) {
		for (unsigned call = 0; call < 2; ++call) {
			for (size_t i = 0; i < sizeof(disps) / sizeof(disps[0]);
			     ++i) {
				int32_t disp = disps[i];
				word = ((call ? 0x34u : 0x30u) << 26) |
				       (ra << 21) | ((uint32_t)disp & 0x1fffff);
				for (size_t j = 0;
				     j < sizeof(pcs) / sizeof(pcs[0]); ++j) {
					uint64_t target =
						pcs[j] + 4 + (int64_t)disp * 4;
					if (!check_transfer(
						    handle, insn, mode, word,
						    pcs[j],
						    call ? ALPHA_INS_BSR :
							   ALPHA_INS_BR,
						    (int64_t)target, false))
						goto failed;
				}
			}
		}
		for (unsigned rb = 0; rb < 32; ++rb) {
			for (unsigned func = 0; func < 4; ++func) {
				for (size_t j = 0;
				     j < sizeof(hints) / sizeof(hints[0]);
				     ++j) {
					word = (0x1au << 26) | (ra << 21) |
					       (rb << 16) | (func << 14) |
					       hints[j];
					if (!check_transfer(handle, insn, mode,
							    word, pcs[1],
							    jump_ids[func],
							    hints[j], true))
						goto failed;
				}
			}
		}
	}
	/* Both integer and floating-point register 31 discard writes. */
	if (!cs_support(CS_SUPPORT_DIET)) {
		static const uint32_t opcodes[] = { 0x10,
						    0x17 }; /* ADDQ, CPYS */
		for (size_t i = 0; i < sizeof(opcodes) / sizeof(opcodes[0]);
		     ++i) {
			cs_regs reads, writes;
			uint8_t nread, nwrite;
			word = (opcodes[i] << 26) | (1u << 21) | (2u << 16) |
			       (0x20u << 5) | 31u;
			if (!decode(handle, insn, mode, word, pcs[1]) ||
			    cs_regs_access(handle, insn, reads, &nread, writes,
					   &nwrite) != CS_ERR_OK ||
			    nwrite || nread != 2)
				goto failed;
		}
	}
	return true;
failed:
	fprintf(stderr,
		"Wrong Alpha detail for word 0x%08" PRIx32 " in mode %u\n",
		word, (unsigned)mode);
	return false;
}

int main(void)
{
	static const cs_mode modes[] = { CS_MODE_LITTLE_ENDIAN,
					 CS_MODE_BIG_ENDIAN };
	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
		csh handle;
		if (cs_open(CS_ARCH_ALPHA, modes[i], &handle) != CS_ERR_OK)
			return 1;
		if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
			cs_close(&handle);
			return 1;
		}
		cs_insn *insn = cs_malloc(handle);
		if (!insn) {
			cs_close(&handle);
			return 1;
		}
		bool ok = check_mode(handle, insn, modes[i]);
		cs_free(insn, 1);
		cs_close(&handle);
		if (!ok)
			return 1;
	}
	return 0;
}

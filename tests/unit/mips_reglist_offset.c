/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>

struct Case {
	csh handle;
	cs_insn *insn;
	bool big;
	bool detail;
	bool check_access;
};

static bool check(struct Case *test, uint32_t word, unsigned size, unsigned id,
		  unsigned reg_count, unsigned base, int displacement)
{
	uint8_t bytes[4];
	for (unsigned i = 0; i < size; i += 2) {
		uint16_t half = word >> (8 * (size - i - 2));
		bytes[i] = test->big ? half >> 8 : half;
		bytes[i + 1] = test->big ? half : half >> 8;
	}
	const uint8_t *cursor = bytes;
	size_t left = size;
	uint64_t address = 0x1000;
	cs_insn *insn = test->insn;
	if (!cs_disasm_iter(test->handle, &cursor, &left, &address, insn) ||
	    insn->id != id || insn->size != size || left != 0 ||
	    cursor != bytes + size || address != 0x1000 + size) {
		fprintf(stderr,
			"MIPS reglist word=%08x big=%u failed decoding\n", word,
			test->big);
		return false;
	}
	if (!test->detail)
		return true;
	const cs_mips *detail = &insn->detail->mips;
	const cs_mips_op *mem = &detail->operands[reg_count];
	bool store = id == MIPS_INS_SWM16 || id == MIPS_INS_SWM32;
	if (detail->op_count != reg_count + 1 || mem->type != MIPS_OP_MEM ||
	    mem->mem.base != base || mem->mem.disp != displacement ||
	    (test->check_access &&
	     mem->access != (store ? CS_AC_WRITE : CS_AC_READ))) {
		fprintf(stderr,
			"MIPS reglist word=%08x count=%u base=%u displacement=%lld expected=%d\n",
			word, detail->op_count, mem->mem.base,
			(long long)mem->mem.disp, displacement);
		return false;
	}
	for (unsigned i = 0; i < reg_count; ++i) {
		const cs_mips_op *reg = &detail->operands[i];
		if (reg->type != MIPS_OP_REG || !reg->is_reglist ||
		    (test->check_access &&
		     reg->access != (store ? CS_AC_READ : CS_AC_WRITE)))
			return false;
	}
	return true;
}

int main(void)
{
	static const int signed_offsets[] = { 0,   4,	8,   12,  16,  20,
					      24,  28,	-32, -28, -24, -20,
					      -16, -12, -8,  -4 };
	// Operand structure is retained in DIET; access metadata is not.
	bool check_access = !cs_support(CS_SUPPORT_DIET);
	for (unsigned r6 = 0; r6 < 2; ++r6) {
		for (unsigned big = 0; big < 2; ++big) {
			for (unsigned output = 0; output < 4; ++output) {
				// MIPS operand details are filled by its printer.
				struct Case test = { .big = big,
						     .detail = output == 3,
						     .check_access =
							     check_access };
				cs_mode mode = r6 ? CS_MODE_MICRO32R6 :
						    CS_MODE_MICRO;
				if (big)
					mode |= CS_MODE_BIG_ENDIAN;
				if (cs_open(CS_ARCH_MIPS, mode, &test.handle) !=
				    CS_ERR_OK)
					return 1;
				cs_option(test.handle, CS_OPT_TEXT,
					  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
				cs_option(test.handle, CS_OPT_DETAIL,
					  output & 2 ? CS_OPT_ON : CS_OPT_OFF);
				test.insn = cs_malloc(test.handle);
				if (!test.insn)
					return 1;
				for (unsigned fields = 0; fields < 128;
				     ++fields) {
					unsigned store = fields >> 6;
					unsigned regs = (fields >> 4) & 3;
					unsigned imm = fields & 15;
					uint16_t word = 0x4500 | fields;
					int displacement = signed_offsets[imm];
					if (r6) {
						word = 0x4402 | (store << 3) |
						       (regs << 8) | (imm << 4);
						displacement = (int)imm * 4;
					}
					unsigned id = store ? MIPS_INS_SWM16 :
							      MIPS_INS_LWM16;
					if (!check(&test, word, 2, id, regs + 2,
						   MIPS_REG_SP, displacement))
						return 1;
				}
				// Encodings from LLVM's MicroMIPS assembly fixtures.
				static const struct {
					uint32_t word;
					unsigned id, count, base;
					int displacement;
				} wide[] = {
					{ 0x20445008, MIPS_INS_LWM32, 2,
					  MIPS_REG_A0, 8 },
					{ 0x2044d008, MIPS_INS_SWM32, 2,
					  MIPS_REG_A0, 8 },
					{ 0x213b5984, MIPS_INS_LWM32, 9,
					  MIPS_REG_K1, -1660 },
					{ 0x213bd984, MIPS_INS_SWM32, 9,
					  MIPS_REG_K1, -1660 },
					{ 0x23245008, MIPS_INS_LWM32, 10,
					  MIPS_REG_A0, 8 },
					{ 0x2324d008, MIPS_INS_SWM32, 10,
					  MIPS_REG_A0, 8 },
				};
				for (unsigned i = 0;
				     i < sizeof(wide) / sizeof(wide[0]); ++i) {
					if (!check(&test, wide[i].word, 4,
						   wide[i].id, wide[i].count,
						   wide[i].base,
						   wide[i].displacement))
						return 1;
				}
				cs_free(test.insn, 1);
				cs_close(&test.handle);
			}
		}
	}
	return 0;
}

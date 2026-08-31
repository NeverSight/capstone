/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>

typedef struct mask_conversion_case {
	uint8_t code[6];
	x86_insn instruction;
	x86_reg destination;
	x86_reg source;
	uint8_t destination_size;
	uint8_t source_size;
} mask_conversion_case;

static bool check(bool condition, const char *message, size_t case_index,
		  cs_opt_value syntax)
{
	if (!condition) {
		fprintf(stderr,
			"EVEX mask-conversion access check failed in case %zu (%s): %s\n",
			case_index,
			syntax == CS_OPT_SYNTAX_ATT ? "AT&T" : "Intel",
			message);
	}
	return condition;
}

static bool has_register(const cs_regs registers, uint8_t count, x86_reg reg)
{
	for (uint8_t i = 0; i < count; ++i) {
		if (registers[i] == reg)
			return true;
	}
	return false;
}

static const cs_x86_op *find_register_operand(const cs_x86 *x86, x86_reg reg)
{
	for (uint8_t i = 0; i < x86->op_count; ++i) {
		if (x86->operands[i].type == X86_OP_REG &&
		    x86->operands[i].reg == reg)
			return &x86->operands[i];
	}
	return NULL;
}

static bool test_case(csh handle, const mask_conversion_case *test,
		      size_t case_index, cs_opt_value syntax)
{
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	bool success = true;
	size_t count = cs_disasm(handle, test->code, sizeof(test->code), 0x1000,
				 1, &insn);

	if (!check(count == 1, "instruction decodes", case_index, syntax))
		return false;
	success &= check(insn[0].id == test->instruction,
			 "public instruction ID is exact", case_index, syntax);
	success &= check(insn[0].detail != NULL, "detail is available",
			 case_index, syntax);
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		const cs_x86_op *destination =
			find_register_operand(x86, test->destination);
		const cs_x86_op *source =
			find_register_operand(x86, test->source);

		success &= check(x86->op_count == 2,
				 "there are exactly two explicit operands",
				 case_index, syntax);
		success &= check(destination != NULL,
				 "destination register is present", case_index,
				 syntax);
		success &= check(source != NULL, "source register is present",
				 case_index, syntax);
		if (destination != NULL) {
			success &= check(destination->size ==
						 test->destination_size,
					 "destination width is exact",
					 case_index, syntax);
			success &= check(destination->access == CS_AC_WRITE,
					 "destination is write-only",
					 case_index, syntax);
		}
		if (source != NULL) {
			success &= check(source->size == test->source_size,
					 "source width is exact", case_index,
					 syntax);
			success &= check(source->access == CS_AC_READ,
					 "source is read-only", case_index,
					 syntax);
		}
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds", case_index, syntax);
		success &= check(regs_read_count == 1,
				 "exactly one register is read", case_index,
				 syntax);
		success &= check(regs_write_count == 1,
				 "exactly one register is written", case_index,
				 syntax);
		success &= check(has_register(regs_read, regs_read_count,
					      test->source),
				 "source is in regs_read", case_index, syntax);
		success &= check(has_register(regs_write, regs_write_count,
					      test->destination),
				 "destination is in regs_write", case_index,
				 syntax);
	}

	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const mask_conversion_case test_cases[] = {
		// VPMOVM2B/W/D/Q: vector destination, K source.
		{ { 0x62, 0xe2, 0x7e, 0x08, 0x28, 0xc1 },
		  X86_INS_VPMOVM2B,
		  X86_REG_XMM16,
		  X86_REG_K1,
		  16,
		  2 },
		{ { 0x62, 0xe2, 0x7e, 0x28, 0x28, 0xca },
		  X86_INS_VPMOVM2B,
		  X86_REG_YMM17,
		  X86_REG_K2,
		  32,
		  4 },
		{ { 0x62, 0x62, 0x7e, 0x48, 0x28, 0xff },
		  X86_INS_VPMOVM2B,
		  X86_REG_ZMM31,
		  X86_REG_K7,
		  64,
		  8 },
		{ { 0x62, 0xe2, 0xfe, 0x08, 0x28, 0xd3 },
		  X86_INS_VPMOVM2W,
		  X86_REG_XMM18,
		  X86_REG_K3,
		  16,
		  1 },
		{ { 0x62, 0xe2, 0xfe, 0x28, 0x28, 0xe5 },
		  X86_INS_VPMOVM2W,
		  X86_REG_YMM20,
		  X86_REG_K5,
		  32,
		  2 },
		{ { 0x62, 0x62, 0xfe, 0x48, 0x28, 0xf6 },
		  X86_INS_VPMOVM2W,
		  X86_REG_ZMM30,
		  X86_REG_K6,
		  64,
		  4 },
		{ { 0x62, 0xe2, 0x7e, 0x08, 0x38, 0xec },
		  X86_INS_VPMOVM2D,
		  X86_REG_XMM21,
		  X86_REG_K4,
		  16,
		  1 },
		{ { 0x62, 0xe2, 0x7e, 0x28, 0x38, 0xf5 },
		  X86_INS_VPMOVM2D,
		  X86_REG_YMM22,
		  X86_REG_K5,
		  32,
		  1 },
		{ { 0x62, 0x62, 0x7e, 0x48, 0x38, 0xef },
		  X86_INS_VPMOVM2D,
		  X86_REG_ZMM29,
		  X86_REG_K7,
		  64,
		  2 },
		{ { 0x62, 0xe2, 0xfe, 0x08, 0x38, 0xf9 },
		  X86_INS_VPMOVM2Q,
		  X86_REG_XMM23,
		  X86_REG_K1,
		  16,
		  1 },
		{ { 0x62, 0x62, 0xfe, 0x28, 0x38, 0xc2 },
		  X86_INS_VPMOVM2Q,
		  X86_REG_YMM24,
		  X86_REG_K2,
		  32,
		  1 },
		{ { 0x62, 0x62, 0xfe, 0x48, 0x38, 0xe6 },
		  X86_INS_VPMOVM2Q,
		  X86_REG_ZMM28,
		  X86_REG_K6,
		  64,
		  1 },

		// VPMOVB/W/D/Q2M: K destination, vector source.
		{ { 0x62, 0xb2, 0x7e, 0x08, 0x29, 0xc8 },
		  X86_INS_VPMOVB2M,
		  X86_REG_K1,
		  X86_REG_XMM16,
		  2,
		  16 },
		{ { 0x62, 0xb2, 0x7e, 0x28, 0x29, 0xd1 },
		  X86_INS_VPMOVB2M,
		  X86_REG_K2,
		  X86_REG_YMM17,
		  4,
		  32 },
		{ { 0x62, 0x92, 0x7e, 0x48, 0x29, 0xff },
		  X86_INS_VPMOVB2M,
		  X86_REG_K7,
		  X86_REG_ZMM31,
		  8,
		  64 },
		{ { 0x62, 0xb2, 0xfe, 0x08, 0x29, 0xda },
		  X86_INS_VPMOVW2M,
		  X86_REG_K3,
		  X86_REG_XMM18,
		  1,
		  16 },
		{ { 0x62, 0xb2, 0xfe, 0x28, 0x29, 0xec },
		  X86_INS_VPMOVW2M,
		  X86_REG_K5,
		  X86_REG_YMM20,
		  2,
		  32 },
		{ { 0x62, 0x92, 0xfe, 0x48, 0x29, 0xf6 },
		  X86_INS_VPMOVW2M,
		  X86_REG_K6,
		  X86_REG_ZMM30,
		  4,
		  64 },
		{ { 0x62, 0xb2, 0x7e, 0x08, 0x39, 0xe5 },
		  X86_INS_VPMOVD2M,
		  X86_REG_K4,
		  X86_REG_XMM21,
		  1,
		  16 },
		{ { 0x62, 0xb2, 0x7e, 0x28, 0x39, 0xee },
		  X86_INS_VPMOVD2M,
		  X86_REG_K5,
		  X86_REG_YMM22,
		  1,
		  32 },
		{ { 0x62, 0x92, 0x7e, 0x48, 0x39, 0xfd },
		  X86_INS_VPMOVD2M,
		  X86_REG_K7,
		  X86_REG_ZMM29,
		  2,
		  64 },
		{ { 0x62, 0xb2, 0xfe, 0x08, 0x39, 0xcf },
		  X86_INS_VPMOVQ2M,
		  X86_REG_K1,
		  X86_REG_XMM23,
		  1,
		  16 },
		{ { 0x62, 0x92, 0xfe, 0x28, 0x39, 0xd0 },
		  X86_INS_VPMOVQ2M,
		  X86_REG_K2,
		  X86_REG_YMM24,
		  1,
		  32 },
		{ { 0x62, 0x92, 0xfe, 0x48, 0x39, 0xf4 },
		  X86_INS_VPMOVQ2M,
		  X86_REG_K6,
		  X86_REG_ZMM28,
		  1,
		  64 },
	};
	static const cs_opt_value syntaxes[] = { CS_OPT_SYNTAX_INTEL,
						 CS_OPT_SYNTAX_ATT };
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "cs_open", 0, CS_OPT_SYNTAX_INTEL))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail", 0, CS_OPT_SYNTAX_INTEL)) {
		cs_close(&handle);
		return 1;
	}

	for (size_t syntax_index = 0;
	     syntax_index < sizeof(syntaxes) / sizeof(syntaxes[0]);
	     ++syntax_index) {
		cs_opt_value syntax = syntaxes[syntax_index];
		success &= check(cs_option(handle, CS_OPT_SYNTAX, syntax) ==
					 CS_ERR_OK,
				 "select syntax", 0, syntax);
		for (size_t i = 0;
		     i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
			success &= test_case(handle, &test_cases[i], i, syntax);
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

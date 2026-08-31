/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>

typedef struct kmask_case {
	uint8_t code[5];
	uint8_t code_size;
	x86_insn instruction;
	x86_reg operands[3];
	uint8_t operand_count;
	bool writes_destination;
} kmask_case;

static bool check(bool condition, const char *message, size_t case_index,
		  cs_opt_value syntax)
{
	if (!condition) {
		fprintf(stderr,
			"K-mask access check failed in case %zu (%s): %s\n",
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

static bool test_case(csh handle, const kmask_case *test, size_t case_index,
		      cs_opt_value syntax)
{
	static const uint64_t expected_test_flags =
		X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_ZF |
		X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_SF |
		X86_EFLAGS_RESET_AF | X86_EFLAGS_RESET_PF;
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	bool success = true;
	size_t count = cs_disasm(handle, test->code, test->code_size, 0x1000, 1,
				 &insn);

	if (!check(count == 1, "instruction decodes", case_index, syntax))
		return false;
	success &= check(insn[0].id == test->instruction,
			 "public instruction ID is exact", case_index, syntax);
	success &= check(insn[0].detail != NULL, "detail is available",
			 case_index, syntax);
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == test->operand_count,
				 "explicit operand count is exact", case_index,
				 syntax);
		for (uint8_t i = 0; i < test->operand_count; ++i) {
			const cs_x86_op *operand =
				find_register_operand(x86, test->operands[i]);
			uint8_t expected_access = test->writes_destination &&
								  i == 0 ?
							  CS_AC_WRITE :
							  CS_AC_READ;

			success &= check(operand != NULL,
					 "expected operand register is present",
					 case_index, syntax);
			if (operand != NULL)
				success &= check(operand->access ==
							 expected_access,
						 "operand access is exact",
						 case_index, syntax);
		}
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds", case_index, syntax);
		if (test->writes_destination) {
			success &= check(regs_read_count ==
						 test->operand_count - 1,
					 "source read count is exact",
					 case_index, syntax);
			success &= check(regs_write_count == 1,
					 "destination write count is exact",
					 case_index, syntax);
			success &=
				check(has_register(regs_write, regs_write_count,
						   test->operands[0]),
				      "destination is in regs_write",
				      case_index, syntax);
			for (uint8_t i = 1; i < test->operand_count; ++i) {
				success &= check(
					has_register(regs_read, regs_read_count,
						     test->operands[i]),
					"source is in regs_read", case_index,
					syntax);
			}
			success &=
				check(x86->eflags == 0,
				      "non-test instruction leaves flags alone",
				      case_index, syntax);
		} else {
			success &= check(regs_read_count == test->operand_count,
					 "test source read count is exact",
					 case_index, syntax);
			success &= check(regs_write_count == 1,
					 "only flags are written", case_index,
					 syntax);
			success &= check(
				has_register(regs_write, regs_write_count,
					     X86_REG_EFLAGS),
				"flags are in regs_write", case_index, syntax);
			for (uint8_t i = 0; i < test->operand_count; ++i) {
				success &= check(
					has_register(regs_read, regs_read_count,
						     test->operands[i]),
					"test operand is in regs_read",
					case_index, syntax);
			}
			success &= check(x86->eflags == expected_test_flags,
					 "flag effects are exact", case_index,
					 syntax);
		}
	}

	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const kmask_case test_cases[] = {
		{ { 0xc5, 0xed, 0x4a, 0xcb },
		  4,
		  X86_INS_KADDB,
		  { X86_REG_K1, X86_REG_K2, X86_REG_K3 },
		  3,
		  true },
		{ { 0xc5, 0xd4, 0x4a, 0xe6 },
		  4,
		  X86_INS_KADDW,
		  { X86_REG_K4, X86_REG_K5, X86_REG_K6 },
		  3,
		  true },
		{ { 0xc4, 0xe1, 0xf5, 0x4a, 0xfa },
		  5,
		  X86_INS_KADDD,
		  { X86_REG_K7, X86_REG_K1, X86_REG_K2 },
		  3,
		  true },
		{ { 0xc4, 0xe1, 0xdc, 0x4a, 0xdd },
		  5,
		  X86_INS_KADDQ,
		  { X86_REG_K3, X86_REG_K4, X86_REG_K5 },
		  3,
		  true },
		{ { 0xc5, 0xcd, 0x4b, 0xef },
		  4,
		  X86_INS_KUNPCKBW,
		  { X86_REG_K5, X86_REG_K6, X86_REG_K7 },
		  3,
		  true },
		{ { 0xc5, 0xc4, 0x4b, 0xf1 },
		  4,
		  X86_INS_KUNPCKWD,
		  { X86_REG_K6, X86_REG_K7, X86_REG_K1 },
		  3,
		  true },
		{ { 0xc4, 0xe1, 0xe4, 0x4b, 0xd4 },
		  5,
		  X86_INS_KUNPCKDQ,
		  { X86_REG_K2, X86_REG_K3, X86_REG_K4 },
		  3,
		  true },
		{ { 0xc5, 0xf9, 0x99, 0xca },
		  4,
		  X86_INS_KTESTB,
		  { X86_REG_K1, X86_REG_K2 },
		  2,
		  false },
		{ { 0xc5, 0xf8, 0x99, 0xdc },
		  4,
		  X86_INS_KTESTW,
		  { X86_REG_K3, X86_REG_K4 },
		  2,
		  false },
		{ { 0xc4, 0xe1, 0xf9, 0x99, 0xee },
		  5,
		  X86_INS_KTESTD,
		  { X86_REG_K5, X86_REG_K6 },
		  2,
		  false },
		{ { 0xc4, 0xe1, 0xf8, 0x99, 0xf9 },
		  5,
		  X86_INS_KTESTQ,
		  { X86_REG_K7, X86_REG_K1 },
		  2,
		  false },
		{ { 0xc5, 0xf9, 0x98, 0xd3 },
		  4,
		  X86_INS_KORTESTB,
		  { X86_REG_K2, X86_REG_K3 },
		  2,
		  false },
		{ { 0xc5, 0xf8, 0x98, 0xe5 },
		  4,
		  X86_INS_KORTESTW,
		  { X86_REG_K4, X86_REG_K5 },
		  2,
		  false },
		{ { 0xc4, 0xe1, 0xf9, 0x98, 0xf7 },
		  5,
		  X86_INS_KORTESTD,
		  { X86_REG_K6, X86_REG_K7 },
		  2,
		  false },
		{ { 0xc4, 0xe1, 0xf8, 0x98, 0xca },
		  5,
		  X86_INS_KORTESTQ,
		  { X86_REG_K1, X86_REG_K2 },
		  2,
		  false },
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

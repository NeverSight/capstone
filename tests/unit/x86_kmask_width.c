/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "K-mask operand-width check failed: %s\n", message);
	}
	return condition;
}

typedef struct mask_width_case {
	const uint8_t *code;
	size_t code_size;
	x86_insn instruction;
	const char *mnemonic;
	const char *registers[3];
	uint8_t operand_count;
	uint8_t operand_size;
} mask_width_case;

static bool test_mask_width(csh handle, const mask_width_case *test_case)
{
	cs_insn *insn = NULL;
	bool success = true;

	size_t count = cs_disasm(handle, test_case->code, test_case->code_size,
			 0x1000, 1, &insn);
	if (!check(count == 1, "instruction decodes")) {
		return false;
	}

	success &= check(insn[0].id == test_case->instruction,
			 "public instruction ID is correct");
	success &= check(strcmp(insn[0].mnemonic, test_case->mnemonic) == 0,
			 "mnemonic is correct");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		success &= check(x86->op_count == test_case->operand_count,
				 "explicit operand count is correct");
		if (x86->op_count == test_case->operand_count) {
			for (size_t i = 0; i < test_case->operand_count; ++i) {
				const cs_x86_op *operand = &x86->operands[i];
				success &= check(operand->type == X86_OP_REG,
						 "operand is a register");
				success &= check(strcmp(cs_reg_name(handle, operand->reg),
							test_case->registers[i]) == 0,
						 "operand register is correct");
				success &= check(operand->size ==
							test_case->operand_size,
						 "mask operand width follows suffix");
			}
		}
	}

	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const uint8_t kandb[] = { 0xc5, 0xd5, 0x41, 0xd6 };
	static const uint8_t kandw[] = { 0xc5, 0xd4, 0x41, 0xd6 };
	static const uint8_t kandd[] = { 0xc4, 0xe1, 0xd5, 0x41, 0xec };
	static const uint8_t kandq[] = { 0xc4, 0xe1, 0xf4, 0x41, 0xda };
	static const uint8_t kmovq[] = { 0xc4, 0xe1, 0xf8, 0x90, 0xd5 };
	static const uint8_t ktestq[] = { 0xc4, 0xe1, 0xf8, 0x99, 0xd6 };
	static const mask_width_case test_cases[] = {
		{ kandb, sizeof(kandb), X86_INS_KANDB, "kandb",
		  { "k2", "k5", "k6" }, 3, 1 },
		{ kandw, sizeof(kandw), X86_INS_KANDW, "kandw",
		  { "k2", "k5", "k6" }, 3, 2 },
		{ kandd, sizeof(kandd), X86_INS_KANDD, "kandd",
		  { "k5", "k5", "k4" }, 3, 4 },
		{ kandq, sizeof(kandq), X86_INS_KANDQ, "kandq",
		  { "k3", "k1", "k2" }, 3, 8 },
		{ kmovq, sizeof(kmovq), X86_INS_KMOVQ, "kmovq",
		  { "k2", "k5", NULL }, 2, 8 },
		{ ktestq, sizeof(ktestq), X86_INS_KTESTQ, "ktestq",
		  { "k2", "k6", NULL }, 2, 8 },
	};
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "cs_open")) {
		return 1;
	}
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			    CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i) {
		success &= test_mask_width(handle, &test_cases[i]);
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

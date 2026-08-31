/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct broadcast_case {
	uint8_t code[6];
	x86_insn instruction;
	const char *mnemonic;
	x86_reg destination;
	x86_reg source;
	uint8_t destination_size;
	uint8_t source_size;
	const char *intel_operands;
	const char *att_operands;
} broadcast_case;

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "VPBROADCAST mask source check failed: %s\n",
			message);
	return condition;
}

static bool has_register(const cs_regs registers, uint8_t count, x86_reg reg)
{
	uint8_t i;

	for (i = 0; i < count; ++i) {
		if (registers[i] == reg)
			return true;
	}
	return false;
}

static bool check_case(csh handle, const broadcast_case *test_case,
		       bool att_syntax)
{
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	const char *expected_operands = att_syntax ? test_case->att_operands :
						     test_case->intel_operands;
	uint8_t destination_index = att_syntax ? 1 : 0;
	uint8_t source_index = att_syntax ? 0 : 1;
	bool success = true;
	size_t count;

	count = cs_disasm(handle, test_case->code, sizeof(test_case->code),
			  0x1000, 1, &insn);
	if (!check(count == 1, "instruction decodes"))
		return false;
	success &= check(insn[0].id == test_case->instruction,
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, test_case->mnemonic) == 0,
			 "mnemonic is exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "operand order is exact");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == 2, "operand count is exact");
		success &= check(
			x86->operands[destination_index].type == X86_OP_REG &&
				x86->operands[destination_index].reg ==
					test_case->destination &&
				x86->operands[destination_index].size ==
					test_case->destination_size &&
				x86->operands[destination_index].access ==
					CS_AC_WRITE,
			"vector destination detail is exact");
		success &=
			check(x86->operands[source_index].type == X86_OP_REG &&
				      x86->operands[source_index].reg ==
					      test_case->source &&
				      x86->operands[source_index].size ==
					      test_case->source_size &&
				      x86->operands[source_index].access ==
					      CS_AC_READ,
			      "mask source width and access are exact");
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &=
			check(regs_read_count == 1 &&
				      has_register(regs_read, regs_read_count,
						   test_case->source),
			      "mask source is read");
		success &=
			check(regs_write_count == 1 &&
				      has_register(regs_write, regs_write_count,
						   test_case->destination),
			      "vector destination is written");
	}
	cs_free(insn, count);
	if (!success) {
		fprintf(stderr, "case: %s %s syntax=%s\n", test_case->mnemonic,
			expected_operands, att_syntax ? "att" : "intel");
	}
	return success;
}

int main(void)
{
	static const broadcast_case cases[] = {
		{ { 0x62, 0xf2, 0x7e, 0x08, 0x3a, 0xc1 },
		  X86_INS_VPBROADCASTMW2D,
		  "vpbroadcastmw2d",
		  X86_REG_XMM0,
		  X86_REG_K1,
		  16,
		  2,
		  "xmm0, k1",
		  "%k1, %xmm0" },
		{ { 0x62, 0xe2, 0x7e, 0x28, 0x3a, 0xc2 },
		  X86_INS_VPBROADCASTMW2D,
		  "vpbroadcastmw2d",
		  X86_REG_YMM16,
		  X86_REG_K2,
		  32,
		  2,
		  "ymm16, k2",
		  "%k2, %ymm16" },
		{ { 0x62, 0x62, 0x7e, 0x48, 0x3a, 0xff },
		  X86_INS_VPBROADCASTMW2D,
		  "vpbroadcastmw2d",
		  X86_REG_ZMM31,
		  X86_REG_K7,
		  64,
		  2,
		  "zmm31, k7",
		  "%k7, %zmm31" },
		{ { 0x62, 0xf2, 0xfe, 0x08, 0x2a, 0xc1 },
		  X86_INS_VPBROADCASTMB2Q,
		  "vpbroadcastmb2q",
		  X86_REG_XMM0,
		  X86_REG_K1,
		  16,
		  1,
		  "xmm0, k1",
		  "%k1, %xmm0" },
		{ { 0x62, 0xe2, 0xfe, 0x28, 0x2a, 0xc2 },
		  X86_INS_VPBROADCASTMB2Q,
		  "vpbroadcastmb2q",
		  X86_REG_YMM16,
		  X86_REG_K2,
		  32,
		  1,
		  "ymm16, k2",
		  "%k2, %ymm16" },
		{ { 0x62, 0x62, 0xfe, 0x48, 0x2a, 0xff },
		  X86_INS_VPBROADCASTMB2Q,
		  "vpbroadcastmb2q",
		  X86_REG_ZMM31,
		  X86_REG_K7,
		  64,
		  1,
		  "zmm31, k7",
		  "%k7, %zmm31" },
	};
	csh handle = 0;
	bool success = true;
	bool att_syntax;
	size_t i;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open x86-64 handle"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	for (att_syntax = false;; att_syntax = true) {
		success &= check(cs_option(handle, CS_OPT_SYNTAX,
					   att_syntax ? CS_OPT_SYNTAX_ATT :
							CS_OPT_SYNTAX_INTEL) ==
					 CS_ERR_OK,
				 "select syntax");
		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
			success &= check_case(handle, &cases[i], att_syntax);
			if (!success)
				break;
		}
		if (!success || att_syntax)
			break;
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

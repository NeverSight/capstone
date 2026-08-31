/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct compute_case {
	uint8_t code[5];
	x86_insn instruction;
	const char *mnemonic;
} compute_case;

typedef struct invalid_case {
	uint8_t code[6];
	uint8_t code_size;
	const char *message;
} invalid_case;

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "AMX FP8/TF32 check failed: %s\n", message);
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

static bool test_case(csh handle, const compute_case *test, bool att_syntax)
{
	static const x86_reg intel_registers[] = {
		X86_REG_TMM6,
		X86_REG_TMM5,
		X86_REG_TMM4,
	};
	static const uint8_t intel_access[] = {
		CS_AC_READ | CS_AC_WRITE,
		CS_AC_READ,
		CS_AC_READ,
	};
	static const x86_reg att_registers[] = {
		X86_REG_TMM4,
		X86_REG_TMM5,
		X86_REG_TMM6,
	};
	static const uint8_t att_access[] = {
		CS_AC_READ,
		CS_AC_READ,
		CS_AC_READ | CS_AC_WRITE,
	};
	const x86_reg *registers = att_syntax ? att_registers : intel_registers;
	const uint8_t *access = att_syntax ? att_access : intel_access;
	const char *operand_text = att_syntax ? "%tmm4, %tmm5, %tmm6" :
						"tmm6, tmm5, tmm4";
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	const char *public_name;
	bool success = true;
	size_t count = cs_disasm(handle, test->code, sizeof(test->code), 0x1000,
				 1, &insn);

	if (!check(count == 1, "AMX compute instruction decodes"))
		return false;
	public_name = cs_insn_name(handle, insn[0].id);
	success &= check(insn[0].id == test->instruction,
			 "AMX compute instruction has its own public ID");
	success &= check(public_name != NULL &&
				 strcmp(public_name, test->mnemonic) == 0,
			 "AMX compute instruction has its public name");
	success &= check(strcmp(insn[0].mnemonic, test->mnemonic) == 0,
			 "AMX compute mnemonic is exact");
	success &= check(strcmp(insn[0].op_str, operand_text) == 0,
			 "AMX compute operand text follows syntax");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->modrm == 0xf5 &&
					 x86->encoding.modrm_offset == 4,
				 "encoding detail is exact");
		success &= check(x86->op_count == 3,
				 "three tile operands are public");
		for (uint8_t i = 0; i < x86->op_count && i < 3; ++i) {
			success &= check(x86->operands[i].type == X86_OP_REG,
					 "tile operand is a register");
			success &= check(x86->operands[i].reg == registers[i],
					 "tile register order is exact");
			success &=
				check(x86->operands[i].size == 0,
				      "runtime-sized tile reports size zero");
			success &= check(x86->operands[i].access == access[i],
					 "tile access is exact");
		}
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &=
			check(regs_read_count == 3 &&
				      has_register(regs_read, regs_read_count,
						   X86_REG_TMM6) &&
				      has_register(regs_read, regs_read_count,
						   X86_REG_TMM5) &&
				      has_register(regs_read, regs_read_count,
						   X86_REG_TMM4),
			      "accumulator and both sources are read");
		success &=
			check(regs_write_count == 1 &&
				      has_register(regs_write, regs_write_count,
						   X86_REG_TMM6),
			      "only the accumulator is written");
	}

	cs_free(insn, count);
	return success;
}

static bool rejects(csh handle, const invalid_case *test)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, test->code, test->code_size, 0x1000, 1,
				 &insn);
	bool success = check(count == 0, test->message);

	if (count != 0)
		cs_free(insn, count);
	return success;
}

int main(void)
{
	static const compute_case test_cases[] = {
		{ { 0xc4, 0xe5, 0x58, 0xfd, 0xf5 },
		  X86_INS_TDPBF8PS,
		  "tdpbf8ps" },
		{ { 0xc4, 0xe5, 0x5b, 0xfd, 0xf5 },
		  X86_INS_TDPBHF8PS,
		  "tdpbhf8ps" },
		{ { 0xc4, 0xe5, 0x5a, 0xfd, 0xf5 },
		  X86_INS_TDPHBF8PS,
		  "tdphbf8ps" },
		{ { 0xc4, 0xe5, 0x59, 0xfd, 0xf5 },
		  X86_INS_TDPHF8PS,
		  "tdphf8ps" },
		{ { 0xc4, 0xe2, 0x59, 0x48, 0xf5 },
		  X86_INS_TMMULTF32PS,
		  "tmmultf32ps" },
		// VEX.X does not encode an operand for this register-only form.
		{ { 0xc4, 0xa5, 0x58, 0xfd, 0xf5 },
		  X86_INS_TDPBF8PS,
		  "tdpbf8ps" },
	};
	static const invalid_case invalid_cases[] = {
		{ { 0xc4, 0xe5, 0x58, 0xfd },
		  4,
		  "truncated FP8 encoding is rejected" },
		{ { 0xc4, 0x65, 0x58, 0xfd, 0xf5 },
		  5,
		  "extended FP8 destination is rejected" },
		{ { 0xc4, 0xc5, 0x58, 0xfd, 0xf5 },
		  5,
		  "extended FP8 source is rejected" },
		{ { 0xc4, 0xe5, 0xd8, 0xfd, 0xf5 }, 5, "FP8 W1 is rejected" },
		{ { 0xc4, 0xe5, 0x5c, 0xfd, 0xf5 },
		  5,
		  "FP8 non-128 VEX length is rejected" },
		{ { 0xc4, 0xe5, 0x38, 0xfd, 0xf5 },
		  5,
		  "out-of-range FP8 VEX tile is rejected" },
		{ { 0xc4, 0xe5, 0x58, 0xfd, 0x35 },
		  5,
		  "FP8 memory form is rejected" },
		{ { 0xc4, 0xe5, 0x58, 0xfd, 0xf6 },
		  5,
		  "FP8 destination and first source must differ" },
		{ { 0xc4, 0xe5, 0x48, 0xfd, 0xf5 },
		  5,
		  "FP8 destination and second source must differ" },
		{ { 0xc4, 0xe5, 0x58, 0xfd, 0xf4 },
		  5,
		  "FP8 source tiles must differ" },
		{ { 0xc4, 0xe2, 0x58, 0xfd, 0xf5 },
		  5,
		  "FP8 opcode on the wrong map is rejected" },
		{ { 0xc4, 0xe2, 0x58, 0x48, 0xf5 },
		  5,
		  "TF32 without the mandatory 66 prefix is rejected" },
		{ { 0xc4, 0xe2, 0x5a, 0x48, 0xf5 },
		  5,
		  "TF32 with F3 is rejected" },
		{ { 0xc4, 0xe2, 0x5b, 0x48, 0xf5 },
		  5,
		  "TF32 with F2 is rejected" },
		{ { 0xc4, 0xe5, 0x59, 0x48, 0xf5 },
		  5,
		  "TF32 opcode on the wrong map is rejected" },
		{ { 0xc4, 0xe2, 0xd9, 0x48, 0xf5 }, 5, "TF32 W1 is rejected" },
		{ { 0xc4, 0xe2, 0x5d, 0x48, 0xf5 },
		  5,
		  "TF32 non-128 VEX length is rejected" },
		{ { 0x66, 0xc4, 0xe5, 0x58, 0xfd, 0xf5 },
		  6,
		  "legacy 66 prefix before FP8 is rejected" },
		{ { 0xf2, 0xc4, 0xe5, 0x58, 0xfd, 0xf5 },
		  6,
		  "legacy F2 prefix before FP8 is rejected" },
		{ { 0xf3, 0xc4, 0xe5, 0x58, 0xfd, 0xf5 },
		  6,
		  "legacy F3 prefix before FP8 is rejected" },
		{ { 0xf0, 0xc4, 0xe5, 0x58, 0xfd, 0xf5 },
		  6,
		  "LOCK prefix before FP8 is rejected" },
		{ { 0x48, 0xc4, 0xe5, 0x58, 0xfd, 0xf5 },
		  6,
		  "REX prefix before FP8 is rejected" },
	};
	csh handle = 0;
	csh handle32 = 0;
	bool success = true;
	size_t i;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit mode"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		success &= test_case(handle, &test_cases[i], false);
	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "select AT&T syntax");
	for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		success &= test_case(handle, &test_cases[i], true);
	for (i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]); ++i)
		success &= rejects(handle, &invalid_cases[i]);

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle32) == CS_ERR_OK,
		   "open 32-bit mode")) {
		cs_close(&handle);
		return 1;
	}
	{
		const invalid_case mode32 = {
			{ 0xc4, 0xe5, 0x58, 0xfd, 0xf5 },
			5,
			"FP8 is rejected outside 64-bit mode",
		};
		success &= rejects(handle32, &mode32);
	}

	cs_close(&handle32);
	cs_close(&handle);
	return success ? 0 : 1;
}

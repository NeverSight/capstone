/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct row_case {
	const char *name;
	uint8_t code[9];
	uint8_t code_size;
	x86_insn id;
	const char *mnemonic;
	bool immediate;
	uint8_t encoding_offset;
} row_case;

static bool check(bool condition, const char *test, const char *message)
{
	if (!condition)
		fprintf(stderr, "AMX row check failed (%s): %s\n", test,
			message);
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

static bool test_case(csh handle, const row_case *test, bool att_syntax)
{
	const char *intel_operands = test->immediate ? "zmm31, tmm0, 0xa5" :
						       "zmm17, tmm6, r23d";
	const char *att_operands = test->immediate ? "$0xa5, %tmm0, %zmm31" :
						     "%r23d, %tmm6, %zmm17";
	const x86_reg expected_intel[] = {
		test->immediate ? X86_REG_ZMM31 : X86_REG_ZMM17,
		test->immediate ? X86_REG_TMM0 : X86_REG_TMM6,
		test->immediate ? X86_REG_INVALID : X86_REG_R23D,
	};
	const uint8_t expected_sizes[] = { 64, 0, test->immediate ? 1 : 4 };
	const uint8_t expected_access[] = { CS_AC_WRITE, CS_AC_READ,
					    CS_AC_READ };
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 }, regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	bool success = true;
	size_t count;

	success &=
		check(cs_option(handle, CS_OPT_SYNTAX,
				att_syntax ? CS_OPT_SYNTAX_ATT :
					     CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
		      test->name, "syntax selection succeeds");
	count = cs_disasm(handle, test->code, test->code_size, 0x1000, 1,
			  &insn);
	if (!check(count == 1, test->name, "instruction decodes"))
		return false;
	success &= check(insn[0].size == test->code_size, test->name,
			 "instruction size is exact");
	success &= check(insn[0].id == test->id, test->name,
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, test->mnemonic) == 0,
			 test->name, "mnemonic is exact");
	success &=
		check(strcmp(insn[0].op_str,
			     att_syntax ? att_operands : intel_operands) == 0,
		      test->name, "operand text is exact");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id),
				test->mnemonic) == 0,
			 test->name, "public instruction name is exact");
	success &= check(insn[0].detail != NULL, test->name,
			 "detail is available");
	if (insn[0].detail) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		uint8_t expected_prefix[4] = {
			0x62,
			test->code[test->encoding_offset + 1],
			test->code[test->encoding_offset + 2],
			test->code[test->encoding_offset + 3],
		};

		success &= check(memcmp(x86->opcode, expected_prefix, 4) == 0,
				 test->name, "EVEX bytes are preserved");
		success &= check(
			x86->prefix[1] == (test->encoding_offset ? 0x64 : 0) &&
				x86->prefix[3] ==
					(test->encoding_offset ? 0x67 : 0),
			test->name, "legacy prefix detail is exact");
		success &=
			check(x86->addr_size == (test->encoding_offset ? 4 : 8),
			      test->name, "address-size detail is exact");
		success &= check(
			x86->modrm == test->code[test->encoding_offset + 5] &&
				x86->encoding.modrm_offset ==
					test->encoding_offset + 5,
			test->name, "ModR/M detail is exact");
		success &= check(
			x86->encoding.imm_offset ==
					(test->immediate ?
						 test->encoding_offset + 6 :
						 0) &&
				x86->encoding.imm_size ==
					(test->immediate ? 1 : 0),
			test->name, "immediate detail is exact");
		success &= check(x86->op_count == 3, test->name,
				 "three explicit operands are public");
		for (uint8_t i = 0; i < x86->op_count && i < 3; ++i) {
			const uint8_t intel_index = att_syntax ? 2 - i : i;
			const cs_x86_op *operand = &x86->operands[i];

			if (test->immediate && intel_index == 2) {
				success &= check(operand->type == X86_OP_IMM &&
							 operand->imm == 0xa5,
						 test->name,
						 "row immediate is exact");
			} else {
				success &= check(
					operand->type == X86_OP_REG &&
						operand->reg ==
							expected_intel
								[intel_index],
					test->name,
					"register operand is exact");
			}
			success &= check(
				operand->size == expected_sizes[intel_index] &&
					operand->access ==
						expected_access[intel_index],
				test->name, "operand size/access is exact");
		}
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 test->name, "cs_regs_access succeeds");
		success &= check(has_register(regs_read, regs_read_count,
					      test->immediate ? X86_REG_TMM0 :
								X86_REG_TMM6),
				 test->name, "tile source is read");
		success &=
			check(test->immediate ||
				      has_register(regs_read, regs_read_count,
						   X86_REG_R23D),
			      test->name, "register row selector is read");
		success &= check(has_register(regs_write, regs_write_count,
					      test->immediate ? X86_REG_ZMM31 :
								X86_REG_ZMM17),
				 test->name, "ZMM destination is written");
	}
	cs_free(insn, count);
	return success;
}

static bool rejects(csh handle, const uint8_t *code, size_t code_size,
		    const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	bool success = check(count == 0, message, "encoding is rejected");

	if (count)
		cs_free(insn, count);
	return success;
}

int main(void)
{
	static const row_case cases[] = {
		{ "TCVTROWD2PS register",
		  { 0x62, 0xe2, 0x46, 0x40, 0x4a, 0xce },
		  6,
		  X86_INS_TCVTROWD2PS,
		  "tcvtrowd2ps",
		  false,
		  0 },
		{ "TCVTROWD2PS immediate",
		  { 0x62, 0x63, 0x7e, 0x48, 0x07, 0xf8, 0xa5 },
		  7,
		  X86_INS_TCVTROWD2PS,
		  "tcvtrowd2ps",
		  true,
		  0 },
		{ "TCVTROWPS2BF16H register",
		  { 0x62, 0xe2, 0x47, 0x40, 0x6d, 0xce },
		  6,
		  X86_INS_TCVTROWPS2BF16H,
		  "tcvtrowps2bf16h",
		  false,
		  0 },
		{ "TCVTROWPS2BF16H immediate",
		  { 0x62, 0x63, 0x7f, 0x48, 0x07, 0xf8, 0xa5 },
		  7,
		  X86_INS_TCVTROWPS2BF16H,
		  "tcvtrowps2bf16h",
		  true,
		  0 },
		{ "TCVTROWPS2BF16L register",
		  { 0x62, 0xe2, 0x46, 0x40, 0x6d, 0xce },
		  6,
		  X86_INS_TCVTROWPS2BF16L,
		  "tcvtrowps2bf16l",
		  false,
		  0 },
		{ "TCVTROWPS2BF16L immediate",
		  { 0x62, 0x63, 0x7e, 0x48, 0x77, 0xf8, 0xa5 },
		  7,
		  X86_INS_TCVTROWPS2BF16L,
		  "tcvtrowps2bf16l",
		  true,
		  0 },
		{ "TCVTROWPS2PHH register",
		  { 0x62, 0xe2, 0x44, 0x40, 0x6d, 0xce },
		  6,
		  X86_INS_TCVTROWPS2PHH,
		  "tcvtrowps2phh",
		  false,
		  0 },
		{ "TCVTROWPS2PHH immediate",
		  { 0x62, 0x63, 0x7c, 0x48, 0x07, 0xf8, 0xa5 },
		  7,
		  X86_INS_TCVTROWPS2PHH,
		  "tcvtrowps2phh",
		  true,
		  0 },
		{ "TCVTROWPS2PHL register",
		  { 0x62, 0xe2, 0x45, 0x40, 0x6d, 0xce },
		  6,
		  X86_INS_TCVTROWPS2PHL,
		  "tcvtrowps2phl",
		  false,
		  0 },
		{ "TCVTROWPS2PHL immediate",
		  { 0x62, 0x63, 0x7f, 0x48, 0x77, 0xf8, 0xa5 },
		  7,
		  X86_INS_TCVTROWPS2PHL,
		  "tcvtrowps2phl",
		  true,
		  0 },
		{ "TILEMOVROW register",
		  { 0x62, 0xe2, 0x45, 0x40, 0x4a, 0xce },
		  6,
		  X86_INS_TILEMOVROW,
		  "tilemovrow",
		  false,
		  0 },
		{ "TILEMOVROW ignored B4",
		  { 0x62, 0xea, 0x45, 0x40, 0x4a, 0xce },
		  6,
		  X86_INS_TILEMOVROW,
		  "tilemovrow",
		  false,
		  0 },
		{ "TILEMOVROW immediate prefixed",
		  { 0x64, 0x67, 0x62, 0x63, 0x7d, 0x48, 0x07, 0xf8, 0xa5 },
		  9,
		  X86_INS_TILEMOVROW,
		  "tilemovrow",
		  true,
		  2 },
	};
	static const uint8_t truncated_imm[] = { 0x62, 0x63, 0x7d,
						 0x48, 0x07, 0xf8 };
	static const uint8_t bad_w[] = { 0x62, 0xe2, 0xc5, 0x40, 0x4a, 0xce };
	static const uint8_t bad_u[] = { 0x62, 0xe2, 0x41, 0x40, 0x4a, 0xce };
	static const uint8_t bad_vl[] = { 0x62, 0xe2, 0x45, 0x28, 0x4a, 0xce };
	static const uint8_t bad_mask[] = { 0x62, 0xe2, 0x45, 0x41, 0x4a, 0xce };
	static const uint8_t bad_zeroing[] = { 0x62, 0xe2, 0x45,
					       0xc0, 0x4a, 0xce };
	static const uint8_t bad_bcast[] = {
		0x62, 0xe2, 0x45, 0x50, 0x4a, 0xce
	};
	static const uint8_t bad_tile_b3[] = { 0x62, 0xc2, 0x45,
					       0x40, 0x4a, 0xce };
	static const uint8_t bad_tile_x3[] = { 0x62, 0xa2, 0x45,
					       0x40, 0x4a, 0xce };
	static const uint8_t bad_memory[] = {
		0x62, 0xe2, 0x45, 0x40, 0x4a, 0x0e
	};
	static const uint8_t bad_imm_vvvv[] = { 0x62, 0x63, 0x75, 0x48,
						0x07, 0xf8, 0xa5 };
	static const uint8_t bad_imm_vprime[] = { 0x62, 0x63, 0x7d, 0x40,
						  0x07, 0xf8, 0xa5 };
	static const uint8_t legacy_lock[] = { 0xf0, 0x62, 0xe2, 0x45,
					       0x40, 0x4a, 0xce };
	static const uint8_t legacy_66[] = { 0x66, 0x62, 0xe2, 0x45,
					     0x40, 0x4a, 0xce };
	static const uint8_t legacy_rex[] = { 0x48, 0x62, 0xe2, 0x45,
					      0x40, 0x4a, 0xce };
	static const uint8_t too_long[] = {
		0x67, 0x67, 0x67, 0x67, 0x67, 0x67, 0x67, 0x67,
		0x67, 0x67, 0x62, 0xe2, 0x45, 0x40, 0x4a, 0xce,
	};
	static const struct {
		const uint8_t *code;
		size_t size;
		const char *name;
	} invalid[] = {
		{ truncated_imm, sizeof(truncated_imm), "truncated immediate" },
		{ bad_w, sizeof(bad_w), "EVEX.W" },
		{ bad_u, sizeof(bad_u), "EVEX.U" },
		{ bad_vl, sizeof(bad_vl), "EVEX.LL" },
		{ bad_mask, sizeof(bad_mask), "EVEX.aaa" },
		{ bad_zeroing, sizeof(bad_zeroing), "EVEX.z" },
		{ bad_bcast, sizeof(bad_bcast), "EVEX.b" },
		{ bad_tile_b3, sizeof(bad_tile_b3), "extended TMM B3" },
		{ bad_tile_x3, sizeof(bad_tile_x3), "extended TMM X3" },
		{ bad_memory, sizeof(bad_memory), "memory form" },
		{ bad_imm_vvvv, sizeof(bad_imm_vvvv), "imm EVEX.vvvv" },
		{ bad_imm_vprime, sizeof(bad_imm_vprime), "imm EVEX.V prime" },
		{ legacy_lock, sizeof(legacy_lock), "legacy LOCK" },
		{ legacy_66, sizeof(legacy_66), "legacy 66" },
		{ legacy_rex, sizeof(legacy_rex), "legacy REX" },
		{ too_long, sizeof(too_long),
		  "instruction longer than 15 bytes" },
	};
	csh handle64 = 0, handle32 = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle64) == CS_ERR_OK,
		   "64-bit mode", "handle opens"))
		return 1;
	if (!check(cs_option(handle64, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "64-bit mode", "detail enables")) {
		cs_close(&handle64);
		return 1;
	}
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		success &= test_case(handle64, &cases[i], false);
		success &= test_case(handle64, &cases[i], true);
	}
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
		success &= rejects(handle64, invalid[i].code, invalid[i].size,
				   invalid[i].name);
	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle32) == CS_ERR_OK,
		   "32-bit mode", "handle opens")) {
		cs_close(&handle64);
		return 1;
	}
	success &= rejects(handle32, cases[0].code, cases[0].code_size,
			   "64-bit mode requirement");
	cs_close(&handle32);
	cs_close(&handle64);
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "APX REX2 public API check failed: %s\n", message);
	}
	return condition;
}

typedef struct rex2_case {
	const uint8_t *code;
	size_t code_size;
	x86_insn instruction;
	const char *mnemonic;
	const char *op_str;
	x86_reg destination_reg;
	x86_reg source_reg;
	const char *destination;
	const char *source;
	uint8_t operand_size;
	uint8_t destination_access;
	uint8_t opcode;
	uint8_t modrm;
	uint8_t modrm_offset;
	bool operand_size_prefix;
	uint64_t eflags;
} rex2_case;

static bool has_register(const cs_regs registers, uint8_t count, x86_reg reg)
{
	for (uint8_t i = 0; i < count; ++i) {
		if (registers[i] == reg)
			return true;
	}
	return false;
}

static bool test_rex2_case(csh handle, const rex2_case *test_case)
{
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, test_case->code, test_case->code_size,
				 0x1000, 1, &insn);

	if (!check(count == 1, "REX2 instruction decodes"))
		return false;

	success &= check(insn[0].size == test_case->code_size,
			 "instruction size is correct");
	success &= check(insn[0].id == test_case->instruction,
			 "public instruction ID is correct");
	success &= check(strcmp(insn[0].mnemonic, test_case->mnemonic) == 0,
			 "mnemonic is correct");
	success &= check(strcmp(insn[0].op_str, test_case->op_str) == 0,
			 "operand text is correct");
	success &= check(insn[0].detail != NULL, "detail is available");

	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		cs_regs regs_read = { 0 };
		cs_regs regs_write = { 0 };
		uint8_t regs_read_count = 0;
		uint8_t regs_write_count = 0;
		uint8_t expected_read_count =
			test_case->destination_access & CS_AC_READ ? 2 : 1;
		uint8_t expected_write_count = test_case->eflags ? 2 : 1;

		success &= check(x86->op_count == 2, "two explicit operands");
		success &= check(x86->opcode[0] == test_case->opcode &&
					 x86->opcode[1] == 0 && x86->opcode[2] == 0 &&
					 x86->opcode[3] == 0,
				 "raw opcode is correct");
		success &= check(x86->modrm == test_case->modrm,
				 "raw ModR/M is correct");
		success &= check(x86->encoding.modrm_offset ==
					 test_case->modrm_offset,
				 "ModR/M offset is correct");
		success &= check(x86->prefix[2] ==
					 (test_case->operand_size_prefix ? 0x66 : 0),
				 "operand-size prefix detail is correct");
		success &= check(x86->eflags == test_case->eflags,
				 "EFLAGS effects are correct");
		if (x86->op_count == 2) {
			const cs_x86_op *destination = &x86->operands[0];
			const cs_x86_op *source = &x86->operands[1];
			success &= check(destination->type == X86_OP_REG &&
						 source->type == X86_OP_REG,
					 "both operands are registers");
			success &= check(destination->reg ==
						 test_case->destination_reg,
					 "destination register ID is correct");
			success &= check(source->reg == test_case->source_reg,
					 "source register ID is correct");
			success &= check(strcmp(cs_reg_name(handle, destination->reg),
						test_case->destination) == 0,
					 "destination register is correct");
			success &= check(strcmp(cs_reg_name(handle, source->reg),
						test_case->source) == 0,
					 "source register is correct");
			success &= check(destination->size == test_case->operand_size &&
						 source->size == test_case->operand_size,
					 "operand widths are correct");
			success &= check(destination->access ==
						test_case->destination_access,
					 "destination access is correct");
			success &= check(source->access == CS_AC_READ,
					 "source is read-only");
		}

		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(regs_read_count == expected_read_count,
				 "read register count is exact");
		success &= check(regs_write_count == expected_write_count,
				 "written register count is exact");
		if (x86->op_count == 2) {
			success &= check(has_register(regs_read, regs_read_count,
						      x86->operands[1].reg),
					 "source appears in read registers");
			success &= check(has_register(regs_write, regs_write_count,
						      x86->operands[0].reg),
					 "destination appears in written registers");
			if (test_case->destination_access & CS_AC_READ) {
				success &= check(has_register(regs_read, regs_read_count,
							      x86->operands[0].reg),
						 "read-write destination appears in reads");
			}
		}
		if (test_case->eflags) {
			success &= check(insn[0].detail->regs_write_count == 1 &&
						 insn[0].detail->regs_write[0] ==
							 X86_REG_EFLAGS,
					 "ADD has an implicit EFLAGS write");
			success &= check(has_register(regs_write, regs_write_count,
						      X86_REG_EFLAGS),
					 "EFLAGS appears in written registers");
		} else {
			success &= check(insn[0].detail->regs_write_count == 0,
					 "MOV has no implicit register writes");
		}
	}

	cs_free(insn, count);
	return success;
}

static bool test_register_names(csh handle)
{
	static const struct {
		x86_reg first;
		const char *suffix;
	} families[] = {
		{ X86_REG_R16, "" },
		{ X86_REG_R16B, "b" },
		{ X86_REG_R16D, "d" },
		{ X86_REG_R16W, "w" },
	};
	bool success = true;

	for (size_t family = 0; family < sizeof(families) / sizeof(families[0]);
	     ++family) {
		for (unsigned int number = 16; number <= 31; ++number) {
			char expected[8];
			x86_reg reg =
				families[family].first + (x86_reg)(number - 16);
			const char *actual = cs_reg_name(handle, reg);

			snprintf(expected, sizeof(expected), "r%u%s", number,
				 families[family].suffix);
			success &= check(actual != NULL,
					 "extended register has a public name");
			if (actual != NULL) {
				success &= check(strcmp(actual, expected) == 0,
						 "extended register name is exact");
			}
		}
	}
	return success;
}

static bool test_att_detail_order(csh handle)
{
	static const uint8_t addq[] = { 0xd5, 0x5d, 0x01, 0xc7 };
	cs_insn *insn = NULL;
	bool success = true;
	size_t count;

	if (!check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
			   CS_ERR_OK,
		   "select AT&T syntax")) {
		return false;
	}

	count = cs_disasm(handle, addq, sizeof(addq), 0x1000, 1, &insn);
	success &= check(count == 1, "REX2 instruction decodes in AT&T syntax");
	if (count == 1) {
		success &= check(strcmp(insn[0].mnemonic, "addq") == 0,
				 "AT&T mnemonic has the width suffix");
		success &= check(strcmp(insn[0].op_str, "%r24, %r31") == 0,
				 "AT&T operands use source-destination order");
		if (insn[0].detail != NULL) {
			const cs_x86 *x86 = &insn[0].detail->x86;
			cs_regs regs_read = { 0 };
			cs_regs regs_write = { 0 };
			uint8_t regs_read_count = 0;
			uint8_t regs_write_count = 0;

			success &= check(x86->op_count == 2,
					 "AT&T detail has two operands");
			if (x86->op_count == 2) {
				success &= check(x86->operands[0].reg == X86_REG_R24 &&
							 x86->operands[0].access ==
								 CS_AC_READ,
						 "AT&T source detail is first");
				success &= check(
					x86->operands[1].reg == X86_REG_R31 &&
						x86->operands[1].access ==
							(CS_AC_READ | CS_AC_WRITE),
						 "AT&T destination detail is second");
			}
			success &= check(cs_regs_access(handle, &insn[0], regs_read,
							&regs_read_count, regs_write,
							&regs_write_count) ==
						 CS_ERR_OK,
					 "AT&T cs_regs_access succeeds");
			success &= check(regs_read_count == 2 &&
						 has_register(regs_read, regs_read_count,
							      X86_REG_R24) &&
						 has_register(regs_read, regs_read_count,
							      X86_REG_R31),
					 "AT&T read set is exact");
			success &= check(regs_write_count == 2 &&
						 has_register(regs_write, regs_write_count,
							      X86_REG_R31) &&
						 has_register(regs_write, regs_write_count,
							      X86_REG_EFLAGS),
					 "AT&T write set is exact");
		}
	}

	cs_free(insn, count);
	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL) ==
				 CS_ERR_OK,
			 "restore Intel syntax");
	return success;
}

static bool test_invalid_rex2(csh handle, const uint8_t *code,
			      size_t code_size, const char *description)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (count != 0) {
		fprintf(stderr,
			"APX REX2 public API check failed: %s decoded as %s %s\n",
			description, insn[0].mnemonic, insn[0].op_str);
		cs_free(insn, count);
		return false;
	}
	return true;
}

static bool test_non64_aad_is_unchanged(void)
{
	static const uint8_t aad[] = { 0xd5, 0x0a };
	static const cs_mode modes[] = { CS_MODE_16, CS_MODE_32 };
	bool success = true;

	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
		csh handle = 0;
		cs_insn *insn = NULL;

		if (!check(cs_open(CS_ARCH_X86, modes[i], &handle) == CS_ERR_OK,
			   "open legacy x86 mode")) {
			success = false;
			continue;
		}

		size_t count =
			cs_disasm(handle, aad, sizeof(aad), 0x1000, 1, &insn);
		success &= check(count == 1,
				 "D5 remains AAD outside 64-bit mode");
		if (count == 1) {
			success &= check(insn[0].id == X86_INS_AAD,
					 "AAD public ID is kept");
			success &= check(insn[0].size == sizeof(aad),
					 "AAD size is kept");
		}

		cs_free(insn, count);
		cs_close(&handle);
	}
	return success;
}

int main(void)
{
	static const uint64_t add_eflags =
		X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
		X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
		X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
	static const uint8_t movb[] = { 0xd5, 0x55, 0x88, 0xca };
	static const uint8_t movw[] = { 0x66, 0xd5, 0x55, 0x89, 0xca };
	static const uint8_t movd[] = { 0xd5, 0x55, 0x89, 0xca };
	static const uint8_t movd_low_egpr[] = { 0xd5, 0x50, 0x89, 0xc1 };
	static const uint8_t movq[] = { 0xd5, 0x5d, 0x89, 0xca };
	static const uint8_t addb[] = { 0xd5, 0x55, 0x00, 0xc7 };
	static const uint8_t addw[] = { 0x66, 0xd5, 0x55, 0x01, 0xc7 };
	static const uint8_t addd[] = { 0xd5, 0x55, 0x01, 0xc7 };
	static const uint8_t addq[] = { 0xd5, 0x5d, 0x01, 0xc7 };
	static const rex2_case test_cases[] = {
		{ movb, sizeof(movb), X86_INS_MOV, "mov", "r26b, r25b",
		  X86_REG_R26B, X86_REG_R25B, "r26b", "r25b", 1,
		  CS_AC_WRITE, 0x88, 0xca, 3, false, 0 },
		{ movw, sizeof(movw), X86_INS_MOV, "mov", "r26w, r25w",
		  X86_REG_R26W, X86_REG_R25W, "r26w", "r25w", 2,
		  CS_AC_WRITE, 0x89, 0xca, 4, true, 0 },
		{ movd, sizeof(movd), X86_INS_MOV, "mov", "r26d, r25d",
		  X86_REG_R26D, X86_REG_R25D, "r26d", "r25d", 4,
		  CS_AC_WRITE, 0x89, 0xca, 3, false, 0 },
		{ movd_low_egpr, sizeof(movd_low_egpr), X86_INS_MOV, "mov",
		  "r17d, r16d", X86_REG_R17D, X86_REG_R16D, "r17d", "r16d",
		  4, CS_AC_WRITE, 0x89, 0xc1, 3, false, 0 },
		{ movq, sizeof(movq), X86_INS_MOV, "mov", "r26, r25",
		  X86_REG_R26, X86_REG_R25, "r26", "r25", 8, CS_AC_WRITE,
		  0x89, 0xca, 3, false, 0 },
		{ addb, sizeof(addb), X86_INS_ADD, "add", "r31b, r24b",
		  X86_REG_R31B, X86_REG_R24B, "r31b", "r24b", 1,
		  CS_AC_READ | CS_AC_WRITE, 0x00, 0xc7, 3, false,
		  add_eflags },
		{ addw, sizeof(addw), X86_INS_ADD, "add", "r31w, r24w",
		  X86_REG_R31W, X86_REG_R24W, "r31w", "r24w", 2,
		  CS_AC_READ | CS_AC_WRITE, 0x01, 0xc7, 4, true,
		  add_eflags },
		{ addd, sizeof(addd), X86_INS_ADD, "add", "r31d, r24d",
		  X86_REG_R31D, X86_REG_R24D, "r31d", "r24d", 4,
		  CS_AC_READ | CS_AC_WRITE, 0x01, 0xc7, 3, false,
		  add_eflags },
		{ addq, sizeof(addq), X86_INS_ADD, "add", "r31, r24",
		  X86_REG_R31, X86_REG_R24, "r31", "r24", 8,
		  CS_AC_READ | CS_AC_WRITE, 0x01, 0xc7, 3, false,
		  add_eflags },
	};
	static const uint8_t rex_before_rex2[] = { 0x48, 0xd5, 0x5d, 0x89,
						   0xca };
	static const uint8_t explicit_map_escape[] = { 0xd5, 0xdd, 0x0f,
						      0xaf, 0xd1 };
	static const uint8_t reserved_map0_row[] = { 0xd5, 0x50, 0x40, 0xc0 };
	static const uint8_t reserved_map1_row[] = { 0xd5, 0x80, 0x30, 0xc0 };
	static const uint8_t prefix_after_rex2[] = { 0xd5, 0x55, 0x66, 0x89,
						    0xca };
	static const uint8_t unsupported_sub[] = { 0xd5, 0x55, 0x29, 0xc7 };
	static const uint8_t unsupported_memory[] = { 0xd5, 0x10, 0x89, 0x00 };
	static const uint8_t truncated_rex2[] = { 0xd5, 0x55 };
	static const uint8_t legacy_aad_in_64[] = { 0xd5, 0x0a };
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit mode")) {
		return 1;
	}
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			    CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		success &= test_rex2_case(handle, &test_cases[i]);
	success &= test_register_names(handle);
	success &= test_att_detail_order(handle);
	success &= test_invalid_rex2(handle, rex_before_rex2,
				     sizeof(rex_before_rex2),
				     "REX before REX2 must fail closed");
	success &= test_invalid_rex2(handle, explicit_map_escape,
				     sizeof(explicit_map_escape),
				     "explicit 0F after REX2 must fail closed");
	success &= test_invalid_rex2(handle, reserved_map0_row,
				     sizeof(reserved_map0_row),
				     "reserved map-0 row must fail closed");
	success &= test_invalid_rex2(handle, reserved_map1_row,
				     sizeof(reserved_map1_row),
				     "reserved map-1 row must fail closed");
	success &= test_invalid_rex2(handle, prefix_after_rex2,
				     sizeof(prefix_after_rex2),
				     "legacy prefix after REX2 must fail closed");
	success &= test_invalid_rex2(handle, unsupported_sub,
				     sizeof(unsupported_sub),
				     "unimplemented REX2 opcode must fail closed");
	success &= test_invalid_rex2(handle, unsupported_memory,
				     sizeof(unsupported_memory),
				     "unimplemented REX2 memory form must fail closed");
	success &= test_invalid_rex2(handle, truncated_rex2,
				     sizeof(truncated_rex2),
				     "truncated REX2 must fail closed");
	success &= test_invalid_rex2(handle, legacy_aad_in_64,
				     sizeof(legacy_aad_in_64),
				     "legacy AAD must not decode in 64-bit mode");

	cs_close(&handle);
	success &= test_non64_aad_is_unchanged();
	return success ? 0 : 1;
}

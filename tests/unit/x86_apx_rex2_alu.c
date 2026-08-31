/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX REX2 ALU public API check failed: %s\n",
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

typedef struct rex2_expectation {
	x86_insn instruction;
	const char *mnemonic;
	const char *op_str;
	x86_reg first_reg;
	x86_reg second_reg;
	uint8_t first_access;
	uint8_t second_access;
	uint8_t operand_size;
	uint8_t opcode;
	uint8_t modrm;
	bool operand_size_prefix;
	uint64_t eflags;
} rex2_expectation;

static bool test_instruction(csh handle, const uint8_t *code, size_t code_size,
			     const rex2_expectation *expected)
{
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (!check(count == 1, "instruction decodes"))
		return false;

	success &= check(insn[0].size == code_size,
			 "instruction consumes the complete encoding");
	success &= check(insn[0].id == expected->instruction,
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected->mnemonic) == 0,
			 "mnemonic is exact");
	success &= check(strcmp(insn[0].op_str, expected->op_str) == 0,
			 "operand text is exact");
	success &= check(insn[0].detail != NULL, "detail is available");

	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		cs_regs regs_read = { 0 };
		cs_regs regs_write = { 0 };
		uint8_t regs_read_count = 0;
		uint8_t regs_write_count = 0;
		uint8_t expected_read_count =
			(expected->first_access & CS_AC_READ ? 1 : 0) +
			(expected->second_access & CS_AC_READ ? 1 : 0);
		uint8_t expected_write_count =
			(expected->first_access & CS_AC_WRITE ? 1 : 0) +
			(expected->second_access & CS_AC_WRITE ? 1 : 0) +
			(expected->eflags != 0 ? 1 : 0);

		success &= check(x86->op_count == 2,
				 "detail has two explicit operands");
		success &= check(x86->opcode[0] == expected->opcode &&
					 x86->opcode[1] == 0 && x86->opcode[2] == 0 &&
					 x86->opcode[3] == 0,
				 "raw opcode is exact");
		success &= check(x86->modrm == expected->modrm,
				 "raw ModR/M is exact");
		success &= check(x86->encoding.modrm_offset == code_size - 1,
				 "ModR/M offset is exact");
		success &= check(x86->prefix[2] ==
					 (expected->operand_size_prefix ? 0x66 : 0),
				 "operand-size prefix detail is exact");
		success &= check(x86->eflags == expected->eflags,
				 "EFLAGS effects are exact");

		if (x86->op_count == 2) {
			const cs_x86_op *first = &x86->operands[0];
			const cs_x86_op *second = &x86->operands[1];

			success &= check(first->type == X86_OP_REG &&
						 second->type == X86_OP_REG,
					 "both explicit operands are registers");
			success &= check(first->reg == expected->first_reg &&
						 second->reg == expected->second_reg,
					 "public register IDs are exact");
			success &= check(first->size == expected->operand_size &&
						 second->size == expected->operand_size,
					 "operand widths are exact");
			success &= check(first->access == expected->first_access &&
						 second->access == expected->second_access,
					 "operand access is exact");
		}

		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(regs_read_count == expected_read_count,
				 "read register count is exact");
		success &= check(regs_write_count == expected_write_count,
				 "written register count is exact");
		if (expected->first_access & CS_AC_READ) {
			success &= check(has_register(regs_read, regs_read_count,
						      expected->first_reg),
					 "first operand appears in reads");
		}
		if (expected->second_access & CS_AC_READ) {
			success &= check(has_register(regs_read, regs_read_count,
						      expected->second_reg),
					 "second operand appears in reads");
		}
		if (expected->first_access & CS_AC_WRITE) {
			success &= check(has_register(regs_write, regs_write_count,
						      expected->first_reg),
					 "first operand appears in writes");
		}
		if (expected->second_access & CS_AC_WRITE) {
			success &= check(has_register(regs_write, regs_write_count,
						      expected->second_reg),
					 "second operand appears in writes");
		}
		if (expected->eflags != 0) {
			success &= check(insn[0].detail->regs_write_count == 1 &&
						 insn[0].detail->regs_write[0] ==
							 X86_REG_EFLAGS,
					 "EFLAGS is the sole implicit write");
			success &= check(has_register(regs_write, regs_write_count,
						      X86_REG_EFLAGS),
					 "EFLAGS appears in writes");
		} else {
			success &= check(insn[0].detail->regs_write_count == 0,
					 "instruction has no implicit write");
		}
	}

	cs_free(insn, count);
	return success;
}

typedef struct rex2_binary_kind {
	x86_insn instruction;
	const char *mnemonic;
	uint8_t forward_byte_opcode;
	uint8_t forward_wide_opcode;
	uint8_t reverse_byte_opcode;
	uint8_t reverse_wide_opcode;
	uint8_t destination_access;
	uint64_t eflags;
} rex2_binary_kind;

static bool test_binary_matrix(csh handle, const rex2_binary_kind *kind)
{
	static const uint8_t widths[] = { 1, 2, 4, 8 };
	static const x86_reg reg_field[] = {
		X86_REG_R24B, X86_REG_R24W, X86_REG_R24D, X86_REG_R24
	};
	static const x86_reg rm_field[] = {
		X86_REG_R31B, X86_REG_R31W, X86_REG_R31D, X86_REG_R31
	};
	static const char *const reg_names[] = {
		"r24b", "r24w", "r24d", "r24"
	};
	static const char *const rm_names[] = {
		"r31b", "r31w", "r31d", "r31"
	};
	bool success = true;
	size_t width_index;

	for (width_index = 0; width_index < sizeof(widths); ++width_index) {
		unsigned int direction;

		for (direction = 0; direction < 2; ++direction) {
			uint8_t code[5];
			size_t code_size = 0;
			uint8_t width = widths[width_index];
			uint8_t opcode;
			bool reverse = direction != 0;
			char op_str[32];
			rex2_expectation expected;

			if (width == 2)
				code[code_size++] = 0x66;
			code[code_size++] = 0xd5;
			code[code_size++] = width == 8 ? 0x5d : 0x55;
			opcode = width == 1 ?
					 (reverse ? kind->reverse_byte_opcode :
						    kind->forward_byte_opcode) :
					 (reverse ? kind->reverse_wide_opcode :
						    kind->forward_wide_opcode);
			code[code_size++] = opcode;
			code[code_size++] = 0xc7;

			memset(&expected, 0, sizeof(expected));
			expected.instruction = kind->instruction;
			expected.mnemonic = kind->mnemonic;
			expected.first_reg = reverse ? reg_field[width_index] :
						       rm_field[width_index];
			expected.second_reg = reverse ? rm_field[width_index] :
							reg_field[width_index];
			expected.first_access = kind->destination_access;
			expected.second_access = CS_AC_READ;
			expected.operand_size = width;
			expected.opcode = opcode;
			expected.modrm = 0xc7;
			expected.operand_size_prefix = width == 2;
			expected.eflags = kind->eflags;
			snprintf(op_str, sizeof(op_str), "%s, %s",
				 reverse ? reg_names[width_index] : rm_names[width_index],
				 reverse ? rm_names[width_index] : reg_names[width_index]);
			expected.op_str = op_str;
			success &= test_instruction(handle, code, code_size, &expected);
		}
	}
	return success;
}

static bool test_test_matrix(csh handle, uint64_t logical_eflags)
{
	static const uint8_t widths[] = { 1, 2, 4, 8 };
	static const x86_reg first_regs[] = {
		X86_REG_R31B, X86_REG_R31W, X86_REG_R31D, X86_REG_R31
	};
	static const x86_reg second_regs[] = {
		X86_REG_R24B, X86_REG_R24W, X86_REG_R24D, X86_REG_R24
	};
	static const char *const op_strings[] = {
		"r31b, r24b", "r31w, r24w", "r31d, r24d", "r31, r24"
	};
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(widths); ++i) {
		uint8_t code[5];
		size_t code_size = 0;
		uint8_t width = widths[i];
		rex2_expectation expected;

		if (width == 2)
			code[code_size++] = 0x66;
		code[code_size++] = 0xd5;
		code[code_size++] = width == 8 ? 0x5d : 0x55;
		code[code_size++] = width == 1 ? 0x84 : 0x85;
		code[code_size++] = 0xc7;

		memset(&expected, 0, sizeof(expected));
		expected.instruction = X86_INS_TEST;
		expected.mnemonic = "test";
		expected.op_str = op_strings[i];
		expected.first_reg = first_regs[i];
		expected.second_reg = second_regs[i];
		expected.first_access = CS_AC_READ;
		expected.second_access = CS_AC_READ;
		expected.operand_size = width;
		expected.opcode = width == 1 ? 0x84 : 0x85;
		expected.modrm = 0xc7;
		expected.operand_size_prefix = width == 2;
		expected.eflags = logical_eflags;
		success &= test_instruction(handle, code, code_size, &expected);
	}
	return success;
}

static bool test_fixed_forms(csh handle, uint64_t add_eflags)
{
	static const uint8_t mov_low_byte[] = { 0xd5, 0x00, 0x88, 0xe5 };
	static const uint8_t add_rex_low_byte[] = { 0xd5, 0x05, 0x00, 0xc1 };
	static const uint8_t mov_egpr_from_low[] = { 0xd5, 0x40, 0x8b, 0xc0 };
	static const uint8_t mov_low_from_egpr[] = { 0xd5, 0x10, 0x8b, 0xc0 };
	static const uint8_t mov_byte_w_ignored[] = { 0xd5, 0x5d, 0x88, 0xc7 };
	static const uint8_t mov_byte_osize_ignored[] = {
		0x66, 0xd5, 0x55, 0x88, 0xc7
	};
	static const uint8_t add_w_overrides_osize[] = {
		0x66, 0xd5, 0x5d, 0x01, 0xc7
	};
	static const uint8_t mov_unused_x_bits[] = { 0xd5, 0x77, 0x89, 0xc7 };
	const rex2_expectation cases[] = {
		{ X86_INS_MOV, "mov", "bpl, spl", X86_REG_BPL, X86_REG_SPL,
		  CS_AC_WRITE, CS_AC_READ, 1, 0x88, 0xe5, false, 0 },
		{ X86_INS_ADD, "add", "r9b, r8b", X86_REG_R9B, X86_REG_R8B,
		  CS_AC_READ | CS_AC_WRITE, CS_AC_READ, 1, 0x00, 0xc1,
		  false, add_eflags },
		{ X86_INS_MOV, "mov", "r16d, eax", X86_REG_R16D, X86_REG_EAX,
		  CS_AC_WRITE, CS_AC_READ, 4, 0x8b, 0xc0, false, 0 },
		{ X86_INS_MOV, "mov", "eax, r16d", X86_REG_EAX, X86_REG_R16D,
		  CS_AC_WRITE, CS_AC_READ, 4, 0x8b, 0xc0, false, 0 },
		{ X86_INS_MOV, "mov", "r31b, r24b", X86_REG_R31B,
		  X86_REG_R24B, CS_AC_WRITE, CS_AC_READ, 1, 0x88, 0xc7, false,
		  0 },
		{ X86_INS_MOV, "mov", "r31b, r24b", X86_REG_R31B,
		  X86_REG_R24B, CS_AC_WRITE, CS_AC_READ, 1, 0x88, 0xc7, true,
		  0 },
		{ X86_INS_ADD, "add", "r31, r24", X86_REG_R31, X86_REG_R24,
		  CS_AC_READ | CS_AC_WRITE, CS_AC_READ, 8, 0x01, 0xc7, true,
		  add_eflags },
		{ X86_INS_MOV, "mov", "r31d, r24d", X86_REG_R31D,
		  X86_REG_R24D, CS_AC_WRITE, CS_AC_READ, 4, 0x89, 0xc7, false,
		  0 },
	};
	static const struct {
		const uint8_t *code;
		size_t size;
	} encodings[] = {
		{ mov_low_byte, sizeof(mov_low_byte) },
		{ add_rex_low_byte, sizeof(add_rex_low_byte) },
		{ mov_egpr_from_low, sizeof(mov_egpr_from_low) },
		{ mov_low_from_egpr, sizeof(mov_low_from_egpr) },
		{ mov_byte_w_ignored, sizeof(mov_byte_w_ignored) },
		{ mov_byte_osize_ignored, sizeof(mov_byte_osize_ignored) },
		{ add_w_overrides_osize, sizeof(add_w_overrides_osize) },
		{ mov_unused_x_bits, sizeof(mov_unused_x_bits) },
	};
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		success &= test_instruction(handle, encodings[i].code,
					    encodings[i].size, &cases[i]);
	return success;
}

static bool test_att_case(csh handle, const uint8_t *code, size_t code_size,
			  const char *mnemonic, const char *op_str,
			  x86_reg first_reg, uint8_t first_access,
			  x86_reg second_reg, uint8_t second_access)
{
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (!check(count == 1, "AT&T instruction decodes"))
		return false;
	success &= check(strcmp(insn[0].mnemonic, mnemonic) == 0,
			 "AT&T mnemonic is exact");
	success &= check(strcmp(insn[0].op_str, op_str) == 0,
			 "AT&T operand text is exact");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		success &= check(x86->op_count == 2,
				 "AT&T detail has two operands");
		if (x86->op_count == 2) {
			success &= check(x86->operands[0].reg == first_reg &&
						 x86->operands[0].access == first_access,
					 "AT&T first operand detail is exact");
			success &= check(x86->operands[1].reg == second_reg &&
						 x86->operands[1].access == second_access,
					 "AT&T second operand detail is exact");
		}
	} else {
		success &= check(false, "AT&T detail is available");
	}
	cs_free(insn, count);
	return success;
}

static bool test_att_syntax(csh handle)
{
	static const uint8_t reverse_subq[] = { 0xd5, 0x5d, 0x2b, 0xc7 };
	static const uint8_t reverse_cmpb[] = { 0xd5, 0x55, 0x3a, 0xc7 };
	static const uint8_t testw[] = { 0x66, 0xd5, 0x55, 0x85, 0xc7 };
	static const uint8_t low_movb[] = { 0xd5, 0x00, 0x88, 0xe5 };
	bool success = true;

	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "select AT&T syntax");
	success &= test_att_case(handle, reverse_subq, sizeof(reverse_subq),
				 "subq", "%r31, %r24", X86_REG_R31, CS_AC_READ,
				 X86_REG_R24, CS_AC_READ | CS_AC_WRITE);
	success &= test_att_case(handle, reverse_cmpb, sizeof(reverse_cmpb),
				 "cmpb", "%r31b, %r24b", X86_REG_R31B,
				 CS_AC_READ, X86_REG_R24B, CS_AC_READ);
	success &= test_att_case(handle, testw, sizeof(testw), "testw",
				 "%r24w, %r31w", X86_REG_R24W, CS_AC_READ,
				 X86_REG_R31W, CS_AC_READ);
	success &= test_att_case(handle, low_movb, sizeof(low_movb), "movb",
				 "%spl, %bpl", X86_REG_SPL, CS_AC_READ,
				 X86_REG_BPL, CS_AC_WRITE);
	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL) ==
				 CS_ERR_OK,
			 "restore Intel syntax");
	return success;
}

static bool test_invalid(csh handle, const uint8_t *code, size_t code_size,
			 const char *description)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (count != 0) {
		fprintf(stderr,
			"APX REX2 ALU public API check failed: %s decoded as %s %s\n",
			description, insn[0].mnemonic, insn[0].op_str);
		cs_free(insn, count);
		return false;
	}
	return true;
}

static bool test_fail_closed(csh handle)
{
	static const uint8_t rex_before_rex2[] = {
		0x48, 0xd5, 0x5d, 0x2b, 0xc7
	};
	static const uint8_t lock_register_add[] = {
		0xf0, 0xd5, 0x55, 0x01, 0xc7
	};
	static const uint8_t prefix_after_rex2[] = {
		0xd5, 0x55, 0x66, 0x89, 0xc7
	};
	static const uint8_t reserved_map0_row[] = {
		0xd5, 0x55, 0x40, 0xc7
	};
	static const uint8_t unsupported_map1[] = {
		0xd5, 0xd5, 0x01, 0xc7
	};
	static const uint8_t memory_form[] = { 0xd5, 0x55, 0x29, 0x07 };
	static const uint8_t truncated[] = { 0xd5, 0x55, 0x2b };
	static const uint8_t evex_ndd[] = {
		0x62, 0xf4, 0x2c, 0x18, 0x31, 0xca
	};
	static const uint8_t evex_nf[] = {
		0x62, 0xf4, 0x7c, 0x0c, 0x30, 0xd9
	};
	bool success = true;

	success &= test_invalid(handle, rex_before_rex2,
				sizeof(rex_before_rex2),
				"REX before REX2 must fail closed");
	success &= test_invalid(handle, lock_register_add,
				sizeof(lock_register_add),
				"LOCK on a register destination must fail closed");
	success &= test_invalid(handle, prefix_after_rex2,
				sizeof(prefix_after_rex2),
				"a prefix after REX2 must fail closed");
	success &= test_invalid(handle, reserved_map0_row,
				sizeof(reserved_map0_row),
				"a reserved map-0 row must fail closed");
	success &= test_invalid(handle, unsupported_map1,
				sizeof(unsupported_map1),
				"an unimplemented map-1 opcode must fail closed");
	success &= test_invalid(handle, memory_form, sizeof(memory_form),
				"an unimplemented memory form must fail closed");
	success &= test_invalid(handle, truncated, sizeof(truncated),
				"a truncated REX2 instruction must fail closed");
	success &= test_invalid(handle, evex_ndd, sizeof(evex_ndd),
				"EVEX NDD remains outside this decoder slice");
	success &= test_invalid(handle, evex_nf, sizeof(evex_nf),
				"EVEX NF remains outside this decoder slice");
	return success;
}

static bool test_non64_aad(void)
{
	static const uint8_t aad[] = { 0xd5, 0x0a };
	static const cs_mode modes[] = { CS_MODE_16, CS_MODE_32 };
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
		csh handle = 0;
		cs_insn *insn = NULL;
		size_t count;

		if (!check(cs_open(CS_ARCH_X86, modes[i], &handle) == CS_ERR_OK,
			   "open legacy x86 mode")) {
			success = false;
			continue;
		}
		count = cs_disasm(handle, aad, sizeof(aad), 0x1000, 1, &insn);
		success &= check(count == 1 && insn[0].id == X86_INS_AAD &&
					 insn[0].size == sizeof(aad),
				 "D5 remains AAD outside 64-bit mode");
		cs_free(insn, count);
		cs_close(&handle);
	}
	return success;
}

int main(void)
{
	static const uint64_t arithmetic_eflags =
		X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
		X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
		X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
	static const uint64_t logical_eflags =
		X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
		X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
		X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
	static const rex2_binary_kind kinds[] = {
		{ X86_INS_MOV, "mov", 0x88, 0x89, 0x8a, 0x8b, CS_AC_WRITE,
		  0 },
		{ X86_INS_ADD, "add", 0x00, 0x01, 0x02, 0x03,
		  CS_AC_READ | CS_AC_WRITE, arithmetic_eflags },
		{ X86_INS_OR, "or", 0x08, 0x09, 0x0a, 0x0b,
		  CS_AC_READ | CS_AC_WRITE, logical_eflags },
		{ X86_INS_AND, "and", 0x20, 0x21, 0x22, 0x23,
		  CS_AC_READ | CS_AC_WRITE, logical_eflags },
		{ X86_INS_SUB, "sub", 0x28, 0x29, 0x2a, 0x2b,
		  CS_AC_READ | CS_AC_WRITE, arithmetic_eflags },
		{ X86_INS_XOR, "xor", 0x30, 0x31, 0x32, 0x33,
		  CS_AC_READ | CS_AC_WRITE, logical_eflags },
		{ X86_INS_CMP, "cmp", 0x38, 0x39, 0x3a, 0x3b, CS_AC_READ,
		  arithmetic_eflags },
	};
	csh handle = 0;
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

	for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i)
		success &= test_binary_matrix(handle, &kinds[i]);
	success &= test_test_matrix(handle, logical_eflags);
	success &= test_fixed_forms(handle, arithmetic_eflags);
	success &= test_att_syntax(handle);
	success &= test_fail_closed(handle);
	cs_close(&handle);
	success &= test_non64_aad();
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct compare_family {
	x86_insn instruction;
	const char *mnemonic;
	uint8_t opcode;
	uint8_t w;
	uint8_t element_size;
} compare_family;

typedef struct vector_length {
	uint8_t evex_length;
	uint8_t size;
	const char *name;
} vector_length;

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "EVEX compare mask-size check failed: %s\n",
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

static uint8_t expected_mask_size(uint8_t vector_size, uint8_t element_size)
{
	unsigned int lanes = vector_size / element_size;
	unsigned int bytes = (lanes + 7) / 8;

	if (bytes <= 1)
		return 1;
	if (bytes <= 2)
		return 2;
	if (bytes <= 4)
		return 4;
	return 8;
}

static bool test_case(csh handle, const compare_family *family,
		      const vector_length *length, uint8_t predicate,
		      const char *syntax)
{
	// With VPCMPD, ZMM and predicate 3/7 these are respectively
	// 62 f3 6d 48 1f cb 03 and 62 f3 6d 48 1f cb 07.
	uint8_t code[] = { 0x62, 0xf3, 0x6d, 0x08,
			   0x1f, 0xcb, 0x03 };
	cs_insn *insn = NULL;
	bool success = true;
	size_t count;
	uint8_t expected_width =
		expected_mask_size(length->size, family->element_size);

	code[2] |= family->w ? 0x80 : 0;
	code[3] = length->evex_length;
	code[4] = family->opcode;
	code[6] = predicate;
	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (count != 1) {
		fprintf(stderr,
			"EVEX compare mask-size check failed: %s %s predicate %u did not decode\n",
			family->mnemonic, length->name, predicate);
		return false;
	}

	success &= check(insn[0].size == sizeof(code),
			 "instruction consumes the complete encoding");
	success &= check(insn[0].id == family->instruction,
			 "public instruction family ID is exact");
	success &= check(strcmp(insn[0].mnemonic, family->mnemonic) == 0,
			 "generic FALSE/TRUE mnemonic is preserved");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		const cs_x86_op *mask = NULL;
		const cs_x86_op *immediate = NULL;
		cs_regs regs_read = { 0 };
		cs_regs regs_write = { 0 };
		uint8_t regs_read_count = 0;
		uint8_t regs_write_count = 0;
		uint8_t vector_count = 0;
		uint8_t i;

		for (i = 0; i < x86->op_count; ++i) {
			const cs_x86_op *operand = &x86->operands[i];

			if (operand->type == X86_OP_REG &&
			    operand->reg == X86_REG_K1) {
				mask = operand;
			} else if (operand->type == X86_OP_REG &&
				   ((operand->reg >= X86_REG_XMM0 &&
				     operand->reg <= X86_REG_XMM31) ||
				    (operand->reg >= X86_REG_YMM0 &&
				     operand->reg <= X86_REG_YMM31) ||
				    (operand->reg >= X86_REG_ZMM0 &&
				     operand->reg <= X86_REG_ZMM31))) {
				++vector_count;
				success &= check(operand->size == length->size,
						 "vector operand size is exact");
			} else if (operand->type == X86_OP_IMM) {
				immediate = operand;
			}
		}
		success &= check(x86->op_count == 4,
				 "generic predicate exposes four operands");
		success &= check(vector_count == 2,
				 "both vector operands are present");
		success &= check(mask != NULL, "K1 destination operand is present");
		if (mask != NULL) {
			if (mask->size != expected_width) {
				fprintf(stderr,
					"EVEX compare mask-size check failed: %s %s predicate %u in %s syntax reports K1 size %u, expected %u\n",
					family->mnemonic, length->name, predicate,
					syntax, (unsigned int)mask->size,
					(unsigned int)expected_width);
				success = false;
			}
			success &= check(mask->access == CS_AC_WRITE,
					 "K1 is a write-only result");
		}
		success &= check(immediate != NULL &&
					 immediate->imm == predicate,
				 "generic predicate immediate is exact");
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(has_register(regs_write, regs_write_count,
					      X86_REG_K1),
				 "K1 appears in the write set");
	}

	cs_free(insn, count);
	return success;
}

static bool run_matrix(csh handle, const char *syntax)
{
	static const compare_family families[] = {
		{ X86_INS_VPCMPB, "vpcmpb", 0x3f, 0, 1 },
		{ X86_INS_VPCMPUB, "vpcmpub", 0x3e, 0, 1 },
		{ X86_INS_VPCMPW, "vpcmpw", 0x3f, 1, 2 },
		{ X86_INS_VPCMPUW, "vpcmpuw", 0x3e, 1, 2 },
		{ X86_INS_VPCMPD, "vpcmpd", 0x1f, 0, 4 },
		{ X86_INS_VPCMPUD, "vpcmpud", 0x1e, 0, 4 },
		{ X86_INS_VPCMPQ, "vpcmpq", 0x1f, 1, 8 },
		{ X86_INS_VPCMPUQ, "vpcmpuq", 0x1e, 1, 8 },
	};
	static const vector_length lengths[] = {
		{ 0x08, 16, "XMM" },
		{ 0x28, 32, "YMM" },
		{ 0x48, 64, "ZMM" },
	};
	static const uint8_t predicates[] = { 3, 7 };
	bool success = true;
	size_t family, length, predicate;

	for (family = 0; family < sizeof(families) / sizeof(families[0]);
	     ++family) {
		for (length = 0; length < sizeof(lengths) / sizeof(lengths[0]);
		     ++length) {
			for (predicate = 0;
			     predicate < sizeof(predicates) / sizeof(predicates[0]);
			     ++predicate) {
				success &= test_case(handle, &families[family],
						     &lengths[length],
						     predicates[predicate], syntax);
			}
		}
	}
	return success;
}

int main(void)
{
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit mode"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			    CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	success &= run_matrix(handle, "Intel");
	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "select AT&T syntax");
	success &= run_matrix(handle, "AT&T");
	cs_close(&handle);
	return success ? 0 : 1;
}

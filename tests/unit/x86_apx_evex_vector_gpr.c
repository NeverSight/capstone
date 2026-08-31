/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct vector_gpr_case {
	const char *name;
	uint8_t code[6];
	x86_insn instruction;
	const char *mnemonic;
	x86_reg destination;
	x86_reg source;
	uint8_t vector_size;
	uint8_t element_size;
	x86_reg mask;
	bool zeroing;
	const char *intel_operands;
	const char *att_operands;
} vector_gpr_case;

static bool check(bool condition, const char *name, const char *message)
{
	if (!condition)
		fprintf(stderr, "%s: %s\n", name, message);
	return condition;
}

static bool has_register(const cs_regs registers, uint8_t count, x86_reg reg)
{
	uint8_t index;

	for (index = 0; index < count; ++index) {
		if (registers[index] == reg)
			return true;
	}
	return false;
}

static bool check_case(csh handle, const vector_gpr_case *test_case,
		       bool att_syntax)
{
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	const char *expected_operands = att_syntax ? test_case->att_operands :
						     test_case->intel_operands;
	bool success = true;
	size_t count = cs_disasm(handle, test_case->code,
				 sizeof(test_case->code), 0x1000, 1, &insn);

	if (!check(count == 1, test_case->name, "instruction decodes"))
		return false;
	success &= check(insn[0].id == test_case->instruction, test_case->name,
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, test_case->mnemonic) == 0,
			 test_case->name, "mnemonic is exact");
	if (strcmp(insn[0].op_str, expected_operands) != 0) {
		fprintf(stderr, "%s: operands were '%s', expected '%s'\n",
			test_case->name, insn[0].op_str, expected_operands);
		success = false;
	}
	success &= check(insn[0].detail != NULL, test_case->name,
			 "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		const uint8_t expected_count = test_case->mask == X86_REG_INVALID ?
						       2 :
						       3;
		const uint8_t source_index = att_syntax ? 0 : expected_count - 1;
		const uint8_t destination_index = att_syntax ? expected_count - 1 : 0;
		const uint8_t mask_index = 1;

		success &= check(x86->op_count == expected_count, test_case->name,
				 "operand count is exact");
		success &= check(
			x86->operands[destination_index].type == X86_OP_REG &&
				x86->operands[destination_index].reg ==
					test_case->destination &&
				x86->operands[destination_index].size ==
					test_case->vector_size &&
				x86->operands[destination_index].access ==
					(test_case->mask != X86_REG_INVALID &&
						 !test_case->zeroing ?
							 CS_AC_READ | CS_AC_WRITE :
							 CS_AC_WRITE),
			test_case->name, "destination detail is exact");
		success &= check(
			x86->operands[source_index].type == X86_OP_REG &&
				x86->operands[source_index].reg == test_case->source &&
				x86->operands[source_index].size ==
					(test_case->element_size == 8 ? 8 : 4) &&
				x86->operands[source_index].access == CS_AC_READ,
			test_case->name, "extended GPR source detail is exact");
		if (test_case->mask != X86_REG_INVALID) {
			const uint8_t lanes =
				test_case->vector_size / test_case->element_size;
			const uint8_t mask_size = (lanes + 7) / 8;

			success &= check(
				x86->operands[mask_index].type == X86_OP_REG &&
					x86->operands[mask_index].reg == test_case->mask &&
					x86->operands[mask_index].size == mask_size &&
					x86->operands[mask_index].access == CS_AC_READ &&
					x86->operands[mask_index].avx_zero_opmask ==
						test_case->zeroing,
				test_case->name, "writemask detail is exact");
		}
		success &= check(
			cs_regs_access(handle, &insn[0], regs_read, &regs_read_count,
				       regs_write, &regs_write_count) == CS_ERR_OK,
			test_case->name, "register access query succeeds");
		success &= check(has_register(regs_read, regs_read_count,
					      test_case->source),
				 test_case->name, "source is reported read");
		success &= check(has_register(regs_write, regs_write_count,
					      test_case->destination),
				 test_case->name, "destination is reported written");
	}

	cs_free(insn, count);
	return success;
}

static bool rejects(csh handle, const uint8_t code[6], cs_mode mode,
		    const char *name)
{
	cs_insn *insn = NULL;
	size_t count;
	csh local_handle = handle;

	if (mode != CS_MODE_64) {
		if (cs_open(CS_ARCH_X86, mode, &local_handle) != CS_ERR_OK)
			return false;
	}
	count = cs_disasm(local_handle, code, 6, 0x1000, 1, &insn);
	cs_free(insn, count);
	if (mode != CS_MODE_64)
		cs_close(&local_handle);
	return check(count == 0, name, "reserved encoding is rejected");
}

int main(void)
{
	static const vector_gpr_case cases[] = {
		{ "byte-xmm", { 0x62, 0x4a, 0x7d, 0x08, 0x7a, 0xf5 },
		  X86_INS_VPBROADCASTB, "vpbroadcastb", X86_REG_XMM30,
		  X86_REG_R29D, 16, 1, X86_REG_INVALID, false,
		  "xmm30, r29d", "%r29d, %xmm30" },
		{ "word-ymm-merge", { 0x62, 0x4a, 0x7d, 0x2f, 0x7b, 0xf5 },
		  X86_INS_VPBROADCASTW, "vpbroadcastw", X86_REG_YMM30,
		  X86_REG_R29D, 32, 2, X86_REG_K7, false,
		  "ymm30 {k7}, r29d", "%r29d, %ymm30 {%k7}" },
		{ "dword-zmm-zero", { 0x62, 0x4a, 0x7d, 0xcf, 0x7c, 0xf5 },
		  X86_INS_VPBROADCASTD, "vpbroadcastd", X86_REG_ZMM30,
		  X86_REG_R29D, 64, 4, X86_REG_K7, true,
		  "zmm30 {k7} {z}, r29d", "%r29d, %zmm30 {%k7} {z}" },
		{ "qword-zmm-merge", { 0x62, 0x4a, 0xfd, 0x4f, 0x7c, 0xf5 },
		  X86_INS_VPBROADCASTQ, "vpbroadcastq", X86_REG_ZMM30,
		  X86_REG_R29, 64, 8, X86_REG_K7, false,
		  "zmm30 {k7}, r29", "%r29, %zmm30 {%k7}" },
	};
	static const uint8_t zero_without_mask[] = {
		0x62, 0x4a, 0x7d, 0x88, 0x7c, 0xf5
	};
	static const uint8_t embedded_broadcast[] = {
		0x62, 0x4a, 0x7d, 0x18, 0x7c, 0xf5
	};
	static const uint8_t missing_fixed_bit[] = {
		0x62, 0x4a, 0x79, 0x08, 0x7c, 0xf5
	};
	csh handle = 0;
	bool success = true;
	bool att_syntax;
	size_t index;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "setup", "open x86-64 handle"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "setup", "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	for (att_syntax = false;; att_syntax = true) {
		success &= check(cs_option(handle, CS_OPT_SYNTAX,
					   att_syntax ? CS_OPT_SYNTAX_ATT :
							CS_OPT_SYNTAX_INTEL) ==
					 CS_ERR_OK,
				 "setup", "select syntax");
		for (index = 0; index < sizeof(cases) / sizeof(cases[0]);
		     ++index)
			success &= check_case(handle, &cases[index], att_syntax);
		if (att_syntax)
			break;
	}

	success &= rejects(handle, zero_without_mask, CS_MODE_64,
			   "zero-without-mask");
	success &= rejects(handle, embedded_broadcast, CS_MODE_64,
			   "reserved-broadcast-bit");
	success &= rejects(handle, missing_fixed_bit, CS_MODE_64,
			   "missing-fixed-bit");
	success &= rejects(handle, cases[2].code, CS_MODE_32,
			   "extended-gpr-outside-64-bit");

	cs_close(&handle);
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "EVEX public detail check failed: %s\n",
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

static bool test_broadcast(csh handle)
{
	typedef struct broadcast_case {
		const char *name;
		uint8_t code[6];
		x86_insn id;
		x86_avx_bcast broadcast;
		uint8_t memory_size;
		x86_reg base;
		const char *text;
	} broadcast_case;
	static const broadcast_case cases[] = {
		{ "VPADDD dword",
		  { 0x62, 0xf1, 0x6d, 0x58, 0xfe, 0x00 },
		  X86_INS_VPADDD,
		  X86_AVX_BCAST_16,
		  4,
		  X86_REG_RAX,
		  "{1to16}" },
		{ "VPUNPCKLDQ dword",
		  { 0x62, 0xf1, 0x65, 0xda, 0x62, 0x08 },
		  X86_INS_VPUNPCKLDQ,
		  X86_AVX_BCAST_16,
		  4,
		  X86_REG_RAX,
		  "{1to16}" },
		{ "VPUNPCKLQDQ qword",
		  { 0x62, 0xd1, 0xd5, 0x5b, 0x6c, 0x20 },
		  X86_INS_VPUNPCKLQDQ,
		  X86_AVX_BCAST_8,
		  8,
		  X86_REG_R8,
		  "{1to8}" },
	};
	bool success = true;
	for (size_t case_index = 0;
	     case_index < sizeof(cases) / sizeof(cases[0]); ++case_index) {
		const broadcast_case *test = &cases[case_index];
		cs_insn *insn = NULL;
		size_t count = cs_disasm(handle, test->code, sizeof(test->code),
					 0x1000, 1, &insn);

		if (count != 1) {
			fprintf(stderr,
				"EVEX public detail check failed (%s): instruction does not decode\n",
				test->name);
			success = false;
			continue;
		}
		success &= check(insn[0].id == test->id,
				 "broadcast instruction ID is exact");
		success &= check(strstr(insn[0].op_str, test->text) != NULL,
				 "broadcast is present in operand text");
		success &= check(insn[0].detail != NULL,
				 "broadcast detail is available");
		if (insn[0].detail != NULL) {
			const cs_x86 *x86 = &insn[0].detail->x86;
			const cs_x86_op *memory = NULL;

			for (uint8_t i = 0; i < x86->op_count; ++i) {
				const cs_x86_op *operand = &x86->operands[i];

				if (operand->type == X86_OP_MEM) {
					memory = operand;
				} else {
					success &= check(
						operand->avx_bcast ==
							X86_AVX_BCAST_INVALID,
						"broadcast is attached only to memory");
				}
			}
			success &= check(memory != NULL,
					 "broadcast memory operand exists");
			if (memory != NULL) {
				success &= check(
					memory->size == test->memory_size,
					"broadcast reads one source element");
				success &=
					check(memory->mem.base == test->base,
					      "broadcast memory base is exact");
				success &= check(
					memory->avx_bcast == test->broadcast,
					"structured broadcast count is exact");
			}
		}
		cs_free(insn, count);
	}
	return success;
}

static bool test_mask_width(csh handle, const uint8_t *code, size_t code_size,
			    x86_insn expected_id, uint8_t expected_width,
			    bool zeroing)
{
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (!check(count == 1, "masked VMOVDQU decodes"))
		return false;
	success &= check(insn[0].id == expected_id,
			 "masked instruction ID matches its element width");
	success &= check(strstr(insn[0].op_str, "{k3}") != NULL,
			 "mask is present in operand text");
	success &= check((strstr(insn[0].op_str, "{z}") != NULL) == zeroing,
			 "zeroing text matches EVEX.z");
	success &= check(insn[0].detail != NULL, "mask detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		const cs_x86_op *mask = NULL;
		cs_regs regs_read = { 0 };
		cs_regs regs_write = { 0 };
		uint8_t regs_read_count = 0;
		uint8_t regs_write_count = 0;

		for (uint8_t i = 0; i < x86->op_count; ++i) {
			if (x86->operands[i].type == X86_OP_REG &&
			    x86->operands[i].reg == X86_REG_K3) {
				mask = &x86->operands[i];
				break;
			}
		}
		success &= check(mask != NULL, "K3 detail operand exists");
		if (mask != NULL) {
			success &=
				check(mask->size == expected_width,
				      "writemask size matches the lane count");
			success &= check(mask->access == CS_AC_READ,
					 "writemask is read-only");
		}
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds for writemask");
		success &= check(has_register(regs_read, regs_read_count,
					      X86_REG_K3),
				 "K3 appears in the read set");
	}
	cs_free(insn, count);
	return success;
}

int main(void)
{
	struct mask_case {
		const uint8_t *code;
		size_t code_size;
		x86_insn id;
		uint8_t width;
		bool zeroing;
	};
	// vmovdqu8 zmm31 {k3} {z}, zmm20
	static const uint8_t bytes8[] = { 0x62, 0x21, 0x7f, 0xcb, 0x6f, 0xfc };
	// vmovdqu16 zmm31 {k3} {z}, zmm20
	static const uint8_t bytes16[] = { 0x62, 0x21, 0xff, 0xcb, 0x6f, 0xfc };
	// vmovdqu32 zmm31 {k3} {z}, zmm20
	static const uint8_t bytes32[] = { 0x62, 0x21, 0x7e, 0xcb, 0x6f, 0xfc };
	// vmovdqu64 zmm31 {k3} {z}, zmm20
	static const uint8_t bytes64[] = { 0x62, 0x21, 0xfe, 0xcb, 0x6f, 0xfc };
	// vmovdqu64 zmm31 {k3}, zmm20
	static const uint8_t merging[] = { 0x62, 0x21, 0xfe, 0x4b, 0x6f, 0xfc };
	static const struct mask_case mask_cases[] = {
		{ bytes8, sizeof(bytes8), X86_INS_VMOVDQU8, 8, true },
		{ bytes16, sizeof(bytes16), X86_INS_VMOVDQU16, 4, true },
		{ bytes32, sizeof(bytes32), X86_INS_VMOVDQU32, 2, true },
		{ bytes64, sizeof(bytes64), X86_INS_VMOVDQU64, 1, true },
		{ merging, sizeof(merging), X86_INS_VMOVDQU64, 1, false },
	};
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

	success &= test_broadcast(handle);
	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "select AT&T syntax");
	success &= test_broadcast(handle);
	success &= check(cs_option(handle, CS_OPT_SYNTAX,
				   CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
			 "restore Intel syntax");
	for (size_t i = 0; i < sizeof(mask_cases) / sizeof(mask_cases[0]);
	     ++i) {
		success &= test_mask_width(handle, mask_cases[i].code,
					   mask_cases[i].code_size,
					   mask_cases[i].id,
					   mask_cases[i].width,
					   mask_cases[i].zeroing);
	}
	cs_close(&handle);
	return success ? 0 : 1;
}

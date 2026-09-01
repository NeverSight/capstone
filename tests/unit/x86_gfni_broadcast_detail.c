/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef enum mask_policy {
	MASK_NONE,
	MASK_MERGE,
	MASK_ZERO,
} mask_policy;

typedef struct gfni_family {
	const char *name;
	x86_insn id;
	uint8_t opcode;
	uint8_t immediate;
} gfni_family;

typedef struct vector_width {
	const char *name;
	uint8_t size;
	uint8_t length_bits;
	x86_reg destination;
	x86_reg source;
	x86_avx_bcast broadcast;
	const char *broadcast_text;
} vector_width;

static bool check(bool condition, const char *test_name, const char *message)
{
	if (!condition)
		fprintf(stderr, "%s: %s\n", test_name, message);
	return condition;
}

static const cs_x86_op *find_register(const cs_x86 *x86, x86_reg reg)
{
	uint8_t i;

	for (i = 0; i < x86->op_count; ++i) {
		if (x86->operands[i].type == X86_OP_REG &&
		    x86->operands[i].reg == reg)
			return &x86->operands[i];
	}
	return NULL;
}

static const cs_x86_op *find_operand(const cs_x86 *x86, x86_op_type type)
{
	uint8_t i;

	for (i = 0; i < x86->op_count; ++i) {
		if (x86->operands[i].type == type)
			return &x86->operands[i];
	}
	return NULL;
}

static bool check_gfni_form(csh handle, const gfni_family *family,
			    const vector_width *width, mask_policy policy,
			    bool att_syntax, int8_t encoded_displacement)
{
	const uint8_t mask_bits = policy == MASK_NONE ? 0 : 2;
	const uint8_t zero_bit = policy == MASK_ZERO ? 0x80 : 0;
	const uint8_t code[] = {
		0x62, 0xf3, 0xed,
		(uint8_t)(0x18 | width->length_bits | mask_bits | zero_bit),
		family->opcode, 0x48, (uint8_t)encoded_displacement,
		family->immediate,
	};
	const int64_t expected_displacement =
		(int64_t)encoded_displacement * 8;
	const uint8_t expected_mask_size = width->size / 8;
	const cs_x86_op *destination = NULL;
	const cs_x86_op *source = NULL;
	const cs_x86_op *mask = NULL;
	const cs_x86_op *memory = NULL;
	const cs_x86_op *immediate = NULL;
	const cs_x86 *x86;
	cs_insn *insn = NULL;
	char test_name[96];
	bool success = true;
	size_t count;

	snprintf(test_name, sizeof(test_name), "%s/%s/%s/%s",
		 family->name, width->name,
		 policy == MASK_NONE ? "unmasked" :
		 policy == MASK_MERGE ? "merge" : "zero",
		 att_syntax ? "att" : "intel");
	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, test_name, "instruction did not decode"))
		return false;

	success &= check(insn[0].id == family->id, test_name,
			 "instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, family->name) == 0, test_name,
			 "mnemonic is exact");
	success &= check(insn[0].size == sizeof(code), test_name,
			 "instruction size is exact");
	success &= check(strstr(insn[0].op_str, width->broadcast_text) != NULL,
			 test_name, "broadcast text is present");
	if (!att_syntax) {
		success &= check(strstr(insn[0].op_str, "qword ptr") != NULL,
				 test_name, "Intel memory qualifier is qword");
		success &= check(strstr(insn[0].op_str, "byte ptr") == NULL,
				 test_name, "Intel memory qualifier is not byte");
	}
	success &= check(insn[0].detail != NULL, test_name,
			 "public detail is available");
	if (insn[0].detail == NULL)
		goto done;

	x86 = &insn[0].detail->x86;
	success &= check(x86->op_count == (policy == MASK_NONE ? 4 : 5),
			 test_name, "operand count is exact");
	destination = find_register(x86, width->destination);
	source = find_register(x86, width->source);
	mask = find_register(x86, X86_REG_K2);
	memory = find_operand(x86, X86_OP_MEM);
	immediate = find_operand(x86, X86_OP_IMM);

	success &= check(destination != NULL, test_name,
			 "destination register exists");
	if (destination != NULL)
		success &= check(destination->size == width->size, test_name,
				 "destination size is exact");
	success &= check(source != NULL, test_name, "source register exists");
	if (source != NULL)
		success &= check(source->size == width->size, test_name,
				 "source size is exact");
	if (policy == MASK_NONE) {
		success &= check(mask == NULL, test_name,
				 "unmasked form has no writemask operand");
	} else {
		success &= check(mask != NULL, test_name, "writemask exists");
		if (mask != NULL) {
			success &= check(mask->size == expected_mask_size, test_name,
					 "writemask size is exact");
			success &= check(mask->avx_zero_opmask ==
						 (policy == MASK_ZERO),
					 test_name, "writemask zeroing is exact");
		}
	}

	success &= check(memory != NULL, test_name, "memory operand exists");
	if (memory != NULL) {
		success &= check(memory->size == 8, test_name,
				 "broadcast reads one qword");
		success &= check(memory->mem.base == X86_REG_RAX, test_name,
				 "memory base is RAX");
		success &= check(memory->mem.disp == expected_displacement,
				 test_name, "compressed displacement is scaled by 8");
		success &= check(memory->avx_bcast == width->broadcast, test_name,
				 "structured broadcast count is exact");
	}
	success &= check(immediate != NULL, test_name, "immediate exists");
	if (immediate != NULL) {
		success &= check(immediate->size == 1, test_name,
				 "immediate size is one byte");
		success &= check((uint8_t)immediate->imm == family->immediate,
				 test_name, "immediate value is exact");
	}
	success &= check(x86->disp == expected_displacement, test_name,
			 "instruction displacement is scaled by 8");
	success &= check(x86->encoding.disp_offset == 6 &&
			 x86->encoding.disp_size == 1,
			 test_name, "compressed displacement encoding is exact");
	success &= check(x86->encoding.imm_offset == 7 &&
			 x86->encoding.imm_size == 1,
			 test_name, "immediate encoding is exact");

done:
	cs_free(insn, count);
	return success;
}

static bool check_full_displacement(csh handle, bool att_syntax)
{
	const uint8_t code[] = { 0x62, 0xf3, 0xed, 0x1a, 0xce, 0x88,
				 0x78, 0x56, 0x34, 0x12, 0x63 };
	const char *test_name = att_syntax ? "disp32/att" : "disp32/intel";
	const cs_x86_op *memory = NULL;
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (!check(count == 1, test_name, "instruction did not decode"))
		return false;
	success &= check(insn[0].id == X86_INS_VGF2P8AFFINEQB, test_name,
			 "instruction ID is exact");
	success &= check(insn[0].detail != NULL, test_name,
			 "public detail is available");
	if (insn[0].detail == NULL)
		goto done;
	memory = find_operand(&insn[0].detail->x86, X86_OP_MEM);
	success &= check(memory != NULL, test_name, "memory operand exists");
	if (memory != NULL) {
		success &= check(memory->size == 8, test_name,
				 "broadcast reads one qword");
		success &= check(memory->mem.disp == INT64_C(0x12345678),
				 test_name, "disp32 is not compressed-scaled");
		success &= check(memory->avx_bcast == X86_AVX_BCAST_2,
				 test_name, "structured broadcast is 1to2");
	}
	success &= check(insn[0].detail->x86.disp == INT64_C(0x12345678),
			 test_name, "instruction disp32 is unchanged");
	success &= check(insn[0].detail->x86.encoding.disp_offset == 6 &&
			 insn[0].detail->x86.encoding.disp_size == 4 &&
			 insn[0].detail->x86.encoding.imm_offset == 10 &&
			 insn[0].detail->x86.encoding.imm_size == 1,
			 test_name, "disp32 and immediate encoding are exact");
	if (!att_syntax)
		success &= check(strstr(insn[0].op_str, "qword ptr") != NULL,
				 test_name, "Intel memory qualifier is qword");

done:
	cs_free(insn, count);
	return success;
}

static bool check_pinsrb_sentinel(csh handle, bool att_syntax)
{
	const uint8_t code[] = { 0x66, 0x0f, 0x3a, 0x20, 0x08, 0x01 };
	const char *test_name = att_syntax ? "pinsrb/att" : "pinsrb/intel";
	const cs_x86_op *memory = NULL;
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (!check(count == 1, test_name, "instruction did not decode"))
		return false;
	success &= check(insn[0].id == X86_INS_PINSRB, test_name,
			 "instruction ID is exact");
	success &= check(insn[0].detail != NULL, test_name,
			 "public detail is available");
	if (insn[0].detail == NULL)
		goto done;
	memory = find_operand(&insn[0].detail->x86, X86_OP_MEM);
	success &= check(memory != NULL, test_name, "memory operand exists");
	if (memory != NULL)
		success &= check(memory->size == 1, test_name,
				 "PINSRB still reads one byte");
	if (!att_syntax)
		success &= check(strstr(insn[0].op_str, "byte ptr") != NULL,
				 test_name, "Intel qualifier remains byte");

done:
	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const gfni_family families[] = {
		{ "vgf2p8affineqb", X86_INS_VGF2P8AFFINEQB, 0xce, 0x63 },
		{ "vgf2p8affineinvqb", X86_INS_VGF2P8AFFINEINVQB, 0xcf, 0xa5 },
	};
	static const vector_width widths[] = {
		{ "xmm", 16, 0x00, X86_REG_XMM1, X86_REG_XMM2,
		  X86_AVX_BCAST_2, "{1to2}" },
		{ "ymm", 32, 0x20, X86_REG_YMM1, X86_REG_YMM2,
		  X86_AVX_BCAST_4, "{1to4}" },
		{ "zmm", 64, 0x40, X86_REG_ZMM1, X86_REG_ZMM2,
		  X86_AVX_BCAST_8, "{1to8}" },
	};
	csh handle = 0;
	bool success = true;
	bool att_syntax;
	size_t family_index;
	size_t width_index;
	mask_policy policy;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "setup", "open x86-64 mode"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "setup", "enable public detail")) {
		cs_close(&handle);
		return 1;
	}

	for (att_syntax = false;; att_syntax = true) {
		if (att_syntax)
			success &= check(cs_option(handle, CS_OPT_SYNTAX,
						   CS_OPT_SYNTAX_ATT) == CS_ERR_OK,
					 "setup", "select AT&T syntax");
		for (family_index = 0;
		     family_index < sizeof(families) / sizeof(families[0]);
		     ++family_index) {
			for (width_index = 0;
			     width_index < sizeof(widths) / sizeof(widths[0]);
			     ++width_index) {
				for (policy = MASK_NONE; policy <= MASK_ZERO;
				     policy = (mask_policy)(policy + 1)) {
					const int8_t displacement =
						((family_index + width_index + policy) & 1) ?
							-2 : 2;

					success &= check_gfni_form(
						handle, &families[family_index],
						&widths[width_index], policy,
						att_syntax, displacement);
				}
			}
		}
		success &= check_full_displacement(handle, att_syntax);
		success &= check_pinsrb_sentinel(handle, att_syntax);
		if (att_syntax)
			break;
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

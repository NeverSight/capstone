/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

enum shift_count_kind {
	SHIFT_COUNT_IMMEDIATE,
	SHIFT_COUNT_ONE,
	SHIFT_COUNT_CL,
};

typedef struct shift_operation {
	x86_insn instruction;
	const char *mnemonic;
	uint8_t group;
	bool reads_carry;
	uint64_t eflags;
} shift_operation;

typedef struct decode_anchor {
	const uint8_t *code;
	size_t code_size;
	x86_insn instruction;
	const char *intel_mnemonic;
	const char *intel_operands;
	const char *att_mnemonic;
	const char *att_operands;
} decode_anchor;

static const shift_operation operations[] = {
	{ X86_INS_ROL, "rol", 0, false,
	  X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF },
	{ X86_INS_ROR, "ror", 1, false,
	  X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF },
	{ X86_INS_RCL, "rcl", 2, true,
	  X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF },
	{ X86_INS_RCR, "rcr", 3, true,
	  X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF },
	{ X86_INS_SHL, "shl", 4, false,
	  X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF |
		  X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF |
		  X86_EFLAGS_MODIFY_CF },
	{ X86_INS_SHR, "shr", 5, false,
	  X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF |
		  X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF |
		  X86_EFLAGS_MODIFY_CF },
	{ X86_INS_SAR, "sar", 7, false,
	  X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF |
		  X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF |
		  X86_EFLAGS_MODIFY_CF },
};

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX EVEX shift/rotate check failed: %s\n",
			message);
	return condition;
}

static x86_reg register_for(uint8_t width, unsigned int number)
{
	static const x86_reg registers_8[] = {
		X86_REG_AL,   X86_REG_CL,   X86_REG_DL,	  X86_REG_BL,
		X86_REG_SPL,  X86_REG_BPL,  X86_REG_SIL,  X86_REG_DIL,
		X86_REG_R8B,  X86_REG_R9B,  X86_REG_R10B, X86_REG_R11B,
		X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B,
		X86_REG_R16B, X86_REG_R17B, X86_REG_R18B, X86_REG_R19B,
		X86_REG_R20B, X86_REG_R21B, X86_REG_R22B, X86_REG_R23B,
		X86_REG_R24B, X86_REG_R25B, X86_REG_R26B, X86_REG_R27B,
		X86_REG_R28B, X86_REG_R29B, X86_REG_R30B, X86_REG_R31B,
	};
	static const x86_reg registers_16[] = {
		X86_REG_AX,   X86_REG_CX,   X86_REG_DX,	  X86_REG_BX,
		X86_REG_SP,   X86_REG_BP,   X86_REG_SI,	  X86_REG_DI,
		X86_REG_R8W,  X86_REG_R9W,  X86_REG_R10W, X86_REG_R11W,
		X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, X86_REG_R15W,
		X86_REG_R16W, X86_REG_R17W, X86_REG_R18W, X86_REG_R19W,
		X86_REG_R20W, X86_REG_R21W, X86_REG_R22W, X86_REG_R23W,
		X86_REG_R24W, X86_REG_R25W, X86_REG_R26W, X86_REG_R27W,
		X86_REG_R28W, X86_REG_R29W, X86_REG_R30W, X86_REG_R31W,
	};
	static const x86_reg registers_32[] = {
		X86_REG_EAX,  X86_REG_ECX,  X86_REG_EDX,  X86_REG_EBX,
		X86_REG_ESP,  X86_REG_EBP,  X86_REG_ESI,  X86_REG_EDI,
		X86_REG_R8D,  X86_REG_R9D,  X86_REG_R10D, X86_REG_R11D,
		X86_REG_R12D, X86_REG_R13D, X86_REG_R14D, X86_REG_R15D,
		X86_REG_R16D, X86_REG_R17D, X86_REG_R18D, X86_REG_R19D,
		X86_REG_R20D, X86_REG_R21D, X86_REG_R22D, X86_REG_R23D,
		X86_REG_R24D, X86_REG_R25D, X86_REG_R26D, X86_REG_R27D,
		X86_REG_R28D, X86_REG_R29D, X86_REG_R30D, X86_REG_R31D,
	};
	static const x86_reg registers_64[] = {
		X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX, X86_REG_RSP,
		X86_REG_RBP, X86_REG_RSI, X86_REG_RDI, X86_REG_R8,  X86_REG_R9,
		X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14,
		X86_REG_R15, X86_REG_R16, X86_REG_R17, X86_REG_R18, X86_REG_R19,
		X86_REG_R20, X86_REG_R21, X86_REG_R22, X86_REG_R23, X86_REG_R24,
		X86_REG_R25, X86_REG_R26, X86_REG_R27, X86_REG_R28, X86_REG_R29,
		X86_REG_R30, X86_REG_R31,
	};

	if (number >= 32)
		return X86_REG_INVALID;
	switch (width) {
	default:
		return X86_REG_INVALID;
	case 1:
		return registers_8[number];
	case 2:
		return registers_16[number];
	case 4:
		return registers_32[number];
	case 8:
		return registers_64[number];
	}
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

static char att_suffix(uint8_t width)
{
	switch (width) {
	default:
		return '?';
	case 1:
		return 'b';
	case 2:
		return 'w';
	case 4:
		return 'l';
	case 8:
		return 'q';
	}
}

static const char *memory_size_name(uint8_t width)
{
	switch (width) {
	default:
		return NULL;
	case 1:
		return "byte";
	case 2:
		return "word";
	case 4:
		return "dword";
	case 8:
		return "qword";
	}
}

static void encode_register_case(uint8_t code[7], size_t *code_size,
				 const shift_operation *operation,
				 uint8_t width,
				 enum shift_count_kind count_kind,
				 uint8_t count_value, bool nd, bool nf,
				 unsigned int destination_number,
				 unsigned int source_number)
{
	unsigned int ndd_number = nd ? destination_number : 0;
	uint8_t pp = width == 2 ? 1 : 0;
	uint8_t w = width == 8 ? 0x80 : 0;

	code[0] = 0x62;
	code[1] = 0xd4 | ((source_number & 8) ? 0 : 0x20) |
		  ((source_number & 16) ? 0x08 : 0);
	code[2] = w | (((~ndd_number) & 0xf) << 3) | 0x04 | pp;
	code[3] = (nd ? 0x10 : 0) | (nf ? 0x04 : 0) |
		  ((ndd_number & 16) ? 0 : 0x08);
	code[4] = count_kind == SHIFT_COUNT_IMMEDIATE ?
			  (width == 1 ? 0xc0 : 0xc1) :
		  count_kind == SHIFT_COUNT_ONE ? (width == 1 ? 0xd0 : 0xd1) :
						  (width == 1 ? 0xd2 : 0xd3);
	code[5] = 0xc0 | (operation->group << 3) | (source_number & 7);
	if (count_kind == SHIFT_COUNT_IMMEDIATE) {
		code[6] = count_value;
		*code_size = 7;
	} else {
		*code_size = 6;
	}
}

static void encode_memory_case(uint8_t code[9], size_t *code_size,
			       const shift_operation *operation, uint8_t width,
			       enum shift_count_kind count_kind,
			       uint8_t count_value, bool nd, bool nf,
			       unsigned int destination_number)
{
	unsigned int ndd_number = nd ? destination_number : 0;
	uint8_t pp = width == 2 ? 1 : 0;
	uint8_t w = width == 8 ? 0x80 : 0;

	code[0] = 0x62;
	/* [r29 + r30*4 + 0x20].  EVEX.U is the X4 address bit here. */
	code[1] = 0x9c;
	code[2] = w | (((~ndd_number) & 0xf) << 3) | pp;
	code[3] = (nd ? 0x10 : 0) | (nf ? 0x04 : 0) |
		  ((ndd_number & 16) ? 0 : 0x08);
	code[4] = count_kind == SHIFT_COUNT_IMMEDIATE ?
			  (width == 1 ? 0xc0 : 0xc1) :
		  count_kind == SHIFT_COUNT_ONE ? (width == 1 ? 0xd0 : 0xd1) :
						  (width == 1 ? 0xd2 : 0xd3);
	code[5] = 0x44 | (operation->group << 3);
	code[6] = 0xb5;
	code[7] = 0x20;
	if (count_kind == SHIFT_COUNT_IMMEDIATE) {
		code[8] = count_value;
		*code_size = 9;
	} else {
		*code_size = 8;
	}
}

static bool check_count_operand(const cs_x86_op *operand,
				enum shift_count_kind count_kind,
				uint8_t count_value)
{
	if (count_kind == SHIFT_COUNT_CL) {
		return operand->type == X86_OP_REG &&
		       operand->reg == X86_REG_CL && operand->size == 1 &&
		       operand->access == CS_AC_READ;
	}
	return operand->type == X86_OP_IMM && operand->imm == count_value &&
	       operand->size == 1 && operand->access == CS_AC_READ;
}

static bool check_flag_detail(const cs_insn *insn,
			      const shift_operation *operation, bool nf)
{
	const cs_detail *detail = insn->detail;
	const cs_x86 *x86 = &detail->x86;
	bool success = true;

	if (operation->reads_carry) {
		success &= check(detail->regs_read_count == 1 &&
					 detail->regs_read[0] == X86_REG_EFLAGS,
				 "carry rotate reads EFLAGS");
	} else {
		success &= check(detail->regs_read_count == 0,
				 "non-carry operation has no implicit read");
	}
	if (nf) {
		success &=
			check(x86->eflags == 0 && detail->regs_write_count == 0,
			      "NF suppresses EFLAGS writes and detail");
	} else {
		success &=
			check(x86->eflags == operation->eflags &&
				      detail->regs_write_count == 1 &&
				      detail->regs_write[0] == X86_REG_EFLAGS,
			      "flag-writing detail is exact");
	}
	return success;
}

static bool check_register_case(csh handle, const shift_operation *operation,
				uint8_t width, enum shift_count_kind count_kind,
				bool nd, bool nf, unsigned int seed,
				bool att_syntax)
{
	unsigned int destination_number = seed;
	unsigned int source_number = nd ? (seed + 11) & 31 : seed;
	uint8_t count_value = (uint8_t)(seed * 13 + 3);
	x86_reg destination = register_for(width, destination_number);
	x86_reg source = register_for(width, source_number);
	const char *destination_name = cs_reg_name(handle, destination);
	const char *source_name = cs_reg_name(handle, source);
	uint8_t code[7];
	size_t code_size;
	char expected_mnemonic[32];
	char expected_operands[128];
	char count_text[16];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	bool success = true;
	size_t count;

	if (count_kind == SHIFT_COUNT_ONE)
		count_value = 1;
	encode_register_case(code, &code_size, operation, width, count_kind,
			     count_value, nd, nf, destination_number,
			     source_number);
	if (count_kind == SHIFT_COUNT_CL)
		snprintf(count_text, sizeof(count_text), "%s",
			 att_syntax ? "%cl" : "cl");
	else
		snprintf(count_text, sizeof(count_text),
			 att_syntax ? "$%u" : "%u", count_value);
	if (att_syntax) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s%c",
			 nf ? "{nf} " : "", operation->mnemonic,
			 att_suffix(width));
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %%%s, %%%s", count_text, source_name,
				 destination_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %%%s", count_text, source_name);
		}
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s",
			 nf ? "{nf} " : "", operation->mnemonic);
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s, %s", destination_name, source_name,
				 count_text);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s", source_name, count_text);
		}
	}

	count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	if (!check(count == 1, "promoted register shift/rotate decodes"))
		goto failed;
	success &= check(insn[0].id == operation->instruction,
			 "public instruction ID is exact");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id),
				operation->mnemonic) == 0,
			 "public instruction name is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "mnemonic, suffix, and NF decorator are exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "register operand order and names are exact");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		uint8_t data_index = att_syntax ? 1 : 0;
		uint8_t count_index = att_syntax ? 0 : (nd ? 2 : 1);
		const cs_x86_op *destination_operand =
			&x86->operands[att_syntax && nd ? 2 : data_index];

		success &= check(memcmp(x86->opcode, code, 4) == 0,
				 "EVEX prefix detail is exact");
		success &= check(x86->addr_size == 8 && x86->modrm == code[5] &&
					 x86->encoding.modrm_offset == 5,
				 "address and ModR/M detail are exact");
		if (count_kind == SHIFT_COUNT_IMMEDIATE) {
			success &= check(x86->encoding.imm_offset == 6 &&
						 x86->encoding.imm_size == 1,
					 "immediate encoding detail is exact");
		}
		success &= check(x86->op_count == (nd ? 3 : 2),
				 "public register operand count is exact");
		success &=
			check(check_count_operand(&x86->operands[count_index],
						  count_kind, count_value),
			      "count operand detail and access are exact");
		if (nd) {
			const cs_x86_op *source_operand =
				&x86->operands[att_syntax ? 1 : 1];

			success &= check(
				destination_operand->type == X86_OP_REG &&
					destination_operand->reg ==
						destination &&
					destination_operand->size == width &&
					destination_operand->access ==
						CS_AC_WRITE,
				"NDD destination detail is exact");
			success &= check(
				source_operand->type == X86_OP_REG &&
					source_operand->reg == source &&
					source_operand->size == width &&
					source_operand->access == CS_AC_READ,
				"NDD source detail is exact");
		} else {
			success &= check(
				destination_operand->type == X86_OP_REG &&
					destination_operand->reg == source &&
					destination_operand->size == width &&
					destination_operand->access ==
						(CS_AC_READ | CS_AC_WRITE),
				"destructive register detail is exact");
		}
		success &= check_flag_detail(&insn[0], operation, nf);
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(
			regs_read_count ==
					1 +
						(count_kind == SHIFT_COUNT_CL &&
								 source !=
									 X86_REG_CL ?
							 1 :
							 0) +
						(operation->reads_carry ? 1 :
									  0) &&
				has_register(regs_read, regs_read_count,
					     source) &&
				(count_kind != SHIFT_COUNT_CL ||
				 has_register(regs_read, regs_read_count,
					      X86_REG_CL)) &&
				(!operation->reads_carry ||
				 has_register(regs_read, regs_read_count,
					      X86_REG_EFLAGS)),
			"source, count, and carry reads are exact");
		success &=
			check(regs_write_count == 1 + (nf ? 0 : 1) &&
				      has_register(regs_write, regs_write_count,
						   nd ? destination : source) &&
				      (nf || has_register(regs_write,
							  regs_write_count,
							  X86_REG_EFLAGS)),
			      "destination and EFLAGS writes are exact");
	}

	if (success) {
		cs_free(insn, count);
		return true;
	}
failed:
	fprintf(stderr,
		"case: op=%s width=%u count=%u nd=%u nf=%u seed=%u syntax=%s\n",
		operation->mnemonic, width, count_kind, nd, nf, seed,
		att_syntax ? "att" : "intel");
	if (count != 0)
		cs_free(insn, count);
	return false;
}

static bool check_memory_case(csh handle, const shift_operation *operation,
			      uint8_t width, enum shift_count_kind count_kind,
			      bool nd, bool nf, bool att_syntax)
{
	const unsigned int destination_number = 31;
	const uint8_t count_value = count_kind == SHIFT_COUNT_ONE ? 1 : 37;
	x86_reg destination = register_for(width, destination_number);
	const char *destination_name = cs_reg_name(handle, destination);
	const char *size_name = memory_size_name(width);
	uint8_t code[9];
	size_t code_size;
	char expected_mnemonic[32];
	char expected_operands[192];
	char count_text[16];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	bool success = true;
	size_t count;

	encode_memory_case(code, &code_size, operation, width, count_kind,
			   count_value, nd, nf, destination_number);
	if (count_kind == SHIFT_COUNT_CL)
		snprintf(count_text, sizeof(count_text), "%s",
			 att_syntax ? "%cl" : "cl");
	else
		snprintf(count_text, sizeof(count_text),
			 att_syntax ? "$%u" : "%u", count_value);
	if (att_syntax) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s%c",
			 nf ? "{nf} " : "", operation->mnemonic,
			 att_suffix(width));
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, 0x20(%%r29,%%r30,4), %%%s", count_text,
				 destination_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, 0x20(%%r29,%%r30,4)", count_text);
		}
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s",
			 nf ? "{nf} " : "", operation->mnemonic);
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s ptr [r29 + r30*4 + 0x20], %s",
				 destination_name, size_name, count_text);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s ptr [r29 + r30*4 + 0x20], %s", size_name,
				 count_text);
		}
	}

	count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	if (!check(count == 1, "promoted memory shift/rotate decodes"))
		goto failed;
	success &= check(insn[0].id == operation->instruction,
			 "memory public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "memory mnemonic, suffix, and NF decorator are exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "memory operand order and rendering are exact");
	success &= check(insn[0].detail != NULL, "memory detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		uint8_t memory_index = att_syntax ? 1 : (nd ? 1 : 0);
		uint8_t count_index = att_syntax ? 0 : (nd ? 2 : 1);
		const cs_x86_op *memory_operand = &x86->operands[memory_index];

		success &= check(memcmp(x86->opcode, code, 4) == 0 &&
					 x86->addr_size == 8 &&
					 x86->modrm == code[5] &&
					 x86->sib == code[6] &&
					 x86->encoding.modrm_offset == 5 &&
					 x86->encoding.disp_offset == 7 &&
					 x86->encoding.disp_size == 1 &&
					 x86->disp == 0x20,
				 "memory encoding detail is exact");
		success &= check(x86->sib_base == X86_REG_R29 &&
					 x86->sib_index == X86_REG_R30 &&
					 x86->sib_scale == 4,
				 "high address-register detail is exact");
		if (count_kind == SHIFT_COUNT_IMMEDIATE) {
			success &= check(x86->encoding.imm_offset == 8 &&
						 x86->encoding.imm_size == 1,
					 "memory immediate detail is exact");
		}
		success &= check(x86->op_count == (nd ? 3 : 2),
				 "public memory operand count is exact");
		success &= check(
			check_count_operand(&x86->operands[count_index],
					    count_kind, count_value),
			"memory count operand detail and access are exact");
		success &= check(
			memory_operand->type == X86_OP_MEM &&
				memory_operand->size == width &&
				memory_operand->access ==
					(nd ? CS_AC_READ :
					      (CS_AC_READ | CS_AC_WRITE)) &&
				memory_operand->mem.segment ==
					X86_REG_INVALID &&
				memory_operand->mem.base == X86_REG_R29 &&
				memory_operand->mem.index == X86_REG_R30 &&
				memory_operand->mem.scale == 4 &&
				memory_operand->mem.disp == 0x20,
			"public memory operand detail and access are exact");
		if (nd) {
			const cs_x86_op *destination_operand =
				&x86->operands[att_syntax ? 2 : 0];

			success &= check(
				destination_operand->type == X86_OP_REG &&
					destination_operand->reg ==
						destination &&
					destination_operand->size == width &&
					destination_operand->access ==
						CS_AC_WRITE,
				"memory NDD destination detail is exact");
		}
		success &= check_flag_detail(&insn[0], operation, nf);
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "memory cs_regs_access succeeds");
		success &= check(
			regs_read_count ==
					2 +
						(count_kind == SHIFT_COUNT_CL ?
							 1 :
							 0) +
						(operation->reads_carry ? 1 :
									  0) &&
				has_register(regs_read, regs_read_count,
					     X86_REG_R29) &&
				has_register(regs_read, regs_read_count,
					     X86_REG_R30) &&
				(count_kind != SHIFT_COUNT_CL ||
				 has_register(regs_read, regs_read_count,
					      X86_REG_CL)) &&
				(!operation->reads_carry ||
				 has_register(regs_read, regs_read_count,
					      X86_REG_EFLAGS)),
			"memory address, count, and carry reads are exact");
		success &=
			check(regs_write_count == (nd ? 1 : 0) + (nf ? 0 : 1) &&
				      (!nd || has_register(regs_write,
							   regs_write_count,
							   destination)) &&
				      (nf || has_register(regs_write,
							  regs_write_count,
							  X86_REG_EFLAGS)),
			      "memory destination and EFLAGS writes are exact");
	}

	if (success) {
		cs_free(insn, count);
		return true;
	}
failed:
	fprintf(stderr,
		"memory case: op=%s width=%u count=%u nd=%u nf=%u syntax=%s\n",
		operation->mnemonic, width, count_kind, nd, nf,
		att_syntax ? "att" : "intel");
	if (count != 0)
		cs_free(insn, count);
	return false;
}

static bool run_matrix(csh handle, bool att_syntax)
{
	static const uint8_t widths[] = { 1, 2, 4, 8 };
	size_t operation_index, width_index;
	unsigned int count_kind, nd, nf, seed;

	if (!check(cs_option(handle, CS_OPT_SYNTAX,
			     att_syntax ? CS_OPT_SYNTAX_ATT :
					  CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
		   "select syntax"))
		return false;
	for (operation_index = 0;
	     operation_index < sizeof(operations) / sizeof(operations[0]);
	     ++operation_index) {
		const shift_operation *operation = &operations[operation_index];
		unsigned int nf_count = operation->reads_carry ? 1 : 2;

		for (width_index = 0;
		     width_index < sizeof(widths) / sizeof(widths[0]);
		     ++width_index) {
			for (count_kind = SHIFT_COUNT_IMMEDIATE;
			     count_kind <= SHIFT_COUNT_CL; ++count_kind) {
				for (nd = 0; nd < 2; ++nd) {
					for (nf = 0; nf < nf_count; ++nf) {
						for (seed = 0; seed < 32;
						     ++seed) {
							if (!check_register_case(
								    handle,
								    operation,
								    widths[width_index],
								    count_kind,
								    nd, nf,
								    seed,
								    att_syntax))
								return false;
						}
						if (!check_memory_case(
							    handle, operation,
							    widths[width_index],
							    count_kind, nd, nf,
							    att_syntax))
							return false;
					}
				}
			}
		}
	}
	return true;
}

static bool check_anchor(csh handle, const decode_anchor *anchor,
			 bool att_syntax)
{
	cs_insn *insn = NULL;
	size_t count;
	bool success = true;

	if (!check(cs_option(handle, CS_OPT_SYNTAX,
			     att_syntax ? CS_OPT_SYNTAX_ATT :
					  CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
		   "select anchor syntax"))
		return false;
	count = cs_disasm(handle, anchor->code, anchor->code_size, 0x1000, 1,
			  &insn);
	if (!check(count == 1, "current XED encoding anchor decodes"))
		return false;
	success &= check(insn[0].id == anchor->instruction,
			 "anchor public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic,
				att_syntax ? anchor->att_mnemonic :
					     anchor->intel_mnemonic) == 0,
			 "anchor mnemonic is exact");
	success &= check(strcmp(insn[0].op_str,
				att_syntax ? anchor->att_operands :
					     anchor->intel_operands) == 0,
			 "anchor operands are exact");
	cs_free(insn, count);
	return success;
}

static bool test_encoding_anchors(csh handle)
{
	static const uint8_t rol_nd_nf[] = { 0x62, 0xdc, 0x04, 0x14,
					     0xc1, 0xc6, 0x03 };
	static const uint8_t ror_nd_nf[] = { 0x62, 0xdc, 0x84, 0x14,
					     0xc1, 0xce, 0x05 };
	static const uint8_t shr_nd_nf_cl[] = { 0x62, 0xdc, 0x04,
						0x14, 0xd3, 0xee };
	static const uint8_t rcl_nd_one[] = {
		0x62, 0xdc, 0x04, 0x10, 0xd1, 0xd6
	};
	static const uint8_t rcr_cl[] = { 0x62, 0xfc, 0x7c, 0x08, 0xd2, 0xdf };
	static const uint8_t shl_nf_memory[] = {
		0x64, 0x62, 0x9c, 0xf8, 0x0c, 0xc1, 0x64, 0xb5, 0x20, 0x03,
	};
	static const uint8_t shr_nd_nf_memory_cl[] = {
		0x62, 0x9c, 0x00, 0x14, 0xd3, 0x6c, 0xb5, 0x20,
	};
	static const uint8_t rcl_nd_memory_one[] = {
		0x65, 0x62, 0x9c, 0x01, 0x10, 0xd1, 0x54, 0xb5, 0x20,
	};
	static const uint8_t sar_nd_nf_memory[] = {
		0x62, 0x9c, 0x01, 0x14, 0xc1, 0x7c, 0xb5, 0x20, 0x25,
	};
	static const decode_anchor anchors[] = {
		{ rol_nd_nf, sizeof(rol_nd_nf), X86_INS_ROL, "{nf} rol",
		  "r31d, r30d, 3", "{nf} roll", "$3, %r30d, %r31d" },
		{ ror_nd_nf, sizeof(ror_nd_nf), X86_INS_ROR, "{nf} ror",
		  "r31, r30, 5", "{nf} rorq", "$5, %r30, %r31" },
		{ shr_nd_nf_cl, sizeof(shr_nd_nf_cl), X86_INS_SHR, "{nf} shr",
		  "r31d, r30d, cl", "{nf} shrl", "%cl, %r30d, %r31d" },
		{ rcl_nd_one, sizeof(rcl_nd_one), X86_INS_RCL, "rcl",
		  "r31d, r30d, 1", "rcll", "$1, %r30d, %r31d" },
		{ rcr_cl, sizeof(rcr_cl), X86_INS_RCR, "rcr", "r23b, cl",
		  "rcrb", "%cl, %r23b" },
		{ shl_nf_memory, sizeof(shl_nf_memory), X86_INS_SHL, "{nf} shl",
		  "qword ptr fs:[r29 + r30*4 + 0x20], 3", "{nf} shlq",
		  "$3, %fs:0x20(%r29,%r30,4)" },
		{ shr_nd_nf_memory_cl, sizeof(shr_nd_nf_memory_cl), X86_INS_SHR,
		  "{nf} shr", "r31d, dword ptr [r29 + r30*4 + 0x20], cl",
		  "{nf} shrl", "%cl, 0x20(%r29,%r30,4), %r31d" },
		{ rcl_nd_memory_one, sizeof(rcl_nd_memory_one), X86_INS_RCL,
		  "rcl", "r31w, word ptr gs:[r29 + r30*4 + 0x20], 1", "rclw",
		  "$1, %gs:0x20(%r29,%r30,4), %r31w" },
		{ sar_nd_nf_memory, sizeof(sar_nd_nf_memory), X86_INS_SAR,
		  "{nf} sar", "r31w, word ptr [r29 + r30*4 + 0x20], 37",
		  "{nf} sarw", "$37, 0x20(%r29,%r30,4), %r31w" },
	};
	uint8_t code[10];
	size_t code_size;
	bool success = true;
	size_t i;

	encode_register_case(code, &code_size, &operations[0], 4,
			     SHIFT_COUNT_IMMEDIATE, 3, true, true, 31, 30);
	success &= check(code_size == sizeof(rol_nd_nf) &&
				 memcmp(code, rol_nd_nf, code_size) == 0,
			 "ROL encoding matches current XED");
	encode_register_case(code, &code_size, &operations[5], 4,
			     SHIFT_COUNT_CL, 0, true, true, 31, 30);
	success &= check(code_size == sizeof(shr_nd_nf_cl) &&
				 memcmp(code, shr_nd_nf_cl, code_size) == 0,
			 "SHR CL encoding matches current XED");
	encode_register_case(code, &code_size, &operations[2], 4,
			     SHIFT_COUNT_ONE, 1, true, false, 31, 30);
	success &= check(code_size == sizeof(rcl_nd_one) &&
				 memcmp(code, rcl_nd_one, code_size) == 0,
			 "RCL implicit-one encoding matches current XED");
	encode_memory_case(code, &code_size, &operations[5], 4, SHIFT_COUNT_CL,
			   0, true, true, 31);
	success &=
		check(code_size == sizeof(shr_nd_nf_memory_cl) &&
			      memcmp(code, shr_nd_nf_memory_cl, code_size) == 0,
		      "memory SHR encoding matches current XED");
	for (i = 0; i < sizeof(anchors) / sizeof(anchors[0]); ++i) {
		success &= check_anchor(handle, &anchors[i], false);
		success &= check_anchor(handle, &anchors[i], true);
		if (!success)
			return false;
	}
	return success;
}

static bool rejects(csh handle, const uint8_t *code, size_t code_size,
		    const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	bool success = check(count == 0, message);

	if (count != 0)
		cs_free(insn, count);
	return success;
}

static bool decodes_as(csh handle, const uint8_t *code, size_t code_size,
		       x86_insn instruction, const char *mnemonic,
		       const char *operands, const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	bool success = check(count == 1, message);

	if (count == 1) {
		success &=
			check(insn[0].id == instruction &&
				      strcmp(insn[0].mnemonic, mnemonic) == 0 &&
				      strcmp(insn[0].op_str, operands) == 0,
			      "legal variant semantics are exact");
		cs_free(insn, count);
	}
	return success;
}

static bool test_legal_variants(csh handle)
{
	static const uint8_t prefixes[] = {
		0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x67,
	};
	uint8_t base[9], code[11];
	size_t base_size, i;
	bool success = true;

	success &= check(cs_option(handle, CS_OPT_SYNTAX,
				   CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
			 "select Intel syntax for legal variants");
	encode_register_case(base, &base_size, &operations[1], 8,
			     SHIFT_COUNT_IMMEDIATE, 5, true, true, 31, 30);
	base[2] |= 1;
	success &= decodes_as(handle, base, base_size, X86_INS_ROR, "{nf} ror",
			      "r31, r30, 5", "W=1 takes precedence over pp=66");

	encode_register_case(base, &base_size, &operations[0], 1,
			     SHIFT_COUNT_ONE, 1, false, false, 30, 30);
	base[2] |= 0x80;
	success &= decodes_as(handle, base, base_size, X86_INS_ROL, "rol",
			      "r30b, 1", "W is ignored for byte form");
	base[1] ^= 0xd0;
	success &= decodes_as(
		handle, base, base_size, X86_INS_ROL, "rol", "r30b, 1",
		"unused register-form EVEX extensions are ignored");

	encode_register_case(base, &base_size, &operations[4], 4,
			     SHIFT_COUNT_CL, 0, true, true, 31, 30);
	base[5] = (base[5] & (uint8_t)~0x38) | (6 << 3);
	success &= decodes_as(handle, base, base_size, X86_INS_SHL, "{nf} shl",
			      "r31d, r30d, cl", "ModR/M /6 is the SHL alias");

	encode_register_case(base, &base_size, &operations[6], 4,
			     SHIFT_COUNT_ONE, 1, false, true, 23, 23);
	for (i = 0; i < sizeof(prefixes); ++i) {
		cs_insn *insn = NULL;
		size_t count;

		code[0] = prefixes[i];
		memcpy(code + 1, base, base_size);
		count = cs_disasm(handle, code, base_size + 1, 0x1000, 1,
				  &insn);
		success &= check(count == 1,
				 "legal segment/address prefix decodes");
		if (count == 1) {
			const cs_x86 *x86 = &insn[0].detail->x86;

			success &= check(
				insn[0].id == X86_INS_SAR &&
					strcmp(insn[0].mnemonic, "{nf} sar") ==
						0 &&
					strcmp(insn[0].op_str, "r23d, 1") == 0,
				"legal prefix preserves semantics");
			success &= check(
				x86->encoding.modrm_offset == 6 &&
					x86->addr_size ==
						(prefixes[i] == 0x67 ? 4 : 8) &&
					x86->prefix[prefixes[i] == 0x67 ? 3 :
									  1] ==
						prefixes[i],
				"legal prefix detail and offsets are exact");
			cs_free(insn, count);
		}
	}

	encode_memory_case(base, &base_size, &operations[4], 4,
			   SHIFT_COUNT_IMMEDIATE, 7, true, true, 31);
	code[0] = 0x67;
	memcpy(code + 1, base, base_size);
	success &=
		decodes_as(handle, code, base_size + 1, X86_INS_SHL, "{nf} shl",
			   "r31d, dword ptr [r29d + r30d*4 + 0x20], 7",
			   "address-size override uses 32-bit EGPR addressing");
	base[2] |= 0x04;
	success &= decodes_as(handle, base, base_size, X86_INS_SHL, "{nf} shl",
			      "r31d, dword ptr [r29 + r14*4 + 0x20], 7",
			      "memory EVEX.U is the X4 address extension");
	return success;
}

static bool test_invalid_encodings(csh handle)
{
	static const uint8_t forbidden_prefixes[] = {
		0x66, 0xf0, 0xf2, 0xf3, 0x40, 0x48,
	};
	static const uint8_t reserved_p2_bits[] = {
		0x80, 0x40, 0x20, 0x02, 0x01,
	};
	uint8_t base[9], code[17];
	size_t base_size, i;
	bool success = true;

	success &= check(cs_option(handle, CS_OPT_SYNTAX,
				   CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
			 "select Intel syntax for invalid encodings");
	encode_register_case(base, &base_size, &operations[0], 4,
			     SHIFT_COUNT_IMMEDIATE, 3, false, false, 23, 23);
	for (i = 1; i < base_size; ++i)
		success &= rejects(handle, base, i,
				   "truncated register encoding is rejected");
	for (i = 0; i < sizeof(reserved_p2_bits); ++i) {
		memcpy(code, base, base_size);
		code[3] |= reserved_p2_bits[i];
		success &= rejects(handle, code, base_size,
				   "reserved EVEX P2 bit is rejected");
	}
	memcpy(code, base, base_size);
	code[2] &= (uint8_t)~0x04;
	success &= rejects(handle, code, base_size,
			   "EVEX.U=0 is rejected for register form");
	memcpy(code, base, base_size);
	code[2] &= (uint8_t)~0x08;
	success &= rejects(handle, code, base_size,
			   "nonzero low VVVV with ND=0 is rejected");
	memcpy(code, base, base_size);
	code[3] &= (uint8_t)~0x08;
	success &= rejects(handle, code, base_size,
			   "nonzero V4 with ND=0 is rejected");

	memcpy(code, base, base_size);
	code[2] = (code[2] & (uint8_t)~3) | 2;
	success &= rejects(handle, code, base_size,
			   "F3 pp is rejected for scalable form");
	code[2] = (code[2] & (uint8_t)~3) | 3;
	success &= rejects(handle, code, base_size,
			   "F2 pp is rejected for scalable form");
	encode_register_case(base, &base_size, &operations[0], 1,
			     SHIFT_COUNT_IMMEDIATE, 3, false, false, 23, 23);
	for (i = 1; i <= 3; ++i) {
		memcpy(code, base, base_size);
		code[2] = (code[2] & (uint8_t)~3) | i;
		success &= rejects(handle, code, base_size,
				   "nonzero pp is rejected for byte form");
	}

	encode_register_case(base, &base_size, &operations[2], 4,
			     SHIFT_COUNT_ONE, 1, true, true, 31, 30);
	success &= rejects(handle, base, base_size, "NF is rejected for RCL");
	encode_register_case(base, &base_size, &operations[3], 4,
			     SHIFT_COUNT_CL, 0, false, true, 30, 30);
	success &= rejects(handle, base, base_size, "NF is rejected for RCR");

	encode_register_case(base, &base_size, &operations[6], 4,
			     SHIFT_COUNT_ONE, 1, false, false, 23, 23);
	for (i = 0; i < sizeof(forbidden_prefixes); ++i) {
		code[0] = forbidden_prefixes[i];
		memcpy(code + 1, base, base_size);
		success &= rejects(handle, code, base_size + 1,
				   "forbidden legacy prefix is rejected");
	}

	encode_memory_case(base, &base_size, &operations[5], 8,
			   SHIFT_COUNT_IMMEDIATE, 3, true, true, 31);
	for (i = 6; i < base_size; ++i)
		success &= rejects(handle, base, i,
				   "truncated memory encoding is rejected");
	memcpy(code, base, base_size);
	code[3] &= (uint8_t)~0x10;
	success &= rejects(handle, code, base_size,
			   "memory nonzero VVVV with ND=0 is rejected");

	encode_register_case(base, &base_size, &operations[0], 4,
			     SHIFT_COUNT_IMMEDIATE, 3, true, true, 31, 30);
	memset(code, 0x64, 10);
	memcpy(code + 10, base, base_size);
	success &= rejects(handle, code, 10 + base_size,
			   "instruction longer than 15 bytes is rejected");
	return success;
}

static bool test_wrong_mode(void)
{
	uint8_t code[7];
	size_t code_size;
	csh handle = 0;
	bool success;

	encode_register_case(code, &code_size, &operations[0], 4,
			     SHIFT_COUNT_IMMEDIATE, 3, true, true, 31, 30);
	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK,
		   "open 32-bit mode"))
		return false;
	success =
		rejects(handle, code, code_size,
			"APX EVEX instruction is rejected outside 64-bit mode");
	cs_close(&handle);
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
		   "enable real detail")) {
		cs_close(&handle);
		return 1;
	}
	success &= test_encoding_anchors(handle);
	success &= run_matrix(handle, false);
	success &= run_matrix(handle, true);
	success &= test_legal_variants(handle);
	success &= test_invalid_encodings(handle);
	cs_close(&handle);
	success &= test_wrong_mode();
	return success ? 0 : 1;
}

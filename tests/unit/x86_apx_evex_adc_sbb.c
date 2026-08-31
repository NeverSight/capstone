/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct arithmetic_operation {
	x86_insn instruction;
	const char *mnemonic;
	uint8_t binary_base;
	uint8_t immediate_group;
	uint64_t eflags;
} arithmetic_operation;

typedef struct decode_anchor {
	const uint8_t *code;
	size_t code_size;
	x86_insn instruction;
	const char *intel_mnemonic;
	const char *intel_operands;
	const char *att_mnemonic;
	const char *att_operands;
} decode_anchor;

static const arithmetic_operation operations[] = {
	{ X86_INS_ADC, "adc", 0x10, 2,
	  X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF |
		  X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF |
		  X86_EFLAGS_MODIFY_CF | X86_EFLAGS_TEST_CF },
	{ X86_INS_SBB, "sbb", 0x18, 3,
	  X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF |
		  X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF |
		  X86_EFLAGS_MODIFY_CF | X86_EFLAGS_TEST_CF },
};

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX EVEX ADC/SBB check failed: %s\n", message);
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
	return width == 1 ? 'b' : width == 2 ? 'w' : width == 4 ? 'l' : 'q';
}

static const char *memory_size_name(uint8_t width)
{
	return width == 1 ? "byte" :
	       width == 2 ? "word" :
	       width == 4 ? "dword" :
			    "qword";
}

static void encode_binary_register(uint8_t code[6],
				   const arithmetic_operation *operation,
				   uint8_t width, bool reverse, bool nd,
				   unsigned int destination_number,
				   unsigned int source1_number,
				   unsigned int source2_number)
{
	unsigned int reg_number = reverse ? source1_number : source2_number;
	unsigned int rm_number = reverse ? source2_number : source1_number;
	unsigned int ndd_number = nd ? destination_number : 0;
	uint8_t pp = width == 2 ? 1 : 0;
	uint8_t w = width == 8 ? 0x80 : 0;

	code[0] = 0x62;
	code[1] = 0x44 | ((reg_number & 8) ? 0 : 0x80) |
		  ((rm_number & 8) ? 0 : 0x20) |
		  ((reg_number & 16) ? 0 : 0x10) |
		  ((rm_number & 16) ? 0x08 : 0);
	code[2] = w | (((~ndd_number) & 0xf) << 3) | 0x04 | pp;
	code[3] = (nd ? 0x10 : 0) | ((ndd_number & 16) ? 0 : 0x08);
	code[4] = operation->binary_base + (reverse ? 2 : 0) +
		  (width == 1 ? 0 : 1);
	code[5] = 0xc0 | ((reg_number & 7) << 3) | (rm_number & 7);
}

static void encode_binary_memory(uint8_t code[8],
				 const arithmetic_operation *operation,
				 uint8_t width, bool reverse, bool nd,
				 unsigned int destination_number,
				 unsigned int register_number)
{
	unsigned int ndd_number = nd ? destination_number : 0;
	uint8_t pp = width == 2 ? 1 : 0;
	uint8_t w = width == 8 ? 0x80 : 0;

	code[0] = 0x62;
	/* The memory operand is [r29 + r30*4 + 0x20]. */
	code[1] = 0x0c | ((register_number & 8) ? 0 : 0x80) |
		  ((register_number & 16) ? 0 : 0x10);
	code[2] = w | (((~ndd_number) & 0xf) << 3) | pp;
	code[3] = (nd ? 0x10 : 0) | ((ndd_number & 16) ? 0 : 0x08);
	code[4] = operation->binary_base + (reverse ? 2 : 0) +
		  (width == 1 ? 0 : 1);
	code[5] = 0x44 | ((register_number & 7) << 3);
	code[6] = 0xb5;
	code[7] = 0x20;
}

static bool check_flag_detail(const cs_insn *insn,
			      const arithmetic_operation *operation)
{
	const cs_detail *detail = insn->detail;

	return check(detail->x86.eflags == operation->eflags &&
			     detail->regs_read_count == 1 &&
			     detail->regs_read[0] == X86_REG_EFLAGS &&
			     detail->regs_write_count == 1 &&
			     detail->regs_write[0] == X86_REG_EFLAGS,
		     "carry input and arithmetic EFLAGS effects are exact");
}

static bool check_binary_register(csh handle,
				  const arithmetic_operation *operation,
				  uint8_t width, bool reverse, bool nd,
				  unsigned int seed, bool att_syntax)
{
	unsigned int destination_number = seed;
	unsigned int source1_number = nd ? (seed + 11) & 31 : seed;
	unsigned int source2_number = (seed + 23) & 31;
	x86_reg destination = register_for(width, destination_number);
	x86_reg source1 = register_for(width, source1_number);
	x86_reg source2 = register_for(width, source2_number);
	const char *destination_name = cs_reg_name(handle, destination);
	const char *source1_name = cs_reg_name(handle, source1);
	const char *source2_name = cs_reg_name(handle, source2);
	uint8_t code[6];
	char expected_mnemonic[16];
	char expected_operands[128];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 }, regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	bool success = true;
	size_t count;

	encode_binary_register(code, operation, width, reverse, nd,
			       destination_number, source1_number,
			       source2_number);
	if (att_syntax) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%c",
			 operation->mnemonic, att_suffix(width));
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%%%s, %%%s, %%%s", source2_name, source1_name,
				 destination_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%%%s, %%%s", source2_name, source1_name);
		}
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s",
			 operation->mnemonic);
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s, %s", destination_name, source1_name,
				 source2_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s", source1_name, source2_name);
		}
	}

	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "binary register form decodes"))
		goto failed;
	success &= check(insn[0].id == operation->instruction,
			 "binary public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0 &&
				 strcmp(insn[0].op_str, expected_operands) == 0,
			 "binary register text and order are exact");
	success &= check(insn[0].detail != NULL,
			 "binary register detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		x86_reg logical[3] = { source1, source2, X86_REG_INVALID };
		uint8_t access[3] = { CS_AC_READ | CS_AC_WRITE, CS_AC_READ, 0 };
		uint8_t logical_count = nd ? 3 : 2;
		uint8_t i;

		if (nd) {
			logical[0] = destination;
			logical[1] = source1;
			logical[2] = source2;
			access[0] = CS_AC_WRITE;
			access[1] = CS_AC_READ;
			access[2] = CS_AC_READ;
		}

		success &= check(memcmp(x86->opcode, code, 4) == 0 &&
					 x86->addr_size == 8 &&
					 x86->modrm == code[5] &&
					 x86->encoding.modrm_offset == 5,
				 "binary register encoding detail is exact");
		success &= check(x86->op_count == logical_count,
				 "binary register operand count is exact");
		for (i = 0; i < logical_count; ++i) {
			uint8_t logical_index =
				att_syntax ? logical_count - 1 - i : i;
			success &= check(
				x86->operands[i].type == X86_OP_REG &&
					x86->operands[i].reg ==
						logical[logical_index] &&
					x86->operands[i].size == width &&
					x86->operands[i].access ==
						access[logical_index],
				"binary register operand detail is exact");
		}
		success &= check_flag_detail(&insn[0], operation);
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "binary register cs_regs_access succeeds");
		success &=
			check(regs_read_count == 3 &&
				      has_register(regs_read, regs_read_count,
						   source1) &&
				      has_register(regs_read, regs_read_count,
						   source2) &&
				      has_register(regs_read, regs_read_count,
						   X86_REG_EFLAGS),
			      "binary data registers and carry input are read");
		success &= check(
			regs_write_count == 2 &&
				has_register(regs_write, regs_write_count,
					     nd ? destination : source1) &&
				has_register(regs_write, regs_write_count,
					     X86_REG_EFLAGS),
			"binary destination and EFLAGS writes are exact");
	}

	cs_free(insn, count);
	if (success)
		return true;
failed:
	fprintf(stderr,
		"binary register: op=%s width=%u reverse=%u nd=%u seed=%u syntax=%s\n",
		operation->mnemonic, width, reverse, nd, seed,
		att_syntax ? "att" : "intel");
	if (count != 0)
		cs_free(insn, count);
	return false;
}

static bool check_binary_memory(csh handle,
				const arithmetic_operation *operation,
				uint8_t width, bool reverse, bool nd,
				bool att_syntax)
{
	const unsigned int destination_number = 31;
	const unsigned int register_number = 28;
	x86_reg destination = register_for(width, destination_number);
	x86_reg source_register = register_for(width, register_number);
	const char *destination_name = cs_reg_name(handle, destination);
	const char *register_name = cs_reg_name(handle, source_register);
	const char *size_name = memory_size_name(width);
	uint8_t code[8];
	char expected_mnemonic[16], expected_operands[192];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 }, regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	bool success = true;
	size_t count;

	encode_binary_memory(code, operation, width, reverse, nd,
			     destination_number, register_number);
	if (att_syntax) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%c",
			 operation->mnemonic, att_suffix(width));
		if (nd && reverse) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "0x20(%%r29,%%r30,4), %%%s, %%%s",
				 register_name, destination_name);
		} else if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%%%s, 0x20(%%r29,%%r30,4), %%%s",
				 register_name, destination_name);
		} else if (reverse) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "0x20(%%r29,%%r30,4), %%%s", register_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%%%s, 0x20(%%r29,%%r30,4)", register_name);
		}
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s",
			 operation->mnemonic);
		if (nd && reverse) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s, %s ptr [r29 + r30*4 + 0x20]",
				 destination_name, register_name, size_name);
		} else if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s ptr [r29 + r30*4 + 0x20], %s",
				 destination_name, size_name, register_name);
		} else if (reverse) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s ptr [r29 + r30*4 + 0x20]",
				 register_name, size_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s ptr [r29 + r30*4 + 0x20], %s", size_name,
				 register_name);
		}
	}

	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "binary memory form decodes"))
		goto failed;
	success &= check(insn[0].id == operation->instruction,
			 "binary memory public ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0 &&
				 strcmp(insn[0].op_str, expected_operands) == 0,
			 "binary memory text and order are exact");
	success &= check(insn[0].detail != NULL,
			 "binary memory detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		uint8_t logical_count = nd ? 3 : 2;
		uint8_t memory_logical_index = reverse ? logical_count - 1 :
					       nd      ? 1 :
							 0;
		uint8_t register_logical_index = reverse ? (nd ? 1 : 0) :
							   logical_count - 1;
		uint8_t destination_logical_index = 0;
		uint8_t i;

		success &= check(memcmp(x86->opcode, code, 4) == 0 &&
					 x86->modrm == code[5] &&
					 x86->sib == code[6] &&
					 x86->addr_size == 8 &&
					 x86->encoding.modrm_offset == 5 &&
					 x86->encoding.disp_offset == 7 &&
					 x86->encoding.disp_size == 1 &&
					 x86->disp == 0x20 &&
					 x86->sib_base == X86_REG_R29 &&
					 x86->sib_index == X86_REG_R30 &&
					 x86->sib_scale == 4,
				 "binary memory encoding detail is exact");
		success &= check(x86->op_count == logical_count,
				 "binary memory operand count is exact");
		for (i = 0; i < logical_count; ++i) {
			uint8_t logical_index =
				att_syntax ? logical_count - 1 - i : i;
			const cs_x86_op *operand = &x86->operands[i];

			if (logical_index == memory_logical_index) {
				success &= check(
					operand->type == X86_OP_MEM &&
						operand->size == width &&
						operand->access ==
							(nd ? CS_AC_READ :
							 reverse ?
							      CS_AC_READ :
							      CS_AC_READ |
									 CS_AC_WRITE) &&
						operand->mem.segment ==
							X86_REG_INVALID &&
						operand->mem.base ==
							X86_REG_R29 &&
						operand->mem.index ==
							X86_REG_R30 &&
						operand->mem.scale == 4 &&
						operand->mem.disp == 0x20,
					"binary memory operand detail is exact");
			} else if (nd &&
				   logical_index == destination_logical_index) {
				success &= check(
					operand->type == X86_OP_REG &&
						operand->reg == destination &&
						operand->size == width &&
						operand->access == CS_AC_WRITE,
					"binary NDD destination detail is exact");
			} else if (logical_index == register_logical_index) {
				success &= check(
					operand->type == X86_OP_REG &&
						operand->reg ==
							source_register &&
						operand->size == width &&
						operand->access ==
							(!nd && reverse ?
								 CS_AC_READ |
									 CS_AC_WRITE :
								 CS_AC_READ),
					"binary register source detail is exact");
			} else {
				success &= check(
					false,
					"unexpected binary logical operand");
			}
		}
		success &= check_flag_detail(&insn[0], operation);
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "binary memory cs_regs_access succeeds");
		success &= check(
			regs_read_count == 4 &&
				has_register(regs_read, regs_read_count,
					     source_register) &&
				has_register(regs_read, regs_read_count,
					     X86_REG_R29) &&
				has_register(regs_read, regs_read_count,
					     X86_REG_R30) &&
				has_register(regs_read, regs_read_count,
					     X86_REG_EFLAGS),
			"binary memory data, address, and carry reads are exact");
		success &= check(
			regs_write_count == (nd || reverse ? 2 : 1) &&
				has_register(regs_write, regs_write_count,
					     X86_REG_EFLAGS) &&
				(!nd ||
				 has_register(regs_write, regs_write_count,
					      destination)) &&
				(nd || !reverse ||
				 has_register(regs_write, regs_write_count,
					      source_register)),
			"binary memory destination and EFLAGS writes are exact");
	}

	cs_free(insn, count);
	if (success)
		return true;
failed:
	fprintf(stderr,
		"binary memory: op=%s width=%u reverse=%u nd=%u syntax=%s\n",
		operation->mnemonic, width, reverse, nd,
		att_syntax ? "att" : "intel");
	if (count != 0)
		cs_free(insn, count);
	return false;
}

static void encode_immediate(uint8_t code[13], size_t *code_size,
			     const arithmetic_operation *operation,
			     uint8_t width, bool sign_extended_byte, bool nd,
			     bool memory, unsigned int destination_number,
			     unsigned int source_number, uint32_t raw_immediate)
{
	unsigned int ndd_number = nd ? destination_number : 0;
	uint8_t opcode = width == 1 ? 0x80 : sign_extended_byte ? 0x83 : 0x81;
	uint8_t pp = width == 2 ? 1 : 0;
	uint8_t w = width == 8 ? 0x80 : 0;
	uint8_t immediate_size = opcode == 0x81 ? (width == 2 ? 2 : 4) : 1;
	size_t cursor;
	uint8_t i;

	code[0] = 0x62;
	if (memory) {
		/* Group extension bits are ignored; address is r29+r30*4+0x20. */
		code[1] = 0x9c;
		code[2] = w | (((~ndd_number) & 0xf) << 3) | pp;
	} else {
		code[1] = 0xd4 | ((source_number & 8) ? 0 : 0x20) |
			  ((source_number & 16) ? 0x08 : 0);
		code[2] = w | (((~ndd_number) & 0xf) << 3) | 0x04 | pp;
	}
	code[3] = (nd ? 0x10 : 0) | ((ndd_number & 16) ? 0 : 0x08);
	code[4] = opcode;
	code[5] = (memory ? 0x44 : 0xc0) | (operation->immediate_group << 3) |
		  (memory ? 0 : source_number & 7);
	if (memory) {
		code[6] = 0xb5;
		code[7] = 0x20;
		cursor = 8;
	} else {
		cursor = 6;
	}
	for (i = 0; i < immediate_size; ++i)
		code[cursor + i] = (uint8_t)(raw_immediate >> (i * 8));
	*code_size = cursor + immediate_size;
}

static int64_t immediate_value(uint8_t width, bool sign_extended_byte,
			       uint32_t raw_immediate)
{
	if (width == 1)
		return raw_immediate & 0xff;
	if (sign_extended_byte)
		return (int8_t)raw_immediate;
	if (width == 2)
		return raw_immediate & 0xffff;
	if (width == 4)
		return raw_immediate;
	return (int32_t)raw_immediate;
}

static void format_immediate(char *buffer, size_t buffer_size, int64_t value,
			     bool att_syntax)
{
	const char *prefix = att_syntax ? "$" : "";

	if (value < -9)
		snprintf(buffer, buffer_size, "%s-0x%llx", prefix,
			 (unsigned long long)(-(value + 1)) + 1);
	else if (value < 0)
		snprintf(buffer, buffer_size, "%s-%llu", prefix,
			 (unsigned long long)(-(value + 1)) + 1);
	else if (value > 9)
		snprintf(buffer, buffer_size, "%s0x%llx", prefix,
			 (unsigned long long)value);
	else
		snprintf(buffer, buffer_size, "%s%llu", prefix,
			 (unsigned long long)value);
}

static bool check_immediate_case(csh handle,
				 const arithmetic_operation *operation,
				 uint8_t width, bool sign_extended_byte,
				 bool nd, bool memory, unsigned int seed,
				 bool att_syntax)
{
	unsigned int destination_number = seed;
	unsigned int source_number = nd ? (seed + 13) & 31 : seed;
	x86_reg destination = register_for(width, destination_number);
	x86_reg source = register_for(width, source_number);
	const char *destination_name = cs_reg_name(handle, destination);
	const char *source_name = cs_reg_name(handle, source);
	const char *size_name = memory_size_name(width);
	uint32_t raw_immediate = width == 1	    ? 0xfe :
				 sign_extended_byte ? 0xf6 :
				 width == 2	    ? 0xbeef :
						      0x89abcdefU;
	int64_t value =
		immediate_value(width, sign_extended_byte, raw_immediate);
	uint8_t immediate_size = width == 1 || sign_extended_byte ? 1 :
				 width == 2			  ? 2 :
								    4;
	uint8_t code[13];
	size_t code_size;
	char expected_mnemonic[16], expected_operands[224];
	char immediate_text[48];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 }, regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	bool success = true;
	size_t count;

	encode_immediate(code, &code_size, operation, width, sign_extended_byte,
			 nd, memory, destination_number, source_number,
			 raw_immediate);
	format_immediate(immediate_text, sizeof(immediate_text), value,
			 att_syntax);
	if (att_syntax) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%c",
			 operation->mnemonic, att_suffix(width));
		if (memory && nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, 0x20(%%r29,%%r30,4), %%%s",
				 immediate_text, destination_name);
		} else if (memory) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, 0x20(%%r29,%%r30,4)", immediate_text);
		} else if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %%%s, %%%s", immediate_text, source_name,
				 destination_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %%%s", immediate_text, source_name);
		}
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s",
			 operation->mnemonic);
		if (memory && nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s ptr [r29 + r30*4 + 0x20], %s",
				 destination_name, size_name, immediate_text);
		} else if (memory) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s ptr [r29 + r30*4 + 0x20], %s", size_name,
				 immediate_text);
		} else if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s, %s", destination_name, source_name,
				 immediate_text);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s", source_name, immediate_text);
		}
	}

	count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	if (!check(count == 1, "immediate form decodes"))
		goto failed;
	success &= check(insn[0].size == code_size &&
				 insn[0].id == operation->instruction,
			 "immediate size and public ID are exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0 &&
				 strcmp(insn[0].op_str, expected_operands) == 0,
			 "immediate text and operand order are exact");
	success &=
		check(insn[0].detail != NULL, "immediate detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		uint8_t logical_count = nd ? 3 : 2;
		uint8_t source_logical_index = nd ? 1 : 0;
		uint8_t immediate_logical_index = logical_count - 1;
		uint8_t i;

		success &=
			check(memcmp(x86->opcode, code, 4) == 0 &&
				      x86->modrm == code[5] &&
				      x86->encoding.modrm_offset == 5 &&
				      x86->encoding.imm_offset ==
					      code_size - immediate_size &&
				      x86->encoding.imm_size == immediate_size,
			      "immediate encoding offsets are exact");
		if (memory) {
			success &= check(
				x86->addr_size == 8 && x86->sib == code[6] &&
					x86->encoding.disp_offset == 7 &&
					x86->encoding.disp_size == 1 &&
					x86->disp == 0x20 &&
					x86->sib_base == X86_REG_R29 &&
					x86->sib_index == X86_REG_R30 &&
					x86->sib_scale == 4,
				"immediate memory encoding detail is exact");
		}
		success &= check(x86->op_count == logical_count,
				 "immediate public operand count is exact");
		for (i = 0; i < logical_count; ++i) {
			uint8_t logical_index =
				att_syntax ? logical_count - 1 - i : i;
			const cs_x86_op *operand = &x86->operands[i];

			if (nd && logical_index == 0) {
				success &= check(
					operand->type == X86_OP_REG &&
						operand->reg == destination &&
						operand->size == width &&
						operand->access == CS_AC_WRITE,
					"immediate NDD destination detail is exact");
			} else if (logical_index == source_logical_index &&
				   memory) {
				success &= check(
					operand->type == X86_OP_MEM &&
						operand->size == width &&
						operand->access ==
							(nd ? CS_AC_READ :
							      CS_AC_READ |
									 CS_AC_WRITE) &&
						operand->mem.base ==
							X86_REG_R29 &&
						operand->mem.index ==
							X86_REG_R30 &&
						operand->mem.scale == 4 &&
						operand->mem.disp == 0x20,
					"immediate memory operand detail is exact");
			} else if (logical_index == source_logical_index) {
				success &= check(
					operand->type == X86_OP_REG &&
						operand->reg == source &&
						operand->size == width &&
						operand->access ==
							(nd ? CS_AC_READ :
							      CS_AC_READ |
									 CS_AC_WRITE),
					"immediate register source detail is exact");
			} else if (logical_index == immediate_logical_index) {
				success &= check(
					operand->type == X86_OP_IMM &&
						operand->imm == value &&
						operand->size == width &&
						operand->access == CS_AC_READ,
					"immediate public value and size are exact");
			} else {
				success &= check(
					false,
					"unexpected immediate logical operand");
			}
		}
		success &= check_flag_detail(&insn[0], operation);
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "immediate cs_regs_access succeeds");
		if (memory) {
			success &= check(
				regs_read_count == 3 &&
					has_register(regs_read, regs_read_count,
						     X86_REG_R29) &&
					has_register(regs_read, regs_read_count,
						     X86_REG_R30) &&
					has_register(regs_read, regs_read_count,
						     X86_REG_EFLAGS),
				"immediate memory address and carry reads are exact");
		} else {
			success &= check(
				regs_read_count == 2 &&
					has_register(regs_read, regs_read_count,
						     source) &&
					has_register(regs_read, regs_read_count,
						     X86_REG_EFLAGS),
				"immediate register and carry reads are exact");
		}
		success &= check(
			regs_write_count == (nd || !memory ? 2 : 1) &&
				has_register(regs_write, regs_write_count,
					     X86_REG_EFLAGS) &&
				(!nd ||
				 has_register(regs_write, regs_write_count,
					      destination)) &&
				(nd || memory ||
				 has_register(regs_write, regs_write_count,
					      source)),
			"immediate destination and EFLAGS writes are exact");
	}

	cs_free(insn, count);
	if (success)
		return true;
failed:
	fprintf(stderr,
		"immediate: op=%s width=%u sign8=%u nd=%u memory=%u seed=%u syntax=%s\n",
		operation->mnemonic, width, sign_extended_byte, nd, memory,
		seed, att_syntax ? "att" : "intel");
	if (count != 0)
		cs_free(insn, count);
	return false;
}

static bool run_matrix(csh handle, bool att_syntax)
{
	static const uint8_t widths[] = { 1, 2, 4, 8 };
	size_t operation_index, width_index;
	unsigned int reverse, nd, seed;

	if (!check(cs_option(handle, CS_OPT_SYNTAX,
			     att_syntax ? CS_OPT_SYNTAX_ATT :
					  CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
		   "select matrix syntax"))
		return false;
	for (operation_index = 0;
	     operation_index < sizeof(operations) / sizeof(operations[0]);
	     ++operation_index) {
		const arithmetic_operation *operation =
			&operations[operation_index];

		for (width_index = 0;
		     width_index < sizeof(widths) / sizeof(widths[0]);
		     ++width_index) {
			uint8_t width = widths[width_index];

			for (reverse = 0; reverse < 2; ++reverse) {
				for (nd = 0; nd < 2; ++nd) {
					for (seed = 0; seed < 32; ++seed) {
						if (!check_binary_register(
							    handle, operation,
							    width, reverse, nd,
							    seed, att_syntax))
							return false;
					}
					if (!check_binary_memory(
						    handle, operation, width,
						    reverse, nd, att_syntax))
						return false;
				}
			}
			for (nd = 0; nd < 2; ++nd) {
				unsigned int sign8_forms = width == 1 ? 1 : 2;
				unsigned int sign8;

				for (sign8 = 0; sign8 < sign8_forms; ++sign8) {
					bool sign_extended_byte = sign8 != 0;

					for (seed = 0; seed < 32; ++seed) {
						if (!check_immediate_case(
							    handle, operation,
							    width,
							    sign_extended_byte,
							    nd, false, seed,
							    att_syntax))
							return false;
					}
					if (!check_immediate_case(
						    handle, operation, width,
						    sign_extended_byte, nd,
						    true, 31, att_syntax))
						return false;
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
	if (!check(count == 1, "current XED anchor decodes"))
		return false;
	success &= check(insn[0].id == anchor->instruction,
			 "anchor public ID is exact");
	success &=
		check(strcmp(insn[0].mnemonic,
			     att_syntax ? anchor->att_mnemonic :
					  anchor->intel_mnemonic) == 0 &&
			      strcmp(insn[0].op_str,
				     att_syntax ? anchor->att_operands :
						  anchor->intel_operands) == 0,
		      "anchor text matches current XED semantics");
	cs_free(insn, count);
	return success;
}

static bool test_encoding_anchors(csh handle)
{
	static const uint8_t adc64_nd[] = {
		0x62, 0x4c, 0x84, 0x10, 0x11, 0xf5,
	};
	static const uint8_t adc64_nd_reverse[] = {
		0x62, 0x4c, 0x84, 0x10, 0x13, 0xf5,
	};
	static const uint8_t adc64_nd_memory_left[] = {
		0x62, 0x0c, 0x80, 0x10, 0x11, 0x64, 0xb5, 0x20,
	};
	static const uint8_t adc64_nd_memory_right[] = {
		0x62, 0x0c, 0x80, 0x10, 0x13, 0x64, 0xb5, 0x20,
	};
	static const uint8_t sbb32_fs_memory[] = {
		0x64, 0x62, 0x0c, 0x78, 0x08, 0x19, 0x64, 0xb5, 0x20,
	};
	static const uint8_t sbb16_nd_address32[] = {
		0x67, 0x62, 0x0c, 0x01, 0x10, 0x1b, 0x64, 0xb5, 0x20,
	};
	static const uint8_t adc8_ignored_w[] = {
		0x62, 0xf4, 0xfc, 0x08, 0x10, 0xc1,
	};
	static const uint8_t sbb64_pp66[] = {
		0x62, 0xf4, 0xfd, 0x08, 0x19, 0xc1,
	};
	static const uint8_t adc8_immediate[] = {
		0x62, 0xdc, 0x7c, 0x08, 0x80, 0xd5, 0xfe,
	};
	static const uint8_t adc8_immediate_ignored_w[] = {
		0x62, 0xdc, 0xfc, 0x08, 0x80, 0xd5, 0xfe,
	};
	static const uint8_t adc64_nd_immediate[] = {
		0x62, 0xdc, 0x84, 0x10, 0x81, 0xd5, 0xfe, 0xff, 0xff, 0xff,
	};
	static const uint8_t adc64_nd_immediate_pp66[] = {
		0x62, 0xdc, 0x85, 0x10, 0x81, 0xd5, 0xfe, 0xff, 0xff, 0xff,
	};
	static const uint8_t sbb64_sign8_pp66[] = {
		0x62, 0xdc, 0xfd, 0x08, 0x83, 0xdd, 0xf6,
	};
	static const uint8_t adc64_memory_immediate[] = {
		0x62, 0x9c, 0xf8, 0x08, 0x81, 0x54,
		0xb5, 0x20, 0x78, 0x56, 0x34, 0x12,
	};
	static const uint8_t sbb32_fs_sign8[] = {
		0x64, 0x62, 0x9c, 0x78, 0x08, 0x83, 0x5c, 0xb5, 0x20, 0xff,
	};
	static const uint8_t sbb16_nd_address32_immediate[] = {
		0x67, 0x62, 0x9c, 0x01, 0x10, 0x81,
		0x5c, 0xb5, 0x20, 0xff, 0xff,
	};
	static const decode_anchor anchors[] = {
		{ adc64_nd, sizeof(adc64_nd), X86_INS_ADC, "adc",
		  "r31, r29, r30", "adcq", "%r30, %r29, %r31" },
		{ adc64_nd_reverse, sizeof(adc64_nd_reverse), X86_INS_ADC,
		  "adc", "r31, r30, r29", "adcq", "%r29, %r30, %r31" },
		{ adc64_nd_memory_left, sizeof(adc64_nd_memory_left),
		  X86_INS_ADC, "adc",
		  "r31, qword ptr [r29 + r30*4 + 0x20], r28", "adcq",
		  "%r28, 0x20(%r29,%r30,4), %r31" },
		{ adc64_nd_memory_right, sizeof(adc64_nd_memory_right),
		  X86_INS_ADC, "adc",
		  "r31, r28, qword ptr [r29 + r30*4 + 0x20]", "adcq",
		  "0x20(%r29,%r30,4), %r28, %r31" },
		{ sbb32_fs_memory, sizeof(sbb32_fs_memory), X86_INS_SBB, "sbb",
		  "dword ptr fs:[r29 + r30*4 + 0x20], r28d", "sbbl",
		  "%r28d, %fs:0x20(%r29,%r30,4)" },
		{ sbb16_nd_address32, sizeof(sbb16_nd_address32), X86_INS_SBB,
		  "sbb", "r31w, r28w, word ptr [r29d + r30d*4 + 0x20]", "sbbw",
		  "0x20(%r29d,%r30d,4), %r28w, %r31w" },
		{ adc8_ignored_w, sizeof(adc8_ignored_w), X86_INS_ADC, "adc",
		  "cl, al", "adcb", "%al, %cl" },
		{ sbb64_pp66, sizeof(sbb64_pp66), X86_INS_SBB, "sbb",
		  "rcx, rax", "sbbq", "%rax, %rcx" },
		{ adc8_immediate, sizeof(adc8_immediate), X86_INS_ADC, "adc",
		  "r29b, 0xfe", "adcb", "$0xfe, %r29b" },
		{ adc8_immediate_ignored_w, sizeof(adc8_immediate_ignored_w),
		  X86_INS_ADC, "adc", "r29b, 0xfe", "adcb", "$0xfe, %r29b" },
		{ adc64_nd_immediate, sizeof(adc64_nd_immediate), X86_INS_ADC,
		  "adc", "r31, r29, -2", "adcq", "$-2, %r29, %r31" },
		{ adc64_nd_immediate_pp66, sizeof(adc64_nd_immediate_pp66),
		  X86_INS_ADC, "adc", "r31, r29, -2", "adcq",
		  "$-2, %r29, %r31" },
		{ sbb64_sign8_pp66, sizeof(sbb64_sign8_pp66), X86_INS_SBB,
		  "sbb", "r29, -0xa", "sbbq", "$-0xa, %r29" },
		{ adc64_memory_immediate, sizeof(adc64_memory_immediate),
		  X86_INS_ADC, "adc",
		  "qword ptr [r29 + r30*4 + 0x20], 0x12345678", "adcq",
		  "$0x12345678, 0x20(%r29,%r30,4)" },
		{ sbb32_fs_sign8, sizeof(sbb32_fs_sign8), X86_INS_SBB, "sbb",
		  "dword ptr fs:[r29 + r30*4 + 0x20], -1", "sbbl",
		  "$-1, %fs:0x20(%r29,%r30,4)" },
		{ sbb16_nd_address32_immediate,
		  sizeof(sbb16_nd_address32_immediate), X86_INS_SBB, "sbb",
		  "r31w, word ptr [r29d + r30d*4 + 0x20], 0xffff", "sbbw",
		  "$0xffff, 0x20(%r29d,%r30d,4), %r31w" },
	};
	uint8_t encoded[13];
	size_t encoded_size;
	bool success = true;
	size_t i;

	encode_binary_register(encoded, &operations[0], 8, false, true, 31, 29,
			       30);
	success &= check(memcmp(encoded, adc64_nd, sizeof(adc64_nd)) == 0,
			 "binary encoding matches current XED");
	encode_immediate(encoded, &encoded_size, &operations[0], 8, false, true,
			 false, 31, 29, 0xfffffffeU);
	success &= check(encoded_size == sizeof(adc64_nd_immediate) &&
				 memcmp(encoded, adc64_nd_immediate,
					sizeof(adc64_nd_immediate)) == 0,
			 "immediate encoding matches current XED");
	for (i = 0; i < sizeof(anchors) / sizeof(anchors[0]); ++i) {
		success &= check_anchor(handle, &anchors[i], false);
		success &= check_anchor(handle, &anchors[i], true);
		if (!success)
			return false;
	}
	return true;
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

static bool test_invalid_encodings(csh handle)
{
	uint8_t binary[8], immediate[13], mutated[20];
	size_t immediate_size;
	bool success = true;
	size_t i;

	if (!check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL) ==
			   CS_ERR_OK,
		   "select invalid-test syntax"))
		return false;
	for (i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
		encode_binary_register(binary, &operations[i], 8, false, true,
				       31, 29, 30);
		memcpy(mutated, binary, 6);
		mutated[3] |= 0x04;
		success &= rejects(
			handle, mutated, 6,
			"NF is reserved for carry-consuming binary forms");
		encode_binary_memory(binary, &operations[i], 4, false, false, 0,
				     28);
		memcpy(mutated, binary, 8);
		mutated[3] |= 0x04;
		success &= rejects(handle, mutated, 8,
				   "NF is reserved for memory binary forms");
		encode_immediate(immediate, &immediate_size, &operations[i], 8,
				 false, true, false, 31, 29, 0x12345678);
		memcpy(mutated, immediate, immediate_size);
		mutated[3] |= 0x04;
		success &= rejects(handle, mutated, immediate_size,
				   "NF is reserved for immediate forms");
	}

	encode_binary_register(binary, &operations[0], 4, false, false, 0, 0,
			       1);
	memcpy(mutated, binary, 6);
	mutated[2] ^= 0x08;
	success &= rejects(handle, mutated, 6,
			   "ND=0 requires the reserved VVVVV value");
	memcpy(mutated, binary, 6);
	mutated[3] ^= 0x08;
	success &= rejects(handle, mutated, 6,
			   "ND=0 requires the reserved V' value");
	memcpy(mutated, binary, 6);
	mutated[2] &= (uint8_t)~0x04;
	success &=
		rejects(handle, mutated, 6, "register form requires EVEX.U=1");
	memcpy(mutated, binary, 6);
	mutated[3] |= 0x80;
	success &= rejects(handle, mutated, 6, "EVEX.z is reserved");
	memcpy(mutated, binary, 6);
	mutated[3] |= 0x20;
	success &= rejects(handle, mutated, 6,
			   "nonzero vector length is reserved");
	memcpy(mutated, binary, 6);
	mutated[3] |= 0x01;
	success &= rejects(handle, mutated, 6, "opmask bits are reserved");
	memcpy(mutated, binary, 6);
	mutated[2] |= 0x02;
	success &= rejects(handle, mutated, 6,
			   "F3 is not a legal scalable prefix");
	memcpy(mutated, binary, 6);
	mutated[2] |= 0x03;
	success &= rejects(handle, mutated, 6,
			   "F2 is not a legal scalable prefix");

	encode_binary_register(binary, &operations[0], 1, false, false, 0, 0,
			       1);
	memcpy(mutated, binary, 6);
	mutated[2] |= 0x01;
	success &= rejects(handle, mutated, 6,
			   "byte binary form requires the NP prefix");

	encode_immediate(immediate, &immediate_size, &operations[0], 8, false,
			 false, false, 0, 0, 0x12345678);
	memcpy(mutated, immediate, immediate_size);
	mutated[5] = (mutated[5] & (uint8_t)~0x38) | 0x08;
	success &= rejects(
		handle, mutated, immediate_size,
		"a different group extension is not decoded as ADC/SBB");
	for (i = 0; i < immediate_size; ++i) {
		success &= rejects(handle, immediate, i,
				   "truncated immediate encoding is rejected");
	}

	encode_binary_memory(binary, &operations[1], 8, true, true, 31, 28);
	for (i = 0; i < sizeof(binary); ++i) {
		success &= rejects(handle, binary, i,
				   "truncated memory encoding is rejected");
	}

	mutated[0] = 0x66;
	memcpy(&mutated[1], binary, sizeof(binary));
	success &= rejects(handle, mutated, sizeof(binary) + 1,
			   "legacy operand-size prefix is rejected");
	mutated[0] = 0xf0;
	memcpy(&mutated[1], binary, sizeof(binary));
	success &= rejects(handle, mutated, sizeof(binary) + 1,
			   "LOCK prefix is rejected");
	mutated[0] = 0x48;
	memcpy(&mutated[1], binary, sizeof(binary));
	success &= rejects(handle, mutated, sizeof(binary) + 1,
			   "legacy REX prefix is rejected");
	memset(mutated, 0x64, 10);
	memcpy(&mutated[10], binary, 6);
	success &= rejects(handle, mutated, 16,
			   "instruction longer than 15 bytes is rejected");
	return success;
}

static bool test_wrong_mode(const uint8_t *code, size_t code_size)
{
	static const cs_mode modes[] = { CS_MODE_16, CS_MODE_32 };
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
		csh handle;

		if (!check(cs_open(CS_ARCH_X86, modes[i], &handle) == CS_ERR_OK,
			   "open non-64-bit handle"))
			return false;
		success &= rejects(handle, code, code_size,
				   "APX promoted ADC/SBB requires 64-bit mode");
		cs_close(&handle);
	}
	return success;
}

int main(void)
{
	csh handle;
	uint8_t wrong_mode_code[6];
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit handle"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}
	success &= run_matrix(handle, false);
	success &= run_matrix(handle, true);
	success &= test_encoding_anchors(handle);
	success &= test_invalid_encodings(handle);
	encode_binary_register(wrong_mode_code, &operations[0], 8, false, true,
			       31, 29, 30);
	success &= test_wrong_mode(wrong_mode_code, sizeof(wrong_mode_code));
	cs_close(&handle);
	return success ? 0 : 1;
}

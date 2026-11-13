/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"

#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86SimpleOutput.h"

static void writeUnsignedImmediate(char *out, uint64_t value)
{
	if (value <= HEX_THRESHOLD) {
		*out = (char)('0' + value);
	} else {
		static const char digits[] = "0123456789abcdef";
		char temp[16], *end = temp + sizeof(temp), *start = end;
		uint64_t n = value;
		do {
			*--start = digits[n & 15];
			n >>= 4;
		} while (n);
		memcpy(out, "0x", 2);
		memcpy(out + 2, start, end - start);
	}
}

static void writePushImmediate(cs_insn *insn, const uint8_t *code,
			       const struct X86SimpleOutput *row, bool wide,
			       uint16_t *insn_size)
{
	const bool imm8 = code[0] == 0x6a;
	const unsigned length = imm8 ? 2 : 5;
	int64_t value;
	if (imm8)
		value = (int8_t)code[1];
	else {
		uint32_t raw = (uint32_t)code[1] | (uint32_t)code[2] << 8 |
			       (uint32_t)code[3] << 16 |
			       (uint32_t)code[4] << 24;
		value = wide ? (int64_t)(int32_t)raw : (int64_t)raw;
	}
	*insn_size = insn->size = length;
	insn->id = row->id;
	memcpy(insn->bytes, code, length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = insn->op_str;
	if (value < 0)
		*out++ = '-';
	writeUnsignedImmediate(out,
			       value < 0 ? (uint64_t)-value : (uint64_t)value);
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, code[0], 0, 0, 0, 0);
		cs_x86_op *op = &insn->detail->x86.operands[0];
		op->type = X86_OP_IMM;
		op->imm = value;
	}
}

static void writeMovRegImm32(cs_insn *insn, const struct X86SimpleOutput *row,
			     const struct X86SimpleRegister *reg,
			     const uint8_t *code, uint8_t rex,
			     uint16_t *insn_size)
{
	const unsigned offset = 1 + (rex != 0);
	const uint8_t *raw = code + offset;
	const uint32_t value = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
			       ((uint32_t)raw[2] << 16) |
			       ((uint32_t)raw[3] << 24);
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)(offset + 4);
	memcpy(insn->bytes, code, insn->size);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	memcpy(insn->op_str, reg->name, sizeof(reg->name));
	char *out = insn->op_str + reg->length;
	memcpy(out, ", ", 2);
	writeUnsignedImmediate(out + 2, value);
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, code[rex != 0], rex, 0,
				      reg->reg, 0);
		cs_x86 *x = &insn->detail->x86;
		x->encoding.modrm_offset = 0;
		x->encoding.imm_offset = (uint8_t)offset;
		x->encoding.imm_size = 4;
		x->operands[1].type = X86_OP_IMM;
		x->operands[1].imm = value;
		x->operands[1].access = 0;
	}
}

/* The /digit selects the same flags and register access as the corresponding
 * ALU register pair. The immediate's public width follows the destination. */
static void writeRegisterImmediate(cs_insn *insn,
				   const struct X86SimpleOutput *row,
				   const struct X86SimpleRegister *reg,
				   const uint8_t *code, uint8_t rex,
				   uint8_t modrm, bool shift,
				   uint16_t *insn_size)
{
	const unsigned offset = 2 + (rex != 0);
	const int immediate = shift ? code[offset] : (int8_t)code[offset];
	const unsigned group = (modrm >> 3) & 7;
	const bool logical = !shift && (group == 1 || group == 4 || group == 6);
	const bool wide = (rex & 8) != 0;
	const bool negative = !logical && immediate < 0;
	const uint64_t value =
		logical ? (wide ? (uint64_t)(int64_t)immediate :
				  (uint32_t)immediate) :
			  (uint64_t)(negative ? -immediate : immediate);
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)(offset + 1);
	memcpy(insn->bytes, code, insn->size);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	memcpy(insn->op_str, reg->name, sizeof(reg->name));
	char *out = insn->op_str + reg->length;
	memcpy(out, ", ", 2);
	out += 2;
	if (negative)
		*out++ = '-';
	writeUnsignedImmediate(out, value);
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, shift ? 0xc1 : 0x83,
				      rex, modrm, reg->reg, 0);
		cs_x86 *x = &insn->detail->x86;
		x->operands[1].type = X86_OP_IMM;
		x->operands[1].imm = logical && !wide ?
					     (int64_t)(uint32_t)immediate :
					     immediate;
		if (!shift)
			x->operands[1].access = 0;
		x->encoding.imm_offset = (uint8_t)offset;
		x->encoding.imm_size = 1;
	}
}

void X86_writeImmediateOutput(const uint8_t *code, cs_insn *insn,
			      uint16_t *insn_size, uint8_t rex,
			      const struct X86SimpleOutput *row,
			      const struct X86SimpleRegister *reg)
{
	const uint8_t opcode = code[rex != 0];
	if (opcode == 0x68 || opcode == 0x6a)
		writePushImmediate(insn, code, row, row->address_size == 8,
				   insn_size);
	else if ((opcode & 0xf8) == 0xb8)
		writeMovRegImm32(insn, row, reg, code, rex, insn_size);
	else
		writeRegisterImmediate(insn, row, reg, code, rex,
				       code[1 + (rex != 0)], opcode == 0xc1,
				       insn_size);
}
#endif
#endif

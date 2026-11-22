/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_REGISTER_IMMEDIATE_OUTPUT_H
#define CS_X86_REGISTER_IMMEDIATE_OUTPUT_H

#include "X86SimpleOutput.h"
#include "X86UnsignedImmediate.h"

/* MOV opcode-register and TEST ModR/M-register forms have unsigned immediates.
 * A register-direct ModR/M byte always has its top two bits set. */
static inline void writeUnsignedRegisterImmediate(
	cs_insn *insn, const struct X86SimpleOutput *row,
	const struct X86SimpleRegister *reg, const uint8_t *code, uint8_t rex,
	uint8_t modrm, unsigned offset, unsigned imm_size, uint16_t *insn_size)
{
	const uint8_t *raw = code + offset;
	const uint32_t value =
		imm_size == 1 ? raw[0] :
				(uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
					((uint32_t)raw[2] << 16) |
					((uint32_t)raw[3] << 24);
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)(offset + imm_size);
	memcpy(insn->bytes, code, insn->size);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	memcpy(insn->op_str, reg->name, sizeof(reg->name));
	char *out = insn->op_str + reg->length;
	memcpy(out, ", ", 2);
	writeUnsignedImmediate(out + 2, value);
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, code[rex != 0], rex,
				      modrm, reg->reg, 0);
		cs_x86 *x = &insn->detail->x86;
		x->encoding.modrm_offset = modrm ? (uint8_t)(offset - 1) : 0;
		x->encoding.imm_offset = (uint8_t)offset;
		x->encoding.imm_size = (uint8_t)imm_size;
		x->operands[1].type = X86_OP_IMM;
		x->operands[1].imm = value;
		x->operands[1].access = 0;
	}
}

#endif

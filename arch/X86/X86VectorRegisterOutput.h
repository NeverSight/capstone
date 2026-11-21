/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_VECTOR_REGISTER_OUTPUT_H
#define CS_X86_VECTOR_REGISTER_OUTPUT_H

#include "X86VectorRegisterWriter.h"

static bool writeVectorRegisters(const uint8_t *code, cs_insn *insn,
				 uint16_t *insn_size,
				 const struct VectorOutputRow *row,
				 unsigned prefix, unsigned ll, unsigned rex,
				 unsigned first_ll, const unsigned *regs,
				 unsigned reg_count)
{
	const unsigned len = prefix + 2 + row->immediate;
	*insn_size = insn->size = (uint16_t)len;
	insn->id = row->id;
	memcpy(insn->bytes, code, len);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, first_ll, regs[0]);
	for (unsigned n = 1; n != reg_count; ++n) {
		memcpy(out, ", ", 2);
		out = writeVectorRegister(out + 2, ll, regs[n]);
	}
	if (row->immediate) {
		const unsigned value = code[prefix + 2];
		memcpy(out, ", ", 2);
		out += 2;
		if (value <= HEX_THRESHOLD) {
			*out = (char)('0' + value);
		} else {
			static const char digits[] = "0123456789abcdef";
			memcpy(out, "0x", 2);
			out += 2;
			if (value >= 16)
				*out++ = digits[value >> 4];
			*out = digits[value & 15];
		}
	}
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		memcpy(d->groups, row->groups, sizeof(row->groups));
		d->groups_count = row->group_count;
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, prefix);
		x->addr_size = 8;
		x->rex = (uint8_t)rex;
		x->modrm = code[prefix + 1];
		x->encoding.modrm_offset = (uint8_t)(prefix + 1);
		x->op_count = (uint8_t)(reg_count + row->immediate);
		static const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0,
						 X86_REG_ZMM0 };
		for (unsigned n = 0; n != reg_count; ++n) {
			cs_x86_op *op = &x->operands[n];
			op->type = X86_OP_REG;
			const unsigned width = n == 0 ? first_ll : ll;
			op->reg = (x86_reg)(bases[width] + regs[n]);
			op->access = (cs_ac_type)row->access[n];
			op->size = (uint8_t)(16 << width);
		}
		if (row->immediate) {
			x->operands[reg_count].type = X86_OP_IMM;
			x->operands[reg_count].imm = code[prefix + 2];
			x->operands[reg_count].access =
				(cs_ac_type)row->access[reg_count];
			x->operands[reg_count].size = 1;
			x->encoding.imm_offset = (uint8_t)(prefix + 2);
			x->encoding.imm_size = 1;
		}
	}
	return true;
}

#endif

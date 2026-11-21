/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_EXTEND_REGISTER_OUTPUT_H
#define CS_X86_EXTEND_REGISTER_OUTPUT_H

static inline void writeExtendRegisters(const uint8_t *code, unsigned length,
					cs_insn *insn, uint16_t *insn_size,
					const struct X86SimpleOutput *row,
					const struct X86SimpleRegister *dst,
					const struct X86SimpleRegister *src,
					uint8_t rex, uint8_t opcode, uint8_t mr,
					bool escaped)
{
	*insn_size = insn->size = length;
	insn->id = row->id;
	memcpy(insn->bytes, code, length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	memcpy(insn->op_str, dst->name, sizeof(dst->name));
	char *next = insn->op_str + dst->length;
	memcpy(next, ", ", 2);
	memcpy(next + 2, src->name, sizeof(src->name));
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row,
				      escaped ? 0x0f : opcode, rex, mr,
				      dst->reg, src->reg);
		if (escaped)
			insn->detail->x86.opcode[1] = opcode;
		if (escaped && rex)
			insn->detail->x86.encoding.modrm_offset = 3;
	}
}

#endif

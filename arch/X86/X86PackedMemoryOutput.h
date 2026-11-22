/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_PACKED_MEMORY_OUTPUT_H
#define CS_X86_PACKED_MEMORY_OUTPUT_H

struct X86SseRegisterOutput {
	struct X86SimpleOutput output;
	bool reverse;
	bool base_memory;
};
static bool writePackedMemory(const uint8_t *code, cs_insn *insn,
			      uint16_t *insn_size,
			      const struct X86SseRegisterOutput *entry,
			      uint8_t rex, unsigned offset, size_t size,
			      bool vex)
{
	const uint8_t mr = code[offset - 1], opcode = code[offset - 2];
	const unsigned number = ((mr >> 3) & 7) | ((rex & 4) << 1);
	const unsigned mod = mr >> 6, rm = mr & 7;
	const bool rip = !mod && rm == 5, sib = rm == 4;
	const unsigned disp_size = mod == 2 || rip ? 4 : mod;
	const unsigned disp_offset = offset + sib,
		       length = disp_offset + disp_size;
	if (size < length || (sib && ((rex & 2) || code[offset] != 0x24)))
		return false;
	const int32_t disp = disp_size == 4 ?
				     X86_readDisp32(code + disp_offset) :
			     disp_size == 1 ? (int8_t)code[disp_offset] :
					      0;
	const struct X86SimpleRegister *base =
		&x86_simple_registers[3][((rex & 1) << 3) | rm];
	const struct X86SimpleOutput *row = &entry->output;
	insn->size = *insn_size = (uint16_t)length;
	insn->id = row->id;
	memcpy(insn->bytes, code, insn->size);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	const unsigned ll = vex && (code[1] & 4);
	char *out = insn->op_str;
	if (!entry->reverse) {
		out = writeVectorRegister(out, ll, number);
		memcpy(out, ", ", 2);
		out += 2;
	}
#ifdef X86_LEGACY_PACKED_MEMORY
	const unsigned width = row->ops[entry->reverse ? 0 : 1].size;
	if (width < 16) {
		memcpy(out, "dword ptr [", 11);
		if (width == 8)
			*out = 'q';
		out += 11;
	} else {
		memcpy(out, "xmmword ptr [", 13);
		out += 13;
	}
#else
	memcpy(out, "xmmword ptr [", 13);
	if (ll)
		*out = 'y';
	out += 13;
#endif
	if (rip) {
		memcpy(out, "rip", 3);
		out += 3;
	} else {
		memcpy(out, base->name, base->length);
		out += base->length;
	}
	out = X86_writeDisplacement(out, disp);
	*out++ = ']';
	if (entry->reverse) {
		memcpy(out, ", ", 2);
		writeVectorRegister(out + 2, ll, number);
	}
	if (insn->detail) {
		const uint16_t reg =
			(uint16_t)((ll ? X86_REG_YMM0 : X86_REG_XMM0) + number);
		X86_writeSimpleDetail(insn->detail, row, 0x0f, rex, mr,
				      entry->reverse ? 0 : reg,
				      entry->reverse ? reg : 0);
		cs_x86 *x = &insn->detail->x86;
		if (vex) {
			memcpy(x->opcode, code, 2);
		} else {
			x->opcode[1] = opcode;
#ifdef X86_LEGACY_PACKED_MEMORY
			if (code[0] == 0x66)
				x->prefix[2] = 0x66;
#endif
		}
		x->encoding.modrm_offset = (uint8_t)(offset - 1);
		if (disp_size) {
			x->encoding.disp_offset = (uint8_t)disp_offset;
			x->encoding.disp_size = (uint8_t)disp_size;
		}
		if (sib) {
			x->sib = 0x24;
			x->sib_base = (x86_reg)base->reg;
			x->sib_scale = 1;
		}
		x->disp = disp;
		cs_x86_op *op = &x->operands[entry->reverse ? 0 : 1];
		op->type = X86_OP_MEM;
		op->mem.base = rip ? X86_REG_RIP : (x86_reg)base->reg;
		op->mem.scale = 1;
		op->mem.disp = disp;
	}
	return true;
}

#endif

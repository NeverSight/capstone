/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_EVEX_MEMORY_RECORD_H
#define CS_X86_EVEX_MEMORY_RECORD_H

#include "X86SimpleOutput.h"
#include "X86VectorRegisterWriter.h"

#include "X86EvexMemoryTables.h"

/* Both paths use the same record and full-vector disp8 tuple. The fallback
 * additionally admits SIB encodings with a real index and a base register. */
#ifdef X86_EVEX_INDEXED_SIB
static inline bool writeIndexedEvexMemory(const uint8_t *code, size_t size,
					  cs_insn *insn, uint16_t *insn_size,
					  const struct X86SimpleRegister *regs)
#else
X86_EVEX_MEMORY_CODE
bool X86_writeEvexMemoryOutput(const uint8_t *code, size_t size, cs_insn *insn,
			       uint16_t *insn_size,
			       const struct X86SimpleRegister *regs)
#endif
{
#ifdef X86_EVEX_INDEXED_SIB
	const bool indexed = true;
#else
	const bool indexed = false;
#endif

	if (size < 6 || (code[1] & 15) != 1 || (code[2] & 0x7c) != 0x7c ||
	    (code[3] & 0x9f) != 8)
		return false;
	const unsigned opcode = x86_evex_memory_opcodes[code[4]];
	const unsigned wpp = ((code[2] >> 5) & 4) | (code[2] & 3);
	const unsigned form = x86_evex_memory_prefixes[opcode >> 1][wpp];
	const unsigned ll = code[3] >> 5;
	const uint8_t modrm = code[5];
	const unsigned mod = modrm >> 6, rm = modrm & 7;
	if (!form || ll >= 3 || mod == 3)
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	const bool sib = rm == 4, rip = !mod && rm == 5;
	const unsigned offset = 6 + sib;
	const unsigned disp_size = mod == 2 || rip ? 4 : mod;
	const unsigned length = offset + disp_size;
	if (size < length ||
	    (indexed ? !sib : sib && ((rxb & 2) || code[6] != 0x24)))
		return false;
	unsigned base_number = rm, scale_bits = 0;
	const struct X86SimpleRegister *index = NULL;
	if (indexed) {
		const uint8_t encoding = code[6];
		base_number = encoding & 7;
		const unsigned number = ((rxb & 2) << 2) |
					((encoding >> 3) & 7);
		if ((!mod && base_number == 5) || number == 4)
			return false;
		index = &regs[number];
		scale_bits = encoding >> 6;
	}
	const unsigned store = opcode & 1;
	const struct EvexMemoryOutputRow *row =
		&x86_evex_memory_rows[form - 1][store][ll];
	const unsigned number = ((modrm >> 3) & 7) | ((rxb & 4) << 1) |
				(~(unsigned)code[1] & 16);
	const struct X86SimpleRegister *base =
		&regs[base_number | ((rxb & 1) << 3)];
	const unsigned width = 16u << ll;
	const int32_t displacement =
		disp_size == 1 ? (int8_t)code[offset] * (int)width :
		disp_size == 4 ? X86_readDisp32(code + offset) :
				 0;
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)length;
	memcpy(insn->bytes, code, length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = insn->op_str;
	if (!store) {
		out = writeVectorRegister(out, ll, number);
		memcpy(out, ", ", 2);
		out += 2;
	}
	memcpy(out, "xmmword ptr [", 13);
	*out = "xyz"[ll];
	out += 13;
	if (rip) {
		memcpy(out, "rip", 3);
		out += 3;
	} else {
		memcpy(out, base->name, sizeof(base->name));
		out += base->length;
	}
	if (index)
		out = X86_writeScaledIndex(out, index, scale_bits);
	out = X86_writeDisplacement(out, displacement);
	*out++ = ']';
	if (store) {
		memcpy(out, ", ", 2);
		writeVectorRegister(out + 2, ll, number);
	}
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		d->groups_count = row->group_count;
		memcpy(d->groups, row->groups, sizeof(row->groups));
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, sizeof(x->opcode));
		x->rex = (uint8_t)(0x40 | ((code[2] >> 4) & 8) | rxb);
		x->addr_size = 8;
		x->modrm = modrm;
		x->encoding.modrm_offset = 5;
		if (disp_size) {
			x->encoding.disp_offset = (uint8_t)offset;
			x->encoding.disp_size = (uint8_t)disp_size;
		}
		x->op_count = 2;
		static const x86_reg vector_bases[] X86_EVEX_MEMORY_DATA = {
			X86_REG_XMM0, X86_REG_YMM0, X86_REG_ZMM0
		};
		cs_x86_op *reg = &x->operands[store];
		reg->type = X86_OP_REG;
		reg->reg = (x86_reg)(vector_bases[ll] + number);
		reg->size = (uint8_t)width;
		reg->access = (cs_ac_type)row->access[store];
		cs_x86_op *mem = &x->operands[!store];
		mem->type = X86_OP_MEM;
		mem->size = (uint8_t)width;
		mem->access = (cs_ac_type)row->access[!store];
		mem->mem.base = rip ? X86_REG_RIP : (x86_reg)base->reg;
		mem->mem.scale = (int)(1u << scale_bits);
		if (index)
			mem->mem.index = (x86_reg)index->reg;
		mem->mem.disp = x->disp = displacement;
		if (sib) {
			x->sib = code[6];
			x->sib_base = mem->mem.base;
			if (indexed)
				x->sib_index = (x86_reg)index->reg;
			x->sib_scale = (int8_t)(1u << scale_bits);
		}
	}
	return true;
}

#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef CS_X86_VEX_SIB_TRANSFER_H
#define CS_X86_VEX_SIB_TRANSFER_H
#include "X86SimpleOutput.h"
#include "X86VectorRegisterWriter.h"

struct VexSibTransfer {
	uint16_t id;
	char mnemonic[8], memory[12];
	uint8_t memory_length, reg_size, mem_size, group_count, groups[4];
	uint8_t access[2][2];
};
#include "X86GenVexSibTransfers.inc"

static char *writeTransferRegister(char *out, bool mask, unsigned number)
{
	if (!mask)
		return writeVectorRegister(out, 0, number);
	*out++ = 'k';
	*out++ = (char)('0' + number);
	return out;
}

/* The caller checked map 0F and a complete memory ModR/M and SIB.
 * Keep the indexed-move record out of the ordinary vector reader. */
static __attribute__((noinline, minsize)) bool
writeVexSibTransfer(const uint8_t *code, size_t size, unsigned prefix,
		    cs_insn *insn, uint16_t *insn_size,
		    const struct X86SimpleRegister *regs)
{
	/* VEX2 encodes inverted R in bit 7. Its W, X and B bits are zero. */
	const bool short_prefix = prefix == 2;
	const unsigned flags = code[prefix - 1] & (short_prefix ? 0x7f : 0xff);
	const unsigned opcode = code[prefix], mr = code[prefix + 1];
	const unsigned offset = prefix + 3;
	if ((flags & 0x7c) != 0x78)
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & (short_prefix ? 4 : 7);
	const bool mask = (opcode & 0xfe) == 0x90;
	unsigned form;
	if (mask) {
		/* ModR/M.reg names K0..K7. */
		if ((flags & 2) || (rxb & 4))
			return false;
		form = ((flags >> 6) & 2) | (flags & 1);
	} else if ((opcode & 0xef) == 0x6e && (flags & 0x83) == 1) {
		form = 6;
	} else {
		if ((opcode & 0xfe) != 0x10 || (flags & 0x82) != 2)
			return false;
		form = 4 + (flags & 1);
	}
	const unsigned mod = mr >> 6, sib = code[prefix + 2];
	const unsigned base_number = (sib & 7) | ((rxb & 1) << 3);
	const unsigned index_number = ((sib >> 3) & 7) | ((rxb & 2) << 2);
	const unsigned disp_size = mod == 2 ? 4 : mod;
	/* Leave base-less and pseudo-index spellings to the full printer. */
	if ((!mod && (sib & 7) == 5) || (index_number == 4 && sib != 0x24) ||
	    size < offset + disp_size)
		return false;

	const int32_t disp = disp_size == 4 ? X86_readDisp32(code + offset) :
			     disp_size == 1 ? (int8_t)code[offset] : 0;
	const struct X86SimpleRegister *base = &regs[base_number];
	const unsigned number = ((mr >> 3) & 7) | ((rxb & 4) << 1);
	const unsigned store = form == 6 ? (opcode >> 4) & 1 : opcode & 1;
	const unsigned scale_bits = sib >> 6;
	const struct VexSibTransfer *row = &vex_sib_transfers[form];
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)(offset + disp_size);
	memcpy(insn->bytes, code, insn->size);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = insn->op_str;
	if (!store) {
		out = writeTransferRegister(out, mask, number);
		memcpy(out, ", ", 2);
		out += 2;
	}
	memcpy(out, row->memory, sizeof(row->memory));
	out += row->memory_length;
	memcpy(out, base->name, sizeof(base->name));
	out += base->length;
	if (index_number != 4)
		out = X86_writeScaledIndex(out, &regs[index_number], scale_bits);
	out = X86_writeDisplacement(out, disp);
	*out++ = ']';
	if (store) {
		memcpy(out, ", ", 2);
		writeTransferRegister(out + 2, mask, number);
	}
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		d->groups_count = row->group_count;
		memcpy(d->groups, row->groups, sizeof(row->groups));
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, prefix);
		x->addr_size = 8;
		x->rex = (uint8_t)(0x40 | ((flags >> 4) & 8) | rxb);
		x->modrm = (uint8_t)mr;
		x->encoding.modrm_offset = (uint8_t)(prefix + 1);
		x->sib = (uint8_t)sib;
		x->sib_base = (x86_reg)base->reg;
		if (index_number != 4)
			x->sib_index = (x86_reg)regs[index_number].reg;
		x->sib_scale = (int8_t)(1u << scale_bits);
		if (disp_size) {
			x->encoding.disp_offset = (uint8_t)offset;
			x->encoding.disp_size = (uint8_t)disp_size;
		}
		x->op_count = 2;
		cs_x86_op *reg = &x->operands[store], *mem = &x->operands[!store];
		reg->type = X86_OP_REG;
		reg->reg = (x86_reg)((mask ? X86_REG_K0 : X86_REG_XMM0) + number);
		reg->size = row->reg_size;
		reg->access = (cs_ac_type)row->access[store][store];
		mem->type = X86_OP_MEM;
		mem->mem.base = x->sib_base;
		mem->mem.index = x->sib_index;
		mem->mem.scale = x->sib_scale;
		mem->mem.disp = x->disp = disp;
		mem->size = row->mem_size;
		mem->access = (cs_ac_type)row->access[store][!store];
	}
	return true;
}
#endif

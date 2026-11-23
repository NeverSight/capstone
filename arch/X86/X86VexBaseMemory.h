/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef CS_X86_VEX_BASE_MEMORY_H
#define CS_X86_VEX_BASE_MEMORY_H
#include "X86SimpleOutput.h"
#include "X86VectorRegisterWriter.h"
#include "X86GenVexBaseMemory.inc"

static const struct X86SimpleRegister vector_rip = { X86_REG_RIP, 3, "rip" };

/* Two vector registers followed by a full-width memory source.
 * The encoding reader has checked the full extent and the semantic row. */
static bool writeVectorMemory(const uint8_t *code, cs_insn *insn,
				 uint16_t *insn_size,
				 const struct VectorOutputRow *row,
				 unsigned prefix, unsigned ll, unsigned rex,
				 unsigned dst, unsigned src,
				 const struct X86SimpleRegister *base,
				 unsigned disp_size, int32_t displacement)
{
	const unsigned length = prefix + 2 + disp_size;
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)length;
	memcpy(insn->bytes, code, length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, ll, dst);
	memcpy(out, ", ", 2);
	out = writeVectorRegister(out + 2, ll, src);
	memcpy(out, ", xmmword ptr [", 15);
	out[2] = "xyz"[ll];
	out += 15;
	memcpy(out, base->name, sizeof(base->name));
	*X86_writeDisplacement(out + base->length, displacement) = ']';
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		d->groups_count = row->group_count;
		memcpy(d->groups, row->groups, sizeof(row->groups));
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, prefix);
		x->rex = (uint8_t)rex;
		x->addr_size = 8;
		x->modrm = code[prefix + 1];
		x->encoding.modrm_offset = (uint8_t)(prefix + 1);
		if (disp_size) {
			x->encoding.disp_offset = (uint8_t)(prefix + 2);
			x->encoding.disp_size = (uint8_t)disp_size;
		}
		x->disp = displacement;
		x->op_count = 3;
		static const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0,
						 X86_REG_ZMM0 };
		for (unsigned i = 0; i < 2; ++i) {
			cs_x86_op *op = &x->operands[i];
			op->type = X86_OP_REG;
			op->reg = (x86_reg)(bases[ll] + (i ? src : dst));
			op->size = (uint8_t)(16 << ll);
			op->access = (cs_ac_type)row->access[i];
		}
		cs_x86_op *mem = &x->operands[2];
		mem->type = X86_OP_MEM;
		mem->mem.base = (x86_reg)base->reg;
		mem->mem.scale = 1;
		mem->mem.disp = displacement;
		mem->size = (uint8_t)(16 << ll);
		mem->access = (cs_ac_type)row->access[2];
	}
	return true;
}

/* The AMD64 fallback checked both prefix bytes and a memory ModR/M. */
static bool writeVexBaseMemory(const uint8_t *code, size_t size, unsigned prefix,
			    cs_insn *insn, uint16_t *insn_size,
			    const struct X86SimpleRegister *regs)
{
	const bool short_prefix = prefix == 2;
	const unsigned flags = code[prefix - 1];
	const unsigned map = short_prefix ? 1 : code[1] & 31;
	if (map < 1 || map > 3 || (flags & 3) != 1)
		return false;
	const unsigned w = short_prefix ? 0 : flags >> 7;
	const unsigned ll = (flags >> 2) & 1, wl = w * 2 + ll,
		       opcode = code[prefix];
	const unsigned plan = vex_base_plans[map - 1][opcode];
	const unsigned index = vex_base_widths[plan][wl];
	if (!index)
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & (short_prefix ? 4 : 7);
	const unsigned dst = ((code[prefix + 1] >> 3) & 7) | ((rxb & 4) << 1);
	const unsigned mod = code[prefix + 1] >> 6;
	const unsigned rm = code[prefix + 1] & 7;
	if (rm == 4)
		return false;
	const bool rip = mod == 0 && rm == 5;
	const unsigned disp_size = rip || mod == 2 ? 4 : mod;
	const unsigned offset = prefix + 2;
	if (size < offset + disp_size)
		return false;
	const int32_t disp = disp_size == 4 ? X86_readDisp32(code + offset) :
			     disp_size == 1 ? (int8_t)code[offset] : 0;
	const struct X86SimpleRegister *base =
		rip ? &vector_rip : &regs[rm | ((rxb & 1) << 3)];
	return writeVectorMemory(code, insn, insn_size, &vex_base_rows[index],
				 prefix, ll, 0x40 | (w << 3) | rxb, dst,
				 (~flags >> 3) & 15, base, disp_size, disp);
}
#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

/* Instantiated for the ordinary address writer and the private mode-specific writers. */

/* No-base SIB and encodings exposing EIZ/RIZ retain the general printer. */
#ifdef X86_MEMORY_IMMEDIATE
#include "X86UnsignedImmediate.h"
static bool X86_MEMORY_IMMEDIATE(
#elif defined(X86_EXTEND64_MEMORY)
static bool X86_EXTEND64_MEMORY(
#elif defined(X86_EXTEND32_MEMORY)
static bool X86_EXTEND32_MEMORY(
#elif defined(X86_MEMORY32_OUTPUT)
static bool X86_MEMORY32_OUTPUT(
#else
bool X86_writeMemoryOutput(
#endif
	const uint8_t *code, size_t size, cs_insn *insn, uint16_t *insn_size,
	const struct X86SimpleOutput *row,
	const struct X86SimpleRegister regs[4][16])
{
#ifdef X86_MEMORY_IMMEDIATE
	const bool wide = X86_IMMEDIATE_WIDE;
#elif defined(X86_EXTEND64_MEMORY)
	const bool wide = true;
#elif defined(X86_MEMORY32_OUTPUT)
	const bool wide = false;
#else
	const bool wide = row->address_size == 8;
#endif
	const uint8_t rex = wide && (code[0] & 0xf0) == 0x40 ? code[0] : 0;
#ifdef X86_EXTEND64_MEMORY
	const unsigned lead = (rex != 0) + (code[rex != 0] == 0x0f);
#elif defined(X86_EXTEND32_MEMORY)
	const unsigned lead = 1; /* The caller consumed the 0F escape. */
#else
	const unsigned lead = rex != 0;
#endif
	const uint8_t opcode = code[lead], modrm = code[lead + 1];
	const unsigned mod = modrm >> 6, rm = modrm & 7;
	const bool sib = rm == 4, disp32_only = !mod && rm == 5;
	const unsigned offset = lead + 2 + sib;
	const unsigned disp_size = mod == 2 || disp32_only ? 4 : mod;
#ifdef X86_MEMORY_IMMEDIATE
	const unsigned imm_size = (opcode & 1) ? 4 : 1;
	const unsigned imm_offset = offset + disp_size;
	const unsigned length = imm_offset + imm_size;
#else
	const unsigned length = offset + disp_size;
#endif
#ifdef X86_MEMORY32_OUTPUT
	if (size < length)
#else
	if (size < length || (disp32_only && !wide))
#endif
		return false;

	unsigned base_reg = rm;
	const struct X86SimpleRegister *index = NULL;
	unsigned scale_bits = 0;
	if (sib) {
		const uint8_t encoding = code[offset - 1];
		const unsigned index_reg = ((rex & 2) << 2) |
					   ((encoding >> 3) & 7);
		base_reg = encoding & 7;
		if ((!mod && base_reg == 5) ||
		    (index_reg == 4 && encoding != 0x24))
			return false;
		if (index_reg != 4) {
			index = &regs[wide ? 3 : 2][index_reg];
			scale_bits = encoding >> 6;
		}
	}

#ifdef X86_EXTEND64_MEMORY
	const bool push = false, load = true;
	const unsigned reg_width = rex & 8 ? 3 : 2;
#elif defined(X86_EXTEND32_MEMORY)
	const bool push = false, load = true;
	const unsigned reg_width = 2; /* r32 destination */
#else
#ifdef X86_MEMORY_IMMEDIATE
	const bool lea = false, load = false;
#else
	const bool push = opcode == 0xff, lea = opcode == 0x8d;
	const bool load = !push && (lea || (opcode & 2));
#endif
	const unsigned reg_width = (opcode & 1) ? ((rex & 8) ? 3 : 2) : lead;
#endif
	const struct X86SimpleRegister *reg =
		&regs[reg_width][((rex & 4) << 1) | ((modrm >> 3) & 7)];
	const struct X86SimpleRegister *base =
		&regs[wide ? 3 : 2][((rex & 1) << 3) | base_reg];
	int32_t displacement = 0;
	if (disp_size == 1) {
		displacement = (int8_t)code[offset];
	} else if (disp_size == 4) {
		displacement = X86_readDisp32(code + offset);
	}
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)length;
	memcpy(insn->bytes, code, length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = insn->op_str;
	if (load) {
		memcpy(out, reg->name, sizeof(reg->name));
		out += reg->length;
		memcpy(out, ", ", 2);
		out += 2;
	}
#if defined(X86_EXTEND32_MEMORY) || defined(X86_EXTEND64_MEMORY)
#ifdef X86_EXTEND64_MEMORY
	if (row->ops[1].size == 4) {
		memcpy(out, "dword ptr [", 11);
		out += 11;
	} else
#endif
	{
		memcpy(out, row->ops[1].size == 1 ? "byte ptr [" : "word ptr [",
		       10);
		out += 10;
	}
#else
	if (lea) {
		*out++ = '[';
	} else if (row->ops[0].size == 1) {
		memcpy(out, "byte ptr [", 10);
		out += 10;
	} else {
		memcpy(out,
		       row->ops[0].size == 8 ? "qword ptr [" : "dword ptr [",
		       11);
		out += 11;
	}
#endif
	if (disp32_only) {
#ifdef X86_MEMORY32_OUTPUT
		/* The absolute address is unsigned in Intel text. The encoded
         * displacement is signed in both public detail fields. */
		out = writeUnsignedImmediate(out, (uint32_t)displacement);
#else
		memcpy(out, "rip", 3);
		out += 3;
#endif
	} else {
		memcpy(out, base->name, sizeof(base->name));
		out += base->length;
	}
	if (index) {
		memcpy(out, " + ", 3);
		out += 3;
		memcpy(out, index->name, sizeof(index->name));
		out += index->length;
		if (scale_bits) {
			*out++ = '*';
			*out++ = (char)('0' + (1u << scale_bits));
		}
	}
#ifdef X86_MEMORY32_OUTPUT
	if (!disp32_only)
#endif
		out = X86_writeDisplacement(out, displacement);
	*out++ = ']';
#ifdef X86_MEMORY_IMMEDIATE
	const uint32_t encoded =
		imm_size == 1 ? code[imm_offset] :
				(uint32_t)X86_readDisp32(code + imm_offset);
	/* MOV to a 64-bit memory operand sign-extends its encoded imm32. */
#if X86_IMMEDIATE_WIDE
	const uint64_t value = row->ops[0].size == 8 ?
				       (uint64_t)(int64_t)(int32_t)encoded :
				       encoded;
#else
	const uint32_t value = encoded;
#endif
	memcpy(out, ", ", 2);
	writeUnsignedImmediate(out + 2, value);
#else
	if (!load && !push) {
		memcpy(out, ", ", 2);
		memcpy(out + 2, reg->name, sizeof(reg->name));
	}
#endif
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, opcode, rex, modrm,
				      load ? reg->reg : 0, load ? 0 : reg->reg);
		cs_x86 *x = &insn->detail->x86;
#ifdef X86_EXTEND64_MEMORY
		if (opcode != 0x63) {
			x->opcode[0] = 0x0f;
			x->opcode[1] = opcode;
		}
		x->encoding.modrm_offset = (uint8_t)(lead + 1);
#elif defined(X86_EXTEND32_MEMORY)
		x->opcode[0] = 0x0f;
		x->opcode[1] = opcode;
#endif
#ifdef X86_MEMORY_IMMEDIATE
		x->operands[1].type = X86_OP_IMM;
		x->operands[1].imm = (int64_t)value;
		x->operands[1].access = 0;
		x->encoding.imm_offset = (uint8_t)imm_offset;
		x->encoding.imm_size = (uint8_t)imm_size;
#endif
		cs_x86_op *mem = &x->operands[load ? 1 : 0];
		mem->type = X86_OP_MEM;
#ifdef X86_MEMORY32_OUTPUT
		mem->mem.base = disp32_only ? X86_REG_INVALID :
					      (x86_reg)base->reg;
#else
		mem->mem.base = disp32_only ? X86_REG_RIP : (x86_reg)base->reg;
#endif
		mem->mem.scale = 1 << scale_bits;
		if (index)
			mem->mem.index = (x86_reg)index->reg;
		mem->mem.disp = x->disp = displacement;
		if (disp_size) {
			x->encoding.disp_offset = (uint8_t)offset;
			x->encoding.disp_size = (uint8_t)disp_size;
		}
		if (sib) {
			x->sib = code[offset - 1];
			x->sib_base = mem->mem.base;
			x->sib_scale = (int8_t)mem->mem.scale;
			x->sib_index = mem->mem.index;
		}
	}
	return true;
}

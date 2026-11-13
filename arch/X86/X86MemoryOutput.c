/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86SimpleOutput.h"

static char *writeDisplacement(char *out, int32_t displacement)
{
	if (displacement >= -128 && displacement <= 127)
		return X86_writeDisp8(out, displacement);
	memcpy(out, displacement < 0 ? " - 0x" : " + 0x", 5);
	out += 5;
	uint32_t magnitude = displacement < 0 ? 0u - (uint32_t)displacement :
						(uint32_t)displacement;
	char digits[8], *start = digits + sizeof(digits);
	do {
		*--start = "0123456789abcdef"[magnitude & 15];
		magnitude >>= 4;
	} while (magnitude);
	const size_t length = (size_t)(digits + sizeof(digits) - start);
	memcpy(out, start, length);
	return out + length;
}

/* Decode one ordinary base, optionally ESP/RSP/R12 via SIB, or RIP-relative
 * disp32. The full reader handles absolute addresses and indexed SIB forms. */
bool X86_writeMemoryOutput(const uint8_t *code, size_t size, cs_insn *insn,
			   uint16_t *insn_size,
			   const struct X86SimpleOutput *row,
			   const struct X86SimpleRegister regs[4][16])
{
	const bool wide = row->address_size == 8;
	const uint8_t rex = wide && (code[0] & 0xf0) == 0x40 ? code[0] : 0;
	const unsigned lead = rex != 0;
	const uint8_t opcode = code[lead], modrm = code[lead + 1];
	const unsigned mod = modrm >> 6, rm = modrm & 7;
	const bool sib = rm == 4, rip = !mod && rm == 5;
	const unsigned offset = lead + 2 + sib;
	const unsigned disp_size = mod == 2 || rip ? 4 : mod;
	const unsigned length = offset + disp_size;
	if (size < length || (rip && !wide) ||
	    (sib && ((rex & 2) || code[offset - 1] != 0x24)))
		return false;

	const bool lea = opcode == 0x8d, load = lea || (opcode & 2);
	const unsigned reg_width = (opcode & 1) ? ((rex & 8) ? 3 : 2) : lead;
	const struct X86SimpleRegister *reg =
		&regs[reg_width][((rex & 4) << 1) | ((modrm >> 3) & 7)];
	const struct X86SimpleRegister *base =
		&regs[wide ? 3 : 2][((rex & 1) << 3) | rm];
	int32_t displacement = 0;
	if (disp_size == 1) {
		displacement = (int8_t)code[offset];
	} else if (disp_size == 4) {
		const uint8_t *p = code + offset;
		displacement =
			(int32_t)((uint32_t)p[0] | (uint32_t)p[1] << 8 |
				  (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24);
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
	if (rip) {
		memcpy(out, "rip", 3);
		out += 3;
	} else {
		memcpy(out, base->name, sizeof(base->name));
		out += base->length;
	}
	out = writeDisplacement(out, displacement);
	*out++ = ']';
	if (!load) {
		memcpy(out, ", ", 2);
		memcpy(out + 2, reg->name, sizeof(reg->name));
	}
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, opcode, rex, modrm,
				      load ? reg->reg : 0, load ? 0 : reg->reg);
		cs_x86 *x = &insn->detail->x86;
		cs_x86_op *mem = &x->operands[load ? 1 : 0];
		mem->type = X86_OP_MEM;
		mem->mem.base = rip ? X86_REG_RIP : (x86_reg)base->reg;
		mem->mem.scale = 1;
		mem->mem.disp = x->disp = displacement;
		if (disp_size) {
			x->encoding.disp_offset = (uint8_t)offset;
			x->encoding.disp_size = (uint8_t)disp_size;
		}
		if (sib) {
			x->sib = code[offset - 1];
			x->sib_base = mem->mem.base;
			x->sib_scale = 1;
		}
	}
	return true;
}

#endif
#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
/* Keep the optional output writer and its records together without adding
 * them to the existing ELF decoder code and constant sections. */
#if defined(__ELF__) && defined(__GNUC__)
#define X86_EVEX_MEMORY_CODE __attribute__((section(".cs_x86_evex_output")))
#define X86_EVEX_MEMORY_DATA \
	__attribute__((section(".cs_x86_evex_output_rodata")))
#else
#define X86_EVEX_MEMORY_CODE
#define X86_EVEX_MEMORY_DATA
#endif
/* Clang may outline the shared inline formatter. Give that same helper
 * the writer's section before including its canonical definition. */
static inline char *
X86_writeDisplacement(char *out, int32_t displacement) X86_EVEX_MEMORY_CODE;
#include "X86SimpleOutput.h"
#ifdef CAPSTONE_X86_EVEX_MEMORY_OUTPUT
#include "X86VectorRegisterWriter.h"
#include "X86GenEvexMemoryOutput.inc"

/* Ordinary unmasked packed moves. Indexed and absolute SIB addresses keep
 * the general printer; disp8 is a full-vector tuple, disp32 is unscaled. */
X86_EVEX_MEMORY_CODE
bool X86_writeEvexMemoryOutput(const uint8_t *code, size_t size, cs_insn *insn,
			       uint16_t *insn_size,
			       const struct X86SimpleRegister *regs)
{
	if (size < 6 || (code[1] & 15) != 1 || (code[2] & 0xfc) != 0xfc ||
	    (code[3] & 0x9f) != 8 || (code[4] & 0xef) != 0x6f)
		return false;
	const unsigned pp = code[2] & 3, ll = code[3] >> 5;
	const uint8_t modrm = code[5];
	const unsigned mod = modrm >> 6, rm = modrm & 7;
	if (pp < 1 || pp > 2 || ll >= 3 || mod == 3)
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	const bool sib = rm == 4, rip = !mod && rm == 5;
	const unsigned offset = 6 + sib;
	const unsigned disp_size = mod == 2 || rip ? 4 : mod;
	const unsigned length = offset + disp_size;
	if (size < length || (sib && ((rxb & 2) || code[6] != 0x24)))
		return false;
	const unsigned store = (code[4] >> 4) & 1;
	const struct EvexMemoryOutputRow *row =
		&evex_memory_rows[pp - 1][store][ll];
	if (!row->id)
		return false;
	const unsigned number = ((modrm >> 3) & 7) | ((rxb & 4) << 1) |
				(~(unsigned)code[1] & 16);
	const struct X86SimpleRegister *base = &regs[rm | ((rxb & 1) << 3)];
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
		x->rex = (uint8_t)(0x48 | rxb);
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
		mem->mem.scale = 1;
		mem->mem.disp = x->disp = displacement;
		if (sib) {
			x->sib = code[6];
			x->sib_base = mem->mem.base;
			x->sib_scale = 1;
		}
	}
	return true;
}
/* Keep the established memory-only entry in the vector reader small. Both
 * writers retain their encoding checks. The six-byte extent was validated
 * by writeEvexOutput before entering this private memory dispatch. */
X86_EVEX_MEMORY_CODE
bool X86_writeEvexMemoryDispatch(const uint8_t *code, size_t size,
				 cs_insn *insn, uint16_t *insn_size,
				 const struct X86SimpleRegister *regs)
{
	if (X86_writeEvexBroadcastPrechecked(code, size, insn, insn_size, regs))
		return true;
	return X86_writeEvexMemoryOutput(code, size, insn, insn_size, regs);
}

#endif
#endif
#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
/* Keep this static text iterator in its own ELF sections. */
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_amd64_text" rodata = \
	".cs_x86_amd64_rodata"
#endif
#include "../../cs_priv.h"
#include "X86ScanAdapter.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86OutputOptions.h"
#define X86_FIXED_VEX2 writeVex2Memory64
#include "X86SimpleOutput.h"
#include "X86GenSimpleOutput.inc"
#include "X86VectorRegisterOutput.h"
#define X86_MEMORY_IMMEDIATE writeMemoryImmediate64
#define X86_IMMEDIATE_WIDE 1
#include "X86MemoryOutputImpl.h"
#undef X86_IMMEDIATE_WIDE
#undef X86_MEMORY_IMMEDIATE

struct X86SseRegisterOutput {
	struct X86SimpleOutput output;
	bool reverse;
	bool base_memory;
};
#include "X86GenSse64RegisterOutput.inc"
#include "X86GenVex64PackedMemory.inc"

#define X86_EXTEND64_MEMORY writeExtendMemory64
#include "X86MemoryOutputImpl.h"
#undef X86_EXTEND64_MEMORY
#include "X86GenExtend64Output.inc"
#include "X86ExtendRegisterOutput.h"

static bool writeExtend64(const uint8_t *code, size_t size, cs_insn *insn,
			  uint16_t *insn_size, unsigned length, uint8_t rex,
			  uint8_t opcode)
{
	const bool escaped = opcode != 0x63;
	const unsigned form = escaped ? ((rex & 8) >> 1) | ((opcode & 8) >> 2) |
						(opcode & 1) :
					8;
	const struct X86SimpleOutput *row = &x86_extend64[form];
	const uint8_t mr = code[length - 1];
	if (mr < 0xc0)
		return writeExtendMemory64(code, size, insn, insn_size, row,
					   x86_simple_registers);
	const struct X86SimpleRegister *dst =
		&x86_simple_registers[(rex & 8) ? 3 : 2]
				     [((rex & 4) << 1) | ((mr >> 3) & 7)];
	const struct X86SimpleRegister *src =
		!escaped     ? x86_simple_registers[2] :
		(opcode & 1) ? x86_extend64_words :
			       x86_simple_registers[rex != 0];
	src += ((rex & 1) << 3) | (mr & 7);
	writeExtendRegisters(code, length, insn, insn_size, row, dst, src, rex,
			     opcode, mr, escaped);
	return true;
}

#ifdef CAPSTONE_X86_NEAR_INDIRECT_OUTPUT
#include "X86GenIndirect64Output.inc"

/* FF /2 and /4 have one explicit 64-bit target. The register and memory
 * forms share their generated access, implicit register and group records. */
static bool writeIndirect64(const uint8_t *code, size_t size, cs_insn *insn,
			    uint16_t *insn_size, uint8_t rex, uint8_t modrm)
{
	const struct X86SimpleOutput *row =
		&x86_indirect64[rex != 0][(modrm & 0x20) != 0];
	if (modrm < 0xc0)
		return X86_writeMemoryOutput(code, size, insn, insn_size, row,
					     x86_simple_registers);
	const struct X86SimpleRegister *reg =
		&x86_simple_registers[3][((rex & 1) << 3) | (modrm & 7)];
	*insn_size = insn->size = (uint16_t)(2 + (rex != 0));
	insn->id = row->id;
	memcpy(insn->bytes, code, insn->size);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	memcpy(insn->op_str, reg->name, sizeof(reg->name));
	if (insn->detail)
		X86_writeSimpleDetail(insn->detail, row, 0xff, rex, modrm,
				      reg->reg, 0);
	return true;
}

#define X86_FIXED_INDIRECT writeIndirect64
#endif

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
	memcpy(out, "xmmword ptr [", 13);
	if (ll)
		*out = 'y';
	out += 13;
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

/* Only the bare VEX2 opcode plan enters here. Packed base-relative
 * loads and stores share their address and detail construction with SSE. */
static bool writeVex2Memory64(const uint8_t *code, size_t size, cs_insn *insn,
			      uint16_t *insn_size)
{
	if (size >= 4 && (code[1] & 0x78) == 0x78 && code[3] < 0xc0) {
		unsigned plan = vex64_packed_plans[code[1] & 7][code[2]];
		const uint8_t rex =
			(uint8_t)(0x40 | ((~(unsigned)code[1] >> 5) & 4));
		if (plan && writePackedMemory(code, insn, insn_size,
					      &vex64_packed_rows[plan], rex, 4,
					      size, true))
			return true;
	}
	return X86_writeVectorOutput(code, size, insn, insn_size,
				     x86_simple_registers[3], true);
}

/* The scalar plans have already declined this instruction. A single opcode
 * lookup supplies the mnemonic, operand order and all implicit effects. */
static bool writeExtraOutput64(cs_struct *handle, const uint8_t *code,
			       size_t size, cs_insn *insn, uint16_t *insn_size)
{
	const bool has_rex = (code[0] & 0xf0) == 0x40;
	if (size < 2u + has_rex)
		return false;
	const uint8_t primary = code[has_rex];
	const unsigned length = 2 + has_rex + (primary == 0x0f);
	if (size < length)
		return false;
	const uint8_t rex_byte = has_rex ? code[0] : 0;
	if ((primary == 0x63 && (rex_byte & 8)) ||
	    (primary == 0x0f && (code[length - 2] & 0xf6) == 0xb6)) {
		if (X86_OUTPUT_UNSUPPORTED(handle, false))
			return false;
		return writeExtend64(code, size, insn, insn_size, length,
				     rex_byte, code[length - 2]);
	}
	if (primary != 0x0f) {
		const uint8_t mr = code[has_rex + 1];
		if ((primary & 0xfe) != 0xc6 || mr >= 0xc0 || (mr & 0x38) ||
		    X86_OUTPUT_UNSUPPORTED(handle, false))
			return false;
		const unsigned prefix_class =
			has_rex ? ((code[0] & 8) ? 2 : 1) : 0;
		/* The MOV store row carries its operand width and access. */
		const unsigned row = x86_simple_plans[1][prefix_class]
						     [0x88 | (primary & 1)] >>
				     2;
		return writeMemoryImmediate64(code, size, insn, insn_size,
					      &x86_simple_outputs[row],
					      x86_simple_registers);
	}
	const uint8_t opcode = code[length - 2];
	const unsigned index = opcode - X86_SSE_REGISTER_FIRST;
	if (index >= sizeof(x86_sse_register_outputs) /
			     sizeof(x86_sse_register_outputs[0]))
		return false;
	const struct X86SseRegisterOutput *entry =
		&x86_sse_register_outputs[index];
	const struct X86SimpleOutput *row = &entry->output;
	if (!row->id || X86_OUTPUT_UNSUPPORTED(handle, false))
		return false;

	const uint8_t rex = has_rex ? code[0] : 0, mr = code[length - 1];
	if (mr < 0xc0)
		return entry->base_memory &&
		       writePackedMemory(code, insn, insn_size, entry, rex,
					 length, size, false);
	const unsigned reg = ((mr >> 3) & 7) | ((rex & 4) << 1);
	const unsigned rm = (mr & 7) | ((rex & 1) << 3);
	const unsigned first = entry->reverse ? rm : reg,
		       second = entry->reverse ? reg : rm;
	*insn_size = insn->size = (uint16_t)length;
	insn->id = row->id;
	memcpy(insn->bytes, code, length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *next = writeVectorRegister(insn->op_str, 0, first);
	memcpy(next, ", ", 2);
	writeVectorRegister(next + 2, 0, second);
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, 0x0f, rex, mr,
				      (uint16_t)(X86_REG_XMM0 + first),
				      (uint16_t)(X86_REG_XMM0 + second));
		insn->detail->x86.opcode[1] = opcode;
		insn->detail->x86.encoding.modrm_offset = (uint8_t)(length - 1);
	}
	return true;
}

#include "X86GenRoundedRegister64.inc"

/* EVEX.b selects embedded rounding for these register-only packed operations.
 * The caller has checked six bytes, register addressing and the EVEX.b bit. */
static bool writeRoundedRegisters(const uint8_t *code, cs_insn *insn,
				  uint16_t *insn_size)
{
	const unsigned map = code[1] & 15, flags = code[2];
	if (map < 1 || map > 3 || !(flags & 4) || (code[3] & 0x87))
		return false;
	const unsigned w = flags >> 7, pp = flags & 3;
	const unsigned plan = evex_rounded_plans[map - 1][code[4]];
	const unsigned index = evex_rounded_prefixes[plan][w * 4 + pp];
	if (!index)
		return false;
	const unsigned rc = code[3] >> 5, rxb = (~(unsigned)code[1] >> 5) & 7;
	const unsigned regs[] = { ((code[5] >> 3) & 7) | ((rxb & 4) << 1) |
					  (~(unsigned)code[1] & 16),
				  ((~flags >> 3) & 15) |
					  ((~(unsigned)code[3] & 8) << 1),
				  (code[5] & 7) | ((rxb & 3) << 3) };
	writeVectorRegisters(code, insn, insn_size, &evex_rounded_rows[index],
			     4, 2, 0x40 | (w << 3) | rxb, 2, regs, 3);
	static const char suffix[][11] = { ", {rn-sae}", ", {rd-sae}",
					   ", {ru-sae}", ", {rz-sae}" };
	/* Three ZMM names and two separators take 16 bytes plus a digit
	 * for each two-digit register number. */
	const unsigned end =
		16 + (regs[0] >= 10) + (regs[1] >= 10) + (regs[2] >= 10);
	memcpy(insn->op_str + end, suffix[rc], sizeof(suffix[rc]));
	if (insn->detail) {
		static const x86_avx_rm modes[] = { X86_AVX_RM_RN,
						    X86_AVX_RM_RD,
						    X86_AVX_RM_RU,
						    X86_AVX_RM_RZ };
		insn->detail->x86.avx_sae = true;
		insn->detail->x86.avx_rm = modes[rc];
	}
	return true;
}

#define X86_FIXED_ROUNDED writeRoundedRegisters
#define X86_FIXED_OUTPUT tryOutput64
#define X86_FIXED_WIDE true
#define X86_OUTPUT_MISS writeExtraOutput64
#include "X86SimpleOutputImpl.h"
#undef X86_OUTPUT_MISS
#undef X86_FIXED_WIDE
#undef X86_FIXED_OUTPUT
#define CS_DECODE_TRY_OUTPUT tryOutput64
#include "../../cs_disasm_internal.h"
#endif

CAPSTONE_INTERNAL bool X86_disasmIterText(csh ud, const uint8_t **code,
					  size_t *size, uint64_t *address,
					  cs_insn *insn)
{
#ifdef CS_DECODE_TRY_OUTPUT
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (handle && handle->arch == CS_ARCH_X86 &&
	    handle->mode == CS_MODE_64 && !handle->no_text)
		return cs_disasm_iter_core(ud, code, size, address, insn);
#endif
	return X86_disasmIter32(ud, code, size, address, insn);
}
#endif

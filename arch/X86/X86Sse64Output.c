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
#include "X86VectorRegisterWriter.h"
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
	const unsigned length = 3 + has_rex;
	if (size < length)
		return false;
	const uint8_t primary = code[has_rex];
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

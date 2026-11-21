/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
/* Keep this optional static member out of the ordinary ELF decoder sections. */
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text=".cs_x86_i386_text" rodata=".cs_x86_i386_rodata"
#endif
#include "../../cs_priv.h"
#include "X86ScanAdapter.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86OutputOptions.h"
#include "X86SimpleOutput.h"
#include "X86GenSimpleOutput.inc"
#include "X86VectorRegisterWriter.h"
#define X86_MEMORY_IMMEDIATE32
#include "X86MemoryOutputImpl.h"
#undef X86_MEMORY_IMMEDIATE32

#include "X86GenVex32MemoryOutput.inc"

/* Bare VEX2, ordinary 32-bit base and a generated full-width memory record. */
static bool writeVex32Memory(const uint8_t *code, size_t size, cs_insn *insn,
			     uint16_t *insn_size)
{
	const unsigned flags = code[1], modrm = code[3];
	const unsigned mod = modrm >> 6, rm = modrm & 7;
	if (rm == 4 || (!mod && rm == 5))
		return false;
	const unsigned plan = vex32_memory_plans[flags & 7][code[2]];
	if (!plan)
		return false;
	const struct Vex32MemoryRow *row = &vex32_memory_rows[plan];
	const unsigned src = (~flags >> 3) & 7;
	if (row->form && src)
		return false;
	const unsigned disp_size = mod == 2 ? 4 : mod, length = 4 + disp_size;
	if (size < length)
		return false;
	const int32_t disp = mod == 2 ? X86_readDisp32(code + 4) :
			     mod      ? (int8_t)code[4] :
					0;
	const unsigned ll = (flags >> 2) & 1, number = (modrm >> 3) & 7;
	const bool store = row->form == 2;
	const unsigned memory = row->form == 0 ? 2 : !store;
	const struct X86SimpleRegister *base = &vex32_base_registers[rm];
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)length;
	memcpy(insn->bytes, code, 4);
	if (disp_size == 4)
		memcpy(insn->bytes + 4, code + 4, 4);
	else if (disp_size)
		insn->bytes[4] = code[4];
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = insn->op_str;
	if (!store) {
		out = writeVectorRegister(out, ll, number);
		memcpy(out, ", ", 2);
		out += 2;
		if (!row->form) {
			out = writeVectorRegister(out, ll, src);
			memcpy(out, ", ", 2);
			out += 2;
		}
	}
	memcpy(out, "xmmword ptr [", 13);
	out[0] = ll ? 'y' : 'x';
	out += 13;
	memcpy(out, base->name, sizeof(base->name));
	out += base->length;
	out = X86_writeDisplacement(out, disp);
	*out++ = ']';
	if (store) {
		memcpy(out, ", ", 2);
		writeVectorRegister(out + 2, ll, number);
	}
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		memcpy(d->groups, row->groups, sizeof(row->groups));
		d->groups_count = row->group_count;
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, 2);
		x->addr_size = 4;
		x->modrm = (uint8_t)modrm;
		x->encoding.modrm_offset = 3;
		x->disp = disp;
		if (disp_size) {
			x->encoding.disp_offset = 4;
			x->encoding.disp_size = (uint8_t)disp_size;
		}
		x->op_count = (uint8_t)(2 + !row->form);
		for (unsigned i = 0; i < x->op_count; ++i) {
			cs_x86_op *op = &x->operands[i];
			op->size = (uint8_t)(16u << ll);
			op->access = (cs_ac_type)row->access[i];
			if (i == memory) {
				op->type = X86_OP_MEM;
				op->mem.base = (x86_reg)base->reg;
				op->mem.scale = 1;
				op->mem.disp = disp;
			} else {
				op->type = X86_OP_REG;
				op->reg = (x86_reg)((ll ? X86_REG_YMM0 :
							  X86_REG_XMM0) +
						    (!row->form && i == 1 ?
							     src :
							     number));
			}
		}
	}
	return true;
}

static bool writeExtraOutput32(cs_struct *handle, const uint8_t *code,
			       size_t size, cs_insn *insn, uint16_t *insn_size)
{
	/* C4/C5 introduce VEX. The /0 forms of C6/C7 encode MOV r/m, immediate. */
	if ((code[0] & 0xfc) != 0xc4 || X86_OUTPUT_UNSUPPORTED(handle, false))
		return false;
	if (code[0] & 2) {
		if (size < 2 || code[1] >= 0xc0 || (code[1] & 0x38))
			return false;
		const unsigned opcode = 0x88 | (code[0] & 1);
		const unsigned row = x86_simple_plans[0][0][opcode] >> 2;
		return writeMemoryImmediate32(code, size, insn, insn_size,
					      &x86_simple_outputs[row],
					      x86_simple_registers);
	}
	const unsigned prefix = code[0] == 0xc5 ? 2 : 3;
	/* LDS/LES, extended registers and W=1 retain the
     * canonical reader. The admitted rows use only XMM/YMM0..7. */
	if (size < prefix + 2 ||
	    (prefix == 2 ?
		     (code[1] & 0xc0) != 0xc0 :
		     (code[1] & 0xe0) != 0xe0 || (code[2] & 0xc0) != 0x40))
		return false;
	if (code[prefix + 1] < 0xc0)
		return prefix == 2 &&
		       writeVex32Memory(code, size, insn, insn_size);
	if (!X86_writeVectorOutput(code, size, insn, insn_size, NULL, true))
		return false;
	if (insn->detail) {
		insn->detail->x86.rex = 0;
		insn->detail->x86.addr_size = 4;
	}
	return true;
}

#define X86_EXTRA_OUTPUT32 writeExtraOutput32
#include "X86SimpleOutputImpl.h"
#undef X86_EXTRA_OUTPUT32
#define CS_DECODE_TRY_OUTPUT tryOutput32
#include "../../cs_disasm_internal.h"
#endif

CAPSTONE_INTERNAL bool X86_disasmIter32(csh ud, const uint8_t **code,
					size_t *size, uint64_t *address,
					cs_insn *insn)
{
#ifdef CS_DECODE_TRY_OUTPUT
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (handle && handle->arch == CS_ARCH_X86 &&
	    handle->mode == CS_MODE_32 && !handle->no_text)
		return cs_disasm_iter_core(ud, code, size, address, insn);
#endif
	return X86_disasmIter(ud, code, size, address, insn);
}
#endif

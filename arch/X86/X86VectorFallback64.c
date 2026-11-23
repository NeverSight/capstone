/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
/* Keep the optional vector fallback in its own ELF sections. */
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_vector_fallback64_text" rodata = \
	".cs_x86_vector_fallback64_rodata"
#endif
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86OutputOptions.h"
#include "X86EvexAdmission.h"
#include "X86SimpleOutput.h"
#include "X86VectorRegisterOutput.h"
#include "X86GenEvexShiftOutput.inc"
#include "../../cs_disasm_internal.h"
#ifdef CAPSTONE_X86_EVEX_MEMORY_OUTPUT
#define X86_EVEX_INDEXED_SIB
#define X86_EVEX_MEMORY_DATA
#include "X86EvexMemoryRecord.h"
#undef X86_EVEX_INDEXED_SIB
#undef X86_EVEX_MEMORY_DATA
#endif

#include "X86GenSimpleOutput.inc"
#define X86_LEGACY_PACKED_MEMORY
#include "X86PackedMemoryOutput.h"
#undef X86_LEGACY_PACKED_MEMORY
#include "X86GenLegacyPackedMemory.inc"

#include "X86GenLegacyRegisterImmediates.inc"
#include "X86GenLegacyMap38Registers.inc"

static void setLegacyRegisterOpcode(cs_insn *insn, const uint8_t *opcode,
				    unsigned count)
{
	if (insn->detail) {
		cs_x86 *x = &insn->detail->x86;
		x->prefix[2] = 0x66;
		memset(x->opcode, 0, sizeof(x->opcode));
		memcpy(x->opcode, opcode, count);
	}
}

/* The caller has checked the escape and the entire register encoding. */
static bool writeLegacyMap38Registers(const uint8_t *code, cs_insn *insn,
				      uint16_t *insn_size, unsigned offset,
				      uint8_t rex)
{
	const unsigned plan = legacy_map38_plans[code[offset - 1]];
	if (!plan)
		return false;
	const unsigned mr = code[offset];
	const unsigned reg = ((mr >> 3) & 7) | ((rex & 4) << 1);
	const unsigned rm = (mr & 7) | ((rex & 1) << 3);
	const unsigned regs[] = { plan & 128 ? rm : reg,
				  plan & 128 ? reg : rm };
	writeVectorRegisters(code, insn, insn_size,
			     &legacy_map38_rows[plan & 127], offset - 1, 0, rex,
			     0, regs, 2);
	setLegacyRegisterOpcode(insn, code + offset - 3, 3);
	return true;
}

/* The caller checked a complete 66 [REX] 0F 70..73 /r ib register form. */
static bool writeLegacyRegisterImmediate(const uint8_t *code, cs_insn *insn,
					 uint16_t *insn_size, unsigned offset,
					 uint8_t rex)
{
	const unsigned opcode = code[offset - 2], mr = code[offset - 1];
	const unsigned field = (mr >> 3) & 7;
	const unsigned plan = legacy_immediate_plans[opcode - 0x70][field];
	if (!plan)
		return false;
	const unsigned rm = (mr & 7) | ((rex & 1) << 3);
	const bool shuffle = opcode == 0x70;
	const unsigned regs[] = { shuffle ? field | ((rex & 4) << 1) : rm, rm };
	writeVectorRegisters(code, insn, insn_size,
			     &legacy_immediate_rows[plan - 1], offset - 2, 0,
			     rex, 0, regs, shuffle ? 2 : 1);
	setLegacyRegisterOpcode(insn, code + offset - 3, 2);
	return true;
}

/* This writer belongs to the private mixed-library reader. In dedicated
 * builds the public iterator shares the same fallback object. */
#ifndef CAPSTONE_X86_PUBLIC_OUTPUT
/* VMOVDQU8 keeps the unmasked transfer's address, length and operands.
 * Insert the writemask after its destination. Only a register destination
 * can request zeroing or read through the mask. */
static bool writeMaskedByteMove(cs_struct *handle, const uint8_t *code,
				size_t size, cs_insn *insn, uint16_t *insn_size)
{
	const unsigned mask = code[3] & 7, ll = (code[3] >> 5) & 3;
	const bool zero = (code[3] & 0x80) != 0;
	const bool memory = code[5] < 0xc0, store = code[4] == 0x7f;
	if (!mask || ll == 3 || (code[1] & 15) != 1 || code[2] != 0x7f ||
	    (code[3] & 0x18) != 8 || (store && (!memory || zero)) ||
	    X86_OUTPUT_UNSUPPORTED(handle, false))
		return false;
	/* The longest transfer uses a SIB and a four-byte displacement. */
	uint8_t plain[11];
	const size_t available = memory ? MIN(size, sizeof(plain)) : 6;
	memcpy(plain, code, available);
	plain[3] &= 0x78;
	if (memory) {
#ifdef CAPSTONE_X86_EVEX_MEMORY_OUTPUT
		if (!X86_writeEvexMemoryOutput(plain, available, insn, insn_size,
					       x86_simple_registers[3]) &&
		    !writeIndexedEvexMemory(plain, available, insn, insn_size,
					    x86_simple_registers[3]))
			return false;
#else
		return false;
#endif
	} else if (!X86_writePlainEvexRegisters(handle, plain, available, insn,
						insn_size)) {
		return false;
	}
	insn->bytes[3] = code[3];
	/* The underlying writer emitted exactly two operands. Their longest
	 * address and vector name leave room for both decorators. */
	char *comma = strchr(insn->op_str, ',');
	memmove(comma + (zero ? 9 : 5), comma, strlen(comma) + 1);
	memcpy(comma, " {k0}", 5);
	comma[3] = (char)('0' + mask);
	if (zero)
		memcpy(comma + 5, " {z}", 4);
	if (insn->detail) {
		cs_x86 *x = &insn->detail->x86;
		x->opcode[3] = code[3];
		x->operands[2] = x->operands[1];
		cs_x86_op *k = &x->operands[1];
		memset(k, 0, sizeof(*k));
		k->type = X86_OP_REG;
		k->reg = (x86_reg)(X86_REG_K0 + mask);
		k->size = (uint8_t)(2u << ll);
		k->access = CS_AC_READ;
		k->avx_zero_opmask = zero;
		x->op_count = 3;
		if (!store && !zero)
			x->operands[0].access = (cs_ac_type)(CS_AC_READ | CS_AC_WRITE);
	}
	return true;
}
#endif

/* The fixed-width AMD64 iterator has already tried its common records. */
CAPSTONE_INTERNAL CS_PRESERVE_MOST bool
X86_decodeOutputMiss64(cs_struct *handle, const uint8_t *code, size_t size,
		       cs_insn *insn, uint16_t *insn_size, bool batch)
{
	if (size >= 7 && code[0] == 0x62 && code[5] >= 0xc0 &&
	    (code[1] & 0x9f) == 0x91 && code[4] >= 0x71 && code[4] <= 0x73 &&
	    !X86_EVEX_REGISTER_PREFIX_REJECTS(code, size) &&
	    !X86_OUTPUT_UNSUPPORTED(handle, false)) {
		const unsigned opcode = code[4];
		const unsigned ll = code[3] >> 5, w = code[2] >> 7;
		const unsigned plan =
			evex_shift_plans[opcode - 0x71][(code[5] >> 3) & 7]
					[w * 3 + ll];
		if (!plan)
			goto fallback;
		const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
		const unsigned regs[] = { ((~(unsigned)code[2] >> 3) & 15) |
						  ((~(unsigned)code[3] & 8)
						   << 1),
					  (code[5] & 7) | ((rxb & 3) << 3) };
		return writeVectorRegisters(code, insn, insn_size,
					    &evex_shift_rows[plan - 1], 4, ll,
					    0x40 | (w << 3) | rxb, ll, regs, 2);
	}
#ifdef CAPSTONE_X86_EVEX_MEMORY_OUTPUT
	if (size >= 7 && code[0] == 0x62 && code[5] < 0xc0 &&
	    (code[5] & 7) == 4 && !X86_OUTPUT_UNSUPPORTED(handle, false) &&
	    writeIndexedEvexMemory(code, size, insn, insn_size,
				   x86_simple_registers[3]))
		return true;
#endif
	if (size >= 6 && code[0] == 0x62 && code[5] >= 0xc0 &&
	    X86_writePlainEvexRegisters(handle, code, size, insn, insn_size))
		return true;
#ifndef CAPSTONE_X86_PUBLIC_OUTPUT
	if (size >= 6 && code[0] == 0x62 && (code[3] & 7) &&
	    (code[4] | 0x10) == 0x7f &&
	    writeMaskedByteMove(handle, code, size, insn, insn_size))
		return true;
#endif
	if (size >= 10 && code[0] == 0x62 && (code[5] & 0xc7) == 5 &&
	    X86_writeEvexRipMemory(handle, code, insn, insn_size))
		return true;
	if (code[0] == 0xc4 &&
	    X86_writeVexRegisterImmediate(handle, code, size, insn, insn_size,
					  x86_simple_registers, true))
		return true;
	if (size >= 4 && (code[0] == 0x66 || (code[0] & 0xfe) == 0xf2)) {
		const uint8_t rex = (code[1] & 0xf0) == 0x40 ? code[1] : 0;
		const unsigned offset = 4 + (rex != 0);
		if (size >= offset && code[offset - 3] == 0x0f) {
			const unsigned opcode = code[offset - 2];
			if (opcode == 0x38 && code[0] == 0x66) {
				if (size > offset && code[offset] >= 0xc0 &&
				    !X86_OUTPUT_UNSUPPORTED(handle, false) &&
				    writeLegacyMap38Registers(
					    code, insn, insn_size, offset, rex))
					return true;
			} else if (code[offset - 1] < 0xc0) {
				const unsigned bank =
					code[0] == 0x66 ? 0 : 1 + (code[0] & 1);
				const unsigned row =
					legacy_packed_plans[bank][opcode];
				if (row &&
				    !X86_OUTPUT_UNSUPPORTED(handle, false) &&
				    writePackedMemory(code, insn, insn_size,
						      &legacy_packed_rows[row],
						      rex, offset, size, false))
					return true;
			} else if (code[0] == 0x66 && opcode >= 0x70 &&
				   opcode <= 0x73 && size > offset &&
				   !X86_OUTPUT_UNSUPPORTED(handle, false) &&
				   writeLegacyRegisterImmediate(
					   code, insn, insn_size, offset, rex))
				return true;
		}
	}
fallback:
#if defined(CAPSTONE_X86_DEDICATED_OUTPUT) && defined(__clang__) && \
	defined(__x86_64__)
	/* The fixed AMD64 decoder has just tried the shared output plans.
	 * Its VEX2 helper also tries the shared writer on a miss. Only its
	 * EVEX register-rounding override can decline before that writer. */
	if (!(size >= 6 && code[0] == 0x62 && code[5] >= 0xc0 &&
	      (code[3] & 0x10)))
		return cs_decode_full_insn_body(handle, code, size, insn,
						insn_size, batch);
#endif
	return cs_decode_full_insn(handle, code, size, insn, insn_size, batch);
}
#endif
#endif

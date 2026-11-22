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

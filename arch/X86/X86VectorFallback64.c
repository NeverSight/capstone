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

#include "X86GenSimpleOutput.inc"
#define X86_LEGACY_PACKED_MEMORY
#include "X86PackedMemoryOutput.h"
#undef X86_LEGACY_PACKED_MEMORY
#include "X86GenLegacyPackedMemory.inc"

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
	if (size >= 4 && (code[0] == 0x66 || (code[0] & 0xfe) == 0xf2)) {
		const uint8_t rex = (code[1] & 0xf0) == 0x40 ? code[1] : 0;
		const unsigned offset = 4 + (rex != 0);
		if (size >= offset && code[offset - 3] == 0x0f &&
		    code[offset - 1] < 0xc0) {
			const unsigned bank =
				code[0] == 0x66 ? 0 : 1 + (code[0] & 1);
			const unsigned row =
				legacy_packed_plans[bank][code[offset - 2]];
			if (row && !X86_OUTPUT_UNSUPPORTED(handle, false) &&
			    writePackedMemory(code, insn, insn_size,
					      &legacy_packed_rows[row], rex,
					      offset, size, false))
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

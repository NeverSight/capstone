/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_EVEX_SCAN_PLAN_H
#define CS_X86_EVEX_SCAN_PLAN_H
#include "X86EvexAdmission.h"
#ifndef X86_EVEX_SCAN_RODATA
#define X86_EVEX_SCAN_RODATA ".cs_x86_evex_scan_rodata"
#endif
#ifndef X86_EVEX_TRANSFER_RODATA
#define X86_EVEX_TRANSFER_RODATA ".cs_x86_evex_transfer_rodata"
#endif
/* ELF can keep each reader's private tables with its hot loop. Other
 * object formats use ordinary translation-unit-local constants. */
#if defined(__ELF__) && defined(__GNUC__)
#define X86_EVEX_SECTION(name) __attribute__((section(name)))
#else
#define X86_EVEX_SECTION(name)
#endif
#include "X86GenEvexScan.inc"
#undef X86_EVEX_SECTION
#undef X86_EVEX_TRANSFER_RODATA
#undef X86_EVEX_SCAN_RODATA

/* Callers provide six bytes of bare EVEX in 64-bit mode. Return the same
 * generated public ID and extent to the ordinary and batch scan entries. */
static inline bool X86_readEvexScanPlan(const uint8_t *code, size_t code_len,
					unsigned *instruction_id,
					unsigned *instruction_length)
{
	const unsigned pp = code[2] & 3;
	if (X86_EVEX_PREFIX_REJECTS(code, code_len, pp))
		return false;
	const unsigned map = code[1] & 15;
	const unsigned index = evex_scan_index[code[4]];
	unsigned id, length;
	if (index & 128) {
		if (X86_EVEX_EXTRACT_SOURCE_REJECTS(code))
			return false;
		unsigned kind;
		if (index == EVEX_SCAN_MOVE) {
			if (map != 1 || !pp)
				return false;
			kind = pp;

#ifdef X86_EVEX_BATCH_PACKED
		} else if (index >= EVEX_SCAN_PACKED) {
			if (map != 1 || pp > 1)
				return false;
			kind = 4 + (index - EVEX_SCAN_PACKED) * 2 + pp;
#endif
		} else {
			if (map != 2 || pp != 1 || code[5] >= 0xc0)
				return false;
			kind = 0;
		}
		id = evex_transfer_scan_ids[kind][code[2] >> 7][code[3] >> 5];
		length = evex_transfer_lengths[((code[5] >> 3) & 24) |
					       (code[5] & 7)];
		/* Only mod=0 with SIB needs its base field to determine
		 * the extent. Every other ordinary SIB value is valid. */
		if (!length) {
			if (code_len < 7)
				return false;
			length = 7 + 4 * ((code[6] & 7) == 5);
		}
	} else {
		if (pp != 1 || code[5] < 0xc0)
			return false;
		const struct EvexScanPlan *plan = &evex_scan_plans[index];
		if (plan->map != map)
			return false;
		if ((plan->length_flags & EVEX_SCAN_RESERVED_SOURCE) &&
		    X86_EVEX_EXTRACT_SOURCE_REJECTS(code))
			return false;
		id = plan->ids[code[2] >> 7][code[3] >> 5];
		length = plan->length_flags & ~EVEX_SCAN_RESERVED_SOURCE;
	}
	if (!id || length > code_len)
		return false;
	*instruction_id = id;
	*instruction_length = length;
	return true;
}
#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "X86FeatureExtension.h"
#ifdef X86_EVEX_REGISTER_SCAN
#include "X86EvexAdmission.h"
#include "X86GenEvexScan.inc"

/* Only a complete, unprefixed EVEX in 64-bit mode reaches this helper.
 * The ordinary output generator owns the admitted IDs and widths. */
__attribute__((noinline, section(".cs_x86_evex_scan_text")))
static x86_feature_decode_result
decodeEvexRegisterScan(csh ud, const uint8_t *code, size_t code_len,
		      MCInst *instr, uint16_t *size, uint8_t opcode)
{
	const cs_struct *handle = (const cs_struct *)(uintptr_t)ud;
	const unsigned pp = code[2] & 3;
	if (handle->mode == CS_MODE_64 &&
	    !X86_EVEX_PREFIX_REJECTS(code, code_len, pp)
#ifdef CAPSTONE_X86_SCAN_ADAPTER
	    && !handle->x86_scan_adapter
#endif
	) {
		const unsigned map = code[1] & 15;
		const unsigned index = evex_scan_index[code[4]];
		unsigned id, length;
		if (index & 128) {
			if (X86_EVEX_EXTRACT_SOURCE_REJECTS(code))
				goto fallback;
			unsigned kind;
			if (index == EVEX_SCAN_MOVE) {
				if (map != 1 || !pp)
					goto fallback;
				kind = pp;
			} else {
				if (map != 2 || pp != 1 || code[5] >= 0xc0)
					goto fallback;
				kind = 0;
			}
			id = evex_transfer_scan_ids[kind][code[2] >> 7]
						  [code[3] >> 5];
			length = evex_transfer_lengths[((code[5] >> 3) & 24) |
						       (code[5] & 7)];
			/* Only mod=0 with SIB needs its base field to determine
			 * the extent. Every other ordinary SIB value is valid. */
			if (!length) {
				if (code_len < 7)
					goto fallback;
				length = 7 + 4 * ((code[6] & 7) == 5);
			}
		} else {
			if (pp != 1 || code[5] < 0xc0)
				goto fallback;
			const struct EvexScanPlan *plan = &evex_scan_plans[index];
			if (plan->map != map)
				goto fallback;
			const unsigned key = (map << 8) | code[4];
			if (X86_EVEX_REGISTER_EXTRACT(key) &&
			    X86_EVEX_EXTRACT_SOURCE_REJECTS(code))
				goto fallback;
			id = plan->ids[code[2] >> 7][code[3] >> 5];
			length = plan->length;
		}
		if (id && code_len >= length) {
			instr->Opcode = 0;
			instr->OpcodePub = id;
			instr->popcode_adjust = 0;
			*size = (uint16_t)length;
			return X86_FEATURE_DECODED;
		}
	}
fallback:
	return X86_decodeFeatureExtension(ud, code, code_len, instr, size,
					  opcode);
}

/* Keep the non-EVEX and non-64-bit fallback ahead of the register helper's
 * working state. Its predicate matches the isolated full-decode entry. */
__attribute__((noinline, section(".cs_x86_evex_scan_text")))
CAPSTONE_INTERNAL x86_feature_decode_result
X86_decodeScanFeatureExtension(csh ud, const uint8_t *code, size_t code_len,
			       MCInst *instr, uint16_t *size, uint8_t opcode)
{
	if (opcode == 0x62 && code_len >= 6 && code[0] == 0x62 &&
	    (((cs_struct *)(uintptr_t)ud)->mode & CS_MODE_64))
		return decodeEvexRegisterScan(ud, code, code_len, instr, size,
					     opcode);
	return X86_decodeFeatureExtensionSlow(ud, code, code_len, instr, size,
					      opcode);
}
#endif
#endif

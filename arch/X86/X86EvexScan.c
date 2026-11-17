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
	if (handle->mode == CS_MODE_64 && code[5] >= 0xc0 &&
	    !X86_EVEX_REGISTER_PREFIX_REJECTS(code, code_len)
#ifdef CAPSTONE_X86_SCAN_ADAPTER
	    && !handle->x86_scan_adapter
#endif
	) {
		const unsigned map = code[1] & 15;
		const struct EvexScanPlan *plan =
			&evex_scan_plans[evex_scan_index[code[4]]];
		if (plan->map == map && code_len >= plan->length) {
			const unsigned id =
				plan->ids[code[2] >> 7][code[3] >> 5];
			const unsigned key = (map << 8) | code[4];
			if (id && (!X86_EVEX_REGISTER_EXTRACT(key) ||
				   !X86_EVEX_EXTRACT_SOURCE_REJECTS(code))) {
				instr->Opcode = 0;
				instr->OpcodePub = id;
				instr->popcode_adjust = 0;
				*size = plan->length;
				return X86_FEATURE_DECODED;
			}
		}
	}
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

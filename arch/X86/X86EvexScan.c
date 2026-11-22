/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "X86FeatureExtension.h"
#ifdef X86_EVEX_REGISTER_SCAN
#include "X86EvexScanPlan.h"

/* Only a complete, unprefixed EVEX in 64-bit mode reaches this helper.
 * The ordinary output generator owns the admitted IDs and widths. */
__attribute__((
	noinline,
	section(".cs_x86_evex_scan_text"))) static x86_feature_decode_result
decodeEvexRegisterScan(csh ud, const uint8_t *code, size_t code_len,
		       MCInst *instr, uint16_t *size, uint8_t opcode)
{
	const cs_struct *handle = (const cs_struct *)(uintptr_t)ud;
	unsigned id, length;
	if (handle->mode == CS_MODE_64 &&
#ifdef CAPSTONE_X86_SCAN_ADAPTER
	    !handle->x86_scan_adapter &&
#endif
	    X86_readEvexScanPlan(code, code_len, &id, &length)) {
		instr->Opcode = 0;
		instr->OpcodePub = id;
		instr->popcode_adjust = 0;
		*size = (uint16_t)length;
		return X86_FEATURE_DECODED;
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

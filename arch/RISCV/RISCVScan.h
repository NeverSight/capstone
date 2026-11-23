/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef CS_RISCV_SCAN_H
#define CS_RISCV_SCAN_H

#include "RISCVModule.h"

/* The scanner is selected for little-endian, non-E modes without output.
 * These major opcodes admit every destination register and immediate. */
static bool getScanInstruction(csh handle, const uint8_t *code, size_t length,
			       MCInst *inst, uint16_t *size, uint64_t address,
			       void *info)
{
	if (length >= 4 && !inst->flat_insn->detail) {
		unsigned opcode;
		const unsigned major = code[0] & 0x7f;
		switch (major) {
		case 0x17:
			opcode = RISCV_AUIPC;
			break;
		case 0x37:
			opcode = RISCV_LUI;
			break;
		case 0x6f:
			opcode = RISCV_JAL;
			break;
		default:
			goto full;
		}
		/* Give an overlapping extension its normal decoding priority. */
		if (!(RISCV_EXTENSION_MAJORS & (UINT32_C(1) << (major >> 2)))) {
			MCInst_setOpcode(inst, opcode);
			*size = 4;
			return true;
		}
	}
full:
	return RISCV_LLVM_getInstruction(handle, code, length, inst, size,
					 address, info);
}

void RISCV_selectScanDecoder(cs_struct *handle)
{
	if (handle->disasm == RISCV_LLVM_getInstruction ||
	    handle->disasm == getScanInstruction) {
		const bool scan = handle->no_text && !handle->detail_opt &&
				  !(handle->mode & CS_MODE_BIG_ENDIAN) &&
				  !RISCV_getFeatureBits(handle->mode,
							RISCV_FeatureRVE);
		handle->disasm = scan ? getScanInstruction :
					RISCV_LLVM_getInstruction;
	}
}

#endif

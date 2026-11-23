/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef CS_RISCV_SCAN_H
#define CS_RISCV_SCAN_H

#include "RISCVModule.h"

#ifdef RISCV_USE_COMPRESSED_DISPATCH
/* The ordinary decoder retains reserved immediates, zero-register hints
 * and encodings whose operation differs between RV32 and RV64. */
static unsigned scanCompressedOpcode(uint16_t word, cs_mode mode)
{
	const unsigned encoding = ((word >> 13) << 2) | (word & 3);
	const unsigned rd = (word >> 7) & 31;
	switch (encoding) {
	case (5 << 2) | 1:
		return RISCV_C_J;
	case (6 << 2) | 1:
		return RISCV_C_BEQZ;
	case (7 << 2) | 1:
		return RISCV_C_BNEZ;
	case (2 << 2) | 0:
		return RISCV_C_LW;
	case (6 << 2) | 0:
		return RISCV_C_SW;
	case (6 << 2) | 2:
		return RISCV_C_SWSP;
	case (2 << 2) | 1:
		return rd ? RISCV_C_LI : 0;
	case (4 << 2) | 2:
		if (!rd || !(word & 0x7c))
			return 0;
		return (word & 0x1000) ? RISCV_C_ADD : RISCV_C_MV;
	case (0 << 2) | 1:
		return rd && (word & 0x107c) ? RISCV_C_ADDI : 0;
	case (2 << 2) | 2:
		return rd ? RISCV_C_LWSP : 0;
	case (3 << 2) | 0:
		return RISCV_getFeatureBits(mode, RISCV_Feature64Bit) ?
			       RISCV_C_LD :
			       0;
	case (7 << 2) | 0:
		return RISCV_getFeatureBits(mode, RISCV_Feature64Bit) ?
			       RISCV_C_SD :
			       0;
	case (3 << 2) | 2:
		return rd && RISCV_getFeatureBits(mode, RISCV_Feature64Bit) ?
			       RISCV_C_LDSP :
			       0;
	case (7 << 2) | 2:
		return RISCV_getFeatureBits(mode, RISCV_Feature64Bit) ?
			       RISCV_C_SDSP :
			       0;
	default:
		return 0;
	}
}

#endif

/* The scanner is selected for little-endian, non-E modes without output.
 * These major opcodes admit every destination register and immediate. */
static bool getScanInstruction(csh handle, const uint8_t *code, size_t length,
			       MCInst *inst, uint16_t *size, uint64_t address,
			       void *info)
{
#ifdef RISCV_USE_COMPRESSED_DISPATCH
	if (length < 2 || inst->flat_insn->detail)
		goto full;
	if ((code[0] & 3) != 3) {
		const uint16_t word = code[0] | ((uint16_t)code[1] << 8);
		const unsigned opcode = scanCompressedOpcode(word, inst->csh->mode);
		if (opcode &&
		    (RISCV_getFeatureBits(inst->csh->mode, RISCV_FeatureStdExtC) ||
		     RISCV_getFeatureBits(inst->csh->mode, RISCV_FeatureStdExtZca))) {
			MCInst_setOpcode(inst, opcode);
			*size = 2;
			return true;
		}
		goto full;
	}
	if (length >= 4) {
#else
	if (length >= 4 && !inst->flat_insn->detail) {
#endif
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

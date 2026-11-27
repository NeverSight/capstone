/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_memory_fallback32_text" rodata = \
	".cs_x86_memory_fallback32_rodata"
#endif
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86OutputOptions.h"
#include "X86SimpleOutput.h"
#include "X86VectorRegisterOutput.h"
#define X86_VEX32_REGISTER_MOVES
#include "X86GenVex32MemoryOutput.inc"
#undef X86_VEX32_REGISTER_MOVES
#include "X86GenSimpleOutput.inc"
#include "../../cs_disasm_internal.h"
#define X86_MEMORY32_OUTPUT
#define X86_MEMORY_IMMEDIATE writeGroup1Memory32
#define X86_IMMEDIATE_WIDE 0
#define X86_GROUP1_IMMEDIATE
#include "X86MemoryOutputImpl.h"
#undef X86_GROUP1_IMMEDIATE
#undef X86_MEMORY_IMMEDIATE
#undef X86_IMMEDIATE_WIDE

#define X86_SEGMENT_LEA32 writeSegmentLea32
#include "X86MemoryOutputImpl.h"
#undef X86_SEGMENT_LEA32
#undef X86_MEMORY32_OUTPUT

/* The fixed-width iterator delegates uncommon encodings here. */
CAPSTONE_INTERNAL CS_PRESERVE_MOST bool
X86_decodeOutputMiss32(cs_struct *handle, const uint8_t *code, size_t size,
		       cs_insn *insn, uint16_t *insn_size, bool batch)
{
	const unsigned opcode = code[0];
	switch (opcode) {
	case 0xc4:
		if (X86_writeVexRegisterImmediate(handle, code, size, insn,
						  insn_size, x86_simple_registers, false))
			return true;
		break;
	case 0xc5:
		if (size >= 4 && (code[1] & 0xf8) == 0xf8 && code[3] >= 0xc0 &&
		    (code[2] == 0x6f || code[2] == 0x7f) &&
		    ((code[1] & 3) == 1 || (code[1] & 3) == 2) &&
		    !X86_OUTPUT_UNSUPPORTED(handle, false)) {
			const unsigned ll = (code[1] >> 2) & 1;
			const unsigned reg = (code[3] >> 3) & 7,
				       rm = code[3] & 7;
			const bool load = code[2] == 0x6f;
			const unsigned operands[] = { load ? reg : rm,
						      load ? rm : reg };
			writeVectorRegisters(
				code, insn, insn_size,
				&vex32_move_rows[(code[1] & 3) - 1], 2, ll, 0,
				ll, operands, 2);
			if (insn->detail)
				insn->detail->x86.addr_size = 4;
			return true;
		}
		break;
	case 0x80:
	case 0x81:
	case 0x83:
		if (size >= 2 && code[1] < 0xc0 &&
		    !X86_OUTPUT_UNSUPPORTED(handle, false)) {
			/* The ModRM group selects the corresponding register ALU
			 * opcode; its row owns operand access and flag effects. */
			const unsigned reg_opcode = (code[1] & 0x38) | (opcode & 1);
			const unsigned row = x86_simple_plans[0][0][reg_opcode] >> 2;
			if (writeGroup1Memory32(code, size, insn, insn_size,
					   &x86_simple_outputs[row],
					   x86_simple_registers))
				return true;
		}
		break;
	case 0x26:
	case 0x2e:
	case 0x36:
	case 0x3e:
	case 0x64:
	case 0x65:
		if (size >= 3 && code[1] == 0x8d && code[2] < 0xc0 &&
		    !X86_OUTPUT_UNSUPPORTED(handle, false)) {
			const unsigned row = x86_simple_plans[0][0][0x8d] >> 2;
			if (writeSegmentLea32(code, size, insn, insn_size,
					      &x86_simple_outputs[row],
					      x86_simple_registers))
				return true;
		}
		break;
	}
	return X86_decodeRegisterFallback32(handle, code, size, insn, insn_size, batch);
}
#endif
#endif

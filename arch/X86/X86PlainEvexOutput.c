/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_plain_evex_text" rodata = \
	".cs_x86_plain_evex_rodata"
#endif
#include "X86OutputOptions.h"
#include "X86SimpleOutput.h"
#include "X86VectorRegisterOutput.h"

enum EvexRegisterOrder {
	EVEX_REGISTERS_THREE,
	EVEX_REGISTERS_PAIR,
	EVEX_REGISTERS_REVERSED
};
struct EvexRegisterOutput {
	struct VectorOutputRow instruction;
	uint8_t order;
};
#include "X86GenPlainEvexRegisterOutput.inc"

/* The caller identified six bytes with an EVEX prefix and register ModR/M. */
bool X86_writePlainEvexRegisters(cs_struct *handle, const uint8_t *code,
				 cs_insn *insn, uint16_t *insn_size)
{
	const unsigned map = code[1] & 15, flags = code[2], p2 = code[3];
	const unsigned ll = p2 >> 5;
	if (map < 1 || map > 3 || !(flags & 4) || (p2 & 0x97) || ll >= 3)
		return false;
	const unsigned prefix = plain_evex_opcodes[map - 1][code[4]];
	const unsigned w = flags >> 7;
	const unsigned row =
		plain_evex_prefixes[prefix][(w * 4 + (flags & 3)) * 3 + ll];
	if (!row)
		return false;
	const struct EvexRegisterOutput *record = &plain_evex_rows[row - 1];
	const bool pair = record->order != EVEX_REGISTERS_THREE;
	const unsigned src = ((~flags >> 3) & 15) | ((~p2 & 8) << 1);
	if ((pair && src != 0) || X86_OUTPUT_UNSUPPORTED(handle, false))
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	const unsigned reg = ((code[5] >> 3) & 7) | ((rxb & 4) << 1) |
			     (~(unsigned)code[1] & 16);
	const unsigned rm = (code[5] & 7) | ((rxb & 3) << 3);
	const bool reversed = record->order == EVEX_REGISTERS_REVERSED;
	const unsigned regs[] = { reversed ? rm : reg,
				  reversed ? reg : (pair ? rm : src), rm };
	return writeVectorRegisters(code, insn, insn_size, &record->instruction,
				    4, ll, 0x40 | (w << 3) | rxb, ll, regs,
				    pair ? 2 : 3);
}
#endif
#endif

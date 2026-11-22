/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_register_fallback32_text" rodata = \
	".cs_x86_register_fallback32_rodata"
#endif
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86OutputOptions.h"
#include "X86RegisterImmediateOutput.h"
#include "X86GenTest32Registers.inc"
#include "../../cs_disasm_internal.h"

CAPSTONE_INTERNAL CS_PRESERVE_MOST bool
X86_decodeRegisterFallback32(cs_struct *handle, const uint8_t *code,
			     size_t size, cs_insn *insn, uint16_t *insn_size,
			     bool batch)
{
	const unsigned opcode = code[0];
	if ((opcode & 0xfe) == 0xf6) {
		const unsigned form = opcode & 1;
		const unsigned width = form ? 4 : 1;
		if (size >= 2 + width && (code[1] & 0xf8) == 0xc0 &&
		    !X86_OUTPUT_UNSUPPORTED(handle, false)) {
			writeUnsignedRegisterImmediate(
				insn, &test32_rows[form],
				&test32_regs[form][code[1] & 7], code, 0,
				code[1], 2, width, insn_size);
			return true;
		}
	}
	return cs_decode_full_insn(handle, code, size, insn, insn_size, batch);
}
#endif
#endif

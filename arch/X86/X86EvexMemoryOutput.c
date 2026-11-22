/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
/* Keep the optional output writer and its records together without adding
 * them to the existing ELF decoder code and constant sections. */
#if defined(__ELF__) && defined(__GNUC__)
#define X86_EVEX_MEMORY_CODE __attribute__((section(".cs_x86_evex_output")))
#define X86_EVEX_MEMORY_DATA \
	__attribute__((section(".cs_x86_evex_output_rodata")))
#else
#define X86_EVEX_MEMORY_CODE
#define X86_EVEX_MEMORY_DATA
#endif
/* Clang may outline the shared inline formatter. Give that same helper
 * the writer's section before including its canonical definition. */
static inline char *
X86_writeDisplacement(char *out, int32_t displacement) X86_EVEX_MEMORY_CODE;
#include "X86SimpleOutput.h"
#ifdef CAPSTONE_X86_EVEX_MEMORY_OUTPUT
#include "X86EvexMemoryTables.h"
#include "X86GenEvexMemoryOutput.inc"
#include "X86EvexMemoryRecord.h"

/* Keep the established memory-only entry in the vector reader small. Both
 * writers retain their encoding checks. The six-byte extent was validated
 * by writeEvexOutput before entering this private memory dispatch. */
X86_EVEX_MEMORY_CODE
bool X86_writeEvexMemoryDispatch(const uint8_t *code, size_t size,
				 cs_insn *insn, uint16_t *insn_size,
				 const struct X86SimpleRegister *regs)
{
	if (X86_writeEvexBroadcastPrechecked(code, size, insn, insn_size, regs))
		return true;
	return X86_writeEvexMemoryOutput(code, size, insn, insn_size, regs);
}

#endif
#endif
#endif

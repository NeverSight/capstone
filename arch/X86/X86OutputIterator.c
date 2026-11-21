/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#include "X86ScanAdapter.h"

#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86OutputOptions.h"
#include "X86SimpleOutput.h"
#include "X86GenSimpleOutput.inc"

#include "X86SimpleOutputImpl.h"

#ifndef CAPSTONE_X86_DEDICATED_OUTPUT
#define CS_DECODE_TRY_OUTPUT X86_trySimpleOutput
#endif
#endif
#include "../../cs_disasm_internal.h"

CAPSTONE_INTERNAL bool X86_disasmIter(csh ud, const uint8_t **code,
				      size_t *size, uint64_t *address,
				      cs_insn *insn)
{
#ifdef CS_DECODE_TRY_OUTPUT
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (handle && handle->arch == CS_ARCH_X86 && !handle->no_text)
		return cs_disasm_iter_core(ud, code, size, address, insn);
#endif
	return cs_disasm_iter(ud, code, size, address, insn);
}
#endif

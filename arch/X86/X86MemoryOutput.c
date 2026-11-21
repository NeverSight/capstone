/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86SimpleOutput.h"

#include "X86MemoryOutputImpl.h"

#endif
#endif

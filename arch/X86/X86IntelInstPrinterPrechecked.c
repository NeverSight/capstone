/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#if defined(CAPSTONE_HAS_X86) && (defined(__GNUC__) || defined(_MSC_VER)) && \
	!defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
// Share the printer and append bodies. The public entry validates the complete
// generated path's extent and stream state before calling this instantiation.
#define CAPSTONE_SSTREAM_PRECHECKED
#include "X86InstPrinter.h"
#define SStream_concat_hex64 X86_Intel_printHexPrechecked
#include "X86IntelInstPrinter.c"
#endif

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
#if defined(_MSC_VER) && !defined(__clang__)
#include "../../SStream.h"
/* The fixed tokens in this bounded printer include their terminating NUL.
 * The register-extension name uses the ordinary dynamic writer. */
static __forceinline void appendPrinterLiteral(SStream *ss, const char *text,
					       size_t extent)
{
	assert(!ss->is_closed && !ss->markup_stream && !ss->prefixed_by_markup);
	assert(extent <= SSTREAM_BUF_LEN &&
	       ss->index <= SSTREAM_BUF_LEN - extent);
	if (extent > 1) {
		memcpy(ss->buffer + ss->index, text, extent);
		ss->index += extent - 1;
	}
}
#define SStream_concat0(ss, literal) \
	appendPrinterLiteral((ss), "" literal, sizeof("" literal))
#endif
#include "X86IntelInstPrinter.c"
#endif

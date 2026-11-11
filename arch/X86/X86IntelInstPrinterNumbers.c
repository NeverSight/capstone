/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "X86InstPrinter.h"
#include "../../MathExtras.h"

#if defined(CAPSTONE_HAS_X86) && defined(CAPSTONE_X86_PRECHECKED_PRINTER)
// The private printer entry proves a plain open stream, default formatter and
// capacity for the complete generated output. A signed uint64 hexadecimal
// spelling needs at most 19 bytes, already included in that generated bound.
void X86_Intel_printHexPrechecked(SStream *OS, uint64_t value, bool negative)
{
	const unsigned digits =
		value ? (64U - CountLeadingZeros_64(value) + 3U) / 4U : 1U;
	char *out = OS->buffer + OS->index;
	OS->index += digits + (negative ? 3U : 2U);
	char *end = OS->buffer + OS->index;
	if (negative)
		*out++ = '-';
	*out++ = '0';
	*out = 'x';
	*end = '\0';

	do {
		*--end = "0123456789abcdef"[value & 15];
		value >>= 4;
	} while (value);
}
#endif

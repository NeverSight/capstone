/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "ARMMapping.h"

#ifdef ARM_FORMATTED_CHAR_CALL
/* The printer supplies "%s" and one NUL-terminated, single-character
 * string at every call. A custom formatter receives these same arguments. */
__attribute__((section(".cs_arm_formatted_char")))
void ARM_formatChar(SStream *O, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	const char *literal = va_arg(args, const char *);
	va_end(args);
	if (cs_vsnprintf == cs_default_vsnprintf)
		SStream_concat1(O, literal[0]);
	else
		SStream_concat(O, fmt, literal);
}
#endif

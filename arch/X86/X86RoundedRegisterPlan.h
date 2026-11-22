/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_ROUNDED_REGISTER_PLAN_H
#define CS_X86_ROUNDED_REGISTER_PLAN_H
#include "X86GenRoundedRegister64.inc"

/* Bare EVEX.b, a register ModR/M and six input bytes were checked by the
 * caller. The ordinary decoder verifies every register and rounding mode
 * represented by the generated row. */
static inline unsigned X86_roundedRegisterRow(const uint8_t *code)
{
	const unsigned map = code[1] & 15, flags = code[2];
	if (map < 1 || map > 3 || !(flags & 4) || (code[3] & 0x87))
		return 0;
	const unsigned prefix = evex_rounded_plans[map - 1][code[4]];
	return evex_rounded_prefixes[prefix][(flags >> 7) * 4 + (flags & 3)];
}
#endif

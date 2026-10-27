/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <limits.h>
#include <stdio.h>
#include "../../arch/X86/X86Mapping.h"

#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "../../arch/X86/X86GenInstrInfo_reduce.inc"
#else
#include "../../arch/X86/X86GenInstrInfo.inc"
#endif

static const struct {
	uint8_t encoded;
	uint8_t operand;
	unsigned id;
} reference[] = {
#include "../../arch/X86/X86ImmSize.inc"
};

static bool check(unsigned id)
{
	uint8_t operand = 0, encoded = 0, actual_encoded = 0xa5;
	for (size_t i = 0; i < sizeof(reference) / sizeof(reference[0]); i++) {
		if (reference[i].id == id) {
			operand = reference[i].operand;
			encoded = reference[i].encoded;
			break;
		}
	}
	uint8_t actual = X86_immediate_size(id, &actual_encoded);
	if (actual != operand || actual_encoded != encoded ||
	    X86_immediate_size(id, NULL) != operand) {
		fprintf(stderr, "id=%u operand=%u/%u encoded=%u/%u\n", id,
			actual, operand, actual_encoded, encoded);
		return false;
	}
	return true;
}

int main(void)
{
	// Includes every full/reduced opcode and all holes in the 16-bit ID domain.
	for (unsigned id = 0; id <= UINT16_MAX; id++) {
		if (!check(id))
			return 1;
	}
	if (!check(UINT16_MAX + 1U) || !check(INT_MAX) ||
	    !check((unsigned)INT_MAX + 1U) || !check(UINT_MAX))
		return 1;
	puts("All 65540 immediate metadata cases passed.");
	return 0;
}

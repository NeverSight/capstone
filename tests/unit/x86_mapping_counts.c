/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdio.h>
#include "../../arch/X86/X86Mapping.h"
#include "../../utils.h"

#ifndef CAPSTONE_DIET
#include "../../arch/X86/X86GenMappingCounts.inc"
#endif

int main(void)
{
#ifndef CAPSTONE_DIET
	for (size_t i = 0; i < ARR_SIZE(x86_mapping_counts); ++i) {
		unsigned counts = x86_mapping_counts[i];
		if ((counts & 31) != count_positive(insns[i].regs_use) ||
		    ((counts >> 5) & 31) != count_positive(insns[i].regs_mod) ||
		    ((counts >> 10) & 15) != count_positive8(insns[i].groups)) {
			fprintf(stderr,
				"Mapping count mismatch at row %zu, opcode %u\n",
				i, insns[i].id);
			return 1;
		}
	}
#endif
	return 0;
}

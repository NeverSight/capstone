/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>
#include "../../arch/Mips/MipsGenShortRegisterNames.inc"

int main(void)
{
	csh handle;
	if (cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32R2, &handle))
		return 1;
	for (unsigned reg = 1; reg < MIPS_REG_ENDING; ++reg) {
		const char *name = cs_reg_name(handle, reg);
		const unsigned index = mips_short_name_indices[reg - 1];
		if (index >=
		    sizeof(mips_short_names) / sizeof(mips_short_names[0])) {
			cs_close(&handle);
			return 2;
		}
		const unsigned length = mips_short_names[index].length;
		const char *text = mips_short_names[index].text;
		if (!name || ((strlen(name) <= 5) != (length != 0)) ||
		    (length && (text[0] != '$' || strlen(text) != length ||
				strcmp(text + 1, name)))) {
			fprintf(stderr, "MIPS register name %u\n", reg);
			cs_close(&handle);
			return 3;
		}
	}
	cs_close(&handle);
	return 0;
}

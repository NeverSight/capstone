/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "CS_OPT_DETAIL check failed: %s\n", message);
	return condition;
}

// call 0x1005; ret
static const uint8_t code[] = { 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3 };

/// Whether cs_disasm gives the first instruction detail.
static bool decodes_with_detail(csh handle, bool *detail)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 0, &insn);
	if (count != 2)
		return false;
	*detail = insn[0].detail != NULL;
	cs_free(insn, count);
	return true;
}

int main(void)
{
	csh handle = 0;
	bool detail = false;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit mode"))
		return 1;
	success &= check(decodes_with_detail(handle, &detail) && !detail,
			 "detail is off by default");

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	success &= check(decodes_with_detail(handle, &detail) && detail,
			 "CS_OPT_ON turns detail on");

	success &=
		check(cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF) == CS_ERR_OK,
		      "the option is accepted");
	success &= check(decodes_with_detail(handle, &detail) && !detail,
			 "CS_OPT_OFF turns detail off again");

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL);
	success &= check(decodes_with_detail(handle, &detail) && detail,
			 "CS_OPT_DETAIL_REAL keeps detail on");
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
	success &= check(decodes_with_detail(handle, &detail) && !detail,
			 "CS_OPT_OFF clears CS_OPT_DETAIL_REAL too");

	cs_close(&handle);
	return success ? 0 : 1;
}

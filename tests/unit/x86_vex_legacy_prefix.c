/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct prefix_case {
	cs_mode mode;
	const char *name;
	uint8_t code[8];
	size_t size;
	/* The decoded text, or NULL when the encoding is #UD. */
	const char *text;
} prefix_case;

static bool check_case(const prefix_case *test)
{
	cs_insn *insn = NULL;
	csh handle;
	size_t count;
	char actual[160] = "";
	bool ok;

	if (cs_open(CS_ARCH_X86, test->mode, &handle) != CS_ERR_OK)
		return false;
	count = cs_disasm(handle, test->code, test->size, 0x1000, 1, &insn);
	if (count == 1)
		snprintf(actual, sizeof(actual), "%s %s", insn->mnemonic,
			 insn->op_str);
	ok = test->text ? count == 1 && insn->size == test->size &&
				  strcmp(actual, test->text) == 0 :
			  count == 0;
	if (!ok)
		fprintf(stderr, "%s: decoded as \"%s\", expected %s\n",
			test->name, actual, test->text ? test->text : "#UD");
	cs_free(insn, count);
	cs_close(&handle);
	return ok;
}

int main(void)
{
	/* A 66, F2, F3 or LOCK prefix anywhere before a VEX or EVEX prefix, or
	 * a REX prefix right before it, makes the instruction #UD, as in XED.
	 * A segment or address-size prefix does not, and neither does a REX
	 * prefix that a later legacy prefix makes ineffective. */
	static const prefix_case cases[] = {
		{ CS_MODE_64, "vex2", { 0xc5, 0xf8, 0x77 }, 3, "vzeroupper " },
		{ CS_MODE_64, "66 vex2", { 0x66, 0xc5, 0xf8, 0x77 }, 4, NULL },
		{ CS_MODE_64, "f2 vex2", { 0xf2, 0xc5, 0xf8, 0x77 }, 4, NULL },
		{ CS_MODE_64, "f3 vex2", { 0xf3, 0xc5, 0xf8, 0x77 }, 4, NULL },
		{ CS_MODE_64, "rex vex2", { 0x48, 0xc5, 0xf8, 0x77 }, 4, NULL },
		{ CS_MODE_64,
		  "cs rex vex2",
		  { 0x2e, 0x48, 0xc5, 0xf8, 0x77 },
		  5,
		  NULL },
		{ CS_MODE_64,
		  "66 cs vex3",
		  { 0x66, 0x2e, 0xc4, 0xe1, 0x74, 0x58, 0xc2 },
		  7,
		  NULL },
		{ CS_MODE_64,
		  "66 evex",
		  { 0x66, 0x62, 0xf1, 0x7c, 0x08, 0x58, 0xc2 },
		  7,
		  NULL },
		{ CS_MODE_64,
		  "rex evex",
		  { 0x48, 0x62, 0xf1, 0x7c, 0x08, 0x58, 0xc2 },
		  7,
		  NULL },
		{ CS_MODE_64,
		  "rex cs vex2",
		  { 0x48, 0x2e, 0xc5, 0xf8, 0x77 },
		  5,
		  "vzeroupper " },
		{ CS_MODE_64,
		  "addr32 vex2",
		  { 0x67, 0xc5, 0xf8, 0x77 },
		  4,
		  "vzeroupper " },
		{ CS_MODE_64,
		  "cs evex",
		  { 0x2e, 0x62, 0xf1, 0x7c, 0x08, 0x58, 0xc2 },
		  7,
		  "vaddps xmm0, xmm0, xmm2" },
		{ CS_MODE_32,
		  "32-bit 66 vex2",
		  { 0x66, 0xc5, 0xf8, 0x77 },
		  4,
		  NULL },
		/* Before a memory ModR/M, C5 is LDS, which 66 may prefix. */
		{ CS_MODE_32,
		  "32-bit 66 lds",
		  { 0x66, 0xc5, 0x07 },
		  3,
		  "lds ax, ptr [edi]" },
	};
	bool ok = true;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		ok &= check_case(&cases[i]);
	return ok ? 0 : 1;
}

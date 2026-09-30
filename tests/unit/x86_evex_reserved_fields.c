/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct evex_case {
	cs_mode mode;
	const char *name;
	uint8_t code[8];
	size_t size;
	/* The decoded text, or NULL when the encoding is #UD. */
	const char *text;
} evex_case;

static bool check_case(const evex_case *test)
{
	cs_insn *insn = NULL;
	csh handle;
	size_t count;
	char actual[256] = "";
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
	/* EVEX fields that the decode tables ignore but that make the
	 * instruction #UD, each next to a legal neighbor, as XED decodes them. */
	static const evex_case cases[] = {
		/* Zeroing needs an opmask. */
		{ CS_MODE_64,
		  "masked zeroing",
		  { 0x62, 0xf1, 0x7c, 0x89, 0x58, 0xc1 },
		  6,
		  "vaddps xmm0 {k1} {z}, xmm0, xmm1" },
		{ CS_MODE_64,
		  "zeroing without mask",
		  { 0x62, 0xf1, 0x7c, 0x88, 0x58, 0xc1 },
		  6,
		  NULL },
		/* L'L = 11 names no vector length, even for scalar forms, but
		 * is the rounding control of a register form with EVEX.b. */
		{ CS_MODE_64,
		  "packed L'L=10",
		  { 0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc1 },
		  6,
		  "vaddps zmm0, zmm0, zmm1" },
		{ CS_MODE_64,
		  "packed L'L=11",
		  { 0x62, 0xf1, 0x7c, 0x68, 0x58, 0xc1 },
		  6,
		  NULL },
		{ CS_MODE_64,
		  "scalar L'L=10",
		  { 0x62, 0xf1, 0x7e, 0x48, 0x58, 0xc1 },
		  6,
		  "vaddss xmm0, xmm0, xmm1" },
		{ CS_MODE_64,
		  "scalar L'L=11",
		  { 0x62, 0xf1, 0x7e, 0x68, 0x58, 0xc1 },
		  6,
		  NULL },
		{ CS_MODE_64,
		  "memory L'L=11",
		  { 0x62, 0xf1, 0x7c, 0x68, 0x58, 0x00 },
		  6,
		  NULL },
		{ CS_MODE_64,
		  "rounding L'L=11",
		  { 0x62, 0xf1, 0x7c, 0x78, 0x58, 0xc1 },
		  6,
		  "vaddps zmm0, zmm0, zmm1, {rz-sae}" },
		/* An opmask register in ModRM.reg has no R or R' extension. */
		{ CS_MODE_64,
		  "mask destination",
		  { 0x62, 0xf1, 0x7d, 0x48, 0x75, 0xc1 },
		  6,
		  "vpcmpeqw k0, zmm0, zmm1" },
		{ CS_MODE_64,
		  "mask destination with R'",
		  { 0x62, 0xe1, 0x7d, 0x48, 0x75, 0xc1 },
		  6,
		  NULL },
		/* A register r/m has no index for EVEX.U to extend. */
		{ CS_MODE_64,
		  "register form with clear U",
		  { 0x62, 0xf1, 0x78, 0x48, 0x58, 0xc1 },
		  6,
		  NULL },
		{ CS_MODE_64,
		  "memory form with clear U",
		  { 0x62, 0xf1, 0x78, 0x48, 0x58, 0x04, 0x0c },
		  7,
		  "vaddps zmm0, zmm0, zmmword ptr [rsp + r17]" },
		/* Outside 64-bit mode EVEX.V' must be clear, and R' is
		 * ignored. */
		{ CS_MODE_32,
		  "32-bit V'",
		  { 0x62, 0xf1, 0x7c, 0x40, 0x58, 0xc1 },
		  6,
		  NULL },
		{ CS_MODE_32,
		  "32-bit VSIB V'",
		  { 0x62, 0xf2, 0x7d, 0x41, 0x90, 0x04, 0xa0 },
		  7,
		  NULL },
		{ CS_MODE_32,
		  "32-bit mask destination with R'",
		  { 0x62, 0xe1, 0x7d, 0x48, 0x75, 0xc1 },
		  6,
		  "vpcmpeqw k0, zmm0, zmm1" },
		/* An opmask register in ModRM.r/m ignores B and X. */
		{ CS_MODE_64,
		  "mask source with X",
		  { 0x62, 0xb2, 0x7e, 0x48, 0x38, 0xc1 },
		  6,
		  "vpmovm2d zmm0, k1" },
		{ CS_MODE_64,
		  "mask source with B",
		  { 0x62, 0xd2, 0x7e, 0x48, 0x38, 0xc1 },
		  6,
		  "vpmovm2d zmm0, k1" },
		{ CS_MODE_64,
		  "VEX mask source with B",
		  { 0xc4, 0xc1, 0x78, 0x90, 0xca },
		  5,
		  "kmovw k1, k2" },
		/* A gather's destination, vector index and VEX mask must be
		 * distinct registers; a scatter has no such rule. */
		{ CS_MODE_64,
		  "VEX gather",
		  { 0xc4, 0xe2, 0x69, 0x92, 0x04, 0x88 },
		  6,
		  "vgatherdps xmm0, xmmword ptr [rax + xmm1*4], xmm2" },
		{ CS_MODE_64,
		  "VEX gather destination is index",
		  { 0xc4, 0xe2, 0x69, 0x92, 0x04, 0x80 },
		  6,
		  NULL },
		{ CS_MODE_64,
		  "VEX gather mask is index",
		  { 0xc4, 0xe2, 0x71, 0x92, 0x04, 0x88 },
		  6,
		  NULL },
		{ CS_MODE_64,
		  "VEX gather mask is destination",
		  { 0xc4, 0xe2, 0x79, 0x92, 0x04, 0x88 },
		  6,
		  NULL },
		{ CS_MODE_32,
		  "32-bit VEX gather destination is index",
		  { 0xc4, 0xe2, 0x69, 0x92, 0x04, 0x80 },
		  6,
		  NULL },
		{ CS_MODE_64,
		  "EVEX gather destination is index",
		  { 0x62, 0xf2, 0x7d, 0x49, 0x92, 0x04, 0x80 },
		  7,
		  NULL },
		{ CS_MODE_64,
		  "EVEX scatter source is index",
		  { 0x62, 0xf2, 0x7d, 0x49, 0xa0, 0x04, 0x80 },
		  7,
		  "vpscatterdd zmmword ptr [rax + zmm0*4] {k1}, zmm0" },
	};
	bool ok = true;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		ok &= check_case(&cases[i]);
	return ok ? 0 : 1;
}

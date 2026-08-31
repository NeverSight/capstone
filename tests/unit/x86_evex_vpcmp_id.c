/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "EVEX compare ID check failed: %s\n", message);
	return condition;
}

static bool test_vpcmp(csh handle, bool expect_detail)
{
	// vpcmpnled k1 {k2}, zmm2, zmm3
	static const uint8_t code[] = { 0x62, 0xf3, 0x6d, 0x4a,
					0x1f, 0xcb, 0x06 };
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	const char *name;

	if (!check(count == 1, "instruction decodes"))
		return false;
	success &= check(strcmp(insn[0].mnemonic, "vpcmpnled") == 0,
			 "condition-specific mnemonic is preserved");
	success &= check(insn[0].id == X86_INS_VPCMPD,
			 "public ID identifies the packed dword compare family");
	name = cs_insn_name(handle, insn[0].id);
	success &= check(name != NULL && strcmp(name, "vpcmpd") == 0,
			 "public instruction name is vpcmpd");
	success &= check((insn[0].detail != NULL) == expect_detail,
			 "detail availability matches the option");
	if (expect_detail && insn[0].detail != NULL) {
		success &= check(insn[0].detail->x86.avx_cc == X86_AVX_CC_NLE,
				 "predicate detail is NLE");
	}
	if (!success) {
		fprintf(stderr, "actual id=%u name=%s mnemonic=%s operands=%s\n",
			insn[0].id, name ? name : "(null)", insn[0].mnemonic,
			insn[0].op_str);
	}

	cs_free(insn, count);
	return success;
}

int main(void)
{
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit mode"))
		return 1;
	success &= test_vpcmp(handle, false);
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			    CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}
	success &= test_vpcmp(handle, true);
	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "select AT&T syntax");
	success &= test_vpcmp(handle, true);
	cs_close(&handle);
	return success ? 0 : 1;
}

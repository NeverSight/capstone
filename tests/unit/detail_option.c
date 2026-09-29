/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

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

/// Decoding with cs_disasm_iter() into an instruction cs_malloc() allocated
/// while detail was on, after detail is turned off, leaves its detail as the
/// last decode with detail filled it.
static bool test_iter(cs_arch arch, cs_mode mode, const uint8_t *insn_code,
		      size_t insn_size)
{
	csh handle = 0;
	cs_insn *insn;
	cs_detail *detail, before;
	const uint8_t *cursor;
	size_t left;
	uint64_t address;
	bool success = true;
	int i;

	if (!cs_support(arch))
		return true;
	if (!check(cs_open(arch, mode, &handle) == CS_ERR_OK, "open"))
		return false;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	insn = cs_malloc(handle);
	detail = insn->detail;
	cursor = insn_code;
	left = insn_size;
	address = 0x1000;
	success &=
		check(cs_disasm_iter(handle, &cursor, &left, &address, insn) &&
			      insn->detail == detail,
		      "decode with detail");
	before = *detail;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
	for (i = 0; success && i < 64; i++) {
		cursor = insn_code;
		left = insn_size;
		address = 0x1000;
		success &= check(cs_disasm_iter(handle, &cursor, &left,
						&address, insn),
				 "decode without detail");
	}
	success &= check(insn->detail == detail, "the detail is kept");
	success &= check(memcmp(&before, detail, sizeof(before)) == 0,
			 "decodes without detail leave it as it was");

	cs_free(insn, 1);
	cs_close(&handle);
	return success;
}

int main(void)
{
	// bl 0x1000
	static const uint8_t aarch64_code[] = { 0x00, 0x00, 0x00, 0x94 };
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

	success &= test_iter(CS_ARCH_X86, CS_MODE_64, code, sizeof(code));
	success &= test_iter(CS_ARCH_AARCH64, CS_MODE_ARM, aarch64_code,
			     sizeof(aarch64_code));
	return success ? 0 : 1;
}

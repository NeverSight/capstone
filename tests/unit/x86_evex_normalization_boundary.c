/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool check_first(csh handle, const char *name, const uint8_t *code,
			size_t code_size, x86_insn expected_id,
			uint16_t expected_size)
{
	cs_insn *instruction = NULL;
	const size_t count =
		cs_disasm(handle, code, code_size, 0x1000, 1, &instruction);
	const bool ok = count == 1 && instruction != NULL &&
			instruction[0].id == expected_id &&
			instruction[0].size == expected_size;

	if (!ok)
		fprintf(stderr,
			"%s: first instruction was rejected or changed by lookahead\n",
			name);
	cs_free(instruction, count);
	return ok;
}

static bool check_trailing_bytes_do_not_change_first(
	csh handle, const char *name, const uint8_t *code, size_t code_size)
{
	uint8_t with_trailing[32];
	cs_insn *standalone = NULL;
	cs_insn *extended = NULL;
	size_t standalone_count;
	size_t extended_count;
	bool ok;

	if (code_size + 16 > sizeof(with_trailing))
		return false;
	memcpy(with_trailing, code, code_size);
	memset(with_trailing + code_size, 0x90, 16);
	standalone_count =
		cs_disasm(handle, code, code_size, 0x1000, 1, &standalone);
	extended_count = cs_disasm(handle, with_trailing, code_size + 16,
				   0x1000, 1, &extended);
	ok = standalone_count == 1 && extended_count == 1 && standalone != NULL &&
	     extended != NULL && standalone[0].id == extended[0].id &&
	     standalone[0].size == extended[0].size &&
	     standalone[0].size == code_size && standalone[0].detail != NULL &&
	     extended[0].detail != NULL &&
	     strcmp(standalone[0].mnemonic, extended[0].mnemonic) == 0 &&
	     strcmp(standalone[0].op_str, extended[0].op_str) == 0 &&
	     memcmp(&standalone[0].detail->x86, &extended[0].detail->x86,
		    sizeof(cs_x86)) == 0;
	if (!ok)
		fprintf(stderr,
			"%s: trailing bytes changed or rejected the first instruction\n",
			name);
	cs_free(standalone, standalone_count);
	cs_free(extended, extended_count);
	return ok;
}

int main(void)
{
	/* The immediate of the following ADD contains 0x62 and an APX-like
	 * suffix.  EVEX normalization must not inspect past the current MOV. */
	static const uint8_t apx_lookahead[] = {
		0x8b, 0x45, 0xf4, 0x05, 0x17, 0xc0, 0x62, 0xe1,
		0x89, 0x45, 0xf4, 0xe9, 0xd0, 0x04, 0x00, 0x00
	};
	/* The following instruction is a scalar 4FMAPS spelling.  Its EVEX
	 * byte must not make the preceding NOP look like an illegal prefix. */
	static const uint8_t fmaps_lookahead[] = {
		0x90, 0x62, 0xf2, 0x5f, 0x68, 0x9b, 0x08
	};
	/* 0x40 is an INC opcode outside 64-bit mode, not a REX prefix. */
	static const uint8_t inc_lookahead[] = {
		0x40, 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9
	};
	/* In 16/32-bit mode 62 /r is BOUND unless the following bytes satisfy
	 * the architectural EVEX prefix structure.  The trailing bytes are
	 * deliberately shaped like a scalar LLIG family. */
	static const uint8_t bound_lookahead[] = {
		0x62, 0x02, 0x05, 0x60, 0xcb, 0xc0, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
	};
	static const struct {
		const char *name;
		uint8_t code[8];
		size_t size;
	} llig_cases[] = {
		{ "avx512er-llig", { 0x62, 0xf2, 0x4d, 0x28, 0xcb, 0xef }, 6 },
		{ "rcp14-llig", { 0x62, 0xf2, 0x7d, 0x28, 0x4d, 0xca }, 6 },
		{ "vfpclass-llig",
		  { 0x62, 0xf3, 0x7d, 0x29, 0x67, 0xda, 0xff }, 7 },
		{ "4fmaps-llig", { 0x62, 0xf2, 0x5f, 0x28, 0x9b, 0x08 }, 6 },
		{ "fs-avx512er-llig",
		  { 0x64, 0x62, 0xf2, 0x4d, 0x28, 0xcb, 0x28 }, 7 },
		{ "fs-rcp14-llig",
		  { 0x64, 0x62, 0xf2, 0x7d, 0x28, 0x4d, 0x08 }, 7 },
		{ "fs-vfpclass-llig",
		  { 0x64, 0x62, 0xf3, 0x7d, 0x29, 0x67, 0x1a, 0xff }, 8 },
		{ "fs-4fmaps-llig",
		  { 0x64, 0x62, 0xf2, 0x5f, 0x28, 0x9b, 0x08 }, 7 },
	};
	csh handle = 0;
	bool ok;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		return 1;
	ok = check_first(handle, "apx-lookahead", apx_lookahead,
			 sizeof(apx_lookahead), X86_INS_MOV, 3);
	ok &= check_first(handle, "4fmaps-lookahead", fmaps_lookahead,
			  sizeof(fmaps_lookahead), X86_INS_NOP, 1);
	for (size_t i = 0; i < sizeof(llig_cases) / sizeof(llig_cases[0]); ++i)
		ok &= check_trailing_bytes_do_not_change_first(
			handle, llig_cases[i].name, llig_cases[i].code,
			llig_cases[i].size);
	cs_close(&handle);

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return 1;
	ok &= check_first(handle, "apx-lookahead-32", apx_lookahead,
			  sizeof(apx_lookahead), X86_INS_MOV, 3);
	ok &= check_first(handle, "inc-lookahead-32", inc_lookahead,
			  sizeof(inc_lookahead), X86_INS_INC, 1);
	ok &= check_first(handle, "bound-lookahead-32", bound_lookahead,
			  sizeof(bound_lookahead), X86_INS_BOUND, 2);
	cs_close(&handle);

	if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK)
		return 1;
	ok &= check_first(handle, "inc-lookahead-16", inc_lookahead,
			  sizeof(inc_lookahead), X86_INS_INC, 1);
	ok &= check_first(handle, "bound-lookahead-16", bound_lookahead,
			  sizeof(bound_lookahead), X86_INS_BOUND, 2);
	cs_close(&handle);
	return ok ? 0 : 1;
}

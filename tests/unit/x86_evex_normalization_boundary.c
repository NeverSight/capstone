/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

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
	csh handle = 0;
	bool ok;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	ok = check_first(handle, "apx-lookahead", apx_lookahead,
			 sizeof(apx_lookahead), X86_INS_MOV, 3);
	ok &= check_first(handle, "4fmaps-lookahead", fmaps_lookahead,
			  sizeof(fmaps_lookahead), X86_INS_NOP, 1);
	cs_close(&handle);

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return 1;
	ok &= check_first(handle, "apx-lookahead-32", apx_lookahead,
			  sizeof(apx_lookahead), X86_INS_MOV, 3);
	ok &= check_first(handle, "inc-lookahead-32", inc_lookahead,
			  sizeof(inc_lookahead), X86_INS_INC, 1);
	cs_close(&handle);

	if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK)
		return 1;
	ok &= check_first(handle, "inc-lookahead-16", inc_lookahead,
			  sizeof(inc_lookahead), X86_INS_INC, 1);
	cs_close(&handle);
	return ok ? 0 : 1;
}

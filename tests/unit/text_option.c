/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "CS_OPT_TEXT check failed: %s\n", message);
	return condition;
}

// mov eax, 1; call 0x100a; cmpeqss xmm0, xmm1; mov rax, [rip + 0x10]; ret
static const uint8_t x86_code[] = { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xe8,
				    0x00, 0x00, 0x00, 0x00, 0xf3, 0x0f,
				    0xc2, 0xc1, 0x00, 0x48, 0x8b, 0x05,
				    0x10, 0x00, 0x00, 0x00, 0xc3 };
#define X86_COUNT 5
// The compare, whose ID the printer adjusts by its predicate.
#define X86_COMPARE 2

static bool test_x86(void)
{
	csh printed = 0, bare = 0;
	cs_insn *expected = NULL, *actual = NULL;
	size_t expected_count, actual_count, i;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &printed) == CS_ERR_OK &&
			   cs_open(CS_ARCH_X86, CS_MODE_64, &bare) == CS_ERR_OK,
		   "open 64-bit mode"))
		return false;
	cs_option(printed, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(bare, CS_OPT_DETAIL, CS_OPT_ON);
	success &= check(cs_option(bare, CS_OPT_TEXT, CS_OPT_OFF) == CS_ERR_OK,
			 "the option is accepted");

	expected_count = cs_disasm(printed, x86_code, sizeof(x86_code), 0x1000,
				   0, &expected);
	actual_count =
		cs_disasm(bare, x86_code, sizeof(x86_code), 0x1000, 0, &actual);
	success &=
		check(expected_count == X86_COUNT && actual_count == X86_COUNT,
		      "every instruction decodes either way");
	for (i = 0; success && i < X86_COUNT; i++) {
		success &=
			check(actual[i].address == expected[i].address &&
				      actual[i].size == expected[i].size &&
				      memcmp(actual[i].bytes, expected[i].bytes,
					     expected[i].size) == 0,
			      "address, size and bytes are the printed ones");
		success &= check(i == X86_COMPARE ||
					 actual[i].id == expected[i].id,
				 "an ID the printer leaves alone is the same");
		success &= check(actual[i].mnemonic[0] == '\0' &&
					 actual[i].op_str[0] == '\0',
				 "no text is printed");
		success &= check(actual[i].detail->x86.op_count == 0,
				 "no operand detail is filled");
	}
	success &= check(success && expected[0].detail->x86.op_count == 2,
			 "the printed decode fills operand detail");

	// cs_disasm_iter reads the same way.
	{
		const uint8_t *code = x86_code;
		size_t size = sizeof(x86_code);
		uint64_t address = 0x1000;
		cs_insn *insn = cs_malloc(bare);

		for (i = 0; success && i < X86_COUNT; i++) {
			success &= check(cs_disasm_iter(bare, &code, &size,
							&address, insn) &&
						 insn->size == actual[i].size &&
						 insn->id == actual[i].id &&
						 insn->mnemonic[0] == '\0',
					 "cs_disasm_iter reads as cs_disasm");
		}
		cs_free(insn, 1);
	}

	// Turned back on, the handle prints again.
	cs_option(bare, CS_OPT_TEXT, CS_OPT_ON);
	cs_free(actual, actual_count);
	actual_count =
		cs_disasm(bare, x86_code, sizeof(x86_code), 0x1000, 0, &actual);
	success &= check(actual_count == X86_COUNT &&
				 strcmp(actual[0].mnemonic, "mov") == 0 &&
				 actual[X86_COMPARE].id ==
					 expected[X86_COMPARE].id,
			 "text is printed again");

	cs_free(expected, expected_count);
	cs_free(actual, actual_count);
	cs_close(&printed);
	cs_close(&bare);
	return success;
}

static bool test_aarch64(void)
{
	// mov w0, #1; bl 0x1004
	static const uint8_t code[] = { 0x20, 0x00, 0x80, 0x52,
					0x00, 0x00, 0x00, 0x94 };
	csh printed = 0, bare = 0;
	cs_insn *expected = NULL, *actual = NULL;
	size_t expected_count, actual_count, i;
	bool success = true;

	if (!cs_support(CS_ARCH_AARCH64))
		return true;
	if (!check(cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &printed) ==
				   CS_ERR_OK &&
			   cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &bare) ==
				   CS_ERR_OK,
		   "open AArch64"))
		return false;
	cs_option(bare, CS_OPT_TEXT, CS_OPT_OFF);
	expected_count =
		cs_disasm(printed, code, sizeof(code), 0x1000, 0, &expected);
	actual_count = cs_disasm(bare, code, sizeof(code), 0x1000, 0, &actual);
	success &= check(expected_count == 2 && actual_count == 2,
			 "AArch64 instructions decode either way");
	for (i = 0; success && i < 2; i++)
		success &= check(actual[i].size == expected[i].size &&
					 actual[i].id == expected[i].id &&
					 actual[i].mnemonic[0] == '\0',
				 "AArch64 reads the same without text");

	cs_free(expected, expected_count);
	cs_free(actual, actual_count);
	cs_close(&printed);
	cs_close(&bare);
	return success;
}

int main(void)
{
	bool success = test_x86();

	success &= test_aarch64();
	return success ? 0 : 1;
}

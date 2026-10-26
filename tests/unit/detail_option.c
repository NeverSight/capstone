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
		cs_option(handle, CS_OPT_TEXT, i % 2 ? CS_OPT_ON : CS_OPT_OFF);
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

typedef struct {
	cs_insn *insn;
	cs_detail *expected, *alternate;
	const uint8_t *bytes;
	size_t result;
	unsigned replace, calls;
	bool observed;
} skipdata_state;

static size_t skipdata_callback(const uint8_t *bytes, size_t size,
				size_t offset, void *opaque)
{
	skipdata_state *state = opaque;
	++state->calls;
	state->observed = state->insn->detail == state->expected &&
			  bytes == state->bytes && size == 1 && offset == 0;
	if (state->replace == 1)
		state->insn->detail = NULL;
	else if (state->replace == 2)
		state->insn->detail = state->alternate;
	return state->result;
}

/* Callback-visible detail and final restoration apply on failure as well as
 * success, including when a callback replaces the pointer itself. */
static bool test_skipdata_detail(unsigned allocated, unsigned detail,
				 unsigned text, unsigned replace,
				 unsigned result, uint8_t prefix)
{
	csh handle = 0;
	bool success = true;
	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open skipdata handle"))
		return false;
	cs_option(handle, CS_OPT_DETAIL, allocated ? CS_OPT_ON : CS_OPT_OFF);
	cs_insn *insn = cs_malloc(handle);
	if (!check(insn != NULL, "allocate skipdata instruction")) {
		cs_close(&handle);
		return false;
	}
	cs_detail *original = insn->detail;
	cs_detail alternate, before;
	memset(&alternate, 0x3c, sizeof(alternate));
	if (original) {
		memset(original, 0xa5, sizeof(*original));
		before = *original;
	}
	cs_option(handle, CS_OPT_DETAIL, detail ? CS_OPT_ON : CS_OPT_OFF);
	cs_option(handle, CS_OPT_TEXT, text ? CS_OPT_ON : CS_OPT_OFF);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	skipdata_state state = { insn,	     detail ? original : NULL,
				 &alternate, &prefix,
				 result,     replace,
				 0,	     false };
	cs_opt_skipdata setup = { ".byte", skipdata_callback, &state };
	cs_option(handle, CS_OPT_SKIPDATA_SETUP, (size_t)&setup);
	const uint8_t *cursor = &prefix;
	size_t left = 1;
	uint64_t address = 0x1000;
	bool decoded = cs_disasm_iter(handle, &cursor, &left, &address, insn);
	success &= check(decoded == (result == 1), "skipdata callback result");
	success &= check(state.calls == 1 && state.observed,
			 "skipdata callback sees the selected detail state");
	success &= check(insn->detail == original,
			 "skipdata restores the original detail pointer");
	success &= check(cursor == &prefix + decoded && left == 1 - decoded &&
				 address == 0x1000 + decoded,
			 "skipdata updates cursors only on success");
	if (original && !detail)
		success &= check(memcmp(original, &before, sizeof(before)) == 0,
				 "skipdata leaves hidden detail unchanged");
	success &= check(cs_errno(handle) == CS_ERR_OK, "skipdata error state");
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
	const uint8_t truncated[] = { 0x0f, 0xc4, 0xc5 };
	for (unsigned p = 0; p < sizeof(truncated); ++p)
		for (unsigned allocated = 0; allocated < 2; ++allocated)
			for (unsigned detail = 0; detail < 2; ++detail)
				for (unsigned text = 0; text < 2; ++text)
					for (unsigned replace = 0; replace < 3;
					     ++replace)
						for (unsigned result = 0;
						     result < 3; ++result)
							success &= test_skipdata_detail(
								allocated,
								detail, text,
								replace, result,
								truncated[p]);
	return success ? 0 : 1;
}

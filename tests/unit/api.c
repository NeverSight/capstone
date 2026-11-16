// Copyright © 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: BSD-3

#include "../../include/capstone/capstone.h"
#include "unit_test.h"
#include <stdio.h>
#include <string.h>

static bool test_cs_mem_setup_fail()
{
	printf("Test test_cs_mem_setup_fail\n");
	cs_opt_mem mem = { .malloc = malloc,
			   .calloc = calloc,
			   .realloc = realloc,
			   .free = free,
			   .vsnprintf = NULL };
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.vsnprintf = vsnprintf;
	mem.malloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.malloc = malloc;
	mem.calloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.calloc = calloc;
	mem.realloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.realloc = realloc;
	mem.free = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);

	mem.free = free;
	CHECK_INT_EQUAL_RET_FALSE(
		(size_t)cs_option(0, CS_OPT_MEM, (size_t)&mem), CS_ERR_OK);

	return true;
}

static void *nonzero_malloc(size_t bytes)
{
	void *p = malloc(bytes);
	if (p)
		memset(p, 1, bytes);
	return p;
}

static bool test_iterator_allocation(void)
{
	const bool x86 = cs_support(CS_ARCH_X86);
	if (!x86 && !cs_support(CS_ARCH_ARM))
		return true;
	cs_opt_mem mem = { nonzero_malloc, calloc, realloc, free, vsnprintf };
	if (cs_option(0, CS_OPT_MEM, (size_t)&mem) != CS_ERR_OK)
		return false;
	csh handle = 0;
	bool ok = cs_open(x86 ? CS_ARCH_X86 : CS_ARCH_ARM,
			  x86 ? CS_MODE_64 : CS_MODE_ARM, &handle) == CS_ERR_OK;
	for (unsigned i = 0; ok && i < 2; ++i) {
		ok = cs_option(handle, CS_OPT_DETAIL,
			       i ? CS_OPT_ON : CS_OPT_OFF) == CS_ERR_OK;
		if (!ok)
			break;
		cs_insn *insn = cs_malloc(handle);
		ok = insn && !insn->alias_id && !insn->is_alias &&
		     !insn->usesAliasDetails && !insn->illegal;
		if (insn)
			cs_free(insn, 1);
	}
	if (handle)
		cs_close(&handle);
	mem.malloc = malloc;
	return cs_option(0, CS_OPT_MEM, (size_t)&mem) == CS_ERR_OK && ok;
}

static bool test_iterator_results(void)
{
	static const struct {
		cs_arch arch;
		cs_mode mode;
		uint8_t bytes[9];
		size_t valid, invalid, skip;
	} cases[] = {
		{ CS_ARCH_X86,
		  CS_MODE_64,
		  { 0xe9, 0, 0, 0, 0, 0x4b, 0xff, 0xff, 0xff },
		  5,
		  4,
		  1 },
		{ CS_ARCH_X86,
		  CS_MODE_32,
		  { 0xe9, 0, 0, 0, 0, 0xff, 0xff },
		  5,
		  2,
		  1 },
		{ CS_ARCH_ARM,
		  CS_MODE_ARM,
		  { 0, 0, 0xa0, 0xe1, 0, 0, 0xa0 },
		  4,
		  3,
		  0 },
		{ CS_ARCH_ARM, CS_MODE_THUMB, { 0, 0xbf, 0 }, 2, 1, 0 },
		{ CS_ARCH_AARCH64,
		  CS_MODE_ARM,
		  { 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03 },
		  4,
		  3,
		  0 },
		{ CS_ARCH_MIPS,
		  CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN,
		  { 0, 0, 0, 0, 0, 0, 0 },
		  4,
		  3,
		  0 },
	};
	/* Vary the low byte: a saved RAX must never replace the boolean result. */
	static const uint64_t addresses[] = { 0x1000, 0x1001, 0x10fa,
					      UINT64_MAX - 4 };
	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
		if (!cs_support(cases[c].arch))
			continue;
		csh handle = 0;
		if (cs_open(cases[c].arch, cases[c].mode, &handle) != CS_ERR_OK)
			return false;
		bool ok = true;
		for (unsigned options = 0; ok && options < 8; ++options) {
			ok = cs_option(handle, CS_OPT_TEXT,
				       options & 1 ? CS_OPT_ON : CS_OPT_OFF) ==
				     CS_ERR_OK &&
			     cs_option(handle, CS_OPT_DETAIL,
				       options & 2 ? CS_OPT_ON : CS_OPT_OFF) ==
				     CS_ERR_OK &&
			     cs_option(handle, CS_OPT_SKIPDATA,
				       options & 4 ? CS_OPT_ON : CS_OPT_OFF) ==
				     CS_ERR_OK;
			cs_insn *insn = ok ? cs_malloc(handle) : NULL;
			ok = ok && insn;
			for (size_t a = 0;
			     ok && a < sizeof(addresses) / sizeof(addresses[0]);
			     ++a) {
				const uint8_t *cursor = cases[c].bytes;
				size_t size = cases[c].valid + cases[c].invalid;
				uint64_t address = addresses[a];
				bool decoded = cs_disasm_iter(
					handle, &cursor, &size, &address, insn);
				ok = decoded && insn->size == cases[c].valid &&
				     insn->address == addresses[a] &&
				     memcmp(insn->bytes, cases[c].bytes,
					    cases[c].valid) == 0 &&
				     cursor ==
					     cases[c].bytes + cases[c].valid &&
				     size == cases[c].invalid &&
				     address == addresses[a] + cases[c].valid;
				if (ok) {
					/* Reuse the successful record for an invalid/truncated instruction. */
					decoded = cs_disasm_iter(handle,
								 &cursor, &size,
								 &address,
								 insn);
					size_t skipped =
						options & 4 ? cases[c].skip : 0;
					ok = decoded == (skipped != 0) &&
					     cursor == cases[c].bytes +
							       cases[c].valid +
							       skipped &&
					     size == cases[c].invalid -
							     skipped &&
					     address == addresses[a] +
								cases[c].valid +
								skipped &&
					     (!skipped ||
					      (insn->id == 0 &&
					       insn->size == skipped)) &&
					     cs_errno(handle) == CS_ERR_OK;
				}
				if (!ok)
					fprintf(stderr,
						"Iterator result mismatch: case=%zu options=%u address=%llu\n",
						c, options,
						(unsigned long long)
							addresses[a]);
			}
			cs_free(insn, insn ? 1 : 0);
		}
		cs_close(&handle);
		if (!ok)
			return false;
	}
	return true;
}

int main()
{
	bool result = true;
	result &= test_cs_mem_setup_fail();
	result &= test_iterator_allocation();
	result &= test_iterator_results();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}

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

int main()
{
	bool result = true;
	result &= test_cs_mem_setup_fail();
	result &= test_iterator_allocation();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}

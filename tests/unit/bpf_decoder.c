// SPDX-License-Identifier: BSD-3-Clause

#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned allocations, releases;
static bool deny_allocation;

static void *CAPSTONE_API counted_malloc(size_t size)
{
	++allocations;
	return deny_allocation ? NULL : malloc(size);
}

static void CAPSTONE_API counted_free(void *ptr)
{
	++releases;
	free(ptr);
}

static bool check_record(csh handle, cs_insn *insn, const uint8_t *bytes,
			 size_t size, bool deny, unsigned length)
{
	const uint8_t *next = bytes;
	uint64_t address = 0x1000;
	size_t left = size;
	allocations = releases = 0;
	deny_allocation = deny;
	bool ok = cs_disasm_iter(handle, &next, &left, &address, insn);
	deny_allocation = false;

	if (ok != (length != 0) || next != bytes + length ||
	    left != size - length || address != 0x1000 + length ||
	    allocations != (size >= 8) || releases != (size >= 8 && !deny)) {
		fprintf(stderr, "BPF length %zu, expected %u, allocator calls %u/%u\n",
			size, length, allocations, releases);
		return false;
	}
	return true;
}

int main(void)
{
	cs_opt_mem memory = { counted_malloc, calloc, realloc, counted_free,
			      vsnprintf };
	if (cs_option(0, CS_OPT_MEM, (size_t)&memory) != CS_ERR_OK)
		return 1;

	static const uint8_t load64[16] = { 0x18, 0, 0, 0, 1, 0, 0, 0,
					    0, 0, 0, 0, 2, 0, 0, 0 };
	static const uint8_t move[8] = { 0xb7, 0, 0, 0, 1 };
	static const uint8_t invalid_dest[8] = { 0xb7, 0x0a, 0, 0, 1 };
	static const uint8_t ret[8] = { 0x06 };
	for (unsigned extended = 0; extended < 2; ++extended) {
		csh handle;
		if (cs_open(CS_ARCH_BPF, extended ? CS_MODE_BPF_EXTENDED :
						    CS_MODE_BPF_CLASSIC,
			    &handle) != CS_ERR_OK)
			return 1;
		cs_insn *insn = cs_malloc(handle);
		if (!insn)
			return 1;

		const uint8_t *single = extended ? move : ret;
		bool ok = check_record(handle, insn, single, 8, false, 8) &&
			  check_record(handle, insn, single, 8, true, 0);
		for (size_t n = 0; n < 8 && ok; ++n)
			ok = check_record(handle, insn, single, n, false, 0);
		if (extended) {
			for (size_t n = 8; n < 16 && ok; ++n)
				ok = check_record(handle, insn, load64, n, false, 0);
			ok = ok && check_record(handle, insn, load64, 16, false, 16) &&
			     check_record(handle, insn, load64, 16, true, 0) &&
			     check_record(handle, insn, invalid_dest, 8, false, 0);
		}
		cs_free(insn, 1);
		cs_close(&handle);
		if (!ok)
			return 1;
	}
	return 0;
}

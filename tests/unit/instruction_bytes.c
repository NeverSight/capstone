/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../cs_disasm_internal.h"
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

static void release_region(uint8_t *region, size_t size)
{
#ifdef _WIN32
	(void)size;
	VirtualFree(region, 0, MEM_RELEASE);
#else
	munmap(region, size);
#endif
}

static uint8_t *guarded_region(size_t readable, size_t page_size)
{
#ifdef _WIN32
	uint8_t *region = VirtualAlloc(NULL, readable + page_size,
				       MEM_RESERVE | MEM_COMMIT,
				       PAGE_READWRITE);
	if (!region)
		return NULL;
	DWORD previous;
	if (!VirtualProtect(region + readable, page_size, PAGE_NOACCESS,
			    &previous)) {
		release_region(region, readable + page_size);
		return NULL;
	}
#else
	uint8_t *region = mmap(NULL, readable + page_size,
			       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
			       -1, 0);
	if (region == MAP_FAILED)
		return NULL;
	if (mprotect(region + readable, page_size, PROT_NONE)) {
		release_region(region, readable + page_size);
		return NULL;
	}
#endif
	return region;
}

static bool check_copies(uint8_t *input, size_t input_size, cs_insn *actual)
{
	unsigned checks = 0;
	for (unsigned seed = 0; seed < 4; ++seed) {
		for (size_t i = 0; i < input_size; ++i)
			input[i] = (uint8_t)(i * 13 + seed * 71);
		for (size_t length = 0; length <= UINT16_MAX; ++length) {
			for (unsigned short_insn = 0; short_insn < 2;
			     ++short_insn) {
				if (short_insn && length > 15)
					continue;
				for (size_t padding = 0; padding < 16;
				     ++padding) {
					const uint8_t *code = input +
							      input_size -
							      padding - length;
					cs_insn expected;
					memset(&expected, 0xa5,
					       sizeof(expected));
					memset(actual, 0xa5, sizeof(*actual));
					expected.size = (uint16_t)length;
					actual->size = (uint16_t)length;
					size_t count =
						length < sizeof(actual->bytes) ?
							length :
							sizeof(actual->bytes);
					for (size_t i = 0; i < count; ++i)
						expected.bytes[i] =
							code[length - count + i];
					uint16_t copied = copy_insn_bytes(
						actual, code, short_insn != 0);
					if (copied != count ||
					    memcmp(actual, &expected,
						   sizeof(expected))) {
						fprintf(stderr,
							"Instruction copy differs: length=%zu short=%u padding=%zu seed=%u\n",
							length, short_insn,
							padding, seed);
						return false;
					}
					++checks;
				}
			}
		}
	}
	printf("Instruction byte copy: %u guarded comparisons passed\n",
	       checks);
	return true;
}

int main(void)
{
	size_t page_size;
#ifdef _WIN32
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	page_size = info.dwPageSize;
#else
	long native_page_size = sysconf(_SC_PAGESIZE);
	if (native_page_size <= 0)
		return 1;
	page_size = (size_t)native_page_size;
#endif
	size_t input_size =
		((UINT16_MAX + 15 + page_size - 1) / page_size) * page_size;
	uint8_t *input = guarded_region(input_size, page_size);
	if (!input)
		return 1;
	uint8_t *output = guarded_region(page_size, page_size);
	if (!output) {
		release_region(input, input_size + page_size);
		return 1;
	}
	cs_insn *actual = (cs_insn *)(output + page_size - sizeof(cs_insn));
	bool success = check_copies(input, input_size, actual);
	release_region(input, input_size + page_size);
	release_region(output, 2 * page_size);
	return success ? 0 : 1;
}

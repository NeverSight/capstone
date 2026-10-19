/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "x86 buffer bounds: %s\n", message);
	return condition;
}

int main(void)
{
	static const struct {
		cs_mode mode;
		uint8_t bytes[15];
		size_t size;
		unsigned int id;
		int64_t value;
		bool memory;
	} cases[] = {
		{ CS_MODE_16,
		  { 0xb8, 0x34, 0x12 },
		  3,
		  X86_INS_MOV,
		  0x1234,
		  false },
		{ CS_MODE_32,
		  { 0xb8, 0x78, 0x56, 0x34, 0x12 },
		  5,
		  X86_INS_MOV,
		  0x12345678,
		  false },
		{ CS_MODE_64,
		  { 0x48, 0xb8, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34,
		    0x12 },
		  10,
		  X86_INS_MOVABS,
		  INT64_C(0x123456789abcdef0),
		  false },
		{ CS_MODE_64,
		  { 0x48, 0x8b, 0x84, 0x8d, 0x78, 0x56, 0x34, 0x12 },
		  8,
		  X86_INS_MOV,
		  0x12345678,
		  true },
	};
	static const uint64_t addresses[] = { 0x1000, UINT64_MAX - 2,
					      UINT64_MAX };
	uint8_t *pages;
	size_t page_size, i, j, n;
	bool success = true;
#ifdef _WIN32
	SYSTEM_INFO system_info;
	DWORD old_protection;
	GetSystemInfo(&system_info);
	page_size = system_info.dwPageSize;
	pages = VirtualAlloc(NULL, 2 * page_size, MEM_RESERVE | MEM_COMMIT,
			     PAGE_READWRITE);
	if (!check(pages != NULL, "allocate guard pages"))
		return 1;
	if (!VirtualProtect(pages + page_size, page_size, PAGE_NOACCESS,
			    &old_protection)) {
		VirtualFree(pages, 0, MEM_RELEASE);
		return 1;
	}
#else
	long native_page_size = sysconf(_SC_PAGESIZE);
	if (!check(native_page_size > 0, "query page size"))
		return 1;
	page_size = (size_t)native_page_size;
	pages = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANON, -1, 0);
	if (!check(pages != MAP_FAILED, "allocate guard pages"))
		return 1;
	if (mprotect(pages + page_size, page_size, PROT_NONE)) {
		munmap(pages, 2 * page_size);
		return 1;
	}
#endif
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		csh handle;
		cs_insn *insn;
		if (!check(cs_open(CS_ARCH_X86, cases[i].mode, &handle) ==
				   CS_ERR_OK,
			   "open decoder")) {
			success = false;
			break;
		}
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		insn = cs_malloc(handle);
		if (!check(insn != NULL, "allocate instruction")) {
			cs_close(&handle);
			success = false;
			break;
		}
		for (j = 0; j < sizeof(addresses) / sizeof(addresses[0]); ++j) {
			for (n = 0; n <= cases[i].size; ++n) {
				uint8_t *start = pages + page_size - n;
				const uint8_t *cursor = start;
				size_t left = n;
				uint64_t address = addresses[j];
				bool decoded;
				memcpy(start, cases[i].bytes, n);
				decoded = cs_disasm_iter(handle, &cursor, &left,
							 &address, insn);
				if (n < cases[i].size) {
					success &= check(
						!decoded && cursor == start &&
							left == n &&
							address == addresses[j],
						"truncation must not consume input");
					continue;
				}
				success &= check(
					decoded && left == 0 &&
						cursor == start + n &&
						address == addresses[j] + n,
					"complete instruction across address wrap");
				if (!decoded)
					continue;
				success &= check(
					insn->id == cases[i].id &&
						insn->size == n &&
						insn->address == addresses[j] &&
						memcmp(insn->bytes, start, n) ==
							0,
					"instruction identity and extent");
				success &=
					check(insn->detail->x86.op_count == 2,
					      "two explicit operands");
				const cs_x86_op *op =
					&insn->detail->x86.operands[1];
				success &=
					cases[i].memory ?
						check(op->type == X86_OP_MEM &&
							      op->mem.disp ==
								      cases[i].value &&
							      op->mem.base ==
								      X86_REG_RBP &&
							      op->mem.index ==
								      X86_REG_RCX &&
							      op->mem.scale ==
								      4,
						      "bounded SIB and displacement") :
						check(op->type == X86_OP_IMM &&
							      op->imm ==
								      cases[i].value,
						      "bounded little-endian immediate");
			}
		}
		cs_free(insn, 1);
		cs_close(&handle);
	}
#ifdef _WIN32
	VirtualFree(pages, 0, MEM_RELEASE);
#else
	munmap(pages, 2 * page_size);
#endif
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>
#include "../../arch/X86/X86ScanAdapter.h"

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

static bool check_call_targets(uint8_t *end)
{
	static const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64,
					 CS_MODE_64 | CS_MODE_X86_AMD };
	bool success = true;
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
		csh handle;
		if (cs_open(CS_ARCH_X86, modes[m], &handle) != CS_ERR_OK)
			return false;
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_insn *insn = cs_malloc(handle);
		if (!insn) {
			cs_close(&handle);
			return false;
		}
		for (size_t prefixes = 0; prefixes <= 12; ++prefixes) {
			uint8_t bytes[17];
			memset(bytes, 0x66, prefixes);
			bytes[prefixes] = 0xe8;
			memset(bytes + prefixes + 1, 0xff, 4);
			for (size_t n = 0; n <= prefixes + 5; ++n) {
				uint8_t *start = end - n;
				memcpy(start, bytes, n);
				uint64_t target = 42, expected = 42;
				uint16_t length = X86_scanCallTarget(
					handle, start, n, UINT64_MAX - 1,
					&target);
				const uint8_t *cursor = start;
				size_t left = n;
				uint64_t address = UINT64_MAX - 1;
				uint16_t expected_length = 0;
				if (cs_disasm_iter(handle, &cursor, &left,
						   &address, insn)) {
					expected_length = insn->size;
					expected = insn->detail->x86.operands[0]
							   .imm;
				}
				success &= check(length == expected_length &&
							 target == expected,
						 "bounded CALL target query");
			}
		}
		cs_free(insn, 1);
		cs_close(&handle);
	}
	return success;
}

static bool check_short_copy(csh handle, cs_insn *iter, uint8_t *end,
			     size_t length)
{
	uint8_t *start = end - length;
	const uint8_t *cursor = start;
	size_t left = length;
	uint64_t address = UINT64_MAX - 7;
	cs_insn *batch = NULL;

	memset(start, 0x2e, length);
	start[length - 1] = 0x90;
	memset(iter->bytes, 0xa5, sizeof(iter->bytes));
	bool decoded = cs_disasm_iter(handle, &cursor, &left, &address, iter);
	size_t count =
		cs_disasm(handle, start, length, UINT64_MAX - 7, 1, &batch);
	bool ok = decoded && count == 1;
	if (ok) {
		ok = iter->id == X86_INS_NOP && batch->id == X86_INS_NOP &&
		     iter->size == length && batch->size == length &&
		     memcmp(iter->bytes, start, length) == 0 &&
		     memcmp(batch->bytes, start, length) == 0 &&
		     cursor == end && left == 0 &&
		     address == UINT64_MAX - 7 + length;
		for (size_t i = length; i < sizeof(iter->bytes); ++i)
			ok &= iter->bytes[i] == 0xa5;
	}
	cs_free(batch, count);
	/* Removing the opcode leaves only prefixes at the guard page. */
	start[length - 1] = 0x2e;
	cursor = start;
	left = length;
	address = 0x1000;
	ok &= !cs_disasm_iter(handle, &cursor, &left, &address, iter) &&
	      cursor == start && left == length && address == 0x1000;
	if (!ok)
		fprintf(stderr, "x86 short-copy bounds: length=%zu\n", length);
	return ok;
}

static bool check_short_copies(uint8_t *end)
{
	static const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	bool success = true;

	for (size_t mode = 0; mode < sizeof(modes) / sizeof(modes[0]); ++mode) {
		csh handle;
		if (!check(cs_open(CS_ARCH_X86, modes[mode], &handle) ==
				   CS_ERR_OK,
			   "open short-copy decoder"))
			return false;
		for (unsigned text = 0; text != 2; ++text) {
			cs_option(handle, CS_OPT_TEXT,
				  text ? CS_OPT_ON : CS_OPT_OFF);
			for (unsigned detail = 0; detail != 2; ++detail) {
				cs_option(handle, CS_OPT_DETAIL,
					  detail ? CS_OPT_ON : CS_OPT_OFF);
				cs_insn *iter = cs_malloc(handle);
				if (!check(iter != NULL,
					   "allocate short-copy instruction")) {
					cs_close(&handle);
					return false;
				}
				for (size_t length = 1; length <= 15; ++length)
					success &= check_short_copy(
						handle, iter, end, length);
				cs_free(iter, 1);
			}
		}
		cs_close(&handle);
	}
	return success;
}

static bool check_escape(csh handle, cs_insn *iter, uint8_t *end,
			 const uint8_t *code, size_t size, unsigned id,
			 size_t instruction_size, bool scan)
{
	bool ok = true;
	for (size_t n = 0; n <= size; ++n) {
		uint8_t *start = end - n;
		const uint8_t *cursor = start;
		size_t left = n;
		uint64_t address = UINT64_MAX - 2;
		cs_insn *batch = NULL;
		bool expected = instruction_size != 0 && n >= instruction_size;
		memcpy(start, code, n);
		bool decoded =
			cs_disasm_iter(handle, &cursor, &left, &address, iter);
		size_t count =
			cs_disasm(handle, start, n, UINT64_MAX - 2, 1, &batch);
		if (scan) {
			uint32_t output[2] = { UINT32_MAX, UINT32_MAX };
			X86ScanBatchResult scanned = X86_scanBatch(
				handle, start, n, UINT64_MAX - 2, output, 1);
			ok &= scanned.count == (expected ? 1 : 0) &&
			      scanned.bytes ==
				      (expected ? instruction_size : 0) &&
			      output[0] ==
				      (expected ? (id << 8) | instruction_size :
						  UINT32_MAX) &&
			      output[1] == UINT32_MAX;
		}
		ok &= decoded == expected && count == (expected ? 1 : 0);
		if (decoded && count == 1) {
			ok &= iter->id == id && batch->id == id &&
			      iter->size == instruction_size &&
			      batch->size == instruction_size &&
			      memcmp(iter->bytes, code, instruction_size) ==
				      0 &&
			      memcmp(batch->bytes, code, instruction_size) ==
				      0 &&
			      cursor == start + instruction_size &&
			      left == n - instruction_size &&
			      address == UINT64_MAX - 2 + instruction_size;
			if (iter->detail && id == X86_INS_VCMPSS)
				ok &= memcmp(iter->detail->x86.opcode, code,
					     4) == 0 &&
				      memcmp(batch->detail->x86.opcode, code,
					     4) == 0;
		} else if (!decoded) {
			ok &= cursor == start && left == n &&
			      address == UINT64_MAX - 2;
		}
		cs_free(batch, count);
	}
	if (!ok)
		fprintf(stderr, "x86 escape bounds: id=%u size=%zu\n", id,
			size);
	return ok;
}

static bool check_escape_boundaries(uint8_t *end)
{
	static const struct {
		cs_mode mode;
		uint8_t code[8];
		size_t size;
		unsigned id;
		size_t instruction_size;
	} cases[] = {
		/* Ordinary terminals must retain checked opcode, addressing and
		 * immediate reads, including invalid branches of a ModR/M group. */
		{ CS_MODE_64, { 0xc3 }, 1, X86_INS_RET, 1 },
		{ CS_MODE_64, { 0x40, 0x88, 0xe0 }, 3, X86_INS_MOV, 3 },
		{ CS_MODE_64,
		  { 0x48, 0x83, 0x44, 0x24, 0x7f, 0x01 },
		  6,
		  X86_INS_ADD,
		  6 },
		{ CS_MODE_32,
		  { 0xb8, 0x44, 0x33, 0x22, 0x11 },
		  5,
		  X86_INS_MOV,
		  5 },
		{ CS_MODE_32, { 0xfe, 0xf8 }, 2, X86_INS_INVALID, 0 },
		{ CS_MODE_16, { 0x83, 0x46, 0x7f, 0x01 }, 4, X86_INS_ADD, 4 },
		{ CS_MODE_16, { 0xe8, 0x01, 0x00, 0x90 }, 4, X86_INS_CALL, 3 },
		/* Scan and raw readers share SIB/no-base, relative and 16-bit
		 * displacement boundaries, including every incomplete value. */
		{ CS_MODE_64,
		  { 0x49, 0x8b, 0x04, 0x25, 0x80, 0xff, 0xff, 0xff },
		  8,
		  X86_INS_MOV,
		  8 },
		{ CS_MODE_64,
		  { 0x48, 0x8b, 0x05, 0x80, 0xff, 0xff, 0xff },
		  7,
		  X86_INS_MOV,
		  7 },
		{ CS_MODE_32,
		  { 0x8b, 0x84, 0x8d, 0x80, 0xff, 0xff, 0xff },
		  7,
		  X86_INS_MOV,
		  7 },
		{ CS_MODE_16, { 0x8b, 0x06, 0x80, 0xff }, 4, X86_INS_MOV, 4 },
		{ CS_MODE_16, { 0x8b, 0x86, 0x80, 0xff }, 4, X86_INS_MOV, 4 },
		{ CS_MODE_64, { 0x48, 0x8d, 0xc0 }, 3, X86_INS_INVALID, 0 },
		{ CS_MODE_32, { 0xc8, 0x34, 0x12, 0x08 }, 4, X86_INS_ENTER, 4 },
		/* UD1's runtime operands and unequal 16-bit lookup read policies
		 * remain on the generic path, including every truncation. */
		{ CS_MODE_64, { 0x0f, 0xb9, 0xc0 }, 3, X86_INS_UD1, 3 },
		{ CS_MODE_16, { 0x0f, 0x6c, 0xc0 }, 3, X86_INS_INVALID, 0 },
#ifndef CAPSTONE_X86_REDUCE
		{ CS_MODE_16, { 0x0f, 0x53, 0xc0 }, 3, X86_INS_RCPPS, 3 },
#endif
		{ CS_MODE_64, { 0x0f, 0xa2 }, 2, X86_INS_CPUID, 2 },
		{ CS_MODE_64, { 0x0f, 0x01, 0xc6 }, 3, X86_INS_WRMSRNS, 3 },
		{ CS_MODE_64, { 0xf3, 0x0f, 0x01, 0xee }, 4, X86_INS_CLUI, 4 },
		{ CS_MODE_64,
		  { 0xf3, 0x0f, 0xc7, 0xf0 },
		  4,
		  X86_INS_SENDUIPI,
		  4 },
		{ CS_MODE_64, { 0xf2, 0x0f, 0x00, 0xf0 }, 4, X86_INS_LKGS, 4 },
		{ CS_MODE_64,
		  { 0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0x01 },
		  6,
		  X86_INS_HRESET,
		  6 },
		{ CS_MODE_64,
		  { 0x64, 0x0f, 0x38, 0xf6, 0x00 },
		  5,
		  X86_INS_WRSSD,
		  5 },
		{ CS_MODE_64, { 0xd5, 0x00, 0x90 }, 3, X86_INS_NOP, 3 },
		{ CS_MODE_64,
		  { 0x62, 0xf4, 0x7c, 0x08, 0x01, 0xc1 },
		  6,
		  X86_INS_ADD,
		  6 },
		{ CS_MODE_64,
		  { 0xc4, 0xe2, 0x7b, 0x49, 0xf0 },
		  5,
		  X86_INS_TILEZERO,
		  5 },
		{ CS_MODE_32, { 0xc4, 0x07 }, 2, X86_INS_LES, 2 },
		{ CS_MODE_32, { 0xc4, 0x21 }, 2, X86_INS_LES, 2 },
		{ CS_MODE_16, { 0xc4, 0x21 }, 2, X86_INS_LES, 2 },
		{ CS_MODE_16, { 0x62, 0x07 }, 2, X86_INS_BOUND, 2 },
		{ CS_MODE_32,
		  { 0x62, 0x02, 0x05, 0x60, 0xcb, 0xc0, 0x90, 0x90 },
		  8,
		  X86_INS_BOUND,
		  2 },
		/* Trailing escapes must not absorb an earlier legacy INC/DEC. */
		{ CS_MODE_32,
		  { 0x40, 0x62, 0xf4, 0x7c, 0x08, 0x01, 0xc1 },
		  7,
		  X86_INS_INC,
		  1 },
		{ CS_MODE_16, { 0x48, 0xd5, 0x00, 0x90 }, 4, X86_INS_DEC, 1 },
#ifndef CAPSTONE_X86_REDUCE
		/* Scalar LLIG and APX addressing normalize different EVEX bytes.
		 * Their raw prefix must survive both batch and iterator decoding. */
		{ CS_MODE_64,
		  { 0x62, 0xf1, 0x6e, 0x28, 0xc2, 0xcb, 0x20 },
		  7,
		  X86_INS_VCMPSS,
		  7 },
		{ CS_MODE_64,
		  { 0x62, 0xf9, 0x6e, 0x28, 0xc2, 0x0b, 0x20 },
		  7,
		  X86_INS_VCMPSS,
		  7 },
		{ CS_MODE_64,
		  { 0x62, 0xf1, 0x6e, 0x68, 0xc2, 0xcb, 0x00 },
		  7,
		  X86_INS_INVALID,
		  0 },
		{ CS_MODE_64, { 0xc5, 0xf8, 0x77 }, 3, X86_INS_VZEROUPPER, 3 },
		{ CS_MODE_64,
		  { 0xc4, 0xe1, 0x74, 0x58, 0xc2 },
		  5,
		  X86_INS_VADDPS,
		  5 },
		{ CS_MODE_64,
		  { 0x62, 0xf1, 0x7c, 0x08, 0x58, 0xc2 },
		  6,
		  X86_INS_VADDPS,
		  6 },
#endif
		{ CS_MODE_64,
		  { 0x66, 0xc4, 0xe1, 0x74, 0x58, 0xc2 },
		  6,
		  X86_INS_INVALID,
		  0 },
		{ CS_MODE_64,
		  { 0xf3, 0xc5, 0xf8, 0x77 },
		  4,
		  X86_INS_INVALID,
		  0 },
	};
	bool ok = true;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		csh handle;
		if (cs_open(CS_ARCH_X86, cases[i].mode, &handle) != CS_ERR_OK)
			return false;
		for (unsigned options = 0; options != 4; ++options) {
			cs_option(handle, CS_OPT_TEXT,
				  options & 1 ? CS_OPT_ON : CS_OPT_OFF);
			cs_option(handle, CS_OPT_DETAIL,
				  options & 2 ? CS_OPT_ON : CS_OPT_OFF);
			cs_insn *iter = cs_malloc(handle);
			if (!iter) {
				cs_close(&handle);
				return false;
			}
			ok &= check_escape(handle, iter, end, cases[i].code,
					   cases[i].size, cases[i].id,
					   cases[i].instruction_size,
					   options == 0);
			cs_free(iter, 1);
		}
		cs_close(&handle);
	}
	return ok;
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
	success &= check_short_copies(pages + page_size);
	success &= check_escape_boundaries(pages + page_size);
	success &= check_call_targets(pages + page_size);
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

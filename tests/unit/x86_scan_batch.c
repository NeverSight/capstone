/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <string.h>
#include "../../arch/X86/X86ScanAdapter.h"

#define CHECK(condition) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "line %u: %s\n", __LINE__, \
				#condition); \
			return false; \
		} \
	} while (0)

static bool compare(csh handle, cs_insn *insn, const uint8_t *code, size_t size,
		    size_t capacity)
{
	uint32_t output[66];
	for (size_t i = 0; i < 66; ++i)
		output[i] = UINT32_C(0xdeadbeef);
	const uint64_t start = UINT64_MAX - 7;
	X86ScanBatchResult batch =
		X86_scanBatch(handle, code, size, start, output, capacity);
	const uint8_t *cursor = code;
	size_t left = size, count = 0;
	uint64_t address = start;
	while (count < capacity &&
	       cs_disasm_iter(handle, &cursor, &left, &address, insn)) {
		CHECK(count < batch.count);
		CHECK(output[count] == ((insn->id << 8) | insn->size));
		++count;
	}
	CHECK(batch.count == count && batch.bytes == size - left);
	for (size_t i = count; i < 66; ++i)
		CHECK(output[i] == UINT32_C(0xdeadbeef));
	return true;
}

static bool check(void)
{
	static const uint8_t code[] = {
		0x90, 0xc3, 0x66, 0x48, 0xd9, 0x30, 0x48, 0x83, 0x44, 0x24,
		0x7f, 0x01, 0x0f, 0x1a, 0x00, 0xc4, 0xe2, 0x79, 0x98, 0xc1,
		0xc5, 0xf8, 0xc2, 0xc1, 0x03, 0xc8, 0x34, 0x12, 0x08, 0xfe,
		0xf8, 0x0f, 0x38, 0xfc, 0x00, 0xc4, 0xe2, 0x79, 0xe0, 0x00,
		0x62, 0xf1, 0x7c, 0x48, 0x28, 0x00, 0xf0, 0x90, 0x90,
		/* Repeated size/segment prefixes and REX.B's XCHG repair. */
		0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x49, 0x90, 0x48, 0x66, 0x90, 0x65, 0x66, 0x67, 0x8b,
		0x44, 0x24, 0x08,
		/* Address-size-dependent MOFFS and generic relative-size repairs. */
		0x66, 0x67, 0xa1, 0x34, 0x12, 0x00, 0x00, 0x66, 0x48, 0xa3,
		0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0xe8,
		0x00, 0x00, 0x00, 0x00, 0x66, 0x48, 0xc3
	};
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	const size_t capacities[] = { 0, 1, 2, 3, 16, 64 };
	uint32_t state = UINT32_C(0x9e3779b9);
	for (size_t m = 0; m < 3; ++m) {
		csh handle = 0;
		CHECK(cs_open(CS_ARCH_X86, modes[m], &handle) == CS_ERR_OK);
		CHECK(cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF) == CS_ERR_OK);
		cs_insn *insn = cs_malloc(handle);
		CHECK(insn);
		for (size_t offset = 0; offset < sizeof(code); ++offset)
			for (size_t size = 0; size <= sizeof(code) - offset;
			     ++size)
				for (size_t c = 0; c < 6; ++c)
					CHECK(compare(handle, insn,
						      code + offset, size,
						      capacities[c]));
		for (size_t i = 0; i < 20000; ++i) {
			uint8_t bytes[32];
			for (size_t j = 0; j < sizeof(bytes); ++j) {
				state ^= state << 13;
				state ^= state >> 17;
				state ^= state << 5;
				bytes[j] = (uint8_t)state;
			}
			CHECK(compare(handle, insn, bytes,
				      i % sizeof(bytes) + 1,
				      capacities[i % 6]));
		}
		uint32_t output = UINT32_C(0xdeadbeef);
		const cs_opt_type options[] = { CS_OPT_TEXT, CS_OPT_DETAIL,
						CS_OPT_SKIPDATA };
		for (size_t i = 0; i < 3; ++i) {
			CHECK(cs_option(handle, options[i], CS_OPT_ON) ==
			      CS_ERR_OK);
			X86ScanBatchResult batch = X86_scanBatch(
				handle, code, sizeof(code), 0, &output, 1);
			CHECK(!batch.count && !batch.bytes &&
			      output == UINT32_C(0xdeadbeef));
			CHECK(cs_option(handle, options[i], CS_OPT_OFF) ==
			      CS_ERR_OK);
		}
		CHECK(!X86_scanBatch(0, code, sizeof(code), 0, &output, 1)
			       .count);
		CHECK(!X86_scanBatch(handle, NULL, 1, 0, &output, 1).count);
		CHECK(!X86_scanBatch(handle, code, 1, 0, NULL, 1).count);
		CHECK(compare(handle, insn, code, sizeof(code), 64));
		cs_free(insn, 1);
		cs_close(&handle);
	}
	if (cs_support(CS_ARCH_ARM)) {
		csh handle;
		uint32_t output = UINT32_C(0xdeadbeef);
		CHECK(cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) == CS_ERR_OK);
		CHECK(cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF) == CS_ERR_OK);
		X86ScanBatchResult batch = X86_scanBatch(
			handle, code, sizeof(code), 0, &output, 1);
		CHECK(!batch.count && !batch.bytes &&
		      output == UINT32_C(0xdeadbeef));
		cs_close(&handle);
	}
	return true;
}

int main(void)
{
	return check() ? 0 : 1;
}

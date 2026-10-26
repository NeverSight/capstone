/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
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

static bool compare(csh query, csh full, cs_insn *insn, const uint8_t *code,
		    size_t size, uint64_t address)
{
	const uint64_t untouched = UINT64_C(0x1122334455667788);
	uint64_t actual = untouched, expected = untouched, next = address;
	const cs_err error = cs_errno(query);
	const uint16_t length =
		X86_scanCallTarget(query, code, size, address, &actual);
	const uint8_t *cursor = code;
	size_t left = size;
	uint16_t expected_length = 0;
	if (cs_disasm_iter(full, &cursor, &left, &next, insn) &&
	    insn->id == X86_INS_CALL && insn->detail->x86.op_count &&
	    insn->detail->x86.operands[0].type == X86_OP_IMM) {
		expected_length = insn->size;
		expected = (uint64_t)insn->detail->x86.operands[0].imm;
	}
	if (length != expected_length || actual != expected) {
		fprintf(stderr,
			"size=%zu address=%" PRIx64
			" length=%u/%u target=%" PRIx64 "/%" PRIx64 " bytes=",
			size, address, length, expected_length, actual,
			expected);
		for (size_t i = 0; i < size; ++i)
			fprintf(stderr, "%02x", code[i]);
		fprintf(stderr, "\n");
		return false;
	}
	CHECK(cs_errno(query) == error);
	return true;
}

static bool check(void)
{
	static const cs_mode modes[] = {
		CS_MODE_16,
		CS_MODE_32,
		CS_MODE_64,
		CS_MODE_16 | CS_MODE_X86_INTEL,
		CS_MODE_32 | CS_MODE_X86_INTEL,
		CS_MODE_64 | CS_MODE_X86_INTEL,
		CS_MODE_16 | CS_MODE_X86_AMD,
		CS_MODE_32 | CS_MODE_X86_AMD,
		CS_MODE_64 | CS_MODE_X86_AMD,
		CS_MODE_16 | CS_MODE_64,
		CS_MODE_32 | CS_MODE_64,
	};
	static const unsigned syntaxes[] = { CS_OPT_SYNTAX_INTEL,
					     CS_OPT_SYNTAX_ATT };
	static const uint8_t prefixes[] = {
		0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x26, 0x2e, 0x36, 0x3e,
		0x64, 0x65, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
		0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	};
	static const uint64_t addresses[] = {
		0,
		0x7fff,
		0xfffe,
		UINT32_MAX - 3,
		UINT32_MAX,
		UINT64_C(0x8000000000000000),
		UINT64_MAX - 3,
		UINT64_MAX,
	};
	static const struct {
		uint8_t bytes[10];
		size_t size;
	} bodies[] = {
		{ { 0xe8, 0, 0, 0, 0 }, 5 },
		{ { 0xe8, 0xff, 0x7f, 0, 0x80 }, 5 },
		{ { 0xe8, 0, 0x80, 0xff, 0x7f }, 5 },
		{ { 0xe8, 0xfb, 0xff, 0xff, 0xff }, 5 },
		{ { 0xff, 0xd0 }, 2 },
		{ { 0xff, 0x15, 0x34, 0x12, 0, 0 }, 6 },
		{ { 0x9a, 0x34, 0x12, 0, 0, 0x78, 0x56 }, 7 },
		{ { 0xe9, 0, 0, 0, 0 }, 5 },
		{ { 0xd5, 0, 0xe8, 0, 0, 0, 0 }, 7 },
		{ { 0xc5, 0xf8, 0xe8, 0xc0 }, 4 },
		{ { 0x62, 0xf1, 0x7c, 0x48, 0xe8, 0xc0 }, 6 },
	};
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
		csh query = 0, full = 0;
		CHECK(cs_open(CS_ARCH_X86, modes[m], &query) == CS_ERR_OK);
		CHECK(cs_open(CS_ARCH_X86, modes[m], &full) == CS_ERR_OK);
		CHECK(cs_option(full, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
		cs_insn *insn = cs_malloc(full);
		CHECK(insn);
		for (size_t syntax = 0; syntax < 2; ++syntax) {
			CHECK(cs_option(full, CS_OPT_SYNTAX,
					syntaxes[syntax]) == CS_ERR_OK);
			CHECK(cs_option(query, CS_OPT_SYNTAX,
					syntaxes[syntax]) == CS_ERR_OK);
			/* Include absent prefixes, every pair, and every truncation. */
			for (size_t p = 0; p <= sizeof(prefixes); ++p)
				for (size_t q = 0; q <= sizeof(prefixes); ++q)
					for (size_t b = 0;
					     b <
					     sizeof(bodies) / sizeof(bodies[0]);
					     ++b) {
						uint8_t code[16];
						size_t size = 0;
						if (p < sizeof(prefixes))
							code[size++] =
								prefixes[p];
						if (q < sizeof(prefixes))
							code[size++] =
								prefixes[q];
						memcpy(code + size,
						       bodies[b].bytes,
						       bodies[b].size);
						size += bodies[b].size;
						for (size_t n = 0; n <= size;
						     ++n)
							CHECK(compare(
								query, full,
								insn, code, n,
								addresses[(p +
									   q + b +
									   n) %
									  8]));
					}
			/* Repeated prefixes reach the architectural 15-byte boundary. */
			for (size_t n = 0; n <= 12; ++n) {
				uint8_t code[17];
				memset(code, 0x66, n);
				memcpy(code + n, bodies[3].bytes,
				       bodies[3].size);
				for (size_t a = 0; a < 8; ++a)
					for (size_t len = 0;
					     len <= n + bodies[3].size; ++len)
						CHECK(compare(query, full, insn,
							      code, len,
							      addresses[a]));
			}
		}
		for (unsigned options = 0; options < 8; ++options) {
			CHECK(cs_option(query, CS_OPT_TEXT,
					options & 1 ? CS_OPT_ON : CS_OPT_OFF) ==
			      CS_ERR_OK);
			CHECK(cs_option(query, CS_OPT_DETAIL,
					options & 2 ? CS_OPT_ON : CS_OPT_OFF) ==
			      CS_ERR_OK);
			CHECK(cs_option(query, CS_OPT_SKIPDATA,
					options & 4 ? CS_OPT_ON : CS_OPT_OFF) ==
			      CS_ERR_OK);
			for (size_t b = 0;
			     b < sizeof(bodies) / sizeof(bodies[0]); ++b)
				CHECK(compare(query, full, insn,
					      bodies[b].bytes, bodies[b].size,
					      UINT64_MAX));
		}
		for (unsigned payload = 0; payload < 256; ++payload) {
			uint8_t code[] = { 0x66, 0xd5, (uint8_t)payload,
					   0xe8, 0xfb, 0xff,
					   0xff, 0xff };
			for (size_t offset = 0; offset <= 1; ++offset)
				for (size_t n = 0; n <= sizeof(code) - offset;
				     ++n)
					CHECK(compare(query, full, insn,
						      code + offset, n,
						      UINT64_MAX - 3));
		}
		uint32_t state = UINT32_C(0x9e3779b9);
		for (unsigned i = 0; i < 20000; ++i) {
			uint8_t code[32];
			for (size_t j = 0; j < sizeof(code); ++j) {
				state ^= state << 13;
				state ^= state >> 17;
				state ^= state << 5;
				code[j] = (uint8_t)state;
			}
			CHECK(compare(query, full, insn, code, i % sizeof(code),
				      addresses[i % 8]));
		}
		cs_free(insn, 1);
		cs_close(&full);
		cs_close(&query);
	}

	csh handle = 0;
	CHECK(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK);
	uint64_t target = 0;
	CHECK(X86_scanCallTarget(handle, bodies[3].bytes, 5, 0x1000, &target) ==
	      5);
	CHECK(target == 0x1000);
	CHECK(cs_option(handle, CS_OPT_MODE, CS_MODE_16) == CS_ERR_OK);
	CHECK(X86_scanCallTarget(handle, bodies[0].bytes, 5, 0x1000, &target) ==
	      3);
	CHECK(target == 0x1003);
	CHECK(!X86_scanCallTarget(0, bodies[0].bytes, 5, 0, &target));
	CHECK(!X86_scanCallTarget(handle, NULL, 5, 0, &target));
	CHECK(!X86_scanCallTarget(handle, bodies[0].bytes, 5, 0, NULL));
	CHECK(target == 0x1003);
	cs_close(&handle);
	return true;
}

int main(void)
{
	return check() ? 0 : 1;
}

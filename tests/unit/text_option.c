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

	// Scans keep the same IDs and boundaries with or without detail.
	for (unsigned detail = 0; detail < 2; ++detail) {
		const uint8_t *code = x86_code;
		size_t size = sizeof(x86_code);
		uint64_t address = 0x1000;
		cs_option(bare, CS_OPT_DETAIL,
			  detail ? CS_OPT_ON : CS_OPT_OFF);
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

static bool same_scan(const cs_insn *a, const cs_insn *b)
{
	return a->id == b->id && a->size == b->size &&
	       a->address == b->address &&
	       memcmp(a->bytes, b->bytes, a->size) == 0 &&
	       a->mnemonic[0] == '\0' && b->mnemonic[0] == '\0' &&
	       a->op_str[0] == '\0' && b->op_str[0] == '\0';
}

/* Detail forces intermediate operand construction even with text disabled. */
static bool check_scan_pair(csh scan, csh detail, const uint8_t *bytes,
			    size_t length, bool valid)
{
	const csh handles[] = { scan, detail };
	cs_insn *batch[2] = { NULL, NULL };
	cs_insn *iter[2] = { NULL, NULL };
	size_t counts[2];
	bool success = true;

	for (unsigned i = 0; i < 2; ++i) {
		const uint8_t *code = bytes;
		size_t remaining = length;
		uint64_t address = 0x1000;
		bool decoded;

		counts[i] = cs_disasm(handles[i], bytes, length, address, 1,
				      &batch[i]);
		success &= check(counts[i] == (valid ? 1 : 0),
				 "scan batch acceptance");
		iter[i] = cs_malloc(handles[i]);
		if (!check(iter[i] != NULL, "allocate scan instruction")) {
			success = false;
			continue;
		}
		decoded = cs_disasm_iter(handles[i], &code, &remaining,
					 &address, iter[i]);
		success &= check(decoded == valid, "scan iterator acceptance");
		if (decoded && counts[i] == 1) {
			success &=
				check(same_scan(iter[i], batch[i]) &&
					      iter[i]->size == length &&
					      code == bytes + length &&
					      remaining == 0 &&
					      address == 0x1000 + length,
				      "scan batch/iterator fields and cursor");
		} else if (!decoded) {
			success &=
				check(code == bytes && remaining == length &&
					      address == 0x1000,
				      "rejected scan leaves cursor unchanged");
		}
	}
	if (valid && counts[0] == 1 && counts[1] == 1)
		success &= check(same_scan(batch[0], batch[1]),
				 "operand validation preserves scan fields");
	for (unsigned i = 0; i < 2; ++i) {
		cs_free(batch[i], counts[i]);
		cs_free(iter[i], 1);
	}
	return success;
}

static bool test_x86_scan_validation(void)
{
	static const struct {
		uint8_t bytes[8];
		size_t length;
		bool valid;
		bool vector;
	} cases[] = {
		/* Direct, split and indexed decisions retain ModR/M consumption. */
		{ { 0x03, 0x00 }, 2, true, false },
		{ { 0x03, 0xc0 }, 2, true, false },
		{ { 0x8d, 0x00 }, 2, true, false },
		{ { 0x80, 0x00, 0x01 }, 3, true, false },
		{ { 0x80, 0xc0, 0x01 }, 3, true, false },
		{ { 0x80, 0xc8, 0x01 }, 3, true, false },
		{ { 0x0f, 0x0f, 0xca, 0xbf }, 4, true, true },
		{ { 0x0f, 0x0f, 0x5c, 0x16, 0x09, 0xbf }, 6, true, true },
		{ { 0x48, 0x8b, 0xc1 }, 3, true, false },
		{ { 0x48, 0x8b, 0x44, 0x88, 0x08 }, 5, true, false },
		{ { 0xd5, 0x7f, 0x8b, 0x44, 0xb7, 0xe0 }, 6, true, false },
		{ { 0x48, 0x8d, 0xc0 }, 3, false, false },
		{ { 0xd5, 0xc0, 0x20, 0xc0 }, 4, false, false },
		{ { 0xd5, 0xc0, 0x21, 0xc0 }, 4, false, false },
		/* Source-owned legacy and EVEX maps share the scan contract. */
		{ { 0xf3, 0x0f, 0x01, 0xee }, 4, true, false },
		{ { 0xf3, 0x0f, 0xc7, 0xf0 }, 4, true, false },
		{ { 0x64, 0x0f, 0x38, 0xf6, 0x00 }, 5, true, false },
		{ { 0xf0, 0xf3, 0x0f, 0x01, 0xee }, 5, false, false },
		{ { 0x0f, 0x38, 0xf6, 0xc0 }, 4, false, false },
		{ { 0x62, 0xf4, 0x7c, 0x08, 0x01, 0xc1 }, 6, true, false },
		{ { 0xc4, 0xe2, 0x69, 0x92, 0x04, 0x88 }, 6, true, true },
		{ { 0xc4, 0xe2, 0x6d, 0x92, 0x04, 0x88 }, 6, true, true },
		{ { 0x62, 0xf2, 0x7d, 0x49, 0x92, 0x04, 0x88 }, 7, true, true },
		{ { 0x62, 0xf2, 0x7d, 0x49, 0xa0, 0x04, 0x80 }, 7, true, true },
		{ { 0xc4, 0xe2, 0x69, 0x92, 0x00 }, 5, false, true },
		{ { 0xc4, 0xe2, 0x79, 0x92, 0x04, 0x88 }, 6, false, true },
		{ { 0x62, 0xf1, 0x7c, 0x88, 0x58, 0xc1 }, 6, false, true },
	};
	csh scan = 0, detail = 0;
	bool success = true;
	const bool reduced = cs_support(CS_SUPPORT_X86_REDUCE);

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &scan) == CS_ERR_OK &&
			   cs_open(CS_ARCH_X86, CS_MODE_64, &detail) ==
				   CS_ERR_OK,
		   "open scan validation handles"))
		return false;
	cs_option(scan, CS_OPT_TEXT, CS_OPT_OFF);
	cs_option(detail, CS_OPT_TEXT, CS_OPT_OFF);
	cs_option(detail, CS_OPT_DETAIL, CS_OPT_ON);
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		if (reduced && cases[i].vector)
			continue;
		success &= check_scan_pair(scan, detail, cases[i].bytes,
					   cases[i].length, cases[i].valid);
		if (cases[i].valid)
			for (size_t length = 0; length < cases[i].length;
			     ++length)
				success &= check_scan_pair(scan, detail,
							   cases[i].bytes,
							   length, false);
	}
	if (!reduced) {
		/* Predicates can change the internal opcode during translation. */
		uint8_t sse[] = { 0xf3, 0x0f, 0xc2, 0xc1, 0 };
		uint8_t vex[] = { 0xc5, 0xf2, 0xc2, 0xc2, 0 };
		for (unsigned immediate = 0; immediate <= UINT8_MAX;
		     ++immediate) {
			sse[sizeof(sse) - 1] = vex[sizeof(vex) - 1] = immediate;
			success &= check_scan_pair(scan, detail, sse,
						   sizeof(sse), true);
			success &= check_scan_pair(scan, detail, vex,
						   sizeof(vex), true);
		}
	}
	cs_close(&scan);
	cs_close(&detail);
	return success;
}

struct scan_transition {
	csh handle;
	unsigned calls;
	bool options_ok;
};

static size_t switch_scan_options(const uint8_t *code, size_t size,
				  size_t offset, void *user_data)
{
	struct scan_transition *state = user_data;
	++state->calls;
	state->options_ok &= size >= offset + 3 && code[offset] == 0x48 &&
			     code[offset + 1] == 0x8d &&
			     code[offset + 2] == 0xc0;
	state->options_ok &=
		cs_option(state->handle, CS_OPT_MODE, CS_MODE_16) == CS_ERR_OK;
	state->options_ok &= cs_option(state->handle, CS_OPT_TEXT, CS_OPT_ON) ==
			     CS_ERR_OK;
	state->options_ok &=
		cs_option(state->handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
	return 3;
}

static bool test_x86_scan_option_transition(void)
{
	/* Invalid LEA invokes skip-data while scanning. The callback changes
	 * bitness and output policy before INC AX and RET on the same handle. */
	static const uint8_t code[] = { 0x48, 0x8d, 0xc0, 0x40, 0xc3 };
	const unsigned ids[] = { 0, X86_INS_INC, X86_INS_RET };
	const uint16_t lengths[] = { 3, 1, 1 };
	bool success = true;
	for (unsigned batch = 0; batch != 2; ++batch) {
		struct scan_transition state = { 0, 0, true };
		if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &state.handle) ==
				   CS_ERR_OK,
			   "open scan transition decoder"))
			return false;
		cs_option(state.handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_insn *iter = cs_malloc(state.handle);
		if (!check(iter != NULL, "allocate retained detail")) {
			cs_close(&state.handle);
			return false;
		}
		cs_detail *saved_detail = iter->detail;
		cs_option(state.handle, CS_OPT_DETAIL, CS_OPT_OFF);
		cs_option(state.handle, CS_OPT_TEXT, CS_OPT_OFF);
		cs_opt_skipdata setup = { ".byte", switch_scan_options,
					  &state };
		cs_option(state.handle, CS_OPT_SKIPDATA_SETUP, (size_t)&setup);
		cs_option(state.handle, CS_OPT_SKIPDATA, CS_OPT_ON);
		cs_insn *instructions = NULL;
		size_t count = 0;
		if (batch) {
			count = cs_disasm(state.handle, code, sizeof(code),
					  UINT64_MAX - 1, 0, &instructions);
			success &= check(count == 3,
					 "batch changes output policy");
		}
		const uint8_t *cursor = code;
		size_t remaining = sizeof(code);
		uint64_t address = UINT64_MAX - 1;
		for (unsigned i = 0; i < 3 && (!batch || i < count); ++i) {
			if (!batch &&
			    !check(cs_disasm_iter(state.handle, &cursor,
						  &remaining, &address, iter),
				   "iterator changes output policy")) {
				success = false;
				break;
			}
			const cs_insn *actual = batch ? &instructions[i] : iter;
			success &= check(
				actual->id == ids[i] &&
					actual->size == lengths[i] &&
					actual->address ==
						(i == 0 ? UINT64_MAX - 1 : i),
				"transition retains IDs, lengths and wrapping addresses");
			if (!batch)
				success &= check(
					iter->detail == saved_detail,
					"callback retains iterator detail ownership");
			if (i == 1)
				success &= check(
					actual->detail &&
						strcmp(actual->mnemonic,
						       "inc") == 0 &&
						strcmp(actual->op_str, "ax") ==
							0,
					"next instruction uses new bitness, text and detail");
		}
		if (!batch)
			success &= check(cursor == code + sizeof(code) &&
						 remaining == 0 && address == 3,
					 "iterator advances across callback");
		success &= check(state.calls == 1 && state.options_ok,
				 "skip-data changes options exactly once");
		cs_free(instructions, count);
		cs_free(iter, 1);
		cs_close(&state.handle);
	}
	return success;
}

static bool test_x86_scan_mode_priority(void)
{
	/* Feature routing uses the 64-bit flag; decoding preserves the existing
	 * 16-before-32-before-64 priority, including the default mode. */
	static const struct {
		cs_mode mode;
		unsigned id;
		uint16_t length;
	} cases[] = {
		{ 0, X86_INS_MOV, 3 },
		{ CS_MODE_16 | CS_MODE_32, X86_INS_DEC, 1 },
		{ CS_MODE_16 | CS_MODE_64, X86_INS_DEC, 1 },
		{ CS_MODE_32 | CS_MODE_64, X86_INS_DEC, 1 },
		{ CS_MODE_16 | CS_MODE_32 | CS_MODE_64, X86_INS_DEC, 1 },
	};
	static const uint8_t opcode[] = { 0x48, 0x8b, 0xc1 };
	static const uint8_t prefixes[] = { 0x66, 0x67 };
	bool success = true;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		for (unsigned prefix_length = 0; prefix_length != 3;
		     ++prefix_length) {
			uint8_t bytes[sizeof(prefixes) + sizeof(opcode)];
			memcpy(bytes, prefixes, prefix_length);
			memcpy(bytes + prefix_length, opcode, sizeof(opcode));
			const size_t length = prefix_length + sizeof(opcode);
			const uint16_t expected_length =
				cases[i].length + prefix_length;
			for (unsigned detail = 0; detail != 2; ++detail) {
				csh handle;
				if (!check(cs_open(CS_ARCH_X86, CS_MODE_64,
						   &handle) == CS_ERR_OK,
					   "open mode-priority decoder"))
					return false;
				success &= check(
					cs_option(handle, CS_OPT_MODE,
						  cases[i].mode) == CS_ERR_OK,
					"select existing mode combination");
				cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF);
				cs_option(handle, CS_OPT_DETAIL,
					  detail ? CS_OPT_ON : CS_OPT_OFF);
				cs_insn *iter = cs_malloc(handle);
				if (!check(iter != NULL,
					   "allocate mode-priority result")) {
					cs_close(&handle);
					return false;
				}
				cs_insn *batch = NULL;
				size_t count = cs_disasm(handle, bytes, length,
							 0x1000, 1, &batch);
				success &= check(
					count == 1 &&
						batch[0].id == cases[i].id &&
						batch[0].size ==
							expected_length,
					"batch preserves bitness priority");
				const uint8_t *cursor = bytes;
				size_t remaining = length;
				uint64_t address = 0x1000;
				bool decoded = cs_disasm_iter(handle, &cursor,
							      &remaining,
							      &address, iter);
				success &= check(
					decoded && iter->id == cases[i].id &&
						iter->size == expected_length &&
						cursor ==
							bytes + expected_length &&
						remaining ==
							length -
								expected_length &&
						address ==
							0x1000 +
								expected_length,
					"iterator preserves bitness priority and cursor");
				if (decoded && count == 1)
					success &= check(
						same_scan(iter, batch),
						"mode-priority output matches");
				cs_free(batch, count);
				cs_free(iter, 1);
				cs_close(&handle);
			}
		}
	}
	return success;
}

static bool test_x86_scan_size_prefixes(void)
{
	static const struct {
		uint8_t bytes[8];
		size_t length;
		bool valid;
	} cases[] = {
		{ { 0x66, 0x55 }, 2, true },
		{ { 0x67, 0x66, 0x8b, 0x5c, 0x24, 0x18 }, 6, true },
		{ { 0x66, 0x67, 0x8b, 0x5c, 0x24, 0x18 }, 6, true },
		{ { 0x67, 0x8b, 0x5c, 0x24, 0x18 }, 5, true },
		{ { 0x66, 0x66, 0xb8, 0x78, 0x56, 0x34, 0x12 }, 7, true },
		{ { 0x67, 0x67, 0x66, 0x8b, 0x5c, 0x24, 0x18 }, 7, true },
		{ { 0x66, 0x0f, 0xb6, 0xc1 }, 4, true },
		/* Address-dependent IDs keep their existing generic repair. */
		{ { 0x67, 0xe3, 0xfe }, 3, true },
		{ { 0x66, 0xa1, 0x34, 0x12 }, 4, true },
		{ { 0x67, 0x66, 0xa1, 0x78, 0x56, 0x34, 0x12 }, 7, true },
		{ { 0x66 }, 1, false },
		{ { 0x67, 0x66, 0x8b, 0x5c, 0x24 }, 5, false },
		{ { 0x66, 0xb8, 0x78, 0x56, 0x34 }, 5, false },
	};
	csh scan = 0, detail = 0;
	if (!check(cs_open(CS_ARCH_X86, CS_MODE_16, &scan) == CS_ERR_OK &&
			   cs_open(CS_ARCH_X86, CS_MODE_16, &detail) ==
				   CS_ERR_OK,
		   "open size-prefix decoders")) {
		if (scan)
			cs_close(&scan);
		return false;
	}
	cs_option(scan, CS_OPT_TEXT, CS_OPT_OFF);
	cs_option(detail, CS_OPT_TEXT, CS_OPT_OFF);
	cs_option(detail, CS_OPT_DETAIL, CS_OPT_ON);
	bool success = true;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		success &= check_scan_pair(scan, detail, cases[i].bytes,
					   cases[i].length, cases[i].valid);
	uint8_t boundary[16];
	memset(boundary, 0x66, sizeof(boundary));
	boundary[14] = 0xc3;
	success &= check_scan_pair(scan, detail, boundary, 15, true);
	boundary[14] = 0x66;
	boundary[15] = 0xc3;
	success &= check_scan_pair(scan, detail, boundary, sizeof(boundary),
				   false);
	cs_close(&scan);
	cs_close(&detail);
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
	bool success = true;

	/* The original text fixture includes SSE, absent from reduced tables. */
	if (!cs_support(CS_SUPPORT_X86_REDUCE))
		success &= test_x86();
	success &= test_x86_scan_validation();
	success &= test_x86_scan_option_transition();
	success &= test_x86_scan_mode_priority();
	success &= test_x86_scan_size_prefixes();
	success &= test_aarch64();
	return success ? 0 : 1;
}

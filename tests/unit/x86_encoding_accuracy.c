/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../arch/X86/X86DisassemblerDecoder.h"
#include "../../arch/X86/X86Disassembler.h"
#include "../../arch/X86/X86Mapping.h"
#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "../../arch/X86/X86GenInstrInfo_reduce.inc"
#else
#include "../../arch/X86/X86GenInstrInfo.inc"
#endif
#ifdef CAPSTONE_X86_REDUCE
#include "../../arch/X86/X86GenDisassemblerTables_reduce.inc"
#else
#include "../../arch/X86/X86GenDisassemblerTables.inc"
#endif

/* The operand readers stop at the first padding entry. Keep this contract
 * checked when the generated tables are updated. */
static bool check_operand_sets(void)
{
	for (size_t set = 0;
	     set < sizeof(x86OperandSets) / sizeof(x86OperandSets[0]); ++set) {
		bool padding = false;
		for (size_t op = 0; op < X86_MAX_OPERANDS; ++op) {
			if (x86OperandSets[set][op].encoding == ENCODING_NONE)
				padding = true;
			else if (padding) {
				fprintf(stderr,
					"operand set %zu has an operand after padding at %zu\n",
					set, op);
				return false;
			}
		}
	}
	return true;
}

/* The raw entry preserves incoming size flags for MOFFS ID selection, even
 * without an encoded prefix. Truncation must retain the same partial read. */
static bool check_inherited_moffs_size(void)
{
	const uint8_t bytes[] = { 0xa1, 0x34, 0x12, 0, 0 };
	const unsigned ids[] = { X86_MOV32ao32, X86_MOV16ao32, X86_MOV32ao16,
				 X86_MOV16ao16 };
	for (unsigned flags = 0; flags != 4; ++flags)
		for (size_t size = 1; size <= sizeof(bytes); ++size) {
			InternalInstruction insn = { 0 };
			insn.hasOpSize = (flags & 1) != 0;
			insn.hasAdSize = (flags & 2) != 0;
			const int status = decodeInstructionScan(
				&insn, bytes, size, CS_MODE_32, NULL, NULL);
			const bool complete = size == sizeof(bytes);
			if ((status == 0) != complete ||
			    insn.instructionID != ids[flags] ||
			    insn.readerCursor != (complete ? 5 : 1) ||
			    insn.immediateOffset != (complete ? 0 : 1) ||
			    insn.immediateSize != (complete ? 0 : 4) ||
			    insn.numImmediatesConsumed != (complete ? 1 : 0) ||
			    insn.consumedDisplacement != complete ||
			    insn.displacementOffset != (complete ? 1 : 0) ||
			    (complete && (insn.displacement != 0x1234 ||
					  insn.displacementSize != 4))) {
				fprintf(stderr, "raw MOFFS flags %u size %zu\n",
					flags, size);
				return false;
			}
		}
	return true;
}

static bool check_internal_scan_mode(void)
{
	const uint8_t bytes[] = { 0x66, 0xb8, 0x34, 0x12, 0x90, 0x90 };
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
		csh handle;
		if (cs_open(CS_ARCH_X86, modes[m], &handle) != CS_ERR_OK)
			return false;
		cs_insn flat = { 0 };
		MCInst insn = { 0 };
		insn.csh = (cs_struct *)(uintptr_t)handle;
		insn.flat_insn = &flat;
		uint16_t size = 0;
		const bool ok = X86_getInstructionScan(handle, bytes,
						       sizeof(bytes), &insn,
						       &size) &&
				size == (modes[m] == CS_MODE_16 ? 6 : 4) &&
				MCInst_getOpcode(&insn) ==
					(modes[m] == CS_MODE_16 ? X86_MOV32ri :
								  X86_MOV16ri);
		cs_close(&handle);
		if (!ok) {
			fprintf(stderr, "internal scan mode %u\n", modes[m]);
			return false;
		}
	}
	return true;
}

/* Cache allocation is optional: every ID and hole must agree with the
 * original binary-search mapping when the cache is unavailable. */
static bool check_id_cache(void)
{
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false;
	cs_struct *arch = (cs_struct *)(uintptr_t)handle;
	uint32_t *cache = arch->x86_insn_lut;
	bool ok = cache != NULL;
	for (unsigned id = 0; id <= arch->x86_insn_lut_max + 1; ++id) {
		cs_insn cached = { 0 }, fallback = { 0 };
		cached.id = fallback.id = UINT32_MAX;
		X86_get_insn_id(arch, &cached, id);
		arch->x86_insn_lut = NULL;
		X86_get_insn_id(arch, &fallback, id);
		arch->x86_insn_lut = cache;
		if (cached.id != fallback.id) {
			fprintf(stderr,
				"ID cache differs from fallback at %u\n", id);
			ok = false;
			break;
		}
	}
	cs_close(&handle);
	return ok;
}

static bool check_instruction_names(void)
{
	static const struct {
		unsigned id;
		const char *name;
	} cases[] = {
		{ X86_INS_ADD, "add" },	  { X86_INS_INC, "inc" },
		{ X86_INS_MOV, "mov" },	  { X86_INS_RDMSR, "rdmsr" },
		{ X86_INS_CLAC, "clac" }, { X86_INS_RDPKRU, "rdpkru" },
	};
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false;
	bool ok = true;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		const char *name = cs_insn_name(handle, cases[i].id);
		if (!name || strcmp(name, cases[i].name)) {
			fprintf(stderr, "instruction %u: expected %s, got %s\n",
				cases[i].id, cases[i].name,
				name ? name : "NULL");
			ok = false;
		}
	}
	cs_close(&handle);
	return ok;
}

static bool same_mapping_result(const cs_insn *a, const cs_insn *b)
{
	if (a->id != b->id || a->address != b->address || a->size != b->size ||
	    memcmp(a->bytes, b->bytes, a->size) ||
	    strcmp(a->mnemonic, b->mnemonic) || strcmp(a->op_str, b->op_str) ||
	    (a->detail != NULL) != (b->detail != NULL))
		return false;
	/* The x86 decoder clears this complete region before populating detail. */
	return !a->detail ||
	       memcmp(a->detail, b->detail,
		      offsetof(cs_detail, x86) + sizeof(cs_x86)) == 0;
}

static bool decode_reference(csh handle, const uint8_t *bytes, size_t size,
			     unsigned id, size_t length,
			     const cs_insn *reference)
{
	cs_insn *batch = NULL, *iter = cs_malloc(handle);
	const uint8_t *cursor = bytes;
	size_t remaining = size;
	uint64_t address = 0x1000;
	size_t count = cs_disasm(handle, bytes, size, address, 1, &batch);
	bool ok = iter != NULL;
	if (iter) {
		bool decoded = cs_disasm_iter(handle, &cursor, &remaining,
					      &address, iter);
		ok &= decoded == (length != 0);
		if (decoded)
			ok &= iter->id == id && iter->size == length &&
			      iter->address == 0x1000 &&
			      memcmp(iter->bytes, bytes, length) == 0 &&
			      cursor == bytes + length &&
			      remaining == size - length &&
			      address == 0x1000 + length;
		else
			ok &= cursor == bytes && remaining == size &&
			      address == 0x1000;
		if (decoded && reference)
			ok &= same_mapping_result(iter, reference);
	}
	if (length)
		ok &= count == 1 && batch->id == id && batch->size == length &&
		      batch->address == 0x1000 &&
		      memcmp(batch->bytes, bytes, length) == 0;
	else
		ok &= count == 0;
	if (count == 1 && reference)
		ok &= same_mapping_result(batch, reference);
	if (!ok) {
		fprintf(stderr, "decode: expected id=%u size=%zu for", id,
			length);
		for (size_t i = 0; i < size; ++i)
			fprintf(stderr, " %02x", bytes[i]);
		fprintf(stderr, "\n");
	}
	cs_free(batch, count);
	cs_free(iter, iter ? 1 : 0);
	return ok;
}

static bool decode(csh handle, const uint8_t *bytes, size_t size, unsigned id,
		   size_t length)
{
	return decode_reference(handle, bytes, size, id, length, NULL);
}

/* Run these fixed acceptance/ID expectations under every text/detail setting.
 * This covers operand validation shared by scan and output-producing paths;
 * the reader, lock and UD1 checks below cover their mode-dependent forms. */
static bool check_scan_validation(csh handle, cs_mode mode)
{
	static const struct {
		uint8_t bytes[8];
		size_t size;
		unsigned id;
	} cases[] = {
		{ { 0xc3 }, 1, X86_INS_RET },
		{ { 0x48, 0x01, 0xd8 }, 3, X86_INS_ADD },
		{ { 0x48, 0x83, 0x44, 0x24, 0x08, 0x81 }, 6, X86_INS_ADD },
		{ { 0x48, 0x8d, 0xc0 }, 3, X86_INS_INVALID },
		{ { 0xd5, 0x7f, 0x8b, 0x44, 0xb7, 0xe0 }, 6, X86_INS_MOV },
		{ { 0xd5, 0xc0, 0x20, 0xc0 }, 4, X86_INS_INVALID },
#ifndef CAPSTONE_X86_REDUCE
		/* An empty operand list still rejects reserved VEX.vvvv. */
		{ { 0xc5, 0xf8, 0x77 }, 3, X86_INS_VZEROUPPER },
		{ { 0xc5, 0xf0, 0x77 }, 3, X86_INS_INVALID },
		{ { 0xc5, 0xf8, 0x58, 0xc1 }, 4, X86_INS_VADDPS },
		/* VSIB is required and destination, index and mask must differ. */
		{ { 0xc4, 0xe2, 0x69, 0x92, 0x04, 0x88 },
		  6,
		  X86_INS_VGATHERDPS },
		{ { 0xc4, 0xe2, 0x69, 0x92, 0x00 }, 5, X86_INS_INVALID },
		{ { 0xc4, 0xe2, 0x69, 0x92, 0x04, 0x80 }, 6, X86_INS_INVALID },
		{ { 0xc4, 0xe2, 0x79, 0x92, 0x04, 0x88 }, 6, X86_INS_INVALID },
		/* Scalar LLIG normalization retains its reserved-length check. */
		{ { 0x62, 0xf1, 0x6e, 0x28, 0xc2, 0xcb, 0x20 },
		  7,
		  X86_INS_VCMPSS },
		{ { 0x62, 0xf1, 0x6e, 0x68, 0xc2, 0xcb, 0x20 },
		  7,
		  X86_INS_INVALID },
#endif
	};
	if (mode != CS_MODE_64)
		return true;
	bool ok = true;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		const size_t length = cases[i].id ? cases[i].size : 0;
		ok &= decode(handle, cases[i].bytes, cases[i].size, cases[i].id,
			     length);
		if (length)
			for (size_t n = 0; n < length; ++n)
				ok &= decode(handle, cases[i].bytes, n,
					     X86_INS_INVALID, 0);
	}
	return ok;
}

/* Public APIs must retain mapping, printer aliases and detail when the
 * optional ID cache is unavailable. The caller supplies each output mode. */
static bool check_public_id_cache(csh handle, cs_mode mode)
{
	static const struct {
		uint8_t bytes[6];
		size_t size;
		unsigned id;
		bool full_only;
	} cases[] = {
		{ { 0x48, 0x8b, 0xc1 }, 3, X86_INS_MOV, false },
		{ { 0x90 }, 1, X86_INS_NOP, false },
		{ { 0x41, 0x90 }, 2, X86_INS_XCHG, false },
		/* AT&T printing overrides the public opcode for CALLpcrel32. */
		{ { 0xe8, 0, 0, 0, 0 }, 5, X86_INS_CALL, false },
		{ { 0xf3, 0x0f, 0x01, 0xee }, 4, X86_INS_CLUI, false },
		{ { 0xf3, 0x0f, 0x01, 0xed }, 4, X86_INS_TESTUI, false },
		/* Predicate aliases vary with text output; use fallback as oracle. */
		{ { 0xf3, 0x0f, 0xc2, 0xc1, 0 }, 5, X86_INS_INVALID, true },
		{ { 0xf3, 0x0f, 0xc2, 0xc1, 0xff }, 5, X86_INS_INVALID, true },
	};
	if (mode != CS_MODE_64)
		return true;
	cs_struct *arch = (cs_struct *)(uintptr_t)handle;
	uint32_t *cache = arch->x86_insn_lut;
	bool ok = cache != NULL;
	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
		if (cases[c].full_only && cs_support(CS_SUPPORT_X86_REDUCE))
			continue;
		cs_insn *reference = NULL;
		arch->x86_insn_lut = NULL;
		size_t count = cs_disasm(handle, cases[c].bytes, cases[c].size,
					 0x1000, 1, &reference);
		arch->x86_insn_lut = cache;
		if (count != 1) {
			fprintf(stderr, "public ID-cache fixture %zu failed\n",
				c);
			ok = false;
		} else {
			if (cases[c].id != X86_INS_INVALID)
				ok &= reference->id == cases[c].id;
			for (unsigned cached = 0; cached != 2; ++cached) {
				arch->x86_insn_lut = cached ? cache : NULL;
				ok &= decode_reference(handle, cases[c].bytes,
						       cases[c].size,
						       reference->id,
						       cases[c].size,
						       reference);
			}
		}
		arch->x86_insn_lut = cache;
		cs_free(reference, count);
	}
	return ok;
}

struct reader_case {
	cs_mode mode;
	uint8_t bytes[10];
	size_t size;
	unsigned id;
	bool memory;
	int64_t value;
};

static bool check_far_pointer_encoding(csh handle, cs_mode mode, bool detail)
{
	static const struct {
		cs_mode mode;
		uint8_t bytes[8];
		size_t size;
	} cases[] = {
		{ CS_MODE_16, { 0x9a, 0x21, 0x4c, 0x94, 0xdb }, 5 },
		{ CS_MODE_32, { 0x9a, 0x21, 0x4c, 0x78, 0x56, 0x94, 0xdb }, 7 },
		{ CS_MODE_16,
		  { 0x66, 0x9a, 0x21, 0x4c, 0x78, 0x56, 0x94, 0xdb },
		  8 },
		{ CS_MODE_32, { 0x66, 0x9a, 0x21, 0x4c, 0x94, 0xdb }, 6 },
	};
	bool ok = true;
	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
		if (cases[c].mode != mode)
			continue;
		for (unsigned jump = 0; jump != 2; ++jump) {
			uint8_t bytes[sizeof(cases[c].bytes)];
			memcpy(bytes, cases[c].bytes, sizeof(bytes));
			bytes[bytes[0] == 0x66 ? 1 : 0] = jump ? 0xea : 0x9a;
			const uint8_t *cursor = bytes;
			size_t remaining = cases[c].size;
			uint64_t address = 0x1000;
			cs_insn *batch = NULL, *iter = cs_malloc(handle);
			size_t count = cs_disasm(handle, bytes, remaining,
						 address, 1, &batch);
			bool decoded = iter && cs_disasm_iter(handle, &cursor,
							      &remaining,
							      &address, iter);
			bool match = count == 1 && decoded;
			if (match) {
				unsigned id = jump ? X86_INS_LJMP :
						     X86_INS_LCALL;
				const cs_insn *results[] = { batch, iter };
				for (size_t r = 0; r != 2; ++r) {
					const cs_insn *insn = results[r];
					match &= insn->id == id &&
						 insn->size == cases[c].size;
					if (detail) {
						const cs_x86_encoding *encoding =
							&insn->detail->x86
								 .encoding;
						/* The final immediate is the 16-bit selector. */
						match &= encoding->imm_offset +
								 2 ==
							 cases[c].size;
						match &= encoding->imm_size ==
							 2;
					}
				}
			}
			if (!match)
				fprintf(stderr,
					"far pointer encoding: case=%zu jump=%u\n",
					c, jump);
			ok &= match;
			cs_free(batch, count);
			cs_free(iter, 1);
		}
	}
	return ok;
}

static bool check_reader_input(csh handle, cs_insn *iter,
			       const struct reader_case *test,
			       const uint8_t *bytes, size_t available,
			       uint64_t start, bool detail)
{
	const uint8_t *cursor = bytes;
	size_t remaining = available;
	uint64_t address = start;
	bool expected = available == test->size;
	bool decoded =
		cs_disasm_iter(handle, &cursor, &remaining, &address, iter);
	bool match = decoded == expected;

	if (decoded) {
		match &= iter->id == test->id && iter->size == available &&
			 iter->address == start &&
			 cursor == bytes + available && remaining == 0 &&
			 address == start + available &&
			 memcmp(iter->bytes, bytes, available) == 0;
	} else {
		match &= cursor == bytes && remaining == available &&
			 address == start;
	}
	if (decoded && detail) {
		const cs_x86 *x86 = &iter->detail->x86;
		bool found = false;
		for (unsigned op = 0; op < x86->op_count; ++op) {
			const cs_x86_op *operand = &x86->operands[op];
			if (test->memory)
				found |= operand->type == X86_OP_MEM &&
					 operand->mem.disp == test->value;
			else
				found |= operand->type == X86_OP_IMM &&
					 operand->imm == test->value;
		}
		match &= found;
	}
	cs_insn *batch = NULL;
	size_t count = cs_disasm(handle, bytes, available, start, 1, &batch);
	match &= count == (expected ? 1 : 0);
	if (count)
		match &= batch[0].id == test->id &&
			 batch[0].size == available &&
			 batch[0].address == start &&
			 memcmp(batch[0].bytes, bytes, available) == 0;
	cs_free(batch, count);
	return match;
}

/* Exact-size allocations also make these checks sensitive to overreads in
 * sanitizer builds. Exercise every truncation and several input alignments. */
static bool check_reader_bounds(csh handle, cs_mode mode, bool detail)
{
	static const struct reader_case cases[] = {
		{ CS_MODE_16,
		  { 0xb8, 0x34, 0x12 },
		  3,
		  X86_INS_MOV,
		  false,
		  0x1234 },
		{ CS_MODE_16,
		  { 0x8b, 0x86, 0x98, 0xfe },
		  4,
		  X86_INS_MOV,
		  true,
		  -360 },
		{ CS_MODE_32,
		  { 0xb8, 0x78, 0x56, 0x34, 0x12 },
		  5,
		  X86_INS_MOV,
		  false,
		  0x12345678 },
		{ CS_MODE_32,
		  { 0x8b, 0x83, 0x98, 0xba, 0xdc, 0xfe },
		  6,
		  X86_INS_MOV,
		  true,
		  -19088744 },
		{ CS_MODE_64,
		  { 0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
		    0x01 },
		  10,
		  X86_INS_MOVABS,
		  false,
		  INT64_C(0x0123456789abcdef) },
		{ CS_MODE_64,
		  { 0x48, 0xa1, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
		    0x01 },
		  10,
		  X86_INS_MOVABS,
		  true,
		  INT64_C(0x0102030405060708) },
		{ CS_MODE_64,
		  { 0x48, 0x8b, 0x84, 0x8b, 0x98, 0xba, 0xdc, 0xfe },
		  8,
		  X86_INS_MOV,
		  true,
		  -19088744 },
		{ CS_MODE_64,
		  { 0x48, 0x83, 0xc0, 0x81 },
		  4,
		  X86_INS_ADD,
		  false,
		  -127 },
	};
	static const uint64_t addresses[] = { 0, 0x1000, UINT64_MAX - 4,
					      UINT64_MAX };
	cs_insn *iter = cs_malloc(handle);
	bool ok = iter != NULL;
	if (!iter)
		return false;

	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
		if (cases[c].mode != mode)
			continue;
		for (size_t available = 0; available <= cases[c].size;
		     ++available) {
			for (size_t alignment = 0; alignment != 8;
			     ++alignment) {
				size_t allocation_size = available + alignment;
				uint8_t *allocation = malloc(
					allocation_size ? allocation_size : 1);
				if (!allocation) {
					cs_free(iter, 1);
					return false;
				}
				uint8_t *bytes = allocation + alignment;
				memcpy(bytes, cases[c].bytes, available);
				for (size_t a = 0;
				     a <
				     sizeof(addresses) / sizeof(addresses[0]);
				     ++a) {
					bool match = check_reader_input(
						handle, iter, &cases[c], bytes,
						available, addresses[a],
						detail);
					if (!match)
						fprintf(stderr,
							"reader bounds: case=%zu size=%zu alignment=%zu address=%zu\n",
							c, available, alignment,
							a);
					ok &= match;
				}
				free(allocation);
			}
		}
	}
	cs_free(iter, 1);
	return ok;
}

static bool check_lock(csh handle, cs_mode mode)
{
	static const struct {
		uint8_t opcode;
		unsigned id;
	} arithmetic[] = { { 0x00, X86_INS_ADD }, { 0x08, X86_INS_OR },
			   { 0x10, X86_INS_ADC }, { 0x18, X86_INS_SBB },
			   { 0x20, X86_INS_AND }, { 0x28, X86_INS_SUB },
			   { 0x30, X86_INS_XOR } };
	static const struct {
		uint8_t bytes[3];
		size_t size;
	} prefixes[] = { { { 0xf0 }, 1 },	{ { 0x66, 0xf0 }, 2 },
			 { { 0x67, 0xf0 }, 2 }, { { 0x64, 0xf0 }, 2 },
			 { { 0xf2, 0xf0 }, 2 }, { { 0xf0, 0xf2 }, 2 },
			 { { 0xf3, 0xf0 }, 2 }, { { 0xf0, 0xf3 }, 2 } };
	static const struct {
		uint8_t bytes[5];
		size_t size;
		unsigned id;
	} forms[] = {
		{ { 0xf0, 0x89, 0x02 }, 3, X86_INS_INVALID },
		{ { 0xf0, 0x39, 0x02 }, 3, X86_INS_INVALID },
		{ { 0xf0, 0x0f, 0xa3, 0x02 }, 4, X86_INS_INVALID },
		{ { 0xf0, 0x90 }, 2, X86_INS_INVALID },
		{ { 0xf0, 0x0f, 0x1f, 0x00 }, 4, X86_INS_INVALID },
		{ { 0x66, 0xf0, 0x0f, 0x1f, 0x00 }, 5, X86_INS_INVALID },
		{ { 0xf0, 0x0f, 0xab, 0x02 }, 4, X86_INS_BTS },
		{ { 0xf0, 0x0f, 0xb3, 0x02 }, 4, X86_INS_BTR },
		{ { 0xf0, 0x0f, 0xbb, 0x02 }, 4, X86_INS_BTC },
		{ { 0xf0, 0x0f, 0xb1, 0x02 }, 4, X86_INS_CMPXCHG },
		{ { 0xf0, 0x0f, 0xc7, 0x0a }, 4, X86_INS_CMPXCHG8B },
		{ { 0xf0, 0x0f, 0xc1, 0x02 }, 4, X86_INS_XADD },
		{ { 0xf0, 0x87, 0x02 }, 3, X86_INS_XCHG },
		{ { 0xf0, 0xff, 0x02 }, 3, X86_INS_INC },
		{ { 0xf0, 0xff, 0x0a }, 3, X86_INS_DEC },
		{ { 0xf0, 0xf7, 0x12 }, 3, X86_INS_NOT },
		{ { 0xf0, 0xf7, 0x1a }, 3, X86_INS_NEG },
	};
	bool ok = true;
	for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); ++p)
		for (size_t a = 0;
		     a < sizeof(arithmetic) / sizeof(arithmetic[0]); ++a)
			for (unsigned form = 0; form != 4; ++form)
				for (unsigned reg = 0; reg != 2; ++reg) {
					uint8_t bytes[5];
					size_t n = prefixes[p].size;
					memcpy(bytes, prefixes[p].bytes, n);
					bytes[n++] =
						arithmetic[a].opcode + form;
					bytes[n++] = reg ? 0xc2 : 0x02;
					bool valid = form < 2 && !reg;
					ok &= decode(handle, bytes, n,
						     arithmetic[a].id,
						     valid ? n : 0);
				}
	for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i)
		ok &= decode(handle, forms[i].bytes, forms[i].size, forms[i].id,
			     forms[i].id ? forms[i].size : 0);
	if (mode == CS_MODE_64) {
		const uint8_t valid[] = { 0xf0, 0xd5, 0x58, 0x31, 0x02 };
		const uint8_t invalid[] = { 0xf0, 0xd5, 0x58, 0x33, 0x02 };
		const uint8_t wide[] = { 0xf0, 0x48, 0x0f, 0xc7, 0x0a };
		ok &= decode(handle, valid, sizeof(valid), X86_INS_XOR,
			     sizeof(valid));
		ok &= decode(handle, invalid, sizeof(invalid), X86_INS_INVALID,
			     0);
		ok &= decode(handle, wide, sizeof(wide), X86_INS_CMPXCHG16B,
			     sizeof(wide));
	}
	return ok;
}

static bool check_segments(csh handle, cs_mode mode)
{
	bool ok = true;
	const uint8_t prefixes[] = { 0x00, 0x66, 0x67, 0x48, 0x4c };
	for (size_t p = 0; p < sizeof(prefixes); ++p) {
		if (p >= 3 && mode != CS_MODE_64)
			continue;
		for (unsigned reg = 0; reg != 2; ++reg) {
			uint8_t bytes[3];
			size_t n = 0;
			if (prefixes[p])
				bytes[n++] = prefixes[p];
			bytes[n++] = 0x8e;
			bytes[n++] = reg ? 0xc8 : 0x0a;
			ok &= decode(handle, bytes, n, X86_INS_INVALID, 0);
			bytes[n - 2] = 0x8c;
			ok &= decode(handle, bytes, n, X86_INS_MOV, n);
			bytes[n - 2] = 0x8e;
			bytes[n - 1] = reg ? 0xe0 : 0x22;
			ok &= decode(handle, bytes, n, X86_INS_MOV, n);
		}
	}
	if (mode == CS_MODE_64) {
		uint8_t rex2[] = { 0xd5, 0x44, 0x8e, 0xc8 };
		ok &= decode(handle, rex2, sizeof(rex2), X86_INS_INVALID, 0);
		rex2[2] = 0x8c;
		ok &= decode(handle, rex2, sizeof(rex2), X86_INS_MOV,
			     sizeof(rex2));
	}
	return ok;
}

struct ud1_case {
	cs_mode mode;
	uint8_t bytes[16];
	size_t size;
	uint8_t address_size, modrm_offset, disp_offset, disp_size;
	x86_reg reg, base, index;
	int scale;
	int64_t displacement;
};

static bool check_ud1(csh handle, const struct ud1_case *test, unsigned syntax,
		      bool detail, bool text)
{
	bool ok = true;
	cs_insn *insn = NULL;
	uint8_t stream[17];
	for (size_t n = 0; n < test->size; ++n)
		ok &= decode(handle, test->bytes, n, X86_INS_INVALID, 0);
	memcpy(stream, test->bytes, test->size);
	stream[test->size] = 0x90;
	ok &= decode(handle, stream, test->size + 1, X86_INS_UD1, test->size);
	size_t count =
		cs_disasm(handle, stream, test->size + 1, 0x1000, 0, &insn);
	ok &= count == 2 && insn[0].id == X86_INS_UD1 &&
	      insn[1].id == X86_INS_NOP &&
	      insn[1].address == 0x1000 + test->size;
	if (count && detail && text && !cs_support(CS_SUPPORT_DIET)) {
		const cs_x86 *x = &insn[0].detail->x86;
		bool memory = (test->bytes[test->modrm_offset] >> 6) != 3;
		unsigned first = syntax == CS_OPT_SYNTAX_ATT ? 1 : 0;
		const cs_x86_op *reg = &x->operands[first];
		const cs_x86_op *rm = &x->operands[1 - first];
		ok &= x->op_count == 2 && reg->type == X86_OP_REG &&
		      reg->reg == test->reg && reg->size == 4 &&
		      rm->size == 4 && x->addr_size == test->address_size &&
		      x->modrm == test->bytes[test->modrm_offset] &&
		      x->encoding.modrm_offset == test->modrm_offset &&
		      x->encoding.disp_offset == test->disp_offset &&
		      x->encoding.disp_size == test->disp_size &&
		      x->disp == test->displacement && !x->encoding.imm_size &&
		      !x->encoding.imm_offset;
		if (memory)
			ok &= rm->type == X86_OP_MEM &&
			      rm->mem.base == test->base &&
			      rm->mem.index == test->index &&
			      rm->mem.scale == test->scale &&
			      rm->mem.disp == test->displacement;
		else
			ok &= rm->type == X86_OP_REG && rm->reg == test->base;
		if (!cs_support(CS_SUPPORT_DIET)) {
			cs_regs reads, writes;
			uint8_t read_count = 0, write_count = 0;
			ok &= reg->access == CS_AC_READ &&
			      rm->access == CS_AC_READ && x->eflags == 0 &&
			      cs_regs_access(handle, &insn[0], reads,
					     &read_count, writes,
					     &write_count) == CS_ERR_OK &&
			      read_count > 0 && write_count == 0 &&
			      strcmp(insn[0].mnemonic, "ud1") == 0 &&
			      insn[0].op_str[0] != '\0';
		}
	}
	cs_free(insn, count);
	if (!ok)
		fprintf(stderr,
			"UD1 detail/boundary: mode=%u size=%zu syntax=%u detail=%d text=%d\n",
			(unsigned)test->mode, test->size, syntax, detail, text);
	return ok;
}

int main(void)
{
	/* UD1's encoded operands are r32/rm32 even with 66 or REX.W.  The
	 * address-size prefix still selects the complete addressing extent. */
	static const struct ud1_case ud1[] = {
		{ CS_MODE_16,
		  { 0x0f, 0xb9, 0xc1 },
		  3,
		  2,
		  2,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_32,
		  { 0x0f, 0xb9, 0xc1 },
		  3,
		  4,
		  2,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0xc1 },
		  3,
		  8,
		  2,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_16,
		  { 0x0f, 0xb9, 0x06, 0x34, 0x12 },
		  5,
		  2,
		  2,
		  3,
		  2,
		  X86_REG_EAX,
		  0,
		  0,
		  1,
		  0x1234 },
		{ CS_MODE_32,
		  { 0x67, 0x0f, 0xb9, 0x46, 0x80 },
		  5,
		  2,
		  3,
		  4,
		  1,
		  X86_REG_EAX,
		  X86_REG_BP,
		  0,
		  1,
		  -128 },
		{ CS_MODE_32,
		  { 0x67, 0x0f, 0xb9, 0x86, 0x34, 0x92 },
		  6,
		  2,
		  3,
		  4,
		  2,
		  X86_REG_EAX,
		  X86_REG_BP,
		  0,
		  1,
		  -28108 },
		{ CS_MODE_16,
		  { 0x67, 0x0f, 0xb9, 0x4c, 0x9a, 0x80 },
		  6,
		  4,
		  3,
		  5,
		  1,
		  X86_REG_ECX,
		  X86_REG_EDX,
		  X86_REG_EBX,
		  4,
		  -128 },
		{ CS_MODE_32,
		  { 0x0f, 0xb9, 0x4c, 0x9a, 0x80 },
		  5,
		  4,
		  2,
		  4,
		  1,
		  X86_REG_ECX,
		  X86_REG_EDX,
		  X86_REG_EBX,
		  4,
		  -128 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0x4c, 0x9a, 0x80 },
		  5,
		  8,
		  2,
		  4,
		  1,
		  X86_REG_ECX,
		  X86_REG_RDX,
		  X86_REG_RBX,
		  4,
		  -128 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0x9c, 0xf6, 0xdd, 0xcc, 0xbb, 0xaa },
		  8,
		  8,
		  2,
		  4,
		  4,
		  X86_REG_EBX,
		  X86_REG_RSI,
		  X86_REG_RSI,
		  8,
		  -1430532899 },
		{ CS_MODE_64,
		  { 0x66, 0x0f, 0xb9, 0x9c, 0xf6, 0xdd, 0xcc, 0xbb, 0xaa },
		  9,
		  8,
		  3,
		  5,
		  4,
		  X86_REG_EBX,
		  X86_REG_RSI,
		  X86_REG_RSI,
		  8,
		  -1430532899 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0x05, 1, 2, 3, 4 },
		  7,
		  8,
		  2,
		  3,
		  4,
		  X86_REG_EAX,
		  X86_REG_RIP,
		  0,
		  1,
		  0x04030201 },
		{ CS_MODE_64,
		  { 0x67, 0x0f, 0xb9, 0x05, 1, 2, 3, 4 },
		  8,
		  4,
		  3,
		  4,
		  4,
		  X86_REG_EAX,
		  X86_REG_EIP,
		  0,
		  1,
		  0x04030201 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0x04, 0x25, 1, 2, 3, 4 },
		  8,
		  8,
		  2,
		  4,
		  4,
		  X86_REG_EAX,
		  0,
		  0,
		  1,
		  0x04030201 },
		{ CS_MODE_64,
		  { 0x66, 0x0f, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0x48, 0x0f, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0xd5, 0x80, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0xd5, 0xc0, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_R16D,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0xd5, 0x98, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_R17D,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0xd5, 0xa0, 0xb9, 0x04, 0x50 },
		  5,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_RAX,
		  X86_REG_R18,
		  2,
		  0 },
		{ CS_MODE_64,
		  { 0x67, 0xd5, 0xa0, 0xb9, 0x04, 0x50 },
		  6,
		  4,
		  4,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_EAX,
		  X86_REG_R18D,
		  2,
		  0 },
	};
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	const unsigned syntaxes[] = { CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT };
	bool ok = check_operand_sets() && check_internal_scan_mode() &&
		  check_inherited_moffs_size() && check_id_cache() &&
		  check_instruction_names();
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m)
		for (size_t s = 0; s < sizeof(syntaxes) / sizeof(syntaxes[0]);
		     ++s)
			for (unsigned detail = 0; detail != 2; ++detail)
				for (unsigned text = 0; text != 2; ++text) {
					csh handle;
					if (cs_open(CS_ARCH_X86, modes[m],
						    &handle) != CS_ERR_OK)
						return 1;
					cs_err err = cs_option(handle,
							       CS_OPT_SYNTAX,
							       syntaxes[s]);
					if (syntaxes[s] == CS_OPT_SYNTAX_ATT &&
					    (err == CS_ERR_X86_ATT ||
					     err == CS_ERR_DIET)) {
						cs_close(&handle);
						continue;
					}
					ok &= err == CS_ERR_OK;
					ok &= cs_option(handle, CS_OPT_DETAIL,
							detail) == CS_ERR_OK;
					ok &= cs_option(handle, CS_OPT_TEXT,
							text) == CS_ERR_OK;
					ok &= check_public_id_cache(handle,
								    modes[m]);
					ok &= check_reader_bounds(
						handle, modes[m],
						detail && text);
					ok &= check_far_pointer_encoding(
						handle, modes[m], detail);
					ok &= check_lock(handle, modes[m]);
					ok &= check_segments(handle, modes[m]);
					ok &= check_scan_validation(handle,
								    modes[m]);
					const uint8_t ud0[] = { 0x0f, 0xff };
					const uint8_t ud2[] = { 0x0f, 0x0b };
					ok &= decode(handle, ud0, sizeof(ud0),
						     X86_INS_UD0, 2);
					ok &= decode(handle, ud2, sizeof(ud2),
						     X86_INS_UD2, 2);
					for (size_t i = 0;
					     i < sizeof(ud1) / sizeof(ud1[0]);
					     ++i)
						if (ud1[i].mode == modes[m])
							ok &= check_ud1(
								handle, &ud1[i],
								syntaxes[s],
								detail, text);
					uint8_t maximum[16];
					memset(maximum, 0x66, sizeof(maximum));
					maximum[14] = 0xc3;
					ok &= decode(handle, maximum, 15,
						     X86_INS_RET, 15);
					maximum[14] = 0x66;
					maximum[15] = 0xc3;
					ok &= decode(handle, maximum, 16,
						     X86_INS_INVALID, 0);
					memset(maximum, 0x66, sizeof(maximum));
					memcpy(maximum + 12, "\x0f\xb9\xc0", 3);
					ok &= decode(handle, maximum, 15,
						     X86_INS_UD1, 15);
					memcpy(maximum + 13, "\x0f\xb9\xc0", 3);
					maximum[12] = 0x66;
					ok &= decode(handle, maximum, 16,
						     X86_INS_INVALID, 0);
					cs_close(&handle);
				}
	return ok ? 0 : 1;
}

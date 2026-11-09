// SPDX-License-Identifier: BSD-3-Clause

#include "../../Mapping.h"
#include <limits.h>
#include <stdio.h>

static bool check_lookup(const insn_map *table, unsigned size, unsigned opcode,
			 unsigned expected)
{
	unsigned actual = find_cs_id(opcode, table, size);
	if (actual != expected) {
		fprintf(stderr, "Opcode %u: expected index %u, got %u\n",
			opcode, expected, actual);
		return false;
	}

	// Check the externally visible instruction ID, including the preserved ID
	// on a miss. Different entries deliberately have different mapped IDs.
	cs_insn insn = { 0 };
	MCInst MI = { 0 };
	insn.id = UINT_MAX;
	MI.flat_insn = &insn;
	MCInst_setOpcode(&MI, opcode);
	map_cs_id(&MI, table, size);
	unsigned expected_id = expected == UINT_MAX ? UINT_MAX :
						      table[expected].mapid;
	if (insn.id != expected_id) {
		fprintf(stderr, "Opcode %u: expected ID %u, got %u\n", opcode,
			expected_id, insn.id);
		return false;
	}
	return true;
}

static bool test_dense_and_sparse(void)
{
	insn_map dense[6] = { 0 };
	insn_map sparse[4] = { 0 };
	static const unsigned short sparse_ids[] = { 1, 3, 9, USHRT_MAX };
	static const unsigned missing[] = { 0, 2, 4, 8, 10, UINT_MAX };
	for (unsigned i = 0; i < 6; ++i) {
		dense[i].id = i;
		dense[i].mapid = 100 + i;
	}
	for (unsigned i = 0; i < 4; ++i) {
		sparse[i].id = sparse_ids[i];
		sparse[i].mapid = 200 + i;
	}
	for (unsigned i = 0; i < 6; ++i)
		if (!check_lookup(dense, 6, i, i))
			return false;
	for (unsigned i = 0; i < 4; ++i)
		if (!check_lookup(sparse, 4, sparse_ids[i], i))
			return false;
	for (unsigned i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i)
		if (!check_lookup(sparse, 4, missing[i], UINT_MAX))
			return false;
	return check_lookup(dense, 6, 6, UINT_MAX) &&
	       check_lookup(dense, 6, UINT_MAX, UINT_MAX) &&
	       check_lookup(dense, 1, 0, 0) &&
	       check_lookup(dense, 1, 1, UINT_MAX) &&
	       check_lookup(sparse, 1, 1, 0) &&
	       check_lookup(sparse, 1, 0, UINT_MAX);
}

static bool test_duplicate_selection(void)
{
	insn_map zeroes[4] = { 0 };
	insn_map duplicates[7] = { 0 };
	static const unsigned short ids[] = { 0, 1, 1, 1, 4, 5, 5 };
	for (unsigned i = 0; i < 4; ++i)
		zeroes[i].mapid = 100 + i;
	for (unsigned i = 0; i < 7; ++i) {
		duplicates[i].id = ids[i];
		duplicates[i].mapid = 200 + i;
	}
	return check_lookup(zeroes, 4, 0, 1) &&
	       check_lookup(duplicates, 7, 0, 0) &&
	       check_lookup(duplicates, 7, 1, 3) &&
	       check_lookup(duplicates, 7, 4, 4) &&
	       check_lookup(duplicates, 7, 5, 5) &&
	       check_lookup(duplicates, 7, 2, UINT_MAX) &&
	       check_lookup(duplicates, 7, 6, UINT_MAX);
}

static bool test_name_lookup(void)
{
	static const name_map names[] = {
		{ 17, "duplicate" },	{ 0, "" },
		{ 89, "different" },	{ 99, "duplicate" },
		{ INT_MAX, "\x80" },	{ 101, NULL },
		{ 202, "unreachable" },
	};
	static const struct {
		int count;
		const char *name;
		int expected;
	} cases[] = {
		{ -1, "duplicate", -1 },
		{ 0, "duplicate", -1 },
		{ 1, "duplicate", 17 },
		{ 1, "", -1 },
		{ 2, "", 0 },
		{ 2, "different", -1 },
		{ 3, "different", 89 },
		{ 7, "duplicate", 17 },
		{ 7, "\x80", INT_MAX },
		{ 7, "\xff", -1 },
		{ 7, "diff", -1 },
		{ 7, "different_suffix", -1 },
		{ 7, "unreachable", -1 },
		{ 7, "absent", -1 },
	};
	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		int actual = name2id(names, cases[i].count, cases[i].name);
		if (actual != cases[i].expected) {
			fprintf(stderr, "Name lookup %u: expected %d, got %d\n",
				i, cases[i].expected, actual);
			return false;
		}
	}
	return true;
}

static bool test_alias_lookup(void)
{
	static const name_map names[] = {
		{ 17, "move" },		  { 23, "move.w" },
		{ 29, "move,pt" },	  { 31, "123456789abcdef" },
		{ 37, "\200" },		  { 0, "zero" },
		{ UINT_MAX, "negative" }, { 41, "" },
		{ 43, "move" },		  { 47, NULL },
		{ 53, "unreachable" },
	};
	static const struct {
		cs_arch arch;
		const char *text;
		int count;
		unsigned expected;
	} cases[] = {
		{ CS_ARCH_ARM, " \tmove.w r0", 11, 17 },
		{ CS_ARCH_AARCH64, "move.w", 11, 17 },
		{ CS_ARCH_MIPS, "move\tr0", 11, 17 },
		{ CS_ARCH_PPC, "move.w r0", 11, 23 },
		{ CS_ARCH_RISCV, "move.w\tr0", 11, 23 },
		{ CS_ARCH_SPARC, "move,pt r0", 11, 17 },
		{ CS_ARCH_SPARC, "move.w r0", 11, 23 },
		{ CS_ARCH_ARM, "move,pt r0", 11, 29 },
		{ CS_ARCH_ARM, "123456789abcdef_suffix", 11, 31 },
		{ CS_ARCH_ARM, "123456789abcde", 11, 0 },
		{ CS_ARCH_ARM, "\200 r0", 11, 37 },
		{ CS_ARCH_ARM, "zero", 11, 0 },
		{ CS_ARCH_ARM, "negative", 11, 0 },
		{ CS_ARCH_ARM, " \t", 11, 41 },
		{ CS_ARCH_ARM, "unreachable", 11, 0 },
		{ CS_ARCH_ARM, "missing", 11, 0 },
		{ CS_ARCH_ARM, "move", INT_MIN, 0 },
		{ CS_ARCH_ARM, "move", 0, 0 },
		{ CS_ARCH_ARM, "move.w", 1, 17 },
		{ CS_ARCH_PPC, "move.w", 1, 0 },
	};
	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		cs_struct handle = { 0 };
		cs_insn insn = { 0 };
		MCInst MI = { 0 };
		SStream stream = { 0 };
		handle.arch = cases[i].arch;
		MI.csh = &handle;
		MI.flat_insn = &insn;
		MI.isAliasInstr = true;
		strcpy(stream.buffer, cases[i].text);
		map_set_alias_id(&MI, &stream, names, cases[i].count);
		if (insn.alias_id != cases[i].expected) {
			fprintf(stderr,
				"Alias lookup %u: expected %u, got %llu\n", i,
				cases[i].expected,
				(unsigned long long)insn.alias_id);
			return false;
		}
		// Non-aliases must not inspect a stream, map or architecture.
		MI.isAliasInstr = false;
		MI.csh = NULL;
		insn.alias_id = 99;
		map_set_alias_id(&MI, NULL, NULL, INT_MAX);
		if (insn.alias_id != 0)
			return false;
	}
	return true;
}

int main(void)
{
	return test_name_lookup() && test_alias_lookup() &&
			       test_dense_and_sparse() &&
			       test_duplicate_selection() &&
			       find_cs_id(0, NULL, 0) == UINT_MAX &&
			       find_cs_id(UINT_MAX, NULL, 0) == UINT_MAX ?
		       0 :
		       1;
}

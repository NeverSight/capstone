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

int main(void)
{
	return test_dense_and_sparse() && test_duplicate_selection() &&
			       find_cs_id(0, NULL, 0) == UINT_MAX &&
			       find_cs_id(UINT_MAX, NULL, 0) == UINT_MAX ?
		       0 :
		       1;
}

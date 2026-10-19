// SPDX-License-Identifier: BSD-3-Clause

#include "../../MCInst.h"
#include "../../MCInstPrinter.h"
#include "../../cs_priv.h"
#include <stdio.h>
#include <string.h>

static bool check_ties(const MCInst *MI, uint64_t tied, uint64_t tying)
{
	for (unsigned i = 0; i < MAX_MC_OPS; ++i) {
		if (MCInst_opIsTied(MI, i) != !!(tied & (UINT64_C(1) << i)) ||
		    MCInst_opIsTying(MI, i) != !!(tying & (UINT64_C(1) << i))) {
			fprintf(stderr,
				"Unexpected tie membership at operand %u\n", i);
			return false;
		}
	}
	return true;
}

static bool test_tie_membership(void)
{
	MCInst MI;
	cs_detail detail = { 0 };
	cs_insn insn = { 0 };
	MCOperandInfo ops[MAX_MC_OPS] = { 0 };
	MCInstrDesc desc = { 0 };
	desc.NumOperands = MAX_MC_OPS;
	desc.OpInfo = ops;
	insn.detail = &detail;
	MCInst_Init(&MI, CS_ARCH_ARM);
	MI.flat_insn = &insn;
	MCInst_handleWriteback(&MI, &desc, 1);
	if (!check_ties(&MI, 0, 0) || detail.writeback)
		return false;

	ops[MAX_MC_OPS - 1].Constraints = CONSTRAINT_MCOI_TIED_TO(15);
	MCInst_handleWriteback(&MI, &desc, 1);
	if (!check_ties(&MI, UINT64_C(1) << 15,
			UINT64_C(1) << (MAX_MC_OPS - 1)) ||
	    !detail.writeback)
		return false;
	MCInst_clear(&MI);
	if (!check_ties(&MI, UINT64_C(1) << 15,
			UINT64_C(1) << (MAX_MC_OPS - 1)))
		return false;

	MCInst_Init(&MI, CS_ARCH_ARM);
	MI.flat_insn = &insn;
	insn.detail = NULL;
	memset(ops, 0, sizeof(ops));
	ops[3].Constraints = CONSTRAINT_MCOI_TIED_TO(0);
	ops[5].Constraints = CONSTRAINT_MCOI_TIED_TO(0);
	MCInst_handleWriteback(&MI, &desc, 1);
	if (!check_ties(&MI, 1, (1 << 3) | (1 << 5)))
		return false;

	ops[3].Constraints = CONSTRAINT_MCOI_TIED_TO(1);
	MCInst_handleWriteback(&MI, &desc, 1);
	if (!check_ties(&MI, 3, (1 << 3) | (1 << 5)))
		return false;
	ops[5].Constraints = CONSTRAINT_MCOI_TIED_TO(2);
	MCInst_handleWriteback(&MI, &desc, 1);
	if (!check_ties(&MI, (1 << 1) | (1 << 2), (1 << 3) | (1 << 5)))
		return false;

	// Updating a shorter description preserves previously populated slots.
	desc.NumOperands = 4;
	ops[3].Constraints = CONSTRAINT_MCOI_TIED_TO(3);
	MCInst_handleWriteback(&MI, &desc, 1);
	if (!check_ties(&MI, (1 << 2) | (1 << 3), (1 << 3) | (1 << 5)))
		return false;

	MCInst_Init(&MI, CS_ARCH_ARM);
	return check_ties(&MI, 0, 0);
}

static bool check_alias(cs_struct *handle, const PatternsForOpcode *table,
			unsigned opcode, const int64_t *operand,
			const char *expected)
{
	static const AliasPattern patterns[] = {
		{ 0, 0, 0, 0 },	 { 5, 0, 1, 1 },  { 10, 1, 1, 1 },
		{ 15, 0, 0, 0 }, { 21, 0, 0, 0 }, { 28, 0, 0, 0 },
	};
	static const AliasPatternCond conditions[] = {
		{ AliasPatternCond_K_Imm, 7 },
		{ AliasPatternCond_K_Imm, 9 },
	};
	static const char strings[] = "zero\0imm7\0imm9\0first\0second\0last";
	const AliasMatchingData data = {
		table, patterns, conditions, strings, NULL,
	};
	MCInst MI;
	MCInst_Init(&MI, CS_ARCH_AARCH64);
	MI.csh = handle;
	MCInst_setOpcode(&MI, opcode);
	if (operand)
		MCOperand_CreateImm0(&MI, *operand);
	const char *actual = matchAliasPatterns(&MI, &data);
	if ((!actual != !expected) ||
	    (actual && strcmp(actual, expected) != 0)) {
		fprintf(stderr, "Unexpected alias for opcode %u\n", opcode);
		return false;
	}
	return true;
}

static bool test_alias_lookup(void)
{
	static const PatternsForOpcode table[] = {
		{ 0, 0, 1 },  { 4, 1, 2 },	    { 19, 3, 1 },
		{ 19, 4, 1 }, { UINT32_MAX, 5, 1 }, { 0, 0, 0 },
	};
	static const PatternsForOpcode other[] = { { 4, 4, 1 }, { 0, 0, 0 } };
	static const PatternsForOpcode empty[] = { { 0, 0, 0 } };
	static const unsigned missing[] = { 1, 3, 5, 18, 20, UINT32_MAX - 1 };
	cs_struct handles[2] = { 0 };
	int64_t seven = 7, eight = 8, nine = 9;

	for (unsigned round = 0; round < 4; ++round) {
		cs_struct *handle = &handles[round % 2];
		if (!check_alias(handle, table, 0, NULL, "zero") ||
		    !check_alias(handle, table, 4, &seven, "imm7") ||
		    !check_alias(handle, table, 4, &nine, "imm9") ||
		    !check_alias(handle, table, 4, &eight, NULL) ||
		    !check_alias(handle, table, 4, NULL, NULL) ||
		    !check_alias(handle, table, 19, NULL, "first") ||
		    !check_alias(handle, table, 19, &seven, NULL) ||
		    !check_alias(handle, table, UINT32_MAX, NULL, "last"))
			return false;
		for (unsigned i = 0; i < sizeof(missing) / sizeof(missing[0]);
		     ++i)
			if (!check_alias(handle, table, missing[i], NULL, NULL))
				return false;
		if (!check_alias(handle, other, 4, NULL, "second") ||
		    !check_alias(handle, empty, 0, NULL, NULL) ||
		    !check_alias(handle, empty, UINT32_MAX, NULL, NULL) ||
		    !check_alias(handle, table, 19, NULL, "first"))
			return false;
	}
	return check_alias(NULL, table, UINT32_MAX, NULL, "last") &&
	       check_alias(NULL, empty, 0, NULL, NULL);
}

int main(void)
{
	return test_tie_membership() && test_alias_lookup() ? 0 : 1;
}

// SPDX-License-Identifier: BSD-3-Clause

#include "../../MCInst.h"
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

int main(void)
{
	return test_tie_membership() ? 0 : 1;
}

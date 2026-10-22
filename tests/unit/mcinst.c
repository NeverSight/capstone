/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../MCInst.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Check the last valid slot, capacity rejection, and reuse after clearing.
 * Both operand tags matter: different backends inspect different tags. */
static bool check_operands(bool registers_first)
{
	MCInst inst = { 0 };
	MCInst_setOpcode(&inst, UINT_MAX);
	MCInst_setOpcodePub(&inst, UINT_MAX - 1);
	for (unsigned i = 0; i < MAX_MC_OPS; ++i) {
		bool reg = (i % 2 == 0) == registers_first;
		if (reg)
			MCOperand_CreateReg0(&inst, UINT_MAX - i);
		else
			MCOperand_CreateImm0(&inst, INT64_MIN + i);
		const MCOperand *op = &inst.Operands[i];
		if (inst.size != i + 1 ||
		    op->Kind != (reg ? kRegister : kImmediate) ||
		    op->MachineOperandType != (reg ? kRegister : kImmediate) ||
		    (reg ? op->RegVal != UINT_MAX - i :
			   op->ImmVal != INT64_MIN + i))
			return false;
	}

#ifndef CAPSTONE_DEBUG
	MCInst full;
	memcpy(&full, &inst, sizeof(full));
	MCOperand_CreateReg0(&inst, 0);
	MCOperand_CreateImm0(&inst, 0);
	if (memcmp(&full, &inst, sizeof(inst)) != 0)
		return false;
#endif

	MCInst_clear(&inst);
	if (inst.size != 0 || MCInst_getOpcode(&inst) != UINT_MAX ||
	    MCInst_getOpcodePub(&inst) != UINT_MAX - 1)
		return false;
	MCOperand_CreateImm0(&inst, INT64_MAX);
	MCOperand_CreateReg0(&inst, UINT_MAX);
	return inst.size == 2 && inst.Operands[0].Kind == kImmediate &&
	       inst.Operands[0].MachineOperandType == kImmediate &&
	       inst.Operands[0].ImmVal == INT64_MAX &&
	       inst.Operands[1].Kind == kRegister &&
	       inst.Operands[1].MachineOperandType == kRegister &&
	       inst.Operands[1].RegVal == UINT_MAX;
}

int main(void)
{
	if (!check_operands(false) || !check_operands(true)) {
		fprintf(stderr, "MCInst operand capacity or reuse failed\n");
		return 1;
	}
	return 0;
}

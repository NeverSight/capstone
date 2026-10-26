/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include "../../MCInstrDesc.h"
#include "../../utils.h"
#include "../../arch/AArch64/AArch64BaseInfo.h"
#include "../../arch/AArch64/AArch64Mapping.h"

#define GET_INSTRINFO_MC_DESC
#include "../../arch/AArch64/AArch64GenInstrInfo.inc"
#include "../../arch/AArch64/AArch64GenPostprocess.inc"

/* Evaluate the real descriptor objects with native enum/constraint values,
 * independently of the generator's source parser. */
int main(void)
{
	unsigned implicit = 0, tied = 0;
	for (unsigned opcode = 0; opcode < ARR_SIZE(AArch64Descs.Insts);
	     ++opcode) {
		const MCInstrDesc *desc =
			&AArch64Descs.Insts[ARR_SIZE(AArch64Descs.Insts) - 1 -
					    opcode];
		unsigned flags = 0;
		for (unsigned i = 0; i < desc->NumOperands; ++i) {
			const MCOperandInfo *op = &desc->OpInfo[i];
			if (op->OperandType == AARCH64_OP_IMPLICIT_IMM_0 ||
			    (op->OperandType == MCOI_OPERAND_REGISTER &&
			     (op->RegClass == AArch64_MPRRegClassID ||
			      op->RegClass == AArch64_MPR8RegClassID ||
			      op->RegClass == AArch64_ZTRRegClassID)))
				flags |= 1;
			if (MCOperandInfo_isTiedToOp(op))
				flags |= 2;
		}
		if (flags != AArch64PostprocessFlags[opcode]) {
			fprintf(stderr, "projection mismatch %u\n", opcode);
			return 1;
		}
		implicit += !!(flags & 1);
		tied += !!(flags & 2);
	}
	printf("%zu descriptors equal: %u implicit, %u tied\n",
	       ARR_SIZE(AArch64Descs.Insts), implicit, tied);
	return 0;
}

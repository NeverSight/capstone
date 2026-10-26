/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include "../../MCInstrDesc.h"
#include "../../utils.h"

#ifdef WRITEBACK_TEST_ARM
#include "../../arch/ARM/ARMBaseInfo.h"
#include "../../arch/ARM/ARMMapping.h"
#define GET_INSTRINFO_MC_DESC
#include "../../arch/ARM/ARMGenInstrInfo.inc"
#include "../../arch/ARM/ARMGenWriteback.inc"
#endif

#ifdef WRITEBACK_TEST_RISCV
#include "../../arch/RISCV/RISCVBaseInfo.h"
#include "../../arch/RISCV/RISCVMapping.h"
#define GET_REGINFO_ENUM
#include "../../arch/RISCV/RISCVGenRegisterInfo.inc"
#define GET_INSTRINFO_MC_DESC
#include "../../arch/RISCV/RISCVGenInstrInfo.inc"
#include "../../arch/RISCV/RISCVGenWriteback.inc"
#endif

/* Native descriptor objects independently check the source projection. */
static bool check(const MCInstrDesc *descs, const uint8_t *flags, size_t count,
		  const char *arch)
{
	unsigned tied = 0;
	for (unsigned opcode = 0; opcode < count; ++opcode) {
		const MCInstrDesc *desc = &descs[count - 1 - opcode];
		bool expected = false;
		for (unsigned i = 0; i < desc->NumOperands; ++i)
			expected |= MCOperandInfo_isTiedToOp(&desc->OpInfo[i]);
		if (expected != flags[opcode]) {
			fprintf(stderr, "%s projection mismatch %u\n", arch,
				opcode);
			return false;
		}
		tied += expected;
	}
	printf("%s: %zu descriptors equal, %u tied\n", arch, count, tied);
	return true;
}

int main(void)
{
#ifdef WRITEBACK_TEST_ARM
	if (!check(ARMDescs.Insts, ARMWritebackFlags, ARR_SIZE(ARMDescs.Insts),
		   "ARM"))
		return 1;
#endif
#ifdef WRITEBACK_TEST_RISCV
	if (!check(RISCVDescs.Insts, RISCVWritebackFlags,
		   ARR_SIZE(RISCVDescs.Insts), "RISCV"))
		return 1;
#endif
	return 0;
}

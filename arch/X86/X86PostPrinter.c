/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "X86Mapping.h"

#ifdef X86_SEPARATE_POSTPRINTER
#include <string.h>

/* Preserve custom broadcast spellings, which may appear on a scalar operand. */
__attribute__((section(".cs_x86_postprinter_text")))
void X86_postprinter(csh handle, cs_insn *insn, SStream *mnem, MCInst *mci)
{
	if (insn && insn->id != X86_INS_VPCMP) {
		if (!insn->detail)
			return;
		if (X86_ONLY_REPAIRS_BROADCAST(insn->detail->x86.opcode[0]) &&
		    !strchr(mnem->buffer, '{'))
			return;
	}
	X86_postprinter_full(handle, insn, mnem, mci);
}
#endif
#endif

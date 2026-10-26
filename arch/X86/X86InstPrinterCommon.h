/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_X86_INSTPRINTERCOMMON_H
#define CS_X86_INSTPRINTERCOMMON_H

#include "../../MCInst.h"
#include "../../SStream.h"

#define CS_X86_MAXIMUM_OPERAND_SIZE 6

static inline uint64_t X86_relativeBranchTarget(cs_mode mode, uint64_t address,
						uint16_t length,
						uint64_t displacement,
						uint8_t immediate_size)
{
	uint64_t target = displacement + length + address;
	if (!(mode & CS_MODE_64))
		target &= UINT64_C(0xffffffff);
	else if ((mode & CS_MODE_X86_AMD) && immediate_size == 2)
		target &= UINT64_C(0xffff);
	return target;
}

void printSSEAVXCC(MCInst *MI, unsigned Op, SStream *O);
void printXOPCC(MCInst *MI, unsigned Op, SStream *O);
void printRoundingControl(MCInst *MI, unsigned Op, SStream *O);

#endif

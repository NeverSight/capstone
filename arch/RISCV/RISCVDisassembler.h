/* Capstone Disassembly Engine */
/* RISC-V Backend By Rodrigo Cortes Porto <porto703@gmail.com> & 
   Shawn Chang <citypw@gmail.com>, HardenedLinux@2018 */

#ifndef CS_RISCVDISASSEMBLER_H
#define CS_RISCVDISASSEMBLER_H

#include "../../include/capstone/capstone.h"
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"
#include "../../MCDisassembler.h"
#include "../../SStream.h"

void RISCV_init(MCRegisterInfo *MRI);

DecodeStatus RISCV_getInstruction(MCInst *MI, uint16_t *Size,
				  const uint8_t *Bytes, size_t BytesLen,
				  uint64_t Address, SStream *CS);

#endif

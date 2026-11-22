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

/* Select the position table in dedicated builds where scanning and detail
 * construction both benefit. GCC's full decoder keeps the descriptor walk. */
#if defined(CAPSTONE_RISCV_INIT_CONSTRUCTED_OPERANDS) && \
	(defined(CAPSTONE_DIET) || \
	 (defined(__linux__) && defined(__clang__) && \
	  (defined(__x86_64__) || defined(__aarch64__))))
#define RISCV_USE_STACK_OPERAND_POSITIONS
#endif

void RISCV_init(MCRegisterInfo *MRI);

DecodeStatus RISCV_getInstruction(MCInst *MI, uint16_t *Size,
				  const uint8_t *Bytes, size_t BytesLen,
				  uint64_t Address, SStream *CS);

#endif

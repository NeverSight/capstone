//===-- X86Disassembler.h - Disassembler for x86 and x86_64 -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_X86_DISASSEMBLER_H
#define CS_X86_DISASSEMBLER_H

#include "capstone/capstone.h"

#include "../../MCInst.h"

#include "../../MCRegisterInfo.h"
#include "X86DisassemblerDecoderCommon.h"

bool X86_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info);

/* The caller selects this entry only with text and detail disabled. */
bool X86_getInstructionScan(csh handle, const uint8_t *code, size_t code_len,
			    MCInst *instr, uint16_t *size);
/* Private result for text-free, detail-free core decoding. */
typedef struct X86ScanResult {
	unsigned opcode;
	unsigned opcode_pub;
	uint16_t length;
	uint8_t popcode_adjust;
} X86ScanResult;

bool X86_getInstructionScanResult(csh handle, const uint8_t *code,
				  size_t code_len, cs_insn *insn,
				  X86ScanResult *result);

/* Scan-only entry after source extension dispatch. */
bool X86_getInstructionAfterExtensions(csh ud, const uint8_t *code,
				       size_t code_len, MCInst *instr,
				       uint16_t *size,
				       uint8_t extension_opcode);
struct InternalInstruction;
bool X86_completeScan(MCInst *instr, struct InternalInstruction *insn,
		      uint16_t *size);

void X86_init(MCRegisterInfo *MRI);

#endif

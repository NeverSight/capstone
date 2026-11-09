//= X86IntelInstPrinter.h - Convert X86 MCInst to assembly syntax -*- C++ -*-=//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an X86 MCInst to Intel style .s file syntax.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_X86_INSTPRINTER_H
#define CS_X86_INSTPRINTER_H

#include "../../MCInst.h"
#include "../../SStream.h"

void X86_Intel_printInst(MCInst *MI, SStream *OS, void *Info);
#if defined(__GNUC__) && !defined(CAPSTONE_DIET) && \
	!defined(CAPSTONE_X86_REDUCE) && defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#define CAPSTONE_X86_PRECHECKED_PRINTER
void X86_Intel_printInstructionPrechecked(MCInst *MI, SStream *OS);
__attribute__((visibility("hidden"), noinline)) void
X86_Intel_printHexPrechecked(SStream *OS, uint64_t value, bool negative);
#endif

void X86_ATT_printInst(MCInst *MI, SStream *OS, void *Info);

#endif

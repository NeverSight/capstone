/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifndef CS_XCOREINSTPRINTER_H
#define CS_XCOREINSTPRINTER_H

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"

void XCore_printInst(MCInst *MI, SStream *O, void *Info);

#endif

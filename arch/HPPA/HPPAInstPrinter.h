/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifndef CS_HPPAINSTPRINTER_H
#define CS_HPPAINSTPRINTER_H

#include <capstone/capstone.h>

#include "../../MCInst.h"
#include "../../SStream.h"

void HPPA_printInst(MCInst *MI, SStream *O, void *Info);

#endif

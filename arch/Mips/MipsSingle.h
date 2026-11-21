/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_MIPS_SINGLE_H
#define CS_MIPS_SINGLE_H

#include <capstone/capstone.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Private static-link entry for callers that decode one MIPS address. Writes
 * the same cs_malloc-owned instruction as cs_disasm_iter, without returning
 * the three advanced cursor values. */
bool Mips_disasmOne(csh handle, const uint8_t *code, size_t size,
		    uint64_t address, cs_insn *insn);

#ifdef __cplusplus
}
#endif
#endif

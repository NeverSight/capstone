/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_EVEX_MEMORY_TABLES_H
#define CS_X86_EVEX_MEMORY_TABLES_H

#include "../../cs_priv.h"

struct EvexMemoryOutputRow {
	uint16_t id;
	char mnemonic[16];
	uint8_t group_count, groups[4], access[2];
};

extern CAPSTONE_INTERNAL const uint8_t x86_evex_memory_opcodes[256];
extern CAPSTONE_INTERNAL const uint8_t x86_evex_memory_prefixes[][8];
extern CAPSTONE_INTERNAL const struct EvexMemoryOutputRow
	x86_evex_memory_rows[][2][3];

#endif

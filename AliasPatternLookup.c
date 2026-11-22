/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "AliasPatternLookup.h"

#if !defined(CAPSTONE_DIET) && \
	(defined(CAPSTONE_HAS_AARCH64) || defined(CAPSTONE_HAS_ARM) || \
	 defined(CAPSTONE_HAS_MIPS) || defined(CAPSTONE_HAS_POWERPC) || \
	 defined(CAPSTONE_HAS_RISCV) || defined(CAPSTONE_HAS_SPARC) || \
	 defined(CAPSTONE_HAS_LOONGARCH))
#include "MathExtras.h"
#include "utils.h"

#if defined(__ELF__) && defined(__GNUC__)
#define ALIAS_PATTERN_CODE __attribute__((section(".cs_alias_pattern_lookup")))
#define ALIAS_PATTERN_DATA __attribute__((section(".cs_alias_pattern_rows")))
#else
#define ALIAS_PATTERN_CODE
#define ALIAS_PATTERN_DATA
#endif

typedef struct {
	uint16_t first_row;
	uint16_t mask;
} AliasOpcodeBlock;

/* The matcher accepts a suffix of its sorted table and owns all operand,
 * feature and alias-printing decisions. */
static inline const char *matchAliasBlock(MCInst *MI, const AliasMatchingData *data,
					  unsigned offset, const AliasOpcodeBlock *blocks,
					  size_t block_count)
{
	const unsigned index = offset / 16;
	if (index >= block_count)
		return NULL;
	const unsigned bit = 1u << (offset % 16);
	const AliasOpcodeBlock block = blocks[index];
	if (!(block.mask & bit))
		return NULL;
	AliasMatchingData suffix = *data;
	suffix.OpToPatterns += block.first_row + CountPopulation_32(block.mask & (bit - 1));
	return matchAliasPatterns(MI, &suffix);
}

#ifdef CAPSTONE_HAS_AARCH64
#include "arch/AArch64/AArch64GenAliasPatternRows.inc"
ALIAS_PATTERN_CODE
const char *matchAArch64AliasPatterns(MCInst *MI, const AliasMatchingData *data)
{
	return matchAliasBlock(MI, data, MI->Opcode - AArch64_FIRST_ALIAS_OPCODE,
			       AArch64_alias_blocks, ARR_SIZE(AArch64_alias_blocks));
}
#endif

#ifdef CAPSTONE_HAS_MIPS
#include "arch/Mips/MipsGenAliasPatternRows.inc"
ALIAS_PATTERN_CODE
const char *matchMipsAliasPatterns(MCInst *MI, const AliasMatchingData *data)
{
	return matchAliasBlock(MI, data, MI->Opcode - Mips_FIRST_ALIAS_OPCODE,
			       Mips_alias_blocks, ARR_SIZE(Mips_alias_blocks));
}
#endif

#ifdef CAPSTONE_HAS_ARM
#include "arch/ARM/ARMGenAliasPatternRows.inc"
ALIAS_PATTERN_CODE
const char *matchARMAliasPatterns(MCInst *MI, const AliasMatchingData *data)
{
	return matchAliasBlock(MI, data, MI->Opcode - ARM_FIRST_ALIAS_OPCODE,
			       ARM_alias_blocks, ARR_SIZE(ARM_alias_blocks));
}
#endif

#ifdef CAPSTONE_HAS_POWERPC
#include "arch/PowerPC/PPCGenAliasPatternRows.inc"
ALIAS_PATTERN_CODE
const char *matchPPCAliasPatterns(MCInst *MI, const AliasMatchingData *data)
{
	return matchAliasBlock(MI, data, MI->Opcode - PPC_FIRST_ALIAS_OPCODE,
			       PPC_alias_blocks, ARR_SIZE(PPC_alias_blocks));
}
#endif

#ifdef CAPSTONE_HAS_RISCV
#include "arch/RISCV/RISCVGenAliasPatternRows.inc"
ALIAS_PATTERN_CODE
const char *matchRISCVAliasPatterns(MCInst *MI, const AliasMatchingData *data)
{
	return matchAliasBlock(MI, data, MI->Opcode - RISCV_FIRST_ALIAS_OPCODE,
			       RISCV_alias_blocks, ARR_SIZE(RISCV_alias_blocks));
}
#endif

#ifdef CAPSTONE_HAS_SPARC
#include "arch/Sparc/SparcGenAliasPatternRows.inc"
ALIAS_PATTERN_CODE
const char *matchSparcAliasPatterns(MCInst *MI, const AliasMatchingData *data)
{
	return matchAliasBlock(MI, data, MI->Opcode - Sparc_FIRST_ALIAS_OPCODE,
			       Sparc_alias_blocks, ARR_SIZE(Sparc_alias_blocks));
}
#endif

#ifdef CAPSTONE_HAS_LOONGARCH
#include "arch/LoongArch/LoongArchGenAliasPatternRows.inc"
ALIAS_PATTERN_CODE
const char *matchLoongArchAliasPatterns(MCInst *MI, const AliasMatchingData *data)
{
	return matchAliasBlock(MI, data, MI->Opcode - LoongArch_FIRST_ALIAS_OPCODE,
			       LoongArch_alias_blocks, ARR_SIZE(LoongArch_alias_blocks));
}
#endif

#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "Mapping.h"

#if defined(CAPSTONE_ISOLATED_ALIAS_LOOKUP) && \
	!defined(CAPSTONE_USE_ALIAS_TRIE) && \
	(defined(CAPSTONE_HAS_AARCH64) || \
	 (defined(CAPSTONE_HAS_MIPS) && !defined(CAPSTONE_DIET)))
#define CAPSTONE_ALIAS_ROLLED_LOOP

#if defined(__ELF__) && defined(__GNUC__)
#define ALIAS_LOOKUP_CODE __attribute__((noinline, section(".cs_alias_lookup")))
#define ALIAS_LOOKUP_DATA __attribute__((section(".cs_alias_lookup_rodata")))
#else
#define ALIAS_LOOKUP_CODE __attribute__((noinline))
#define ALIAS_LOOKUP_DATA
#endif

/* Preserve the original caller ABI while the generated trie owns lookup.
 * Keep a compiler-outlined parser in the same dedicated code section. */
static void map_set_alias_id_trie_impl(MCInst *MI, const SStream *O,
				       const alias_trie_node *trie,
				       size_t trie_size) ALIAS_LOOKUP_CODE
	__attribute__((minsize));
#include "MappingAlias.h"

#ifdef CAPSTONE_HAS_AARCH64
static const alias_trie_node aarch64_alias_trie[] ALIAS_LOOKUP_DATA = {
#include "arch/AArch64/AArch64GenAliasTrie.inc"
};

ALIAS_LOOKUP_CODE
void map_set_aarch64_alias_id(MCInst *MI, const SStream *O, const name_map *map,
			      int map_size)
{
	(void)map;
	(void)map_size;
	map_set_alias_id_trie_impl(MI, O, aarch64_alias_trie,
				   ARR_SIZE(aarch64_alias_trie));
}
#endif

#if defined(CAPSTONE_HAS_MIPS) && !defined(CAPSTONE_DIET)
static const alias_trie_node mips_alias_trie[] ALIAS_LOOKUP_DATA = {
#include "arch/Mips/MipsGenAliasTrie.inc"
};

ALIAS_LOOKUP_CODE
void map_set_mips_alias_id(MCInst *MI, const SStream *O, const name_map *map,
			   int map_size)
{
	(void)map;
	(void)map_size;
	map_set_alias_id_trie_impl(MI, O, mips_alias_trie,
				   ARR_SIZE(mips_alias_trie));
}
#endif

#endif

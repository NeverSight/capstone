/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_MAPPING_ALIAS_H
#define CS_MAPPING_ALIAS_H

#include "Mapping.h"
#include "utils.h"

static inline bool char_ends_mnem(const char c, cs_arch arch)
{
	switch (arch) {
	default:
		return (!c || c == ' ' || c == '\t' || c == '.');
	case CS_ARCH_PPC:
	case CS_ARCH_RISCV:
		return (!c || c == ' ' || c == '\t');
	case CS_ARCH_SPARC:
		return (!c || c == ' ' || c == '\t' || c == ',');
	}
}

#ifdef CAPSTONE_ALIAS_ROLLED_LOOP
static
#else
static inline
#endif
	void map_set_alias_id_trie_impl(MCInst *MI, const SStream *O,
					const alias_trie_node *trie,
					size_t trie_size)
{
	unsigned int id = 0;
	if (MCInst_isAlias(MI)) {
		const char *name = O->buffer;
		while (is_blank_char(*name))
			++name;
		unsigned int state = 1;
		/* The public alias parser considers at most 15 bytes. */
#ifdef CAPSTONE_ALIAS_ROLLED_LOOP
#pragma clang loop unroll(disable)
#endif
		for (size_t i = 0; i < 15; ++i) {
			if (char_ends_mnem(name[i], MI->csh->arch))
				break;
			unsigned int next =
				trie[state].offset + (unsigned char)name[i];
			if (next >= trie_size || trie[next].parent != state) {
				state = 0;
				break;
			}
			state = next;
		}
		id = trie[state].id;
	}
	MI->flat_insn->alias_id = id;
}

#endif

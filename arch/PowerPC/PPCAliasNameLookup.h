/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_PPC_ALIAS_NAME_LOOKUP_H
#define CS_PPC_ALIAS_NAME_LOOKUP_H

#ifdef PPC_INDEXED_ALIAS_NAMES
#include "../../MappingAlias.h"
/* This lookup uses the PowerPC name map only. Keep its loop out of the
 * shared ELF instruction decoder and alias lookup sections. */
__attribute__((noinline, minsize, section(".cs_ppc_alias_text")))
void PPC_setAliasId(MCInst *MI, const SStream *O,
		    const ppc_alias_name *names, unsigned mask)
{
	unsigned id = 0;
	if (MCInst_isAlias(MI)) {
		const char *name = O->buffer;
		while (is_blank_char(*name))
			++name;
		size_t length = 0;
		unsigned hash = 0;
		while (length < 15 && !char_ends_mnem(name[length], CS_ARCH_PPC)) {
			hash = hash * 33 + (unsigned char)name[length];
			++length;
		}
		for (unsigned index = names[hash & mask].first; index;) {
			const ppc_alias_name *entry = &names[index - 1];
			size_t matched = 0;
			while (matched < length &&
			       entry->name[matched] == name[matched])
				++matched;
			if (matched == length && !entry->name[matched]) {
				id = entry->id;
				break;
			}
			index = entry->next;
		}
	}
	MI->flat_insn->alias_id = id;
}
#endif

#endif

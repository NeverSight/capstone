/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static bool compare_halfwords(csh scan, cs_insn *a, csh full, cs_insn *b)
{
	for (uint32_t word = 0; word <= UINT16_MAX; ++word) {
		const uint8_t bytes[] = { (uint8_t)word, (uint8_t)(word >> 8),
					  0x49, 0x7f };
		/* Two bytes check standalone encodings and truncated long forms.
		 * Four bytes also check the priority of a short instruction. */
		for (size_t length = 2; length <= 4; length += 2) {
			const uint8_t *pa = bytes, *pb = bytes;
			size_t na = length, nb = length;
			uint64_t pc = 0x10000, ip = pc;
			bool accepted = cs_disasm_iter(scan, &pa, &na, &pc, a);
			bool reference = cs_disasm_iter(full, &pb, &nb, &ip, b);
			if (accepted == reference && pa == pb && na == nb &&
			    pc == ip && (!accepted ||
				(a->id == b->id && a->size == b->size &&
				 a->address == b->address && a->illegal == b->illegal &&
				 a->is_alias == b->is_alias && !a->mnemonic[0] &&
				 !a->op_str[0] && !memcmp(a->bytes, b->bytes, a->size))))
				continue;
			fprintf(stderr, "word 0x%04x, %zu bytes\n", (unsigned)word, length);
			return false;
		}
	}
	return true;
}

int main(void)
{
	csh scan = 0, full = 0;
	cs_insn *a = NULL, *b = NULL;
	bool ok = false;
	if (cs_open(CS_ARCH_XCORE, CS_MODE_LITTLE_ENDIAN, &scan) ||
	    cs_open(CS_ARCH_XCORE, CS_MODE_LITTLE_ENDIAN, &full) ||
	    cs_option(scan, CS_OPT_TEXT, CS_OPT_OFF))
		goto done;
	a = cs_malloc(scan);
	b = cs_malloc(full);
	ok = a && b && compare_halfwords(scan, a, full, b);
done:
	if (a)
		cs_free(a, 1);
	if (b)
		cs_free(b, 1);
	if (scan)
		cs_close(&scan);
	if (full)
		cs_close(&full);
	return ok ? 0 : 1;
}

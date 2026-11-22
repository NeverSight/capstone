/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../arch/Mips/MipsSingle.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static bool compare(csh handle, const uint8_t *bytes, size_t n, uint64_t pc,
		    cs_insn *iter, cs_insn *one)
{
	const uint8_t *cursor = bytes;
	size_t remaining = n;
	uint64_t address = pc;
	const bool expected =
		cs_disasm_iter(handle, &cursor, &remaining, &address, iter);
	const cs_err error = cs_errno(handle);
	if (Mips_disasmOne(handle, bytes, n, pc, one) != expected ||
	    cs_errno(handle) != error)
		return false;
	return !expected ||
	       (address == pc + one->size && remaining == n - one->size &&
		memcmp(iter, one, offsetof(cs_insn, detail)) == 0 &&
		memcmp(iter->detail, one->detail,
		       offsetof(cs_detail, mips) + sizeof(cs_mips)) == 0);
}

static bool profile(cs_mode mode, bool big)
{
	csh handle;
	if (cs_open(CS_ARCH_MIPS, mode | (big ? CS_MODE_BIG_ENDIAN : 0),
		    &handle))
		return false;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn *iter = cs_malloc(handle), *one = cs_malloc(handle);
	bool ok = iter && one;
	if (ok) {
		cs_detail *a = iter->detail, *b = one->detail;
		memset(iter, 0, sizeof(*iter));
		memset(one, 0, sizeof(*one));
		iter->detail = a;
		one->detail = b;
		memset(a, 0, sizeof(*a));
		memset(b, 0, sizeof(*b));
	}
	for (unsigned opts = 0; ok && opts < 8; ++opts) {
		cs_option(handle, CS_OPT_DETAIL,
			  opts & 1 ? CS_OPT_ON : CS_OPT_OFF);
		cs_option(handle, CS_OPT_TEXT,
			  opts & 2 ? CS_OPT_ON : CS_OPT_OFF);
		cs_option(handle, CS_OPT_SKIPDATA,
			  opts & 4 ? CS_OPT_ON : CS_OPT_OFF);
		// All first halfwords in compressed modes, including truncated
		// prefixes. Classic patterns vary both register and immediate bits.
		const unsigned stride = opts == 1 ? 1 : 61;
		for (unsigned v = 0; ok && v < 65536; v += stride) {
			uint16_t suffix = (uint16_t)(v * 251u + 7u);
			uint8_t bytes[4];
			bytes[big ? 0 : 1] = (uint8_t)(v >> 8);
			bytes[big ? 1 : 0] = (uint8_t)v;
			bytes[big ? 2 : 3] = (uint8_t)(suffix >> 8);
			bytes[big ? 3 : 2] = (uint8_t)suffix;
			uint64_t pc = UINT64_C(0x12345000) + v * 4;
			ok = compare(handle, bytes, 4, pc, iter, one) &&
			     compare(handle, bytes, v & 3, pc, iter, one);
		}
	}
	/* Vary every suffix behind an EXTEND prefix; the prefix can select
	 * registers, immediates, reserved forms and instruction groups. */
	if (ok && (mode & CS_MODE_MIPS16)) {
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF);
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
		for (unsigned v = 0; ok && v < 65536; ++v) {
			const uint16_t prefix = 0xf000 | (v & 0x7ff);
			uint8_t bytes[4];
			bytes[big ? 0 : 1] = (uint8_t)(prefix >> 8);
			bytes[big ? 1 : 0] = (uint8_t)prefix;
			bytes[big ? 2 : 3] = (uint8_t)(v >> 8);
			bytes[big ? 3 : 2] = (uint8_t)v;
			ok = compare(handle, bytes, sizeof(bytes),
				     UINT64_C(0xfffffffc) - 2 * v, iter, one);
		}
	}
	cs_free(iter, iter ? 1 : 0);
	cs_free(one, one ? 1 : 0);
	cs_close(&handle);
	return ok;
}

int main(void)
{
	const cs_mode modes[] = { CS_MODE_MIPS32R2,
				  CS_MODE_MIPS64R2,
				  CS_MODE_MIPS32R6,
				  CS_MODE_MIPS64R6,
				  CS_MODE_MIPS16,
				  CS_MODE_MIPS32R2 | CS_MODE_MIPS16,
				  CS_MODE_MIPS32R2 | CS_MODE_MICRO,
				  CS_MODE_MIPS64R2 | CS_MODE_MICRO };
	for (unsigned i = 0; i < sizeof(modes) / sizeof(*modes); ++i)
		for (unsigned big = 0; big < 2; ++big)
			if (!profile(modes[i], big != 0)) {
				fprintf(stderr,
					"MIPS single-instruction mismatch, mode %u, big %u\n",
					(unsigned)modes[i], big);
				return 1;
			}
	return 0;
}

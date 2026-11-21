/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_UNSIGNED_IMMEDIATE_H
#define CS_X86_UNSIGNED_IMMEDIATE_H

static char *writeUnsignedImmediate(char *out, uint64_t value)
{
	if (value <= HEX_THRESHOLD) {
		*out = (char)('0' + value);
		return out + 1;
	} else {
		static const char digits[] = "0123456789abcdef";
		char temp[16], *end = temp + sizeof(temp), *start = end;
		uint64_t n = value;
		do {
			*--start = digits[n & 15];
			n >>= 4;
		} while (n);
		memcpy(out, "0x", 2);
		memcpy(out + 2, start, end - start);
		return out + 2 + (end - start);
	}
}

#endif

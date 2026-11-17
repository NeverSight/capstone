/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_EVEX_ADMISSION_H
#define CS_X86_EVEX_ADMISSION_H

/* Arguments are local values. Keep the extent check before field reads. */
#define X86_EVEX_REGISTER_PREFIX_REJECTS(code, size) \
	((size) < 6 || ((code)[2] & 7) != 5 || ((code)[3] & 0x97) || \
	 ((code)[3] & 0x60) == 0x60)
#define X86_EVEX_REGISTER_EXTRACT(key) (((key) & ~0x22u) == 0x319)
#define X86_EVEX_EXTRACT_SOURCE_REJECTS(code) \
	(((code)[2] & 0x78) != 0x78 || !((code)[3] & 8))

#endif

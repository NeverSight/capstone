/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_VECTOR_REGISTER_WRITER_H
#define CS_X86_VECTOR_REGISTER_WRITER_H

static char *writeVectorRegister(char *out, unsigned length_code,
				 unsigned number)
{
	*out++ = "xyz"[length_code];
	*out++ = 'm';
	*out++ = 'm';
	if (number >= 10)
		*out++ = (char)('0' + number / 10);
	*out++ = (char)('0' + number % 10);
	return out;
}

#endif

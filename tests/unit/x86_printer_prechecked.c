/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../arch/X86/X86Disassembler.h"
#include "../../arch/X86/X86InstPrinter.h"
#include "../../arch/X86/X86Mapping.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifdef CAPSTONE_X86_PRECHECKED_PRINTER
static int passthrough(char *buffer, size_t size, const char *format,
		       va_list args)
{
	return vsnprintf(buffer, size, format, args);
}

typedef struct {
	MCInst internal;
	cs_insn public;
	cs_detail detail;
	SStream stream;
	cs_struct handle;
} Result;

static void print(Result *out, const Result *seed, size_t index, unsigned flags,
		  bool generic)
{
	*out = *seed;
	out->internal.csh = &out->handle;
	out->internal.flat_insn = &out->public;
	out->public.detail = seed->public.detail ? &out->detail : NULL;
	out->handle.doing_mem = false;
	memset(&out->stream, 0xa5, sizeof(out->stream));
	out->stream.index = index;
	out->stream.buffer[index] = 0;
	out->stream.is_closed = flags & 1;
	out->stream.markup_stream = flags & 2;
	out->stream.prefixed_by_markup = flags & 4;
	out->stream.unsigned_num = flags & 8;
	cs_vsnprintf = generic ? passthrough : vsnprintf;
	X86_Intel_printInst(&out->internal, &out->stream, NULL);
	cs_vsnprintf = vsnprintf;
	// Compare complete private/public values after normalizing object addresses.
	out->internal.csh = NULL;
	out->internal.flat_insn = NULL;
	out->public.detail = NULL;
}

int main(void)
{
	static const uint8_t code[][15] = {
		{ 0x90 },
		{ 0xc3 },
		{ 0x50 },
		{ 0x58 },
		{ 0xa5 },
		{ 0xf3, 0x64, 0xa5 },
		{ 0xf0, 0x01, 0x00 },
		{ 0x48, 0x8b, 0x84, 0x8b, 0xff, 0xff, 0xff, 0x7f },
		{ 0x64, 0x8b, 0x84, 0x8b, 0xff, 0xff, 0xff, 0x80 },
		{ 0xb8, 0xff, 0xff, 0xff, 0xff },
		{ 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0 },
		{ 0x48, 0xb8, 0xff, 0, 0, 0, 0, 0, 0, 0 },
		{ 0x48, 0xb8, 0, 0, 1, 0, 0, 0, 0, 0 },
		{ 0x48, 0xb8, 0, 0, 0, 0, 1, 0, 0, 0 },
		{ 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 1 },
		{ 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0x80 },
		{ 0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 1 },
		{ 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
		{ 0xe8, 0xff, 0xff, 0xff, 0x7f },
		{ 0x0f, 0xae, 0x00 },
		{ 0xd9, 0x20 },
		{ 0xc5, 0xf8, 0x59, 0xc1 },
		{ 0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc1 },
		{ 0xf3, 0x0f, 0xc2, 0xc1, 0 },
	};
	static const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	static const cs_opt_value syntaxes[] = { CS_OPT_SYNTAX_INTEL,
						 CS_OPT_SYNTAX_MASM };
	unsigned long comparisons = 0;
	for (unsigned mode = 0; mode < 3; ++mode) {
		csh handle = 0;
		if (cs_open(CS_ARCH_X86, modes[mode], &handle))
			return 1;
		for (unsigned syntax = 0; syntax < 2; ++syntax) {
			if (cs_option(handle, CS_OPT_SYNTAX, syntaxes[syntax]))
				return 2;
			for (unsigned details = 0; details < 2; ++details) {
				cs_option(handle, CS_OPT_DETAIL,
					  details ? CS_OPT_ON : CS_OPT_OFF);
				for (unsigned ci = 0;
				     ci < sizeof(code) / sizeof(code[0]);
				     ++ci) {
					Result seed = { 0 }, expected, actual;
					seed.handle =
						*(cs_struct *)(uintptr_t)handle;
					MCInst_InitX86(&seed.internal);
					seed.internal.csh = &seed.handle;
					seed.internal.flat_insn = &seed.public;
					seed.public.detail =
						details ? &seed.detail : NULL;
					seed.internal.address =
						seed.public.address = UINT64_C(
							0xffffffff80000000);
					uint16_t size = 0;
					if (!X86_getInstruction(
						    (csh)(uintptr_t)&seed.handle,
						    code[ci], sizeof(code[ci]),
						    &seed.internal, &size,
						    seed.public.address, NULL))
						continue;
					seed.public.size = size;
					X86_get_insn_id(&seed.handle,
							&seed.public,
							seed.internal.Opcode);
					for (size_t index = 0;
					     index < SSTREAM_BUF_LEN; ++index)
						for (unsigned flags = 0;
						     flags < 16; ++flags) {
							print(&expected, &seed,
							      index, flags,
							      true);
							print(&actual, &seed,
							      index, flags,
							      false);
							if (memcmp(&actual.internal,
								   &expected.internal,
								   sizeof(MCInst)) ||
							    memcmp(&actual.public,
								   &expected.public,
								   sizeof(cs_insn)) ||
							    memcmp(&actual.detail,
								   &expected.detail,
								   sizeof(cs_detail)) ||
							    memcmp(&actual.stream,
								   &expected.stream,
								   sizeof(SStream))) {
								fprintf(stderr,
									"printer state mismatch: mode=%u syntax=%u detail=%u case=%u index=%zu flags=%u\n",
									mode,
									syntax,
									details,
									ci,
									index,
									flags);
								return 3;
							}
							++comparisons;
						}
				}
			}
		}
		cs_close(&handle);
	}
	printf("Compared %lu complete printer stream/private/detail states\n",
	       comparisons);
	return comparisons ? 0 : 4;
}
#else
int main(void)
{
	return 77;
}
#endif

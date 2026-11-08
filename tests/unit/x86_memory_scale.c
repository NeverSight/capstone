/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../arch/X86/X86InstPrinterCommon.h"
#include "../../cs_priv.h"

static void old_write(SStream *s, uint64_t scale, bool att)
{
	SStream_concat(s, att ? ", %" PRIu64 : "*%" PRIu64, scale);
}
static void new_write(SStream *s, uint64_t scale, bool att)
{
	X86_printMemoryScale(s, scale, att);
}
static unsigned hook_mode, calls;
static char hook_format[32];
static uint64_t hook_value;
static int hook(char *out, size_t size, const char *fmt, va_list ap)
{
	++calls;
	strcpy(hook_format, fmt);
	va_list copy;
	va_copy(copy, ap);
	hook_value = va_arg(copy, uint64_t);
	va_end(copy);
	if (hook_mode == 3)
		cs_vsnprintf = vsnprintf;
	memset(out, 0x5a, size);
	int n = vsnprintf(out, size, fmt, ap);
	if (hook_mode == 1)
		return -1;
	if (hook_mode == 2)
		return 1000;
	return n;
}
static int verify(void)
{
	const uint64_t values[] = { 0, 1, 2, 3,	 4,  5,		 6,
				    7, 8, 9, 10, 16, UINT32_MAX, UINT64_MAX };
	uint64_t count = 0;
	for (unsigned h = 0; h < 5; ++h)
		for (unsigned att = 0; att < 2; ++att)
			for (unsigned flags = 0; flags < 16; ++flags)
				for (size_t index = 0;
				     index < (cs_support(CS_SUPPORT_DIET) ?
						      SSTREAM_BUF_LEN :
						      SSTREAM_BUF_LEN + 4);
				     ++index)
					for (unsigned v = 0;
					     v <
					     sizeof(values) / sizeof(values[0]);
					     ++v) {
						SStream a, b;
						memset(&a, 0xa5, sizeof(a));
						a.index =
							index == SSTREAM_BUF_LEN +
										3 ?
								SIZE_MAX :
								index;
						a.is_closed = (flags & 1) != 0;
						a.markup_stream = (flags & 2) !=
								  0;
						a.prefixed_by_markup =
							(flags & 4) != 0;
						a.unsigned_num = (flags & 8) !=
								 0;
						if (a.index < SSTREAM_BUF_LEN)
							a.buffer[a.index] = 0;
						memcpy(&b, &a, sizeof(a));
						hook_mode = h - 1;
						calls = 0;
						hook_format[0] = 0;
						hook_value = 0;
						cs_vsnprintf = h ? hook :
								   vsnprintf;
						old_write(&a, values[v], att);
						unsigned old_calls = calls;
						uint64_t old_value = hook_value;
						char old_format[32];
						strcpy(old_format, hook_format);
						bool old_default =
							cs_vsnprintf ==
							vsnprintf;
						calls = 0;
						hook_format[0] = 0;
						hook_value = 0;
						cs_vsnprintf = h ? hook :
								   vsnprintf;
						new_write(&b, values[v], att);
						if (memcmp(&a, &b, sizeof(a)) ||
						    old_calls != calls ||
						    old_value != hook_value ||
						    strcmp(old_format,
							   hook_format) ||
						    old_default !=
							    (cs_vsnprintf ==
							     vsnprintf)) {
							fprintf(stderr,
								"mismatch hook=%u att=%u flags=%u index=%zu scale=%" PRIu64
								"\n",
								h, att, flags,
								index,
								values[v]);
							return 1;
						}
						++count;
					}
	cs_vsnprintf = vsnprintf;
	printf("{\"comparisons\":%" PRIu64 "}\n", count);
	return 0;
}
int main(void)
{
	const cs_opt_mem saved = { cs_mem_malloc, cs_mem_calloc, cs_mem_realloc,
				   cs_mem_free, cs_vsnprintf };
	int result = verify();
	cs_vsnprintf = saved.vsnprintf;
	return result;
}

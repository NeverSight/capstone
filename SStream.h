/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_SSTREAM_H_
#define CS_SSTREAM_H_

#include "include/capstone/platform.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef enum {
	Markup_Immediate,
	Markup_Register,
	Markup_Target,
	Markup_Memory,
} SStreamMarkup;

#define SSTREAM_BUF_LEN 512

typedef struct SStream {
	char buffer[SSTREAM_BUF_LEN];
	size_t index;
	bool is_closed;
	bool markup_stream; ///< If true, markups to the stream are allowed.
	bool prefixed_by_markup; ///< Set after the stream wrote a markup for an operand.
	bool unsigned_num; ///< Print all numbers as unsigned. Set with CS_OPT_UNSIGNED.
} SStream;

#define SSTREAM_RETURN_IF_CLOSED(OS) \
	do { \
		if (OS->is_closed) \
			return; \
	} while (0)

void SStream_Init(SStream *ss);
void SStream_opt_unum(SStream *ss, bool print_unsigned_numbers);

const char *SStream_replc(const SStream *ss, char elem, char repl);

void SStream_replc_str(SStream *ss, char chr, const char *rstr);

const char *SStream_rbuf(const SStream *ss);

void SStream_extract_mnem_opstr(const SStream *ss, char *mnem_buf,
				size_t mnem_buf_size, char *op_str_buf,
				size_t op_str_buf_size);

void SStream_trimls(SStream *ss);

void SStream_Flush(SStream *ss, FILE *file);

void SStream_Open(SStream *ss);

void SStream_Close(SStream *ss);

void SStream_concat(SStream *ss, const char *fmt, ...);

// Append a lowercase 0x-prefixed magnitude, optionally preceded by a minus sign.
void SStream_concat_hex64(SStream *ss, uint64_t value, bool negative);

void SStream_concat0(SStream *ss, const char *s);

// Append an alias mnemonic prefix containing no NUL bytes. The source is a
// static table, disjoint from the stream. Preserve custom allocation callbacks.
void SStream_concat0_substr(SStream *ss, const char *s, size_t len);

// The caller supplies the exact length of the NUL-terminated string.
// Source bytes must not overlap the append range.
static inline void SStream_concat0_n(SStream *ss, const char *s, size_t len)
{
#ifndef CAPSTONE_DIET
	assert(ss && s);
	if (ss->is_closed || len == 0)
		return;
	if (len < SSTREAM_BUF_LEN && ss->index < SSTREAM_BUF_LEN - len &&
	    !(ss->markup_stream && ss->prefixed_by_markup)) {
		char *out = ss->buffer + ss->index;
		// Two fixed-size copies cover short table names without a libc call.
		// Both reads and writes stay within the exact string length.
		if (len > 32) {
			memcpy(out, s, len);
		} else if (len >= 16) {
			memcpy(out, s, 16);
			memcpy(out + len - 16, s + len - 16, 16);
		} else if (len >= 8) {
			memcpy(out, s, 8);
			memcpy(out + len - 8, s + len - 8, 8);
		} else if (len >= 4) {
			memcpy(out, s, 4);
			memcpy(out + len - 4, s + len - 4, 4);
		} else if (len >= 2) {
			memcpy(out, s, 2);
			memcpy(out + len - 2, s + len - 2, 2);
		} else {
			out[0] = s[0];
		}
		ss->index += len;
		ss->buffer[ss->index] = '\0';
		return;
	}
#else
	(void)len;
#endif
	SStream_concat0(ss, s);
}

#if defined(__GNUC__) && !defined(CAPSTONE_DIET)
// Expose constant tokens to the compiler without expanding the general writer.
static inline __attribute__((always_inline)) void
SStream_concat0_inline(SStream *ss, const char *s)
{
	assert(ss && s);
	if (ss->is_closed)
		return;
	const size_t len = __builtin_strlen(s);
	if (len == 0)
		return;
	if (len < SSTREAM_BUF_LEN && ss->index < SSTREAM_BUF_LEN - len &&
	    !(ss->markup_stream && ss->prefixed_by_markup)) {
		memcpy(ss->buffer + ss->index, s, len);
		ss->index += len;
		ss->buffer[ss->index] = '\0';
		return;
	}
	SStream_concat0(ss, s);
}
// Inline parameters can hide literal lengths; keep this test at the call site.
#define SStream_concat0(ss, s) \
	(__builtin_constant_p(__builtin_strlen(s)) ? \
		 SStream_concat0_inline((ss), (s)) : \
		 (SStream_concat0)((ss), (s)))
#endif

void SStream_concat1(SStream *ss, const char c);

void printInt64Bang(SStream *O, int64_t val);

void printUInt64Bang(SStream *O, uint64_t val);

void printInt64(SStream *O, int64_t val);
void printUInt64(SStream *O, uint64_t val);

void printInt32Bang(SStream *O, int32_t val);

void printInt8(SStream *O, int8_t val);
void printInt16(SStream *O, int16_t val);
void printInt16HexOffset(SStream *O, int16_t val);

void printInt32(SStream *O, int32_t val);
void printInt32Hex(SStream *ss, int32_t val);
void printInt32HexOffset(SStream *ss, int32_t val);

void printUInt32Bang(SStream *O, uint32_t val);

void printUInt8(SStream *ss, uint8_t val);
void printUInt16(SStream *ss, uint16_t val);
void printUInt32(SStream *O, uint32_t val);

// print number in decimal mode
void printInt32BangDec(SStream *O, int32_t val);

void printFloat(SStream *O, float val);

void printfFloat(SStream *ss, const char *fmt, float val);

void printFloatBang(SStream *O, float val);

void printExpr(SStream *O, uint64_t val);

SStream *markup_OS(SStream *OS, SStreamMarkup style);

#endif

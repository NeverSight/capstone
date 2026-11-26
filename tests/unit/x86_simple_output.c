/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../arch/X86/X86ScanAdapter.h"
#include "../../cs_priv.h"
#include "../../utils.h"
#include <stdio.h>
#include <string.h>

/* An unrelated custom mnemonic selects the ordinary Intel decoder. Compare
 * both public records, including the parts an iterator leaves untouched. */
static bool (*private_iter)(csh, const uint8_t **, size_t *, uint64_t *,
			    cs_insn *) = X86_disasmIter;

static bool compare_at(csh handles[2], const uint8_t *input, size_t length,
		       unsigned seed, uint64_t address)
{
	cs_insn insn[2];
	cs_detail detail[2];
	const uint8_t *cursor[2] = { input, input };
	size_t left[2] = { length, length };
	uint64_t ip[2] = { address, address };
	bool ok[2];
	for (unsigned side = 0; side < 2; ++side) {
		memset(&insn[side], seed, sizeof(insn[side]));
		memset(&detail[side], seed, sizeof(detail[side]));
		insn[side].is_alias = insn[side].usesAliasDetails = false;
		insn[side].illegal = false;
		insn[side].detail = &detail[side];
		ok[side] = (side ? cs_disasm_iter : private_iter)(
			handles[side], &cursor[side], &left[side], &ip[side],
			&insn[side]);
		if (insn[side].detail != &detail[side])
			return false;
		insn[side].detail = NULL;
	}
	if (ok[0] == ok[1] && cursor[0] == cursor[1] && left[0] == left[1] &&
	    ip[0] == ip[1] && cs_errno(handles[0]) == cs_errno(handles[1]) &&
	    !memcmp(&insn[0], &insn[1], sizeof(cs_insn)) &&
	    !memcmp(&detail[0], &detail[1], sizeof(cs_detail)))
		return true;
	fprintf(stderr, "x86 output mismatch at length %zu bytes", length);
	for (size_t i = 0; i < length; ++i)
		fprintf(stderr, " %02x", input[i]);
	fputc('\n', stderr);
	return false;
}

static bool compare(csh handles[2], const uint8_t *input, size_t length,
		    unsigned seed)
{
	return compare_at(handles, input, length, seed, UINT64_MAX - seed);
}

static bool check_branches(csh handles[2])
{
	const uint32_t bits[] = { 0,	1,    9,	  10,	     0x7f,
				  0x80, 0xff, 0x80000000, 0xffffffff };
	for (unsigned op = 0; op < 256; ++op) {
		bool near_jcc = op >= 0x80 && op <= 0x8f;
		bool short_jump = (op >= 0x70 && op <= 0x7f) || op == 0xeb;
		if (!near_jcc && !short_jump && op != 0xe8 && op != 0xe9)
			continue;
		size_t offset = near_jcc ? 2 : 1, width = short_jump ? 1 : 4;
		uint8_t bytes[6] = { 0x0f };
		bytes[offset - 1] = (uint8_t)op;
		for (unsigned i = 0; i < sizeof(bits) / sizeof(bits[0]); ++i) {
			for (unsigned j = 0; j < width; ++j)
				bytes[offset + j] =
					(uint8_t)(bits[i] >> (8 * j));
			for (size_t length = 1; length <= offset + width;
			     ++length)
				if (!compare(handles, bytes, length, i))
					return false;
		}
	}
	/* Exercise every possible leading nibble, including address wraparound. */
	const uint8_t jump[] = { 0xeb, 0 };
	for (unsigned shift = 0; shift < 64; shift += 4) {
		for (uint64_t top = 1; top <= 15; ++top) {
			uint64_t first = top << shift;
			for (unsigned n = 0; n < 3; ++n) {
				uint64_t target = first + n - 1;
				if (!compare_at(handles, jump, sizeof(jump), n,
						target - sizeof(jump)))
					return false;
			}
		}
	}
	return true;
}

static void custom_postprinter(csh handle, cs_insn *insn, SStream *stream,
			       MCInst *mci)
{
	(void)handle;
	(void)insn;
	(void)mci;
	strcpy(stream->buffer, "custom\toperand");
}

static void custom_id(cs_struct *handle, cs_insn *insn, unsigned int id)
{
	(void)handle;
	(void)id;
	insn->id = X86_INS_INT3;
}

static bool check_callbacks(csh handles[2])
{
	const uint8_t nop = 0x90, push = 0x50;
	cs_struct *a = (cs_struct *)(uintptr_t)handles[0];
	cs_struct *b = (cs_struct *)(uintptr_t)handles[1];
	PostPrinter_t original = a->post_printer;
	a->post_printer = b->post_printer = custom_postprinter;
	if (!compare(handles, &nop, 1, 0x5a))
		return false;
	a->post_printer = b->post_printer = original;
	a->insn_id = b->insn_id = custom_id;
	return compare(handles, &push, 1, 0xa5);
}

static bool check_memory(csh handles[2], cs_mode mode)
{
	uint8_t bytes[4];
	for (unsigned prefix = 0; prefix <= (mode == CS_MODE_64 ? 16u : 0u);
	     ++prefix) {
		bytes[0] = prefix ? (uint8_t)(0x3f + prefix) : 0;
		for (unsigned op = 0x88; op <= 0x8b; ++op) {
			bytes[1] = (uint8_t)op;
			for (unsigned mr = 0; mr < 0x80; ++mr) {
				bytes[2] = (uint8_t)mr;
				for (unsigned n = 0;
				     n < (mr >= 0x40 ? 256u : 1u); ++n) {
					bytes[3] = (uint8_t)n;
					size_t len = 2 + (prefix != 0) +
						     (mr >= 0x40);
					if (!compare(handles,
						     bytes + (prefix == 0), len,
						     mr ^ n))
						return false;
				}
			}
		}
	}
	return true;
}

static bool check_mov_imm32(csh handles[2], cs_mode mode)
{
	static const uint32_t boundaries[] = {
		0,    1,     9,	     10,	 15,	     16,	0x7f,
		0x80, 0x100, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff
	};
	for (unsigned p = 0; p <= (mode == CS_MODE_64 ? 16u : 0u); ++p) {
		for (unsigned op = 0xb8; op <= 0xbf; ++op) {
			for (unsigned sample = 0; sample < 1024; ++sample) {
				uint32_t imm =
					sample < sizeof(boundaries) /
								sizeof(boundaries
									       [0]) ?
						boundaries[sample] :
						sample * UINT32_C(2654435761);
				uint8_t bytes[] = { (uint8_t)(0x3f + p),
						    (uint8_t)op,
						    (uint8_t)imm,
						    (uint8_t)(imm >> 8),
						    (uint8_t)(imm >> 16),
						    (uint8_t)(imm >> 24),
						    0x11,
						    0x22,
						    0x33,
						    0x44 };
				const uint8_t *code = bytes + !p;
				size_t size = sizeof(bytes) - !p;
				if (!compare(handles, code, size, sample) ||
				    !compare(handles, code,
					     (sample + op) % size, p))
					return false;
			}
		}
	}
	return true;
}

static bool check_sib_base_mov(csh handles[2], cs_mode mode)
{
	for (unsigned p = 0; p <= (mode == CS_MODE_64 ? 16u : 0u); ++p)
		for (unsigned opcode = 0x88; opcode <= 0x8b; ++opcode)
			for (unsigned reg_mod = 0; reg_mod < 16; ++reg_mod)
				for (unsigned sib = 0; sib < 256; ++sib) {
					uint8_t bytes[] = {
						(uint8_t)(0x3f + p),
						(uint8_t)opcode,
						(uint8_t)(((reg_mod & 8) << 3) |
							  ((reg_mod & 7) << 3) |
							  4),
						(uint8_t)sib,
						(uint8_t)(sib ^ reg_mod ^ p),
						0xfe,
						0xff,
						0
					};
					const uint8_t *code = bytes + !p;
					size_t len = sizeof(bytes) - !p;
					if (!compare(handles, code, len, sib) ||
					    !compare(handles, code,
						     (reg_mod + sib + p) % len,
						     opcode))
						return false;
				}
	return true;
}

static bool check_shift_immediate(csh handles[2], cs_mode mode)
{
	for (unsigned p = 0; p < (mode == CS_MODE_64 ? 17u : 1u); ++p) {
		uint8_t rex = p ? (uint8_t)(0x3f + p) : 0;
		for (unsigned modrm = 0xc0; modrm <= 0xff; ++modrm) {
			for (unsigned count = 0; count < 256; ++count) {
				uint8_t bytes[] = { rex, 0xc1, (uint8_t)modrm,
						    (uint8_t)count };
				size_t length = 3 + !!rex;
				if (!compare(handles, bytes + !rex, length,
					     count))
					return false;
				if (!count)
					for (size_t n = 0; n < length; ++n)
						if (!compare(handles,
							     bytes + !rex, n,
							     modrm))
							return false;
			}
		}
	}
	return true;
}

static bool check_push_immediates(csh handles[2])
{
	for (unsigned op = 0x68; op <= 0x6a; op += 2) {
		for (unsigned n = 0; n < 4096; ++n) {
			uint32_t imm = n < 256 ? n : n * UINT32_C(2654435761);
			uint8_t code[] = { (uint8_t)op, (uint8_t)imm,
					   (uint8_t)(imm >> 8),
					   (uint8_t)(imm >> 16),
					   (uint8_t)(imm >> 24) };
			for (unsigned length = 0; length <= sizeof(code);
			     ++length)
				if (!compare(handles, code, length, n))
					return false;
		}
	}
	return true;
}

static bool check_lea(csh handles[2], cs_mode mode)
{
	static const uint32_t edges[] = { 0,	      1,	  9,
					  10,	      0x7f,	  0x80,
					  0x7fffffff, 0x80000000, 0xfffffff6,
					  0xffffffff };
	for (unsigned p = 0; p <= (mode == CS_MODE_64 ? 16u : 0u); ++p)
		for (unsigned mr = 0; mr < 256; ++mr)
			for (unsigned j = 0;
			     j < sizeof(edges) / sizeof(edges[0]); ++j) {
				const uint32_t v = edges[j];
				const bool sib = (mr & 7) == 4 && mr < 0xc0;
				uint8_t bytes[10] = { (uint8_t)(p + 0x3f), 0x8d,
						      (uint8_t)mr, 0x24 };
				unsigned at = 3 + sib;
				if (sib && (j & 1))
					bytes[3] = (uint8_t)(mr + 31 * j);
				for (unsigned i = 0; i < 4; ++i)
					bytes[at + i] = (uint8_t)(v >> (8 * i));
				for (unsigned n = 0; n <= at + 4 - !p; ++n)
					if (!compare(handles, bytes + !p, n,
						     mr + p + j))
						return false;
			}
	return true;
}

/* Compare public buffers, padding, failure cursors and every truncation. */
static bool check_mov_disp32(csh handles[2], cs_mode mode)
{
	static const uint32_t disps[] = { 0,	      1,	  9,
					  10,	      0x80,	  0x7fffffff,
					  0x80000000, 0xfffffff6, 0xffffffff };
	for (unsigned p = 0; p <= (mode == CS_MODE_64 ? 16u : 0u); ++p) {
		for (unsigned op = 0x88; op <= 0x8b; ++op) {
			for (unsigned mr = 0; mr < 0xc0; ++mr) {
				if (mr < 0x80 && (mr & 0xc7) != 5 &&
				    (mr & 0xc7) != 4)
					continue;
				for (unsigned j = 0;
				     j < sizeof(disps) / sizeof(disps[0]);
				     ++j) {
					uint8_t bytes[8] = {
						(uint8_t)(0x3f + p),
						(uint8_t)op, (uint8_t)mr, 0x24
					};
					const bool sib = (mr & 7) == 4;
					if (sib && (j & 1))
						bytes[3] =
							(uint8_t)(37 * j + mr);
					const unsigned offset = 3 + sib;
					for (unsigned k = 0; k < 4; ++k)
						bytes[offset + k] =
							(uint8_t)(disps[j] >>
								  (8 * k));
					for (size_t len = 0;
					     len <= offset + 4 - !p; ++len) {
						if (!compare(handles,
							     bytes + !p, len,
							     mr + j + p))
							return false;
					}
				}
			}
		}
	}
	return true;
}

static bool check_group1(csh handles[2], cs_mode mode)
{
	uint8_t bytes[4];
	for (unsigned p = 0; p <= (mode == CS_MODE_64 ? 16u : 0u); ++p) {
		bytes[0] = p ? (uint8_t)(0x3f + p) : 0;
		bytes[1] = 0x83;
		for (unsigned mr = 0xc0; mr < 256; ++mr)
			for (unsigned imm = 0; imm < 256; ++imm) {
				bytes[2] = (uint8_t)mr;
				bytes[3] = (uint8_t)imm;
				if (!compare(handles, bytes + !p, 3 + !!p,
					     imm ^ mr ^ p))
					return false;
			}
	}
	return true;
}

static bool check_evex_extract(csh handles[2])
{
	static const uint8_t opcodes[] = { 0x19, 0x1b, 0x39, 0x3b };
	for (unsigned op = 0; op < sizeof(opcodes); ++op)
		for (unsigned wl = 0; wl < 8; ++wl)
			for (unsigned pair = 0; pair < 1024; ++pair) {
				const unsigned dst = pair & 31, src = pair >> 5;
				const unsigned ext =
					((src & 8) << 4) | ((dst & 16) << 2) |
					((dst & 8) << 2) | (src & 16);
				uint8_t b[] = {
					0x62,
					(uint8_t)((0xf0 ^ ext) | 3),
					(uint8_t)(0x7d | (wl >> 2) << 7),
					(uint8_t)(8 | (wl & 3) << 5),
					opcodes[op],
					(uint8_t)(0xc0 | (src & 7) << 3 |
						  (dst & 7)),
					(uint8_t)(pair * 37)
				};
				if (!compare(handles, b, sizeof(b), pair) ||
				    !compare(handles, b, pair % sizeof(b),
					     pair))
					return false;
				b[2] ^= (pair & 1) ? (1u << ((pair >> 1) & 7)) :
						     0;
				b[3] ^= (pair & 1) ? 0 :
						     (1u << ((pair >> 1) & 7));
				if (!compare(handles, b, sizeof(b), pair))
					return false;
			}
	return true;
}

static bool check_evex(csh handles[2])
{
	/* Every SIB, every extension bit and each displacement form. Vary
     * the vector length, full-vector tuple and direction independently. */
	for (unsigned sib = 0; sib < 256; ++sib)
		for (unsigned ext = 0; ext < 16; ++ext)
			for (unsigned mod = 0; mod < 3; ++mod)
				for (unsigned load = 0; load < 2; ++load) {
					uint8_t code[] = {
						0x62,
						(uint8_t)(ext << 4 | 1),
						(uint8_t)(0x7c |
							  (1 + (ext + sib) % 3) |
							  ((sib & 1) << 7)),
						(uint8_t)(8 | ((sib + ext) % 3)
								      << 5),
						(uint8_t)(load ? 0x6f : 0x7f),
						(uint8_t)(mod << 6 |
							  ((sib + ext) & 7)
								  << 3 |
							  4),
						(uint8_t)sib,
						0x80,
						0xff,
						0,
						0x80
					};
					const unsigned length =
						7 +
						(mod == 2 || (!mod &&
							      (sib & 7) == 5) ?
							 4 :
							 mod);
					if (!compare(handles, code, length,
						     sib) ||
					    !compare(handles, code, length - 1,
						     ext))
						return false;
				}
	/* Compare all EVEX embedded rounding modes, truncations, and register
	 * extensions for packed arithmetic. Include masked and memory forms. */
	for (unsigned n = 0; n < 4096; ++n) {
		const uint8_t ops[] = { 0x58, 0x59, 0x5c, 0x5e,
					0x98, 0xa8, 0xb8, 0xbc };
		const unsigned family = n & 7;
		const uint8_t bytes[] = {
			0x62,
			(uint8_t)((n & 0xf0) | (family < 4 ? 1 : 2)),
			(uint8_t)(((n >> 3) & 0xf8) | 4 | ((n >> 10) & 3)),
			(uint8_t)((((n >> 5) & 3) << 5) | 0x10 |
				  ((n >> 4) & 8) | (n % 13 == 0 ? 1 : 0)),
			ops[family],
			(uint8_t)((n % 11 == 0 ? 0x40 : 0xc0) |
				  ((n >> 1) & 63)),
			0x80,
			0,
			0,
			0
		};
		const size_t extent = n % 5 == 0 ? (n >> 8) % 7 : sizeof(bytes);
		if (!compare(handles, bytes, extent, n))
			return false;
	}

	static const uint16_t forms[] = { 0x1ef, 0x2dc, 0x2dd, 0x2de, 0x2df,
					  0x344, 0x325, 0x1fe, 0x200 };
	static const uint8_t tails[] = { 0,    4,    0x45, 0x85,
					 0xc0, 0xcb, 0xf7, 0xff };
	for (unsigned i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i)
		for (unsigned reg = 0; reg < 32; ++reg)
			for (unsigned wl = 0; wl < 8; ++wl)
				for (unsigned j = 0; j < sizeof(tails); ++j) {
					uint8_t bytes[12] = {
						0x62,
						(uint8_t)((reg << 4) |
							  (forms[i] >> 8)),
						(uint8_t)(((wl & 4) << 5) |
							  ((reg & 15) << 3) |
							  5),
						(uint8_t)(((wl & 3) << 5) |
							  ((reg >> 4) << 3)),
						(uint8_t)forms[i],
						tails[j],
						5,
						0x80,
						0xff,
						9,
						0,
						0x7f
					};
					for (size_t n = 5; n <= sizeof(bytes);
					     ++n)
						if (!compare(handles, bytes, n,
							     reg ^ wl ^ j))
							return false;
				}
	return true;
}

static bool check_vex_indexed(csh handles[2])
{
	const uint8_t base_shapes[][9] = {
		{ 0xc5, 0xdd, 0xfe, 0x22 },
		{ 0xc4, 0x42, 0xed, 0xa8, 0x45, 0xf6 },
		{ 0xc4, 0x42, 0xed, 0xa8, 0x85, 0x00, 0x00, 0x00, 0x80 },
	};
	const unsigned lengths[] = { 4, 6, 9 };
	for (unsigned i = 0; i < ARR_SIZE(base_shapes); ++i)
		for (unsigned n = 1; n <= lengths[i]; ++n)
			if (!compare(handles, base_shapes[i], n, n))
				return false;
	for (unsigned fma = 0; fma < 2; ++fma)
		for (unsigned p = 0; p < (fma ? 128u : 4u); ++p)
			for (unsigned m = 0; m < 16; ++m)
				for (unsigned sib = 0; sib < 256; ++sib) {
					const unsigned rxb = p & 7;
					uint8_t bytes[] = {
						0xc4,
						(uint8_t)((rxb << 5) | 2),
						(uint8_t)(((p >> 3) << 3) |
							  ((m & 1) << 2) | 1),
						0xa8,
						(uint8_t)(((m & 8) << 3) |
							  ((m & 7) << 3) | 4),
						(uint8_t)sib,
						(uint8_t)(sib ^ p ^ m),
						0x80,
						1,
						0xff,
						0
					};
					if (!fma) {
						bytes[1] = 0xc5;
						bytes[2] = (uint8_t)(0x78 |
								     ((p & 1)
								      << 7) |
								     ((p & 2)
								      << 1));
						bytes[3] = 0x28;
					}
					const uint8_t *start = bytes + !fma;
					const size_t len = sizeof(bytes) - !fma;
					if (!compare(handles, start, len,
						     sib ^ p) ||
					    !compare(handles, start,
						     (sib + p + m) % len, m))
						return false;
				}
	return true;
}

static bool check_plain_evex_registers(csh handles[2])
{
	const uint8_t rip[] = { 0x62, 0xf1, 0x65, 0x48, 0xfe,
				0x1d, 0x73, 0x70, 0x33, 0x00 };
	uint8_t specimen[sizeof(rip)];
	for (unsigned k = 0; k < 8; ++k) {
		memcpy(specimen, rip, sizeof(rip));
		specimen[1] ^= (uint8_t)((k & 3) << 5);
		if (k & 4)
			specimen[9] = 0x80;
		for (size_t n = 1; n <= sizeof(specimen); ++n)
			if (!compare(handles, specimen, n, k))
				return false;
	}

	// Unmasked EVEX.0F3A shuffles take a seventh control byte.
	uint8_t shuffle[] = { 0x62, 0xf3, 0xdd, 0x48, 0x43, 0xdc, 0 };
	for (unsigned value = 0; value < 256; ++value) {
		shuffle[6] = (uint8_t)value;
		if (!compare(handles, shuffle, sizeof(shuffle), value) ||
		    !compare(handles, shuffle, sizeof(shuffle) - 1, value))
			return false;
	}
	static const uint8_t flags[] = { 0,    8,    0x28, 0x48,
					 0x68, 0x18, 0x49, 0xc9 };
	for (unsigned map = 1; map <= 3; ++map)
		for (unsigned op = 0; op <= 255; ++op)
			for (unsigned wpp = 0; wpp < 8; ++wpp)
				for (unsigned k = 0; k < sizeof(flags); ++k) {
					const uint8_t p1 =
						(uint8_t)((wpp / 4 << 7) |
							  (wpp % 4) | 4 |
							  ((k & 1) ? 0x78 :
								     0x28));
					uint8_t b[] = {
						0x62,
						(uint8_t)(((k * 5 + op) << 4) | map),
						p1,
						flags[k],
						(uint8_t)op,
						(uint8_t)(0xc0 | ((op * 7 + k) & 63))
					};
					if (!compare(handles, b, sizeof(b),
						     op ^ k) ||
					    !compare(handles, b, sizeof(b) - 1,
						     k))
						return false;
				}
	return true;
}
static bool check_legacy_map38_registers(csh handles[2])
{
	static const uint8_t opcodes[] = { 0x00, 0x17, 0x40, 0xdc, 0xde, 0xff };
	for (unsigned p = 0; p <= 16; ++p)
		for (unsigned n = 0; n < sizeof(opcodes); ++n)
			for (unsigned mr = 0xc0; mr <= 0xff; ++mr) {
				uint8_t bytes[] = {
					0x66, (uint8_t)(0x3f + p), 0x0f,
					0x38, opcodes[n],	   (uint8_t)mr
				};
				if (!p)
					bytes[1] = 0x66;
				const uint8_t *start = bytes + !p;
				const size_t length = sizeof(bytes) - !p;
				if (!compare(handles, start, length, mr) ||
				    !compare(handles, start, length - 1, mr))
					return false;
			}
	return true;
}

static bool check_legacy_register_immediates(csh handles[2])
{
	static const uint8_t values[] = { 0, 9, 10, 15, 16, 127, 128, 255 };
	for (unsigned p = 0; p <= 16; ++p)
		for (unsigned opcode = 0x70; opcode <= 0x73; ++opcode)
			for (unsigned mr = 0xc0; mr <= 0xff; ++mr)
				for (unsigned k = 0; k < sizeof(values); ++k) {
					uint8_t bytes[] = { 0x66,
							    (uint8_t)(0x3f + p),
							    0x0f,
							    (uint8_t)opcode,
							    (uint8_t)mr,
							    values[k] };
					if (!p)
						bytes[1] = 0x66;
					const uint8_t *start = bytes + !p;
					const size_t length =
						sizeof(bytes) - !p;
					if (!compare(handles, start, length,
						     mr ^ values[k]) ||
					    !compare(handles, start, length - 1,
						     values[k]))
						return false;
				}
	return true;
}

static bool check_legacy_vectors(csh handles[2], cs_mode mode)
{
	for (unsigned prefix = 0; prefix <= (mode == CS_MODE_64 ? 16u : 0u);
	     ++prefix)
		for (unsigned opcode = 0; opcode <= 0xff; ++opcode)
			for (unsigned mr = 0; mr <= 0xff; ++mr) {
				uint8_t bytes[] = {
					0x66,	     (uint8_t)(0x3f + prefix),
					0x0f,	     (uint8_t)opcode,
					(uint8_t)mr, 0x95,
					0x10,	     0x80,
					0xff,	     0xa5,
					0x0f
				};
				const uint8_t *start = bytes;
				if (!prefix) {
					bytes[1] = 0x66;
					++start;
				}
				const size_t size = sizeof(bytes) - !prefix;
				/* Exercise unprefixed register, memory and truncated
				 * encodings against the ordinary decoder. */
				if (!compare(handles, start + 1, size - 1,
					     mr) ||
				    !compare(handles, start + 1,
					     (mr + opcode) % (3 + !!prefix),
					     0xa5))
					return false;
				if (!compare(handles, start, size,
					     mr ^ opcode) ||
				    !compare(handles, start,
					     (mr + opcode + prefix) % size,
					     0xa5))
					return false;
			}
	return true;
}

static bool check_indexed_memory(csh handles[2], cs_mode mode)
{
	const uint8_t opcodes[] = { 0x88, 0x89, 0x8a, 0x8b, 0x8d };
	for (unsigned p = 0; p <= (mode == CS_MODE_64 ? 16u : 0u); ++p)
		for (unsigned o = 0; o < sizeof(opcodes); ++o)
			for (unsigned mod = 0; mod < 3; ++mod)
				for (unsigned sib = 0; sib < 256; ++sib) {
					uint8_t bytes[] = {
						(uint8_t)(0x3f + p),
						opcodes[o],
						(uint8_t)((mod << 6) |
							  (sib & 0x38) | 4),
						(uint8_t)sib,
						0x80,
						0xff,
						0x7f,
						0x80
					};
					const unsigned disp =
						mod == 2 || (!mod &&
							     (sib & 7) == 5) ?
							4 :
							mod;
					if (!compare(handles, bytes + !p,
						     4 + disp - !p, sib ^ p))
						return false;
				}
	return true;
}

static bool check_push_memory(csh handles[2], cs_mode mode)
{
	for (unsigned p = 0; p <= (mode == CS_MODE_64 ? 16u : 0u); ++p)
		for (unsigned mr = 0; mr < 256; ++mr)
			for (unsigned variant = 0; variant < 4; ++variant) {
				const uint8_t sibs[] = { 0x24, 0x6a, 0x25,
							 0xfe };
				uint8_t bytes[] = { (uint8_t)(0x3f + p),
						    0xff,
						    (uint8_t)mr,
						    sibs[variant],
						    0x80,
						    0x01,
						    0xff,
						    0x80 };
				for (size_t n = 0; n <= sizeof(bytes) - !p; ++n)
					if (!compare(handles, bytes + !p, n,
						     p ^ mr ^ variant))
						return false;
			}
	return true;
}

static bool check_masked_byte_moves(csh handles[2])
{
	static const uint8_t forms[][11] = {
		{ 0x62, 0xf1, 0x7f, 0xc9, 0x6f, 0xc0 },
		{ 0x62, 0xd1, 0x7f, 0x49, 0x6f, 0x57, 1 },
		{ 0x62, 0xa1, 0x7f, 0xa9, 0x6f, 0x5c, 0x19, 2 },
		{ 0x62, 0x91, 0x7f, 0x0f, 0x7f, 0x5c, 0x1a, 4 },
	};
	for (unsigned i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i)
		for (size_t n = 0; n <= sizeof(forms[i]); ++n)
			if (!compare(handles, forms[i], n, i))
				return false;
	return true;
}

static bool check_vex_clear(csh handles[2])
{
	for (unsigned flags = 0; flags < 256; ++flags) {
		uint8_t bytes[] = { 0xc5, (uint8_t)flags, 0x77, 0xc0 };
		for (size_t length = 1; length <= sizeof(bytes); ++length)
			if (!compare(handles, bytes, length, flags))
				return false;
	}
	return true;
}

static bool check_vex_rip_loads(csh handles[2])
{
	const uint32_t edges[] = {
		0,   1,	  9,   10,	   15,	       16,	   127,
		128, 255, 256, 0x7fffffff, 0x80000000, 0xffffff7f, 0xffffffff
	};
	for (unsigned flags = 0; flags < 256; ++flags) {
		for (unsigned n = 0; n < 3; ++n) {
			const uint8_t opcodes[] = { 0x10, 0x28, 0x6f };
			for (unsigned mr = 0; mr < 256; ++mr) {
				const uint32_t disp = edges[(mr + flags + n) %
							    (sizeof(edges) /
							     sizeof(edges[0]))];
				uint8_t bytes[] = { 0xc5,
						    (uint8_t)flags,
						    opcodes[n],
						    (uint8_t)mr,
						    (uint8_t)disp,
						    (uint8_t)(disp >> 8),
						    (uint8_t)(disp >> 16),
						    (uint8_t)(disp >> 24),
						    0x80,
						    0xff };
				if (!compare(handles, bytes, sizeof(bytes),
					     mr ^ flags) ||
				    !compare(handles, bytes,
					     (mr + flags + n) % 9, flags))
					return false;
			}
		}
	}
	return true;
}

static bool check_rex_stack(csh handles[2])
{
	for (unsigned rex = 0x40; rex < 0x50; ++rex) {
		for (unsigned op = 0x50; op < 0x60; ++op) {
			uint8_t bytes[] = { (uint8_t)rex, (uint8_t)op, 0xaa,
					    0x55 };
			for (size_t n = 0; n <= sizeof(bytes); ++n)
				if (!compare(handles, bytes, n, rex ^ op))
					return false;
		}
	}
	return true;
}

static bool check_evex_memory_modrm(csh handles[2], uint8_t opcode,
				    unsigned wpp, unsigned ll, unsigned ext)
{
	static const uint32_t displacements[] = {
		0, 1, 0x7f, 0x80, 0xff, 0x80000000, 0x7fffffff, 0xffffffff
	};
	const uint8_t prefix = (uint8_t)(0x7c | ((wpp & 4) << 5) | (wpp & 3));
	for (unsigned mr = 0; mr < 256; ++mr) {
		const unsigned sib = (mr & 7) == 4 && mr < 0xc0;
		uint8_t bytes[11] = { 0x62,   (uint8_t)(ext << 4 | 1),
				      prefix, (uint8_t)(ll << 5 | 8),
				      opcode, (uint8_t)mr,
				      0x24 };
		const uint32_t value =
			displacements[(mr + ext) % ARR_SIZE(displacements)];
		for (unsigned n = 0; n < 4; ++n)
			bytes[6 + sib + n] = (uint8_t)(value >> (8 * n));
		if (!compare(handles, bytes, sizeof(bytes), mr + ext) ||
		    !compare(handles, bytes, (mr + ext) % sizeof(bytes), ll))
			return false;
	}
	return true;
}

static bool check_evex_memory_moves(csh handles[2])
{
	static const uint8_t opcodes[][2] = { { 0x6f, 0x7f },
					      { 0x10, 0x11 },
					      { 0x28, 0x29 } };
	for (unsigned kind = 0; kind < ARR_SIZE(opcodes); ++kind)
		for (unsigned wpp = 0; wpp < 8; ++wpp)
			for (unsigned store = 0; store < 2; ++store)
				for (unsigned ll = 0; ll < 4; ++ll)
					for (unsigned ext = 0; ext < 16; ++ext)
						if (!check_evex_memory_modrm(
							    handles,
							    opcodes[kind][store],
							    wpp, ll, ext))
							return false;
	/* Sweep reserved fields, masks, W, map and both neighboring opcodes. */
	uint8_t bytes[] = { 0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x58, 0x80 };
	for (unsigned kind = 0; kind < ARR_SIZE(opcodes); ++kind) {
		bytes[2] = kind == 0 ? 0xfe : 0x7c;
		bytes[4] = opcodes[kind][0];
		for (unsigned field = 1; field <= 4; ++field) {
			const uint8_t save = bytes[field];
			for (unsigned value = 0; value < 256; ++value) {
				bytes[field] = (uint8_t)value;
				if (!compare(handles, bytes, sizeof(bytes),
					     value))
					return false;
			}
			bytes[field] = save;
		}
	}
	return true;
}
static bool check_broadcast(csh handles[2])
{
	static const uint8_t disp[] = { 0, 1, 0x7f, 0x80, 0xff };
	for (unsigned rx = 0; rx < 16; ++rx)
		for (unsigned w = 0; w < 2; ++w)
			for (unsigned ll = 0; ll < 4; ++ll)
				for (unsigned mr = 0; mr < 256; ++mr)
					for (unsigned j = 0; j < sizeof(disp);
					     ++j) {
						const bool sib = (mr & 7) ==
									 4 &&
								 mr < 0xc0;
						uint8_t bytes[] = {
							0x62,
							(uint8_t)(0x02 |
								  rx << 4),
							(uint8_t)(0x7d |
								  w << 7),
							(uint8_t)(8 | ll << 5),
							0x1a,
							(uint8_t)mr,
							0x24,
							0,
							0x55,
							0xaa,
							0xff
						};
						if (sib && j == 0)
							bytes[6] = (uint8_t)mr;
						bytes[6 + sib] = disp[j];
						if (!compare(handles, bytes,
							     sizeof(bytes),
							     mr + j) ||
						    !compare(handles, bytes,
							     (mr + j) % 9,
							     rx + j))
							return false;
					}
	/* Reserved and masked EVEX payloads must fall back to the canonical decoder. */
	uint8_t bytes[] = { 0x62, 0xf2, 0xfd, 0x48, 0x1a, 0x58, 0x80 };
	for (unsigned field = 1; field <= 3; ++field) {
		uint8_t save = bytes[field];
		for (unsigned v = 0; v < 256; ++v) {
			bytes[field] = (uint8_t)v;
			if (!compare(handles, bytes, sizeof(bytes), field + v))
				return false;
		}
		bytes[field] = save;
	}
	return true;
}

static bool check_padding(csh handles[2])
{
	static const uint8_t forms[][9] = { { 0x0f, 0x1f, 0 },
					    { 0x0f, 0x1f, 0x40, 0 },
					    { 0x0f, 0x1f, 0x44, 0, 0 },
					    { 0x0f, 0x1f, 0x80, 0, 0, 0, 0 },
					    { 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0 },
					    { 0x66, 0x90 },
					    { 0x66, 0x0f, 0x1f, 0x44, 0, 0 },
					    { 0x66, 0x0f, 0x1f, 0x84, 0, 0, 0,
					      0, 0 },
					    { 0xf3, 0x0f, 0x1e, 0xfa },
					    { 0xf3, 0x0f, 0x1e, 0xfb } };
	for (unsigned i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i) {
		uint8_t bytes[sizeof(forms[0])];
		for (unsigned j = 0; j < sizeof(bytes); ++j) {
			memcpy(bytes, forms[i], sizeof(bytes));
			for (unsigned value = 0; value < 256; ++value) {
				bytes[j] = (uint8_t)value;
				if (!compare(handles, bytes, sizeof(bytes),
					     value ^ i) ||
				    !compare(handles, bytes, (value + j) % 10,
					     i + j))
					return false;
			}
		}
	}
	return true;
}

static bool check_vex2_base_memory(csh handles[2])
{
	const uint32_t disps[] = { 0,	       1,	  9,	10,
				   0x7f,       0x80,	  0xff, 0x12345678,
				   0x80000000, 0xffffffff };
	static const uint8_t ops[] = { 0x6f, 0x7f, 0xe5, 0xf5,
				       0xfd, 0xfe, 0xef, 0xc6 };
	for (unsigned flags = 0; flags < 256; ++flags) {
		for (unsigned mr = 0; mr < 0xc0; ++mr) {
			for (unsigned i = 0; i < sizeof(ops); ++i) {
				const unsigned op = ops[i];
				uint8_t bytes[] = { 0xc5,
						    (uint8_t)flags,
						    (uint8_t)op,
						    (uint8_t)mr,
						    0,
						    0,
						    0,
						    0,
						    0 };
				unsigned seed = flags + mr + op;
				uint32_t disp =
					disps[seed % (sizeof(disps) /
						      sizeof(disps[0]))];
				for (unsigned j = 0; j < 4; ++j)
					bytes[4 + j] =
						(uint8_t)(disp >> (j * 8));
				if (!compare(handles, bytes, sizeof(bytes),
					     seed) ||
				    !compare(handles, bytes,
					     seed % sizeof(bytes), seed))
					return false;
			}
		}
	}
	return true;
}

static bool check_vex_register_forms(csh handles[2])
{
	static const uint16_t forms[] = { 0x1ef, 0x1d4, 0x1fe, 0x200, 0x2dc,
					  0x2dd, 0x2de, 0x2df, 0x344, 0x30f,
					  0x171, 0x172, 0x173 };
	for (unsigned i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i) {
		for (unsigned n = 0; n < 65536; ++n) {
			unsigned map = forms[i] >> 8;
			uint8_t bytes[] = { 0xc4,
					    (uint8_t)((n & 0xe0) | map),
					    (uint8_t)((n >> 6 & 0xfc) | 1),
					    (uint8_t)forms[i],
					    (uint8_t)(0xc0 |
						      ((n >> 10) ^ n) % 64),
					    (uint8_t)(n >> 8) };
			if (!compare(handles, bytes, sizeof(bytes), n) ||
			    !compare(handles, bytes, n % sizeof(bytes), n))
				return false;
			if (map == 1) {
				bytes[1] = 0xc5;
				if (!compare(handles, bytes + 1,
					     sizeof(bytes) - 1, n))
					return false;
			}
		}
	}
	return true;
}

static bool check_alu_immediates(csh handles[2], cs_mode mode)
{
	static const uint32_t edges[] = { 0,	      9,	  10,
					  0x7f,	      0x80,	  0xff,
					  0x100,      0x7fffffff, 0x80000000,
					  0xffff0000, 0xffffff7f, 0xfffffff6,
					  0xffffffff };
	for (unsigned p = 0; p <= (mode == CS_MODE_64 ? 16u : 0u); ++p) {
		for (unsigned mr = 0; mr < 256; ++mr) {
			for (unsigned j = 0; j < 32; ++j) {
				uint32_t v =
					j < sizeof(edges) / sizeof(edges[0]) ?
						edges[j] :
						(uint32_t)(j * 256 + mr) *
							UINT32_C(2654435761);
				uint8_t b[] = {
					(uint8_t)(0x3f + p), 0x81,
					(uint8_t)mr,	     (uint8_t)v,
					(uint8_t)(v >> 8),   (uint8_t)(v >> 16),
					(uint8_t)(v >> 24)
				};
				if (!compare(handles, b + !p, sizeof(b) - !p,
					     mr + j) ||
				    !compare(handles, b + !p,
					     (mr + j) % (sizeof(b) - !p), v))
					return false;
			}
		}
	}
	return true;
}

static bool check_indirect_memory(csh handles[2], cs_mode mode)
{
	for (unsigned prefix = 0; prefix < (mode == CS_MODE_64 ? 17u : 1u);
	     ++prefix) {
		for (unsigned mr = 0; mr < 256; ++mr) {
			const unsigned variants =
				mr < 0xc0 && (mr & 7) == 4 ? 256u : 1u;
			for (unsigned sib = 0; sib < variants; ++sib) {
				uint8_t code[] = { (uint8_t)(0x3f + prefix),
						   0xff,
						   (uint8_t)mr,
						   (uint8_t)sib,
						   0xff,
						   0xff,
						   0xff,
						   0x80 };
				const uint8_t *start = code + !prefix;
				const size_t length = sizeof(code) - !prefix;
				for (size_t n = 1; n <= length; ++n)
					if (!compare(handles, start, n,
						     mr + sib + prefix))
						return false;
			}
		}
	}
	return true;
}

static bool check_absolute_addresses32(csh handles[2])
{
	static const uint32_t addresses[] = {
		0, 9, 10, 0x502dc4, 0x7fffffff, 0x80000000u, UINT32_MAX
	};
	static const uint8_t opcodes[] = { 0x00, 0x03, 0x38, 0x3b, 0x84, 0x89,
					   0x8b, 0x8d, 0xc6, 0xc7, 0xff };
	for (unsigned op = 0; op < sizeof(opcodes); ++op) {
		for (unsigned group = 0; group < 8; ++group) {
			for (unsigned i = 0;
			     i < sizeof(addresses) / sizeof(addresses[0]);
			     ++i) {
				const uint32_t address = addresses[i];
				const uint8_t code[] = {
					opcodes[op],
					(uint8_t)((group << 3) | 5),
					(uint8_t)address,
					(uint8_t)(address >> 8),
					(uint8_t)(address >> 16),
					(uint8_t)(address >> 24),
					0xff,
					0xfe,
					0xfd,
					0xfc
				};
				for (size_t len = 1; len <= sizeof(code); ++len)
					if (!compare(handles, code, len,
						     group + i + op))
						return false;
			}
		}
	}
	return true;
}

/* Segment, ModR/M, SIB and truncation are compared against the ordinary
 * decoder, including the complete public detail and reused output record. */
static bool check_vex_register_immediates(csh handles[2], cs_mode mode)
{
	const uint8_t opcodes[] = { 0x00, 0x01, 0x14, 0x15, 0x16, 0x17,
				    0x18, 0x19, 0x38, 0x39, 0xf0 };
	for (unsigned i = 0; i < sizeof(opcodes); ++i) {
		for (unsigned bits = 0; bits < 256; ++bits) {
			const unsigned ext =
				mode == CS_MODE_32 ? 7 : (bits >> 1) & 7;
			uint8_t code[] = { 0xc4,
					   (uint8_t)(ext << 5 | 3),
					   (uint8_t)bits,
					   opcodes[i],
					   (uint8_t)(0xc0 | ((bits ^ i) & 63)),
					   (uint8_t)(bits * 37) };
			if (!compare(handles, code, sizeof(code), bits) ||
			    !compare(handles, code, sizeof(code) - 1, i))
				return false;
		}
	}
	return true;
}

static bool check_vex32_register_moves(csh handles[2])
{
	for (unsigned flags = 0; flags < 256; ++flags)
		for (unsigned mr = 0xc0; mr <= 0xff; ++mr)
			for (unsigned op = 0x6f; op <= 0x7f; op += 0x10) {
				const uint8_t bytes[] = { 0xc5, (uint8_t)flags,
							  (uint8_t)op,
							  (uint8_t)mr };
				for (size_t n = 1; n <= sizeof(bytes); ++n)
					if (!compare(handles, bytes, n,
						     mr + flags))
						return false;
			}
	return true;
}

static bool check_segment_lea32(csh handles[2])
{
	const uint8_t prefixes[] = { 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65 };
	for (unsigned p = 0; p < sizeof(prefixes); ++p)
		for (unsigned mr = 0; mr < 256; ++mr)
			for (unsigned sib = 0; sib < ((mr & 7) == 4 ? 256u : 1u); ++sib) {
				uint8_t code[] = { prefixes[p], 0x8d, mr, sib,
						   0x80, 0xff, 0xff, 0xff };
				if (!compare(handles, code, sizeof(code), mr ^ sib))
					return false;
				if ((mr & 0x38) == 0)
					for (size_t len = 1; len < sizeof(code); ++len)
						if (!compare(handles, code, len, mr ^ sib))
							return false;
			}
	return true;
}

static bool check_memory_flag_immediates(csh handles[2], cs_mode mode)
{
	const uint8_t values[] = { 0, 9, 10, 0x7f, 0x80, 0xff };
	const uint8_t sibs[] = { 0x24, 0x08, 0x4d, 0xa5, 0xfc, 0xff };
	const uint8_t opcodes[] = { 0x80, 0x81, 0x82, 0x83, 0xf6, 0xf7 };
	for (unsigned prefix = 0; prefix < (mode == CS_MODE_64 ? 17u : 1u);
	     ++prefix) {
		for (unsigned index = 0; index < sizeof(opcodes); ++index) {
			const unsigned opcode = opcodes[index];
			for (unsigned mr = 0; mr <= 0xff; ++mr) {
				if ((mr & 0x30) != (opcode >= 0xf6 ? 0 : 0x30))
					continue;
				for (unsigned n = 0; n < sizeof(values); ++n) {
					uint8_t code[12];
					memset(code, values[n], sizeof(code));
					code[0] = (uint8_t)(0x3f + prefix);
					code[1] = (uint8_t)opcode;
					code[2] = (uint8_t)mr;
					if ((mr & 7) == 4)
						code[3] = sibs[n];
					const uint8_t *start = code + !prefix;
					for (size_t length = 1;
					     length <= sizeof(code) - !prefix;
					     ++length)
						if (!compare(handles, start,
							     length,
							     prefix + mr + n))
							return false;
				}
			}
		}
	}
	return true;
}

static bool check_alu_memory(csh handles[2], cs_mode mode)
{
	const unsigned prefixes = mode == CS_MODE_64 ? 17 : 1;
	for (unsigned p = 0; p < prefixes; ++p) {
		for (unsigned n = 0; n < 34; ++n) {
			const unsigned opcode = n < 32 ? ((n >> 2) << 3) |
								 (n & 3) :
							 0x84 + n - 32;
			for (unsigned mr = 0; mr < 0xc0; ++mr) {
				uint32_t value = (uint32_t)(n * 256 + mr + p) *
						 UINT32_C(2654435761);
				uint8_t b[] = { (uint8_t)(0x3f + p),
						(uint8_t)opcode,
						(uint8_t)mr,
						(uint8_t)value,
						(uint8_t)(value >> 8),
						(uint8_t)(value >> 16),
						(uint8_t)(value >> 24),
						0x80 };
				if ((mr & 7) == 4 && (mr & 8))
					b[3] = 0x24;
				if (!compare(handles, b + !p, sizeof(b) - !p,
					     value) ||
				    !compare(handles, b + !p,
					     (p + mr + n) % (sizeof(b) - !p),
					     value))
					return false;
			}
		}
	}
	return true;
}

static bool check_extend64(csh handles[2])
{
	static const uint8_t ops[] = { 0x63, 0xb6, 0xb7, 0xbe, 0xbf };
	for (unsigned prefix = 0; prefix <= 16; ++prefix)
		for (size_t op = 0; op < sizeof(ops); ++op)
			for (unsigned mr = 0; mr < 256; ++mr) {
				uint8_t bytes[10] = { 0 };
				unsigned n = 0;
				if (prefix)
					bytes[n++] = (uint8_t)(0x3f + prefix);
				if (ops[op] != 0x63)
					bytes[n++] = 0x0f;
				bytes[n++] = ops[op];
				bytes[n++] = (uint8_t)mr;
				bytes[n++] = (uint8_t)(mr & 8 ? 0x25 : 0xa3);
				bytes[n++] = 0x80;
				bytes[n++] = 0xfe;
				bytes[n++] = 0xff;
				bytes[n++] = 0xff;
				const unsigned seed =
					prefix + mr + (unsigned)op;
				if (!compare(handles, bytes, n, seed) ||
				    !compare(handles, bytes, seed % n + 1,
					     seed))
					return false;
			}
	return true;
}

static bool check_group3_registers32(csh handles[2])
{
	for (unsigned op = 0xf6; op <= 0xf7; ++op) {
		for (unsigned mr = 0xd0; mr <= 0xff; ++mr) {
			const uint8_t bytes[] = { (uint8_t)op, (uint8_t)mr };
			if (!compare(handles, bytes, sizeof(bytes), mr))
				return false;
		}
	}
	return true;
}

static bool check_extend32(csh handles[2])
{
	for (unsigned op = 0xb6; op <= 0xbf; ++op) {
		if ((op & 0xf6) != 0xb6)
			continue;
		for (unsigned mr = 0; mr <= 0xff; ++mr) {
			for (unsigned sib = 0; sib < 256;
			     sib += (mr & 7) == 4 ? 1 : 256) {
				const uint8_t b[] = { 0x0f,	   (uint8_t)op,
						      (uint8_t)mr, (uint8_t)sib,
						      0x80,	   0x12,
						      0xf1,	   0xc7 };
				unsigned seed = op + mr + sib;
				if (!compare(handles, b, sizeof(b), seed) ||
				    !compare(handles, b, seed % sizeof(b),
					     seed))
					return false;
			}
		}
	}
	return true;
}

static bool check_vex_packed_memory(csh handles[2])
{
	const uint8_t opcodes[] = { 0x10, 0x11, 0x28, 0x29, 0x51, 0x6f, 0x7f };
	const uint8_t modrm[] = {
		0x00, 0x04, 0x05, 0x44, 0x73, 0x84, 0xbc, 0xfd
	};
	const uint8_t sibs[] = { 0x24, 0x25, 0x64, 0xdc };
	for (unsigned i = 0; i < sizeof(opcodes); ++i)
		for (unsigned flags = 0; flags < 256; ++flags)
			for (unsigned m = 0; m < sizeof(modrm); ++m)
				for (unsigned s = 0;
				     s <
				     ((modrm[m] & 7) == 4 ? sizeof(sibs) : 1);
				     ++s) {
					uint8_t code[] = {
						0xc5,	    (uint8_t)flags,
						opcodes[i], modrm[m],
						sibs[s],    0xff,
						0xff,	    0xff,
						0x80
					};
					for (unsigned length = 1;
					     length <= sizeof(code); ++length)
						if (!compare(handles, code,
							     length,
							     flags + s +
								     length))
							return false;
				}
	return true;
}

static bool check_sse_base_memory(csh handles[2])
{
	const uint8_t opcodes[] = { 0x10, 0x11, 0x12, 0x16,
				    0x28, 0x29, 0x58, 0x59 };
	const uint8_t sibs[] = { 0x24, 0x25, 0x64, 0xdc };
	for (unsigned i = 0; i < sizeof(opcodes); ++i) {
		for (unsigned prefix = 0; prefix <= 16; ++prefix) {
			const unsigned skip = !prefix;
			for (unsigned mr = 0; mr < 0xc0; ++mr) {
				const bool sib = (mr & 7) == 4;
				for (unsigned j = 0;
				     j < (sib ? sizeof(sibs) : 1); ++j) {
					uint8_t code[] = { (uint8_t)(0x3f +
								     prefix),
							   0x0f,
							   opcodes[i],
							   (uint8_t)mr,
							   0xff,
							   0xff,
							   0xff,
							   0x80,
							   0x80 };
					if (sib)
						code[4] = sibs[j];
					for (unsigned len = 1;
					     len <= sizeof(code) - skip; ++len)
						if (!compare(handles,
							     code + skip, len,
							     mr + j + len))
							return false;
				}
			}
		}
	}
	return true;
}

static bool check_sse_rip_memory(csh handles[2])
{
	const uint8_t opcodes[] = { 0x10, 0x11, 0x12, 0x16,
				    0x28, 0x29, 0x58, 0x59 };
	const uint32_t values[] = { 0,		 9,	      10,
				    127,	 128,	      0xffffffffu,
				    0xffffff80u, 0x80000000u, 0x7fffffffu };
	for (unsigned prefix = 0; prefix <= 16; ++prefix) {
		for (unsigned i = 0; i < sizeof(opcodes); ++i) {
			for (unsigned field = 0; field < 8; ++field) {
				uint8_t bytes[] = {
					prefix ? (uint8_t)(0x3f + prefix) : 0,
					0x0f,
					opcodes[i],
					(uint8_t)((field << 3) | 5),
					0,
					0,
					0,
					0
				};
				const unsigned skip = !prefix;
				for (unsigned n = 0;
				     n < sizeof(values) / sizeof(values[0]);
				     ++n) {
					for (unsigned k = 0; k < 4; ++k)
						bytes[4 + k] =
							(uint8_t)(values[n] >>
								  (8 * k));
					for (unsigned len =
						     n ? sizeof(bytes) - skip :
							 1;
					     len <= sizeof(bytes) - skip; ++len)
						if (!compare(handles,
							     bytes + skip, len,
							     n + field))
							return false;
				}
			}
		}
	}
	return true;
}

static bool check_mov_memory_immediates(csh handles[2], cs_mode mode)
{
	static const uint32_t values[] = { 0,	       1,	  9,
					   10,	       0x7f,	  0x80,
					   0xff,       0x100,	  0x7fffffff,
					   0x80000000, 0xffffffff };
	uint8_t bytes[15];
	for (unsigned prefix = 0; prefix < (mode == CS_MODE_64 ? 17u : 1u);
	     ++prefix) {
		unsigned lead = prefix != 0;
		bytes[0] = (uint8_t)(0x3f + prefix);
		for (unsigned opcode = 0xc6; opcode <= 0xc7; ++opcode) {
			bytes[lead] = (uint8_t)opcode;
			for (unsigned mr = 0; mr < 256; ++mr) {
				bytes[lead + 1] = (uint8_t)mr;
				bool sib = mr < 0xc0 && (mr & 7) == 4;
				for (unsigned sb = 0; sb < (sib ? 256u : 1u);
				     ++sb) {
					unsigned offset = lead + 2;
					if (sib)
						bytes[offset++] = (uint8_t)sb;
					unsigned mod = mr >> 6;
					unsigned disp =
						mod == 1 ? 1 :
						mod == 2 ? 4 :
						mod == 0 && ((mr & 7) == 5 ||
							     (sib &&
							      (sb & 7) == 5)) ?
							   4 :
							   0;
					for (unsigned sample = 0;
					     sample <
					     sizeof(values) / sizeof(values[0]);
					     ++sample) {
						uint32_t displacement = values
							[(sample + 4) %
							 (sizeof(values) /
							  sizeof(values[0]))];
						for (unsigned i = 0; i < disp;
						     ++i)
							bytes[offset + i] =
								(uint8_t)(displacement >>
									  (i *
									   8));
						unsigned imm_offset =
							offset + disp;
						unsigned width =
							opcode == 0xc6 ? 1 : 4;
						for (unsigned i = 0; i < width;
						     ++i)
							bytes[imm_offset + i] =
								(uint8_t)(values[sample] >>
									  (i *
									   8));
						unsigned length =
							imm_offset + width;
						if (!compare(handles, bytes,
							     length,
							     sample ^ mr ^ sb))
							return false;
						if (!sample)
							for (unsigned truncated =
								     1;
							     truncated < length;
							     ++truncated)
								if (!compare(
									    handles,
									    bytes,
									    truncated,
									    mr ^ sb))
									return false;
					}
				}
			}
		}
	}
	/* Every byte value, independently of the addressing and boundary matrix. */
	for (unsigned imm = 0; imm < 256; ++imm) {
		const uint8_t simple[] = { 0xc6, 0x00, (uint8_t)imm };
		if (!compare(handles, simple, sizeof(simple), imm))
			return false;
	}
	return true;
}

static bool check_primary_batches(csh handle)
{
	static const uint8_t code[] = {
		0xb8, 0xc5, 0xfd, 0x6f, 0xc1, /* VEX-looking bytes in a MOV immediate */
		0xc5, 0xfd, 0x6f, 0xc1,
		/* RORX with register and SIB+disp8 sources, each followed by imm8. */
		0xc4, 0xe3, 0x7b, 0xf0, 0xc8, 0x08,
		0xc4, 0xe3, 0xfb, 0xf0, 0x44, 0x24, 0x18, 0x20,
		0xc5, 0xfd, 0x6f, 0x84, 0x25, 0, 0, 0, 0,
		0x62, 0xf3, 0x7d, 0x48, 0x44, 0xc1, 0x11, /* VPCLMULQDQ */
		0x0f, 0x10, 0x44, 0x24, 0x08, /* MOVUPS */
		0x48, 0x0f, 0x6e, 0x0b, /* MOVQ mm1, [rbx] */
		0x48, 0x0f, 0x7e, 0x0b, /* MOVQ [rbx], mm1 */
		0x66, 0x44, 0x0f, 0x58, 0xc1, /* ADDPD */
		0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x10, /* MOVDQU */
		0x62, 0xf1, 0x6d, 0x48, 0x73, 0xdb, 0x11, /* VPSRLDQ */
		0x62, 0xf1, 0x6d, 0x48, 0x73, 0xfb, 0xff, /* VPSLLDQ */
		0x62, 0xf1, 0x6d, 0x49, 0x73, 0xfb, 0xff, /* masked group */
		0x62, 0xf2, 0xed, 0x18, 0xa8, 0xd9, /* VFMADD213PD {rn-sae} */
		0x62, 0xf2, 0xed, 0x78, 0xa8, 0xd9, /* VFMADD213PD {rz-sae} */
		0x62, 0xf2, 0xed, 0x19, 0xa8, 0xd9, /* masked register */
		0xf2, 0x44, 0x0f, 0x10, 0xc1, /* MOVSD */
		0xf3, 0x4c, 0x0f, 0x2a, 0xc2, /* CVTSI2SS */
		0x48, 0xf2, 0x0f, 0x11, 0x08, /* REX before repeat prefix */
		0x66, 0x0f, 0x84, 1, 0, 0, 0, /* size-dependent near JE */
		0x62, 0xf1, 0x7c, 0x48, 0x10, 0x44, 0x24, 1, /* VMOVUPS */
		0x62, 0xf1, 0xfd, 0x28, 0x29, 0xc1, /* VMOVAPD */
		0x62, 0xf1, 0xfe, 0x48, 0x6f, 0x44, 0x24, 1, /* VMOVDQU64 */

		0x83, 0x6c, 0x24, 0x08, 0xff, /* SUB dword ptr [esp+8],-1 */
		0x8b, 0x04, 0x2d, 0xc5, 0, 0, 0, /* base-less SIB */
		0x81, 0xf9, 0xc5, 0xfd, 0x77, 0, /* CMP ECX,imm32 */
		0xc5, 0xf8, 0x77, 0x90, 0xc5, 0xf0, 0x77
	};
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF) ||
	    cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF))
		return false;
	for (size_t start = 0; start < sizeof(code); ++start) {
		for (size_t n = 0; n <= sizeof(code) - start; ++n) {
			for (size_t cap = 0; cap <= 16; ++cap) {
				uint32_t a[16], b[16];
				memset(a, 0xa5, sizeof(a));
				memcpy(b, a, sizeof(a));
				X86ScanBatchResult x = X86_scanBatch(
					handle, code + start, n, UINT64_MAX - 5, a, cap);
				X86ScanBatchResult y = X86_scanNativeBatch(
					handle, code + start, n, UINT64_MAX - 5, b, cap);
				if (x.bytes != y.bytes || x.count != y.count ||
				    memcmp(a, b, sizeof(a)))
					return false;
			}
		}
	}
	return true;
}

static bool check_evex_immediate_shifts(csh handles[2])
{
	for (unsigned opcode = 0x71; opcode <= 0x73; ++opcode)
		for (unsigned group = 0; group < 8; ++group)
			for (unsigned wl = 0; wl < 8; ++wl)
				for (unsigned pair = 0; pair < 1024; ++pair) {
					const unsigned dst = pair & 31,
						       src = pair >> 5;
					uint8_t code[] = {
						0x62,
						(uint8_t)(0xf1 ^
							  ((src & 24) << 2)),
						(uint8_t)((wl >> 2) << 7 |
							  ((~dst & 15) << 3) |
							  5),
						(uint8_t)((wl & 3) << 5 |
							  ((~dst & 16) >> 1)),
						(uint8_t)opcode,
						(uint8_t)(0xc0 | group << 3 |
							  (src & 7)),
						(uint8_t)(pair * 37)
					};
					if (!compare(handles, code,
						     sizeof(code), pair))
						return false;
					if (pair < 32) {
						// Include opmask, zeroing, broadcast and extended group encodings.
						code[3] |=
							(uint8_t)((pair & 7) |
								  ((pair & 8)
								   << 4) |
								  (pair & 16));
						code[1] ^= (uint8_t)(((pair & 1)
								      << 7) |
								     ((pair & 2)
								      << 3));
						if (!compare(handles, code,
							     sizeof(code),
							     pair) ||
						    !compare(handles, code,
							     pair % sizeof(code),
							     pair))
							return false;
					}
				}
	return true;
}


static bool check_legacy_memory(csh handles[2], uint8_t mandatory)
{
	const uint8_t opcodes[] = { 0x10, 0x11, 0x12, 0x16,
				    0x28, 0x29, 0x58, 0x6f, 0x7f };
	const uint8_t sibs[] = { 0x24, 0x25, 0x64, 0xdc };
	for (unsigned i = 0; i < sizeof(opcodes); ++i) {
		for (unsigned prefix = 0; prefix <= 16; ++prefix) {
			const unsigned skip = !prefix;
			for (unsigned mr = 0; mr < 0xc0; ++mr) {
				const bool sib = (mr & 7) == 4;
				for (unsigned j = 0;
				     j < (sib ? sizeof(sibs) : 1); ++j) {
					uint8_t code[] = { mandatory, (uint8_t)(0x3f +
								     prefix),
							   0x0f,
							   opcodes[i],
							   (uint8_t)mr,
							   0xff,
							   0xff,
							   0xff,
							   0x80,
							   0x80 };
					if (sib)
						code[5] = sibs[j];
					if (skip)
						code[1] = mandatory;
					for (unsigned len = 1;
					     len <= sizeof(code) - skip; ++len)
						if (!compare(handles,
							     code + skip, len,
							     mr + j + len))
							return false;
				}
			}
		}
	}
	return true;
}

static bool check_mode(cs_mode mode)
{
	csh handles[2] = { 0 };
	bool ok = false;
	for (unsigned i = 0; i < 2; ++i)
		if (cs_open(CS_ARCH_X86, mode, &handles[i]) != CS_ERR_OK)
			goto done;
	cs_opt_mnem ordinary = { X86_INS_UD2, "ud2" };
	if (cs_option(handles[1], CS_OPT_MNEMONIC, (size_t)&ordinary))
		goto done;
	for (unsigned detail = 0; detail < 2; ++detail) {
		for (unsigned side = 0; side < 2; ++side)
			if (cs_option(handles[side], CS_OPT_DETAIL,
				      detail ? CS_OPT_ON : CS_OPT_OFF))
				goto done;
		if (!check_branches(handles) || !check_memory(handles, mode) ||
		    !check_lea(handles, mode) ||
		    !check_mov_disp32(handles, mode) ||
		    !check_group1(handles, mode) ||
		    !check_push_immediates(handles) ||
		    !check_shift_immediate(handles, mode) ||
		    !check_mov_imm32(handles, mode) ||
		    !check_sib_base_mov(handles, mode) ||
		    !check_indexed_memory(handles, mode) ||
		    !check_push_memory(handles, mode) ||
		    (mode == CS_MODE_64 &&
		     (!check_vex_rip_loads(handles) ||
		      !check_sse_rip_memory(handles) ||
		      (private_iter == X86_disasmIterText &&
		       (!check_plain_evex_registers(handles) ||
			!check_evex_immediate_shifts(handles) ||
			!check_masked_byte_moves(handles) ||
			!check_vex_clear(handles) ||
			!check_sse_base_memory(handles) ||
			!check_legacy_register_immediates(handles) ||
			!check_legacy_map38_registers(handles) ||
			!check_legacy_memory(handles, 0x66) ||
			!check_legacy_memory(handles, 0xf2) ||
			!check_legacy_memory(handles, 0xf3) ||
			!check_vex_packed_memory(handles))))) ||
		    !check_rex_stack(handles) ||
		    (mode == CS_MODE_64 && !check_broadcast(handles)) ||
		    !check_evex_memory_moves(handles) ||
		    !check_padding(handles) ||
		    (mode == CS_MODE_32 &&
		     (!check_segment_lea32(handles) ||
		      !check_vex32_register_moves(handles) ||
		      !check_memory_flag_immediates(handles, mode))) ||
		    !check_alu_memory(handles, mode) ||
		    !check_vex_register_immediates(handles, mode) ||
		    (mode == CS_MODE_32 && private_iter != X86_disasmIter &&
		     (!check_absolute_addresses32(handles) ||
		      !check_extend32(handles) || !check_group3_registers32(handles))) ||
		    (mode == CS_MODE_64 && private_iter != X86_disasmIter &&
		     !check_extend64(handles)) ||
		    (private_iter != X86_disasmIter &&
		     !check_indirect_memory(handles, mode)) ||
		    !check_alu_immediates(handles, mode) ||
		    !check_legacy_vectors(handles, mode) ||
		    (mode == CS_MODE_32 && private_iter != X86_disasmIter &&
		     !check_vex2_base_memory(handles)) ||
		    (private_iter != X86_disasmIter &&
		     !check_mov_memory_immediates(handles, mode)) ||
		    !check_vex_register_forms(handles) ||
		    (mode == CS_MODE_64 &&
		     (!check_evex(handles) || !check_evex_extract(handles) ||
		      !check_vex_indexed(handles))))
			goto done;
		for (unsigned op = 0; op < 256; ++op) {
			uint8_t bytes[3] = { 0, (uint8_t)op, 0 };
			if (!compare(handles, bytes + 1, 1, op))
				goto done;
			for (unsigned tail = 0; tail < 256; ++tail) {
				bytes[2] = (uint8_t)tail;
				if (!compare(handles, bytes + 1, 2, op ^ tail))
					goto done;
			}
			if (mode != CS_MODE_64)
				continue;
			for (unsigned rex = 0x40; rex < 0x50; ++rex) {
				bytes[0] = (uint8_t)rex;
				for (unsigned mr = 0xc0; mr < 256; ++mr) {
					bytes[2] = (uint8_t)mr;
					if (!compare(handles, bytes, 3,
						     rex ^ op ^ mr))
						goto done;
				}
			}
		}
	}
	ok = check_callbacks(handles) && check_primary_batches(handles[0]);
done:
	for (unsigned i = 0; i < 2; ++i)
		if (handles[i])
			cs_close(&handles[i]);
	return ok;
}

int main(void)
{
	private_iter = X86_disasmIter32;
	if (!check_mode(CS_MODE_32))
		return 1;
	private_iter = X86_disasmIterText;
	if (!check_mode(CS_MODE_32) || !check_mode(CS_MODE_64))
		return 1;
	private_iter = X86_disasmIter;
	return check_mode(CS_MODE_32) && check_mode(CS_MODE_64) ? 0 : 1;
}

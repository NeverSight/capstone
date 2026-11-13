/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../arch/X86/X86ScanAdapter.h"
#include "../../cs_priv.h"
#include <stdio.h>
#include <string.h>

/* An unrelated custom mnemonic selects the ordinary Intel decoder. Compare
 * both public records, including the parts an iterator leaves untouched. */
static bool compare(csh handles[2], const uint8_t *input, size_t length,
		    unsigned seed)
{
	cs_insn insn[2];
	cs_detail detail[2];
	const uint8_t *cursor[2] = { input, input };
	size_t left[2] = { length, length };
	uint64_t ip[2] = { UINT64_MAX - seed, UINT64_MAX - seed };
	bool ok[2];
	for (unsigned side = 0; side < 2; ++side) {
		memset(&insn[side], seed, sizeof(insn[side]));
		memset(&detail[side], seed, sizeof(detail[side]));
		insn[side].is_alias = insn[side].usesAliasDetails = false;
		insn[side].illegal = false;
		insn[side].detail = &detail[side];
		ok[side] = (side ? cs_disasm_iter : X86_disasmIter)(
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

static bool check_evex(csh handles[2])
{
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
				if (!compare(handles, start, size,
					     mr ^ opcode) ||
				    !compare(handles, start,
					     (mr + opcode + prefix) % size,
					     0xa5))
					return false;
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
		    !check_legacy_vectors(handles, mode) ||
		    (mode == CS_MODE_64 &&
		     (!check_evex(handles) || !check_vex_indexed(handles))))
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
	ok = check_callbacks(handles);
done:
	for (unsigned i = 0; i < 2; ++i)
		if (handles[i])
			cs_close(&handles[i]);
	return ok;
}

int main(void)
{
	return check_mode(CS_MODE_32) && check_mode(CS_MODE_64) ? 0 : 1;
}

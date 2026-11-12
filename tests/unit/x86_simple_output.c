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
		if (!check_branches(handles) || !check_memory(handles, mode))
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

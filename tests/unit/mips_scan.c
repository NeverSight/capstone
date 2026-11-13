/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <string.h>
#include "../../cs_priv.h"

/* An installed decoder callback can inspect the decoded MC operands. It
 * also gives these tests the ordinary table decoder as an independent path. */
static Disasm_t ordinary;
static unsigned operand_count;

static bool inspect_operands(csh handle, const uint8_t *code, size_t length,
			     MCInst *inst, uint16_t *size, uint64_t address,
			     void *info)
{
	bool ok = ordinary(handle, code, length, inst, size, address, info);
	operand_count = MCInst_getNumOperands(inst);
	return ok;
}

static bool compare(csh handles[2], uint32_t word, bool big_endian,
		    size_t length, bool has_operands)
{
	uint8_t code[4];
	for (unsigned i = 0; i < 4; ++i)
		code[big_endian ? 3 - i : i] = (uint8_t)(word >> (8 * i));
	const uint8_t *cursor[2] = { code, code };
	size_t left[2] = { length, length };
	uint64_t pc[2] = { UINT64_MAX - 2, UINT64_MAX - 2 };
	cs_insn insn[2];
	cs_detail detail[2];
	bool ok[2];
	for (unsigned i = 0; i < 2; ++i) {
		memset(&insn[i], 0xa5, sizeof(insn[i]));
		memset(&detail[i], 0x5a, sizeof(detail[i]));
		insn[i].is_alias = insn[i].usesAliasDetails = insn[i].illegal =
			false;
		insn[i].detail = &detail[i];
		ok[i] = cs_disasm_iter(handles[i], &cursor[i], &left[i], &pc[i],
				       &insn[i]);
		if (insn[i].detail != &detail[i])
			return false;
		insn[i].detail = NULL;
	}
	if (ok[0] == ok[1] && left[0] == left[1] && pc[0] == pc[1] &&
	    cursor[0] == cursor[1] &&
	    cs_errno(handles[0]) == cs_errno(handles[1]) &&
	    !memcmp(&insn[0], &insn[1], sizeof(cs_insn)) &&
	    !memcmp(&detail[0], &detail[1], sizeof(cs_detail)) &&
	    (!has_operands || (ok[1] && operand_count > 0)))
		return true;
	fprintf(stderr, "MIPS scan mismatch for %08x, length %zu, %s-endian\n",
		(unsigned)word, length, big_endian ? "big" : "little");
	return false;
}

static bool check_mode(cs_mode mode)
{
	static const uint32_t words[] = {
		0x24080001, 0x3128ffff, 0x35080000,
		0x3928ffff, 0x8fa80000, 0xafa8fffc,
	};
	static const uint32_t others[] = {
		0x6508ffff, 0xdfa80000, 0xffa8fffc, 0x10000002,
		0,	    0x03e00008, 0xffffffff,
	};
	csh handles[2] = { 0 };
	bool success = false, big_endian = (mode & CS_MODE_BIG_ENDIAN) != 0;
	for (unsigned i = 0; i < 2; ++i)
		if (cs_open(CS_ARCH_MIPS, mode, &handles[i]))
			goto done;
	cs_struct *reference = (cs_struct *)(uintptr_t)handles[1];
	ordinary = reference->disasm;
	reference->disasm = inspect_operands;
	for (unsigned options = 0; options < 4; ++options) {
		for (unsigned i = 0; i < 2; ++i)
			if (cs_option(handles[i], CS_OPT_TEXT,
				      options & 1 ? CS_OPT_ON : CS_OPT_OFF) ||
			    cs_option(handles[i], CS_OPT_DETAIL,
				      options & 2 ? CS_OPT_ON : CS_OPT_OFF))
				goto done;
		for (unsigned i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
			for (size_t length = 0; length <= 4; ++length)
				if (!compare(handles, words[i], big_endian,
					     length, length == 4))
					goto done;
		for (unsigned i = 0; i < sizeof(others) / sizeof(others[0]);
		     ++i)
			if (!compare(handles, others[i], big_endian, 4, false))
				goto done;
	}
	success = true;
done:
	for (unsigned i = 0; i < 2; ++i)
		if (handles[i])
			cs_close(&handles[i]);
	return success;
}

int main(void)
{
	const cs_mode modes[] = { CS_MODE_MIPS32, CS_MODE_MIPS64,
				  CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN,
				  CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN };
	for (unsigned i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i)
		if (!check_mode(modes[i]))
			return 1;
	return 0;
}

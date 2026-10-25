/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>

static bool check(const cs_insn *insn, unsigned id, unsigned size,
		  unsigned access, unsigned length, bool detail, bool text)
{
	/* CS_OPT_TEXT_OFF is a scan: operand detail is not produced. */
	if (!detail || !text)
		return insn && insn->id == id && insn->size == length &&
		       (detail || !insn->detail);
	if (!insn || !insn->detail || insn->id != id || insn->size != length ||
	    insn->detail->x86.op_count != 1 ||
	    insn->detail->x86.operands[0].type != X86_OP_MEM ||
	    insn->detail->x86.operands[0].size != size ||
	    insn->detail->x86.operands[0].access != access) {
		fprintf(stderr,
			"x87 id=%u: expected %u bytes/access %u/length %u, got %u/%u/%u\n",
			id, size, access, length,
			insn && insn->detail ?
				insn->detail->x86.operands[0].size :
				0,
			insn && insn->detail ?
				insn->detail->x86.operands[0].access :
				0,
			insn ? insn->size : 0);
		return false;
	}
	return true;
}
enum test_options {
	DETAIL = 1,
	TEXT = 2,
	OPERAND_PREFIX = 4,
	ADDRESS_PREFIX = 8,
	REX_W = 16,
	CANCEL_REX = 32,
};

static bool check_case(cs_mode mode, cs_opt_value syntax, unsigned options,
		       unsigned family)
{
	const unsigned ids[] = { X86_INS_FNSTENV, X86_INS_FLDENV,
				 X86_INS_FNSAVE, X86_INS_FRSTOR };
	const bool detail = (options & DETAIL) != 0;
	const bool text = (options & TEXT) != 0;
	const bool prefix = (options & OPERAND_PREFIX) != 0;
	const bool rex = (options & REX_W) != 0;
	const bool cancel_rex = (options & CANCEL_REX) != 0;
	const bool short_environment = ((mode == CS_MODE_16) != prefix) &&
				       !(rex && !cancel_rex);
	const unsigned size =
		(short_environment ? 14 : 28) + (family >= 2 ? 80 : 0);
	const unsigned access = family % 2 ? CS_AC_READ : CS_AC_WRITE;
	csh handle;
	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
		return false;
	cs_option(handle, CS_OPT_DETAIL, detail ? CS_OPT_ON : CS_OPT_OFF);
	cs_option(handle, CS_OPT_TEXT, text ? CS_OPT_ON : CS_OPT_OFF);
	cs_option(handle, CS_OPT_SYNTAX, syntax);
	uint8_t bytes[6];
	unsigned length = 0;
	if (cancel_rex)
		bytes[length++] = 0x48;
	if (prefix)
		bytes[length++] = 0x66;
	if (options & ADDRESS_PREFIX)
		bytes[length++] = 0x67;
	if (rex && !cancel_rex)
		bytes[length++] = 0x48;
	bytes[length++] = family < 2 ? 0xd9 : 0xdd;
	bytes[length++] = family % 2 ? 0x20 : 0x30;

	cs_insn *insn = NULL;
	const size_t count = cs_disasm(handle, bytes, length, 0x1000, 1, &insn);
	bool success = count == 1 && check(insn, ids[family], size, access,
					   length, detail, text);
	if (count && !text)
		success &= !insn->mnemonic[0] && !insn->op_str[0];
	cs_free(insn, count);
	insn = cs_malloc(handle);
	const uint8_t *cursor = bytes;
	size_t remaining = length;
	uint64_t pc = 0x1000;
	if (!insn || !cs_disasm_iter(handle, &cursor, &remaining, &pc, insn))
		success = false;
	else {
		success &= !remaining && cursor == bytes + length &&
			   pc == 0x1000 + length &&
			   check(insn, ids[family], size, access, length,
				 detail, text);
		if (!text)
			success &= !insn->mnemonic[0] && !insn->op_str[0];
	}
	cs_free(insn, 1);
	cs_close(&handle);
	return success;
}

int main(void)
{
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	const cs_opt_value syntaxes[] = { CS_OPT_SYNTAX_INTEL,
					  CS_OPT_SYNTAX_ATT };
	bool success = true;
	unsigned observations = 0;
	for (unsigned m = 0; m < 3; ++m)
		for (unsigned s = 0; s < 2; ++s)
			for (unsigned options = 0; options < 64; ++options) {
				if ((options & REX_W) && modes[m] != CS_MODE_64)
					continue;
				if ((options & CANCEL_REX) &&
				    ((options & (REX_W | OPERAND_PREFIX)) !=
				     (REX_W | OPERAND_PREFIX)))
					continue;
				for (unsigned family = 0; family < 4;
				     ++family) {
					success &= check_case(modes[m],
							      syntaxes[s],
							      options, family);
					observations += 2;
				}
			}
	printf("%u x87 environment API observations\n", observations);
	return success ? 0 : 1;
}

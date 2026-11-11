/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>

static bool check_form(csh handle, cs_mode mode, bool att, bool immediate,
		       bool memory)
{
	uint8_t vex[] = { 0xc4, 0xe2, 0x48, 0xf7, 0xd3 };
	uint8_t xop[] = { 0x8f, 0xea, 0x78, 0x10, 0xd3, 7, 5, 0, 0 };
	uint8_t *code = immediate ? xop : vex;
	size_t size = immediate ? sizeof(xop) : sizeof(vex);
	if (mode == CS_MODE_64)
		code[2] |= 0x80;
	if (memory)
		code[4] = 0x10;

	/* AMD APM Vol. 3, BEXTR (register and immediate forms). */
	const uint64_t flags = X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			       X86_EFLAGS_UNDEFINED_SF |
			       X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_RESET_CF |
			       X86_EFLAGS_RESET_OF;
	cs_insn *insn = NULL;
	if (cs_disasm(handle, code, size, 0, 1, &insn) != 1)
		return false;
	const cs_x86 *x86 = &insn->detail->x86;
	const cs_x86_op *dst = &x86->operands[att ? 2 : 0];
	const cs_x86_op *control = &x86->operands[att ? 0 : 2];
	bool valid =
		insn->id == X86_INS_BEXTR && insn->size == size &&
		x86->eflags == flags && x86->op_count == 3 &&
		dst->type == X86_OP_REG && dst->access == CS_AC_WRITE &&
		x86->operands[1].type == (memory ? X86_OP_MEM : X86_OP_REG) &&
		x86->operands[1].access == CS_AC_READ &&
		control->type == (immediate ? X86_OP_IMM : X86_OP_REG) &&
		control->access == (immediate ? CS_AC_INVALID : CS_AC_READ);
	cs_free(insn, 1);
	return valid;
}

static bool check_mode(cs_mode mode)
{
	csh handle;
	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
		return false;
	bool ok = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
	for (unsigned att = 0; att < 2; ++att) {
		cs_err err = cs_option(handle, CS_OPT_SYNTAX,
				       att ? CS_OPT_SYNTAX_ATT :
					     CS_OPT_SYNTAX_INTEL);
		if (att && err == CS_ERR_X86_ATT)
			continue;
		if (err != CS_ERR_OK) {
			ok = false;
			break;
		}
		/* Reduced builds retain BMI1 but omit the XOP decoder. */
		unsigned forms = cs_support(CS_SUPPORT_X86_REDUCE) ? 1 : 2;
		for (unsigned immediate = 0; immediate < forms; ++immediate)
			for (unsigned memory = 0; memory < 2; ++memory)
				if (!check_form(handle, mode, att, immediate,
						memory)) {
					fprintf(stderr,
						"BEXTR mode=%u att=%u immediate=%u memory=%u\n",
						(unsigned)mode, att, immediate,
						memory);
					ok = false;
				}
	}
	cs_close(&handle);
	return ok;
}

int main(void)
{
	if (cs_support(CS_SUPPORT_DIET))
		return 0;
	bool ok32 = check_mode(CS_MODE_32);
	bool ok64 = check_mode(CS_MODE_64);
	return ok32 && ok64 ? 0 : 1;
}

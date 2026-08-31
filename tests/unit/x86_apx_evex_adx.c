/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
static bool ck(bool v, const char *s)
{
	if (!v)
		fprintf(stderr, "ADX: %s\n", s);
	return v;
}
static bool dec(csh h, const uint8_t *b, size_t n, cs_insn **i)
{
	return cs_disasm(h, b, n, 0x1000, 1, i) == 1;
}
static bool form(csh h, const uint8_t b[6], x86_insn id, const char *n,
		 uint64_t f)
{
	cs_insn *i = NULL;
	const cs_x86 *x;
	bool ok;
	if (!ck(dec(h, b, 6, &i), "legal rejected"))
		return false;
	x = &i->detail->x86;
	ok = ck(i->id == id && !strcmp(i->mnemonic, n), "ID/name") &&
	     ck(x->op_count == 3, "NDD count") &&
	     ck(x->operands[0].reg == X86_REG_R17 &&
			x->operands[0].access == CS_AC_WRITE,
		"dst") &&
	     ck(x->operands[1].reg == X86_REG_R18 &&
			x->operands[1].access == CS_AC_READ,
		"src1") &&
	     ck(x->operands[2].reg == X86_REG_R19 &&
			x->operands[2].access == CS_AC_READ,
		"src2") &&
	     ck(x->operands[0].size == 8 && x->eflags == f, "width/flags");
	cs_free(i, 1);
	return ok;
}
int main(void)
{
	static const uint8_t cx[] = { 0x62, 0xec, 0xf5, 0x10, 0x66, 0xd3 },
			     ox[] = { 0x62, 0xec, 0xf6, 0x10, 0x66, 0xd3 };
	static const uint8_t two[] = { 0x62, 0xec, 0xfd, 0x08, 0x66, 0xd3 },
			     mem[] = { 0x62, 0x8c, 0x75, 0x10,
				       0x66, 0x54, 0xb5, 0x20 };
	static const uint8_t bad[][6] = {
		{ 0x62, 0xec, 0xf5, 0x14, 0x66, 0xd3 },
		{ 0x62, 0xec, 0xf4, 0x10, 0x66, 0xd3 },
		{ 0x62, 0xec, 0xf7, 0x10, 0x66, 0xd3 },
		{ 0x62, 0xec, 0xf5, 0x30, 0x66, 0xd3 }
	};
	csh h;
	cs_insn *i = NULL;
	size_t k;
	bool ok = true;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK)
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	ok &= form(h, cx, X86_INS_ADCX, "adcx",
		   X86_EFLAGS_TEST_CF | X86_EFLAGS_MODIFY_CF);
	ok &= form(h, ox, X86_INS_ADOX, "adox",
		   X86_EFLAGS_TEST_OF | X86_EFLAGS_MODIFY_OF);
	ok &= ck(dec(h, two, sizeof(two), &i), "two operand");
	if (i) {
		ok &= ck(i->detail->x86.op_count == 2, "two detail");
		cs_free(i, 1);
		i = NULL;
	}
	ok &= ck(dec(h, mem, sizeof(mem), &i), "memory");
	if (i) {
		ok &= ck(i->detail->x86.operands[2].type == X86_OP_MEM,
			 "memory detail");
		cs_free(i, 1);
		i = NULL;
	}
	for (k = 0; k < sizeof(bad) / sizeof(bad[0]); ++k) {
		ok &= ck(!dec(h, bad[k], 6, &i), "reserved accepted");
		if (i) {
			cs_free(i, 1);
			i = NULL;
		}
	}
	cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	ok &= ck(dec(h, cx, 6, &i), "AT&T");
	if (i) {
		ok &= ck(!strcmp(i->mnemonic, "adcxq") &&
				 !strcmp(i->op_str, "%r19, %r18, %r17"),
			 "AT&T text");
		cs_free(i, 1);
	}
	cs_close(&h);
	return ok ? 0 : 1;
}

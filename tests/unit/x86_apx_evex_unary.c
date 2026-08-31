#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
static bool d(csh h, const uint8_t *b, cs_insn **i)
{
	return cs_disasm(h, b, 6, 0, 1, i) == 1;
}
int main(void)
{
	static const struct {
		x86_insn id;
		const char *n;
		uint8_t op, m;
		uint64_t f;
	} v[] = { { X86_INS_INC, "inc", 0xff, 0xc3,
		    X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			    X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF |
			    X86_EFLAGS_MODIFY_PF },
		  { X86_INS_DEC, "dec", 0xff, 0xcb,
		    X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			    X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF |
			    X86_EFLAGS_MODIFY_PF },
		  { X86_INS_NEG, "neg", 0xf7, 0xdb,
		    X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			    X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF |
			    X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF },
		  { X86_INS_NOT, "not", 0xf7, 0xd3, 0 } };
	static const uint8_t bad[][6] = {
		{ 0x62, 0xec, 0xf5, 0x30, 0xff, 0xc3 },
		{ 0x62, 0xec, 0xf5, 0x14, 0xf7, 0xd3 },
		{ 0x62, 0xec, 0xf6, 0x10, 0xff, 0xc3 },
		{ 0x62, 0xec, 0xf5, 0x08, 0xff, 0xc3 }
	};
	csh h;
	cs_insn *i = NULL;
	bool ok = true;
	size_t k;
	uint8_t b[] = { 0x62, 0xec, 0xf5, 0x10, 0, 0 };
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	for (k = 0; k < 4; k++) {
		b[4] = v[k].op;
		b[5] = v[k].m;
		if (!d(h, b, &i)) {
			ok = false;
			continue;
		}
		ok &= i->id == v[k].id && !strcmp(i->mnemonic, v[k].n) &&
		      i->detail->x86.op_count == 2 &&
		      i->detail->x86.operands[0].reg == X86_REG_R17 &&
		      i->detail->x86.operands[0].access == CS_AC_WRITE &&
		      i->detail->x86.operands[1].reg == X86_REG_R19 &&
		      i->detail->x86.operands[1].access == CS_AC_READ &&
		      i->detail->x86.eflags == v[k].f;
		cs_free(i, 1);
		i = NULL;
	}
	for (k = 0; k < 4; k++) {
		if (d(h, bad[k], &i)) {
			ok = false;
			cs_free(i, 1);
			i = NULL;
		}
	}
	cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	b[4] = 0xf7;
	b[5] = 0xdb;
	if (!d(h, b, &i))
		ok = false;
	else {
		ok &= !strcmp(i->mnemonic, "negq") &&
		      !strcmp(i->op_str, "%r19, %r17");
		cs_free(i, 1);
	}
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "APX unary focused failure\n");
	return ok ? 0 : 1;
}

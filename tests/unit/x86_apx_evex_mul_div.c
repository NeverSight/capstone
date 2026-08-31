#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
int main(void)
{
	static const struct {
		x86_insn id;
		uint8_t g;
	} v[] = { { X86_INS_MUL, 4 }, { X86_INS_DIV, 6 }, { X86_INS_IDIV, 7 } };
	csh h;
	cs_insn *i = NULL;
	bool ok = true;
	unsigned k, nf;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	for (k = 0; k < 3; k++)
		for (nf = 0; nf < 2; nf++) {
			uint8_t c[] = { 0x62, 0xec,
					0xfd, (uint8_t)(8 | (nf ? 4 : 0)),
					0xf7, (uint8_t)(0xc3 | (v[k].g << 3)) };
			if (cs_disasm(h, c, 6, 0, 1, &i) != 1) {
				ok = false;
				continue;
			}
			ok &= i->id == v[k].id &&
			      i->detail->x86.op_count == 1 &&
			      i->detail->x86.operands[0].reg == X86_REG_R19 &&
			      i->detail->x86.operands[0].access == CS_AC_READ;
			cs_free(i, 1);
			i = NULL;
			c[3] |= 0x10;
			if (cs_disasm(h, c, 6, 0, 1, &i)) {
				ok = false;
				cs_free(i, 1);
				i = NULL;
			}
		}
	cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	{
		uint8_t c[] = { 0x62, 0xec, 0xfd, 8, 0xf7, 0xf3 };
		if (cs_disasm(h, c, 6, 0, 1, &i) != 1)
			ok = false;
		else {
			ok &= i->mnemonic[0] == 'd' && i->op_str[0] == '%';
			cs_free(i, 1);
		}
	}
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "APX MUL/DIV focused failure\n");
	return ok ? 0 : 1;
}

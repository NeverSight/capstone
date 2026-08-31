#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
int main(void)
{
	static const struct {
		x86_insn id;
		uint8_t op;
	} v[] = { { X86_INS_ANDN, 0xf2 }, { X86_INS_BZHI, 0xf5 } };
	csh h;
	cs_insn *i = NULL;
	bool ok = true;
	unsigned k, nf;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	for (k = 0; k < 2; k++)
		for (nf = 0; nf < 2; nf++) {
			uint8_t c[] = { 0x62,	 0xea,
					0xf4,	 (uint8_t)(nf ? 4 : 0),
					v[k].op, 0xd3 };
			if (cs_disasm(h, c, 6, 0, 1, &i) != 1) {
				ok = false;
				continue;
			}
			ok &= i->id == v[k].id &&
			      i->detail->x86.op_count == 3 &&
			      i->detail->x86.operands[0].reg == X86_REG_R18 &&
			      i->detail->x86.operands[0].access ==
				      CS_AC_WRITE &&
			      i->detail->x86.operands[1].reg == X86_REG_R17 &&
			      i->detail->x86.operands[2].reg == X86_REG_R19;
			cs_free(i, 1);
			i = NULL;
			c[3] |= 0x10;
			if (cs_disasm(h, c, 6, 0, 1, &i)) {
				ok = false;
				cs_free(i, 1);
				i = NULL;
			}
		}
	for (k = 0; k < 2; ++k) {
		const uint8_t memory[] = { 0x64, 0x62, 0x8a, 0xf0, 0x00,
					   v[k].op, 0x54, 0xa5, 0x20 };
		if (cs_disasm(h, memory, sizeof(memory), 0, 1, &i) != 1)
			ok = false;
		else {
			const cs_x86 *x86 = &i->detail->x86;
			const cs_x86_op *mem = &x86->operands[2];
			ok &= i->id == v[k].id && x86->op_count == 3 &&
			      x86->operands[0].reg == X86_REG_R18 &&
			      x86->operands[1].reg == X86_REG_R17 &&
			      mem->type == X86_OP_MEM && mem->size == 8 &&
			      mem->access == CS_AC_READ &&
			      mem->mem.segment == X86_REG_FS &&
			      mem->mem.base == X86_REG_R29 &&
			      mem->mem.index == X86_REG_R28 &&
			      mem->mem.scale == 4 && mem->mem.disp == 0x20;
			cs_free(i, 1);
			i = NULL;
		}
	}
	cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	{
		uint8_t c[] = { 0x62, 0xea, 0xf4, 0, 0xf2, 0xd3 };
		if (cs_disasm(h, c, 6, 0, 1, &i) != 1)
			ok = false;
		else {
			ok &= i->op_str[0] == '%';
			cs_free(i, 1);
		}
	}
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "APX BMI ternary failure\n");
	return ok ? 0 : 1;
}

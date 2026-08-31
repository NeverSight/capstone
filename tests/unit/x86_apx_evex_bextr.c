#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
int main(void)
{
	const uint64_t flags = X86_EFLAGS_MODIFY_ZF |
			       X86_EFLAGS_UNDEFINED_AF |
			       X86_EFLAGS_UNDEFINED_SF |
			       X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_RESET_CF |
			       X86_EFLAGS_RESET_OF;
	csh h;
	cs_insn *i = NULL;
	bool ok = true;
	unsigned nf;
	uint8_t reg[] = { 0x62, 0xea, 0xf4, 0, 0xf7, 0xd3 };
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	for (nf = 0; nf < 2; nf++) {
		reg[3] = nf ? 4 : 0;
		if (cs_disasm(h, reg, 6, 0, 1, &i) != 1) {
			ok = false;
			continue;
		}
		ok &= i->id == X86_INS_BEXTR && i->detail->x86.op_count == 3 &&
		      i->detail->x86.operands[0].reg == X86_REG_R18 &&
		      i->detail->x86.operands[0].access == CS_AC_WRITE &&
		      i->detail->x86.operands[1].reg == X86_REG_R19 &&
		      i->detail->x86.operands[2].reg == X86_REG_R17 &&
		      i->detail->x86.eflags == (nf ? 0 : flags) &&
		      i->detail->regs_write_count == (nf ? 0 : 1) &&
		      (nf || i->detail->regs_write[0] == X86_REG_EFLAGS);
		cs_free(i, 1);
		i = NULL;
	}
	reg[3] = 0x10;
	if (cs_disasm(h, reg, 6, 0, 1, &i)) {
		ok = false;
		cs_free(i, 1);
		i = NULL;
	}
	{
		const uint8_t memory[] = { 0x64, 0x62, 0x8a, 0xf0, 0x00,
					   0xf7, 0x54, 0xa5, 0x20 };
		if (cs_disasm(h, memory, sizeof(memory), 0, 1, &i) != 1)
			ok = false;
		else {
			const cs_x86 *x86 = &i->detail->x86;
			const cs_x86_op *mem = &x86->operands[1];
			ok &= i->id == X86_INS_BEXTR && x86->op_count == 3 &&
			      x86->operands[0].reg == X86_REG_R18 &&
			      x86->operands[2].reg == X86_REG_R17 &&
			      mem->type == X86_OP_MEM && mem->size == 8 &&
			      mem->access == CS_AC_READ &&
			      mem->mem.segment == X86_REG_FS &&
			      mem->mem.base == X86_REG_R29 &&
			      mem->mem.index == X86_REG_R28 &&
			      mem->mem.scale == 4 && mem->mem.disp == 0x20 &&
			      x86->eflags == flags &&
			      i->detail->regs_write_count == 1 &&
			      i->detail->regs_write[0] == X86_REG_EFLAGS;
			cs_free(i, 1);
			i = NULL;
		}
	}
	cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	reg[3] = 0;
	if (cs_disasm(h, reg, 6, 0, 1, &i) != 1)
		ok = false;
	else {
		ok &= i->op_str[0] == '%';
		cs_free(i, 1);
	}
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "APX BEXTR failure\n");
	return ok ? 0 : 1;
}

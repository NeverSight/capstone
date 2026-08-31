#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
int main(void)
{
	uint8_t c[] = { 0x62, 0xeb, 0xff, 8, 0xf0, 0xd3, 7 };
	csh h;
	cs_insn *i = NULL;
	bool ok = true;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	if (cs_disasm(h, c, 7, 0, 1, &i) != 1)
		ok = false;
	else {
		ok &= i->id == X86_INS_RORX && i->detail->x86.op_count == 3 &&
		      i->detail->x86.operands[0].reg == X86_REG_R18 &&
		      i->detail->x86.operands[1].reg == X86_REG_R19 &&
		      i->detail->x86.operands[2].imm == 7 &&
		      i->detail->x86.encoding.imm_offset == 6 &&
		      i->detail->x86.encoding.imm_size == 1 &&
		      i->detail->x86.eflags == 0;
		cs_free(i, 1);
		i = NULL;
	}
	c[3] = 12;
	if (cs_disasm(h, c, 7, 0, 1, &i)) {
		ok = false;
		cs_free(i, 1);
		i = NULL;
	}
	{
		const uint8_t memory[] = { 0x64, 0x62, 0xab, 0xfb, 0x08,
					   0xf0, 0x54, 0xa5, 0x20, 0x07 };
		const uint8_t address32[] = { 0x67, 0x64, 0x62, 0xab, 0x7b,
					     0x08, 0xf0, 0x54, 0xa5, 0x20,
					     0x07 };
		const struct {
			const uint8_t *code;
			size_t size;
			x86_reg destination;
			x86_reg base;
			x86_reg index;
			uint8_t address_size;
		} cases[] = {
			{ memory, sizeof(memory), X86_REG_R18, X86_REG_R21,
			  X86_REG_R28, 8 },
			{ address32, sizeof(address32), X86_REG_R18D,
			  X86_REG_R21D, X86_REG_R28D, 4 },
		};
		for (unsigned int k = 0; k < sizeof(cases) / sizeof(cases[0]); ++k) {
			if (cs_disasm(h, cases[k].code, cases[k].size, 0, 1, &i) != 1)
				ok = false;
			else {
				const cs_x86 *x86 = &i->detail->x86;
				const cs_x86_op *mem = &x86->operands[1];
				ok &= i->id == X86_INS_RORX && x86->op_count == 3 &&
				      x86->operands[0].reg == cases[k].destination &&
				      mem->type == X86_OP_MEM &&
				      mem->access == CS_AC_READ &&
				      mem->mem.segment == X86_REG_FS &&
				      mem->mem.base == cases[k].base &&
				      mem->mem.index == cases[k].index &&
				      mem->mem.scale == 4 && mem->mem.disp == 0x20 &&
				      x86->operands[2].imm == 7 &&
				      x86->addr_size == cases[k].address_size &&
				      x86->eflags == 0;
				cs_free(i, 1);
				i = NULL;
			}
		}
	}
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "APX RORX failure\n");
	return ok ? 0 : 1;
}

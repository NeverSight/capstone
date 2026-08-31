#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
int main(void)
{
	static const x86_insn ids[] = { X86_INS_BLSR, X86_INS_BLSMSK,
					X86_INS_BLSI };
	csh h;
	cs_insn *i = NULL;
	bool ok = true;
	unsigned g, nf;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	for (g = 1; g <= 3; g++)
		for (nf = 0; nf < 2; nf++) {
			uint8_t c[] = { 0x62, 0xea,
					0xf4, (uint8_t)(nf ? 4 : 0),
					0xf3, (uint8_t)(0xc3 | (g << 3)) };
			if (cs_disasm(h, c, 6, 0, 1, &i) != 1) {
				ok = false;
				continue;
			}
			ok &= i->id == ids[g - 1] &&
			      i->detail->x86.op_count == 2 &&
			      i->detail->x86.operands[0].reg == X86_REG_R17 &&
			      i->detail->x86.operands[0].access ==
				      CS_AC_WRITE &&
			      i->detail->x86.operands[1].reg == X86_REG_R19 &&
			      i->detail->x86.operands[1].access == CS_AC_READ;
			cs_free(i, 1);
			i = NULL;
			c[3] |= 0x10;
			if (cs_disasm(h, c, 6, 0, 1, &i)) {
				ok = false;
				cs_free(i, 1);
				i = NULL;
			}
		}
	{
		const uint8_t memory[] = { 0x64, 0x62, 0x8a, 0xf0, 0x00,
					   0xf3, 0x5c, 0xa5, 0x20 };
		if (cs_disasm(h, memory, sizeof(memory), 0, 1, &i) != 1)
			ok = false;
		else {
			const cs_x86 *x86 = &i->detail->x86;
			const cs_x86_op *mem = &x86->operands[1];
			ok &= i->id == X86_INS_BLSI && x86->op_count == 2 &&
			      x86->operands[0].reg == X86_REG_R17 &&
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
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "APX BLS failure\n");
	return ok ? 0 : 1;
}

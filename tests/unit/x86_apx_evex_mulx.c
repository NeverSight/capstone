#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
	uint8_t c[] = { 0x62, 0xea, 0xf7, 0, 0xf6, 0xd3 };
	csh h;
	cs_insn *i = NULL;
	bool ok = true;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	if (cs_disasm(h, c, 6, 0, 1, &i) != 1)
		ok = false;
	else {
		ok &= i->id == X86_INS_MULX && i->detail->x86.op_count == 3 &&
		      i->detail->x86.operands[0].reg == X86_REG_R18 &&
		      i->detail->x86.operands[0].access == CS_AC_WRITE &&
		      i->detail->x86.operands[1].reg == X86_REG_R17 &&
		      i->detail->x86.operands[1].access == CS_AC_WRITE &&
		      i->detail->x86.operands[2].reg == X86_REG_R19 &&
		      i->detail->x86.operands[2].access == CS_AC_READ &&
		      i->detail->x86.eflags == 0;
		cs_free(i, 1);
		i = NULL;
	}
	{
		const uint8_t mem[] = { 0x64, 0x62, 0x8a, 0xf7, 0x00,
					0xf6, 0x54, 0xb5, 0x20 };
		if (cs_disasm(h, mem, sizeof(mem), 0, 1, &i) != 1)
			ok = false;
		else {
			const cs_x86_op *m = &i->detail->x86.operands[2];
			ok &= !strcmp(i->mnemonic, "mulx") &&
			      !strcmp(i->op_str,
				      "r18, r17, qword ptr fs:[r29 + r14*4 + 0x20]") &&
			      m->type == X86_OP_MEM && m->access == CS_AC_READ &&
			      m->size == 8 && m->mem.segment == X86_REG_FS &&
			      m->mem.base == X86_REG_R29 &&
			      m->mem.index == X86_REG_R14 && m->mem.scale == 4 &&
			      m->mem.disp == 0x20 &&
			      i->detail->regs_read_count == 1 &&
			      i->detail->regs_read[0] == X86_REG_RDX;
			cs_free(i, 1);
			i = NULL;
		}
		cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		if (cs_disasm(h, mem, sizeof(mem), 0, 1, &i) != 1)
			ok = false;
		else {
			ok &= !strcmp(i->mnemonic, "mulxq") &&
			      !strcmp(i->op_str,
				      "%fs:0x20(%r29,%r14,4), %r17, %r18") &&
			      i->detail->x86.operands[0].type == X86_OP_MEM &&
			      i->detail->x86.operands[0].access == CS_AC_READ &&
			      i->detail->x86.operands[1].reg == X86_REG_R17 &&
			      i->detail->x86.operands[2].reg == X86_REG_R18;
			cs_free(i, 1);
			i = NULL;
		}
		cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	}
	{
		const uint8_t mem[] = { 0x64, 0x62, 0x8a, 0xf3, 0x00,
					0xf6, 0x54, 0xa5, 0x20 };
		if (cs_disasm(h, mem, sizeof(mem), 0, 1, &i) != 1)
			ok = false;
		else {
			const cs_x86 *x86 = &i->detail->x86;
			const cs_x86_op *memory = &x86->operands[2];
			ok &= i->id == X86_INS_MULX && x86->op_count == 3 &&
			      x86->operands[0].reg == X86_REG_R18 &&
			      x86->operands[1].reg == X86_REG_R17 &&
			      memory->type == X86_OP_MEM && memory->size == 8 &&
			      memory->access == CS_AC_READ &&
			      memory->mem.segment == X86_REG_FS &&
			      memory->mem.base == X86_REG_R29 &&
			      memory->mem.index == X86_REG_R28 &&
			      memory->mem.scale == 4 && memory->mem.disp == 0x20;
			cs_free(i, 1);
			i = NULL;
		}
	}
	c[3] = 4;
	if (cs_disasm(h, c, 6, 0, 1, &i)) {
		ok = false;
		cs_free(i, 1);
		i = NULL;
	}
	c[3] = 0x10;
	if (cs_disasm(h, c, 6, 0, 1, &i)) {
		ok = false;
		cs_free(i, 1);
		i = NULL;
	}
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "APX MULX failure\n");
	return ok ? 0 : 1;
}

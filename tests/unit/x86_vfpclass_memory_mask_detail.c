#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <stdio.h>

static bool check(csh h, uint8_t p1, uint8_t p2, uint8_t opcode,
		  uint8_t expected_size)
{
	uint8_t code[] = { 0x62, 0xf3, p1, p2, opcode, 0x1a, 0xff };
	cs_insn *i = NULL;
	bool ok = false, reads_mask = false, reads_dst = false,
	     writes_dst = false;
	if (cs_disasm(h, code, sizeof(code), 0, 1, &i) == 1 && i->detail) {
		cs_x86 *x = &i->detail->x86;
		cs_regs reads, writes;
		uint8_t read_count = 0, write_count = 0;
		cs_regs_access(h, i, reads, &read_count, writes, &write_count);
		for (unsigned r = 0; r < read_count; r++) {
			reads_mask |= reads[r] == X86_REG_K1;
			reads_dst |= reads[r] == X86_REG_K3;
		}
		for (unsigned r = 0; r < write_count; r++)
			writes_dst |= writes[r] == X86_REG_K3;
		ok = x->op_count == 4 && x->operands[0].type == X86_OP_REG &&
		     x->operands[0].reg == X86_REG_K3 &&
		     x->operands[0].size == expected_size &&
		     x->operands[0].access == CS_AC_WRITE &&
		     x->operands[1].type == X86_OP_REG &&
		     x->operands[1].reg == X86_REG_K1 &&
		     x->operands[1].size == expected_size &&
		     x->operands[1].access == CS_AC_READ &&
		     x->operands[2].type == X86_OP_MEM && reads_mask &&
		     !reads_dst && writes_dst;
	}
	if (!ok && i)
		fprintf(stderr, "%s %s sizes=%u/%u access=%u/%u rr=%u/%u/%u\n",
			i->mnemonic, i->op_str, i->detail->x86.operands[0].size,
			i->detail->x86.operands[1].size,
			i->detail->x86.operands[0].access,
			i->detail->x86.operands[1].access, reads_mask,
			reads_dst, writes_dst);
	cs_free(i, 1);
	return ok;
}

int main(void)
{
	csh h;
	bool ok = true;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	for (unsigned type = 0; type < 2; type++) {
		uint8_t p1 = type ? 0xfd : 0x7d;
		uint8_t sizes[3] = { 1, 1, (uint8_t)(type ? 1 : 2) };
		for (unsigned ll = 0; ll < 3; ll++) {
			ok &= check(h, p1, (uint8_t)(0x09 + (ll << 5)), 0x66,
				    sizes[ll]);
			ok &= check(h, p1, (uint8_t)(0x19 + (ll << 5)), 0x66,
				    sizes[ll]);
		}
	}
	for (unsigned type = 0; type < 2; type++) {
		uint8_t p1 = type ? 0xfd : 0x7d;
		for (unsigned ll = 0; ll < 3; ll++)
			ok &= check(h, p1, (uint8_t)(0x09 + (ll << 5)), 0x67,
				    1);
	}
	cs_close(&h);
	return ok ? 0 : 1;
}

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <stdio.h>

static bool check_regs(csh h, cs_insn *insn)
{
	cs_regs reads, writes;
	uint8_t read_count = 0, write_count = 0;
	cs_err err = cs_regs_access(h, insn, reads, &read_count, writes,
				    &write_count);
	if (cs_support(CS_SUPPORT_DIET))
		return err == CS_ERR_DIET;
	if (err != CS_ERR_OK)
		return false;

	bool reads_mask = false, reads_dst = false, writes_dst = false;
	for (unsigned r = 0; r < read_count; r++) {
		reads_mask |= reads[r] == X86_REG_K1;
		reads_dst |= reads[r] == X86_REG_K3;
	}
	for (unsigned r = 0; r < write_count; r++)
		writes_dst |= writes[r] == X86_REG_K3;
	return reads_mask && !reads_dst && writes_dst;
}

static bool check(csh h, bool att, uint8_t p1, uint8_t p2, uint8_t opcode,
		  uint8_t modrm, uint8_t expected_size)
{
	uint8_t code[] = { 0x62, 0xf3, p1, p2, opcode, modrm, 0xff };
	cs_insn *i = NULL;
	size_t count = cs_disasm(h, code, sizeof(code), 0, 1, &i);
	bool ok = false;
	if (cs_support(CS_SUPPORT_X86_REDUCE)) {
		/* VFPCLASS is omitted from the reduced opcode tables. */
		ok = count == 0;
	} else if (count == 1 && i->detail) {
		cs_x86 *x = &i->detail->x86;
		const cs_x86_op *dst = &x->operands[att ? 2 : 0];
		const cs_x86_op *mask = &x->operands[att ? 3 : 1];
		const cs_x86_op *source = &x->operands[att ? 1 : 2];
		ok = check_regs(h, i) && x->op_count == 4 &&
		     dst->type == X86_OP_REG && dst->reg == X86_REG_K3 &&
		     dst->size == expected_size && dst->access == CS_AC_WRITE &&
		     mask->type == X86_OP_REG && mask->reg == X86_REG_K1 &&
		     mask->size == expected_size &&
		     mask->access == CS_AC_READ &&
		     source->type == (modrm == 0x1a ? X86_OP_MEM : X86_OP_REG);
	}
	if (!ok)
		fprintf(stderr,
			"VFPCLASS %02x %02x %02x %02x (%s), expected mask width %u\n",
			p1, p2, opcode, modrm, att ? "ATT" : "Intel",
			expected_size);
	cs_free(i, count);
	return ok;
}

static bool check_forms(csh h, bool att)
{
	bool ok = true;
	for (unsigned type = 0; type < 2; type++) {
		uint8_t p1 = type ? 0xfd : 0x7d;
		uint8_t sizes[3] = { 1, 1, (uint8_t)(type ? 1 : 2) };
		for (unsigned ll = 0; ll < 3; ll++) {
			ok &= check(h, att, p1, (uint8_t)(0x09 + (ll << 5)),
				    0x66, 0x1a, sizes[ll]);
			ok &= check(h, att, p1, (uint8_t)(0x09 + (ll << 5)),
				    0x66, 0xda, sizes[ll]);
			ok &= check(h, att, p1, (uint8_t)(0x19 + (ll << 5)),
				    0x66, 0x1a, sizes[ll]);
		}
	}
	for (unsigned type = 0; type < 2; type++) {
		uint8_t p1 = type ? 0xfd : 0x7d;
		for (unsigned ll = 0; ll < 3; ll++) {
			ok &= check(h, att, p1, (uint8_t)(0x09 + (ll << 5)),
				    0x67, 0x1a, 1);
			ok &= check(h, att, p1, (uint8_t)(0x09 + (ll << 5)),
				    0x67, 0xda, 1);
		}
	}
	return ok;
}

int main(void)
{
	csh h;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h))
		return 1;
	bool ok = cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK &&
		  check_forms(h, false);
	if (cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) == CS_ERR_OK)
		ok &= check_forms(h, true);
	cs_close(&h);
	return ok ? 0 : 1;
}

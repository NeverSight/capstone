/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static bool check_indexed(csh handle, unsigned syntax, bool same_base)
{
	/* fldx.d $fs3, $t1, $s8; the address is GR[rj] + GR[rk]. */
	uint8_t bytes[] = { 0xbb, 0x7d, 0x34, 0x38 };
	if (same_base)
		bytes[1] = (uint8_t)((bytes[1] & 3) | (13 << 2));
	cs_insn *insn;
	if (cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 1, &insn) != 1)
		return false;
	const cs_loongarch *detail = &insn->detail->loongarch;
	const unsigned index = same_base ? LOONGARCH_REG_R13 :
					   LOONGARCH_REG_R31;
	const bool no_names = (syntax & CS_OPT_SYNTAX_NOREGNAME) != 0;
	const char *prefix = syntax & CS_OPT_SYNTAX_NO_DOLLAR ? "" : "$";
	const char *dst = no_names ? "f27" : "fs3";
	const char *base = no_names ? "r13" : "t1";
	const char *idx = same_base ? base : no_names ? "r31" : "s8";
	char operands[64];
	snprintf(operands, sizeof(operands), "%s%s, %s%s, %s%s", prefix, dst,
		 prefix, base, prefix, idx);
	cs_regs read, written;
	uint8_t nr = 0, nw = 0;
	cs_err access = cs_regs_access(handle, insn, read, &nr, written, &nw);
	bool ok = insn->id == LOONGARCH_INS_FLDX_D && detail->op_count == 2 &&
		  detail->operands[0].type == LOONGARCH_OP_REG &&
		  detail->operands[1].type == LOONGARCH_OP_MEM &&
		  detail->operands[1].mem.base == LOONGARCH_REG_R13 &&
		  detail->operands[1].mem.index == index &&
		  !strcmp(cs_reg_name(handle, detail->operands[0].reg), dst) &&
		  !strcmp(cs_reg_name(handle, index), idx) &&
		  !strcmp(insn->op_str, operands) && access == CS_ERR_OK &&
		  nr == (same_base ? 1 : 2) && read[0] == LOONGARCH_REG_R13 &&
		  (same_base || read[1] == index) && nw == 1 &&
		  written[0] == detail->operands[0].reg;
	if (!ok)
		fprintf(stderr,
			"LoongArch syntax %u: %s %s; expected %s, read %u of %u registers\n",
			syntax, insn->mnemonic, insn->op_str, operands, nr,
			same_base ? 1 : 2);
	cs_free(insn, 1);
	return ok;
}

static bool check_alias_view(csh handle, size_t view)
{
	const bool real = (view & CS_OPT_DETAIL_REAL) != 0;
	static const struct {
		uint8_t code[4];
		unsigned id, alias_operands, group;
	} forms[] = {
		{ { 0x28, 0x01, 0x15, 0x00 }, LOONGARCH_INS_OR, 2, 0 },
		{ { 0x20, 0x00, 0x00, 0x4c },
		  LOONGARCH_INS_JIRL,
		  0,
		  LOONGARCH_GRP_RET },
		{ { 0xa0, 0x00, 0x00, 0x4c },
		  LOONGARCH_INS_JIRL,
		  1,
		  LOONGARCH_GRP_JUMP },
		{ { 0xa1, 0x00, 0x00, 0x4c },
		  LOONGARCH_INS_JIRL,
		  3,
		  LOONGARCH_GRP_CALL },
	};
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF) ||
	    cs_option(handle, CS_OPT_DETAIL, view))
		return false;
	for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i) {
		cs_insn *insn;
		if (cs_disasm(handle, forms[i].code, 4, 0x1000, 1, &insn) != 1)
			return false;
		const cs_loongarch *d = &insn->detail->loongarch;
		bool ok = insn->id == forms[i].id &&
			  d->op_count == (real ? 3 : forms[i].alias_operands) &&
			  (!forms[i].group ||
			   cs_insn_group(handle, insn, forms[i].group));
		if (i == 0)
			ok = ok && d->operands[0].reg == LOONGARCH_REG_R8 &&
			     d->operands[1].reg == LOONGARCH_REG_R9 &&
			     (!real || d->operands[2].reg == LOONGARCH_REG_R0);
		cs_free(insn, 1);
		if (!ok)
			return false;
	}
	return true;
}

int main(void)
{
	const unsigned syntax[] = { CS_OPT_SYNTAX_DEFAULT,
				    CS_OPT_SYNTAX_NOREGNAME,
				    CS_OPT_SYNTAX_NO_DOLLAR,
				    CS_OPT_SYNTAX_NOREGNAME |
					    CS_OPT_SYNTAX_NO_DOLLAR };
	bool ok = true;
	for (size_t i = 0; i < sizeof(syntax) / sizeof(syntax[0]); ++i) {
		csh handle;
		if (cs_open(CS_ARCH_LOONGARCH, CS_MODE_LOONGARCH64, &handle))
			return 1;
		if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) ||
		    cs_option(handle, CS_OPT_SYNTAX, syntax[i]) ||
		    !check_indexed(handle, syntax[i], false) ||
		    !check_indexed(handle, syntax[i], true))
			ok = false;
		if (!check_alias_view(handle, CS_OPT_DETAIL_ALIAS) ||
		    !check_alias_view(handle, CS_OPT_DETAIL_REAL))
			ok = false;
		cs_close(&handle);
	}
	return !ok;
}

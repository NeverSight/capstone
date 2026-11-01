#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct system_case {
	uint8_t bytes[10];
	uint8_t size;
	unsigned int id;
	const char *name;
	bool only64;
	bool privileged;
} system_case;

static const system_case cases[] = {
	{ { 0xf2, 0x0f, 0x01, 0xca }, 4, X86_INS_ERETS, "erets", true, true },
	{ { 0xf3, 0x0f, 0x01, 0xca }, 4, X86_INS_ERETU, "eretu", true, true },
	{ { 0xf3, 0x0f, 0x01, 0xec }, 4, X86_INS_UIRET, "uiret", true, false },
	{ { 0xf3, 0x0f, 0x01, 0xee }, 4, X86_INS_CLUI, "clui", true, false },
	{ { 0xf3, 0x0f, 0x01, 0xef }, 4, X86_INS_STUI, "stui", true, false },
	{ { 0xf3, 0x0f, 0x01, 0xed }, 4, X86_INS_TESTUI, "testui", true, false },
	{ { 0xf3, 0x0f, 0xc7, 0xf0 },
	  4,
	  X86_INS_SENDUIPI,
	  "senduipi",
	  true,
	  false },
	{ { 0xf2, 0x0f, 0x00, 0xf0 }, 4, X86_INS_LKGS, "lkgs", true, true },
	{ { 0xf3, 0x0f, 0x3a, 0xf0, 0xc0, 0xab },
	  6,
	  X86_INS_HRESET,
	  "hreset",
	  false,
	  true },
	{ { 0x0f, 0x01, 0xfe }, 3, X86_INS_INVLPGB, "invlpgb", false, true },
	{ { 0x0f, 0x01, 0xff }, 3, X86_INS_TLBSYNC, "tlbsync", false, true },
	{ { 0xf3, 0x0f, 0x01, 0xff }, 4, X86_INS_PSMASH, "psmash", true, true },
	{ { 0xf2, 0x0f, 0x01, 0xff },
	  4,
	  X86_INS_PVALIDATE,
	  "pvalidate",
	  false,
	  true },
	{ { 0xf3, 0x0f, 0x01, 0xfe },
	  4,
	  X86_INS_RMPADJUST,
	  "rmpadjust",
	  true,
	  true },
	{ { 0xf2, 0x0f, 0x01, 0xfe },
	  4,
	  X86_INS_RMPUPDATE,
	  "rmpupdate",
	  true,
	  true },
	{ { 0xf3, 0x0f, 0x01, 0xfd },
	  4,
	  X86_INS_RMPQUERY,
	  "rmpquery",
	  true,
	  true },
	{ { 0xf2, 0x0f, 0x01, 0xfd }, 4, X86_INS_RMPREAD, "rmpread", true, true },
	{ { 0xf2, 0x0f, 0x01, 0xfc }, 4, X86_INS_RMPOPT, "rmpopt", true, true },
	{ { 0xf3, 0x0f, 0x01, 0xfc }, 4, X86_INS_RMPCHKD, "rmpchkd", true, true },
	{ { 0xf2, 0x0f, 0x01, 0xd9 },
	  4,
	  X86_INS_VMGEXIT,
	  "vmgexit",
	  false,
	  false },
	{ { 0xf3, 0x0f, 0x01, 0xd9 },
	  4,
	  X86_INS_VMGEXIT,
	  "vmgexit",
	  false,
	  false },
};

static bool check_snp_detail(csh h, const cs_insn *insn)
{
	const cs_detail *d = insn->detail;
	const cs_x86 *x = &d->x86;
	cs_regs reads = { 0 }, writes = { 0 }, actual_reads, actual_writes;
	uint8_t nr = 0, nw = 0, actual_nr = 0, actual_nw = 0;
	uint64_t flags = X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF |
			 X86_EFLAGS_MODIFY_PF;
	if (insn->id == X86_INS_VMGEXIT)
		return x->eflags == 0 && d->groups_count == 1 &&
		       d->groups[0] == X86_GRP_VM && d->regs_read_count == 0 &&
		       d->regs_write_count == 0;
	reads[nr++] = X86_REG_RAX;
	writes[nw++] = X86_REG_EAX;
	switch (insn->id) {
	case X86_INS_PSMASH:
		break;
	case X86_INS_PVALIDATE:
		reads[0] = x->addr_size == 8 ? X86_REG_RAX :
			   x->addr_size == 4 ? X86_REG_EAX :
					       X86_REG_AX;
		reads[nr++] = X86_REG_ECX;
		reads[nr++] = X86_REG_EDX;
		flags |= X86_EFLAGS_MODIFY_CF;
		break;
	case X86_INS_RMPADJUST:
		reads[nr++] = X86_REG_RCX;
		reads[nr++] = X86_REG_RDX;
		break;
	case X86_INS_RMPQUERY:
		reads[nr++] = X86_REG_RDX;
		writes[nw++] = X86_REG_RCX;
		writes[nw++] = X86_REG_RDX;
		break;
	case X86_INS_RMPREAD:
	case X86_INS_RMPUPDATE:
		reads[nr++] = X86_REG_RCX;
		reads[nr++] = x->prefix[1] == 0x65 ? X86_REG_GS :
			      x->prefix[1] == 0x64 ? X86_REG_FS :
						     X86_REG_DS;
		break;
	case X86_INS_RMPOPT:
		reads[nr++] = X86_REG_RCX;
		nw = 0;
		flags = X86_EFLAGS_MODIFY_CF;
		break;
	case X86_INS_RMPCHKD:
		reads[nr++] = X86_REG_RCX;
		writes[0] = X86_REG_RAX;
		writes[nw++] = X86_REG_RCX;
		flags = X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_ZF |
			X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF |
			X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF;
		break;
	default:
		return false;
	}
	writes[nw++] = X86_REG_EFLAGS;
	return x->eflags == flags && d->regs_read_count == nr &&
	       d->regs_write_count == nw &&
	       memcmp(d->regs_read, reads, nr * sizeof(reads[0])) == 0 &&
	       memcmp(d->regs_write, writes, nw * sizeof(writes[0])) == 0 &&
	       cs_regs_access(h, insn, actual_reads, &actual_nr, actual_writes,
			      &actual_nw) == CS_ERR_OK &&
	       actual_nr == nr && actual_nw == nw &&
	       memcmp(actual_reads, reads, nr * sizeof(reads[0])) == 0 &&
	       memcmp(actual_writes, writes, nw * sizeof(writes[0])) == 0;
}

static bool check(csh h, cs_mode mode, const system_case *test, bool att)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(h, test->bytes, test->size, 0, 1, &insn);
	bool valid = !(test->only64 && mode != CS_MODE_64) &&
		     !(test->id == X86_INS_INVLPGB && mode == CS_MODE_16);
	bool ok = count == (size_t)valid;
	if (valid && count) {
		cs_detail *d = insn->detail;
		cs_x86 *x = &d->x86;
		const bool fred = test->id == X86_INS_ERETS ||
				  test->id == X86_INS_ERETU;
		ok &= insn->id == test->id && insn->size == test->size &&
		      strcmp(insn->mnemonic, test->name) == 0 &&
		      strcmp(cs_insn_name(h, insn->id), test->name) == 0 &&
		      d->groups_count ==
			      (unsigned)(test->privileged ||
					 test->id == X86_INS_UIRET ||
					 test->id == X86_INS_VMGEXIT) +
				      (unsigned)fred &&
		      (!test->privileged || d->groups[0] == X86_GRP_PRIVILEGE);
		if (test->id >= X86_INS_PSMASH && test->id <= X86_INS_VMGEXIT) {
			ok &= check_snp_detail(h, insn);
		} else if (test->id == X86_INS_TESTUI) {
			ok &= d->regs_write_count == 1 &&
			      d->regs_write[0] == X86_REG_EFLAGS &&
			      x->eflags == (X86_EFLAGS_MODIFY_CF |
					    X86_EFLAGS_RESET_ZF |
					    X86_EFLAGS_RESET_AF |
					    X86_EFLAGS_RESET_OF |
					    X86_EFLAGS_RESET_PF |
					    X86_EFLAGS_RESET_SF);
		} else if (test->id == X86_INS_UIRET || fred) {
			ok &= d->groups[fred ? 1 : 0] == X86_GRP_IRET &&
			      d->regs_read_count ==
				      (test->id == X86_INS_ERETS ? 4 : 2) &&
			      d->regs_write_count ==
				      (test->id == X86_INS_ERETU ? 4 : 2) &&
			      d->regs_read[0] == X86_REG_RSP &&
			      d->regs_read[1] == X86_REG_EFLAGS &&
			      d->regs_write[0] == X86_REG_RSP &&
			      d->regs_write[1] == X86_REG_EFLAGS &&
			      x->eflags == (X86_EFLAGS_MODIFY_CF |
					    X86_EFLAGS_MODIFY_PF |
					    X86_EFLAGS_MODIFY_AF |
					    X86_EFLAGS_MODIFY_ZF |
					    X86_EFLAGS_MODIFY_SF |
					    X86_EFLAGS_MODIFY_TF |
					    X86_EFLAGS_MODIFY_DF |
					    X86_EFLAGS_MODIFY_OF |
					    X86_EFLAGS_MODIFY_NT |
					    X86_EFLAGS_MODIFY_RF |
					    (fred ? X86_EFLAGS_MODIFY_IF : 0));
			if (test->id == X86_INS_ERETS)
				ok &= d->regs_read[2] == X86_REG_CS &&
				      d->regs_read[3] == X86_REG_SS;
			if (test->id == X86_INS_ERETU)
				ok &= d->regs_write[2] == X86_REG_CS &&
				      d->regs_write[3] == X86_REG_SS;
		} else {
			ok &= x->eflags == 0;
		}
		if (test->id == X86_INS_SENDUIPI || test->id == X86_INS_LKGS) {
			const bool l = test->id == X86_INS_LKGS;
			ok &= x->op_count == 1 &&
			      x->operands[0].type == X86_OP_REG &&
			      x->operands[0].reg ==
				      (l ? X86_REG_AX : X86_REG_RAX) &&
			      x->operands[0].size == (l ? 2 : 8) &&
			      x->operands[0].access == CS_AC_READ &&
			      strcmp(insn->op_str,
				     l ? (att ? "%ax" : "ax") :
					 (att ? "%rax" : "rax")) == 0;
			ok &= d->regs_write_count == (unsigned)l &&
			      (!l || d->regs_write[0] == X86_REG_GS);
		} else if (test->id == X86_INS_HRESET) {
			ok &= x->op_count == 1 &&
			      x->operands[0].type == X86_OP_IMM &&
			      x->operands[0].imm == 0xab &&
			      x->operands[0].size == 1 &&
			      x->encoding.imm_offset == 5 &&
			      x->encoding.imm_size == 1 &&
			      d->regs_read_count == 1 &&
			      d->regs_read[0] == X86_REG_EAX;
		} else {
			ok &= x->op_count == 0 && insn->op_str[0] == '\0';
		}
		if (test->id == X86_INS_INVLPGB) {
			ok &= d->regs_read_count == 3 &&
			      d->regs_read[0] == (mode == CS_MODE_64 ?
							  X86_REG_RAX :
							  X86_REG_EAX) &&
			      d->regs_read[1] == X86_REG_EDX &&
			      d->regs_read[2] == X86_REG_ECX;
		}
	}
	if (!ok)
		fprintf(stderr, "%s mode %u syntax %u: %s %s\n", test->name,
			mode, att, count ? insn->mnemonic : "decode failed",
			count ? insn->op_str : "");
	cs_free(insn, count);
	return ok;
}

static bool decodes(csh h, const uint8_t *bytes, size_t size, bool expected)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(h, bytes, size, 0, 1, &insn);
	bool ok = expected ? count == 1 && insn->size == size : count == 0;
	cs_free(insn, count);
	return ok;
}

static bool check_prefixes_and_memory(csh h, cs_mode mode)
{
	bool ok = true;
	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		const system_case *c = &cases[i];
		uint8_t bytes[16];
		if ((c->only64 && mode != CS_MODE_64) ||
		    (c->id == X86_INS_INVLPGB && mode == CS_MODE_16))
			continue;
		if (c->id >= X86_INS_PSMASH && c->id <= X86_INS_VMGEXIT) {
			system_case prefixed = *c;
			memmove(prefixed.bytes + 1, prefixed.bytes,
				prefixed.size++);
			prefixed.bytes[0] = 0x67;
			ok &= check(h, mode, &prefixed, false);
			if (c->id == X86_INS_RMPREAD ||
			    c->id == X86_INS_RMPUPDATE) {
				for (unsigned segment = 0x64; segment <= 0x65;
				     ++segment) {
					prefixed.bytes[0] = segment;
					ok &= check(h, mode, &prefixed, false);
				}
			}
		}
		for (size_t n = 1; n < c->size; ++n)
			ok &= decodes(h, c->bytes, n, false);
		bytes[0] = 0xf0;
		memcpy(bytes + 1, c->bytes, c->size);
		ok &= decodes(h, bytes, c->size + 1, false);
		bytes[0] = 0x66;
		ok &= decodes(h, bytes, c->size + 1,
			      c->id != X86_INS_INVLPGB &&
				      c->id != X86_INS_TLBSYNC);
		memset(bytes, 0x2e, 16);
		memcpy(bytes + 15 - c->size, c->bytes, c->size);
		ok &= decodes(h, bytes, 15, true);
		memmove(bytes + 1, bytes, 15);
		bytes[0] = 0x2e;
		ok &= decodes(h, bytes, 16, false);
	}
	if (mode == CS_MODE_64) {
		const uint8_t memory[] = { 0x65, 0x67, 0xf2, 0x43, 0x0f,
					   0x00, 0x74, 0xac, 0xf8 };
		const uint8_t extended[] = {
			0x66, 0xf3, 0x41, 0x0f, 0xc7, 0xf3
		};
		const uint8_t addr32[] = { 0x67, 0x0f, 0x01, 0xfe };
		cs_insn *insn = NULL;
		size_t n = cs_disasm(h, memory, sizeof(memory), 0, 1, &insn);
		ok &= n == 1;
		if (n) {
			cs_x86 *x = &insn->detail->x86;
			const cs_x86_op *o = &x->operands[0];
			cs_regs reads, writes;
			uint8_t nr = 0, nw = 0;
			ok &= insn->id == X86_INS_LKGS &&
			      insn->size == sizeof(memory) &&
			      x->op_count == 1 && o->type == X86_OP_MEM &&
			      o->size == 2 && o->access == CS_AC_READ &&
			      o->mem.segment == X86_REG_GS &&
			      o->mem.base == X86_REG_R12D &&
			      o->mem.index == X86_REG_R13D &&
			      o->mem.scale == 4 && o->mem.disp == -8 &&
			      x->encoding.modrm_offset == 6 &&
			      x->encoding.disp_offset == 8 &&
			      x->encoding.disp_size == 1 && x->addr_size == 4;
			ok &= cs_regs_access(h, insn, reads, &nr, writes,
					     &nw) == CS_ERR_OK &&
			      nr == 3 && nw == 1 && writes[0] == X86_REG_GS;
		}
		cs_free(insn, n);
		n = cs_disasm(h, extended, sizeof(extended), 0, 1, &insn);
		ok &= n == 1 &&
		      insn->detail->x86.operands[0].reg == X86_REG_R11 &&
		      insn->detail->x86.operands[0].size == 8;
		cs_free(insn, n);
		n = cs_disasm(h, addr32, sizeof(addr32), 0, 1, &insn);
		ok &= n == 1 && insn->detail->regs_read[0] == X86_REG_EAX;
		cs_free(insn, n);
	}
	if (!ok)
		fprintf(stderr, "prefix/memory details failed in mode %u\n",
			mode);
	return ok;
}

int main(void)
{
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	bool ok = true;
	for (unsigned m = 0; m < 3; ++m) {
		csh h;
		if (cs_open(CS_ARCH_X86, modes[m], &h) != CS_ERR_OK)
			return 1;
		cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
		for (unsigned att = 0; att < 2; ++att) {
			cs_option(h, CS_OPT_SYNTAX,
				  att ? CS_OPT_SYNTAX_ATT :
					CS_OPT_SYNTAX_INTEL);
			for (unsigned c = 0;
			     c < sizeof(cases) / sizeof(cases[0]); ++c)
				ok &= check(h, modes[m], &cases[c], att);
			ok &= check_prefixes_and_memory(h, modes[m]);
		}
		cs_close(&h);
	}
	return !ok;
}

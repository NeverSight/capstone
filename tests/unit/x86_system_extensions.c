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
};

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
		ok &= insn->id == test->id && insn->size == test->size &&
		      strcmp(insn->mnemonic, test->name) == 0 &&
		      strcmp(cs_insn_name(h, insn->id), test->name) == 0 &&
		      d->groups_count == (unsigned)test->privileged &&
		      (!test->privileged || d->groups[0] == X86_GRP_PRIVILEGE);
		if (test->id == X86_INS_TESTUI) {
			ok &= d->regs_write_count == 1 &&
			      d->regs_write[0] == X86_REG_EFLAGS &&
			      x->eflags == (X86_EFLAGS_MODIFY_CF |
					    X86_EFLAGS_RESET_ZF |
					    X86_EFLAGS_RESET_AF |
					    X86_EFLAGS_RESET_OF |
					    X86_EFLAGS_RESET_PF |
					    X86_EFLAGS_RESET_SF);
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

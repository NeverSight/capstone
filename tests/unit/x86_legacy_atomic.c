/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static int check(csh h, const uint8_t *code, size_t length, unsigned id,
		 unsigned width, unsigned address, bool compare, bool att,
		 x86_reg source, x86_reg add, x86_reg base, unsigned modoff)
{
	cs_insn *in = NULL;
	if (cs_disasm(h, code, length, 0x1000, 1, &in) != 1) {
		fprintf(stderr, "failed to decode id=%u width=%u address=%u\n",
			id, width, address);
		return 1;
	}
	const cs_detail *d = in->detail;
	const cs_x86 *x = &d->x86;
	unsigned mi = att ? (compare ? 2 : 1) : 0,
		 ri = compare ? 1 : (att ? 0 : 1), ai = att ? 0 : 2;
	const cs_x86_op *m = &x->operands[mi], *r = &x->operands[ri];
	int bad =
		in->id != id || in->size != length || x->addr_size != address ||
		x->op_count != (compare ? 3 : 2) || m->type != X86_OP_MEM ||
		m->size != width || m->access != CS_AC_READ_WRITE ||
		m->mem.segment != X86_REG_FS || m->mem.base != base ||
		m->mem.index != X86_REG_INVALID || m->mem.scale != 1 ||
		r->type != X86_OP_REG || r->reg != source || r->size != width ||
		r->access != (compare ? CS_AC_READ_WRITE : CS_AC_READ) ||
		x->encoding.modrm_offset != modoff ||
		x->modrm != code[modoff] || x->encoding.imm_size ||
		x->encoding.imm_offset || d->regs_read_count ||
		d->regs_write_count != (compare ? 1 : 0) || d->groups_count;
	if (compare)
		bad |= x->operands[ai].type != X86_OP_REG ||
		       x->operands[ai].reg != add ||
		       x->operands[ai].size != width ||
		       x->operands[ai].access != CS_AC_READ ||
		       d->regs_write[0] != X86_REG_EFLAGS ||
		       x->eflags !=
			       (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
				X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF |
				X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
	else
		bad |= x->eflags != 0;
	if (bad)
		fprintf(stderr, "invalid detail: %s %s\n", in->mnemonic,
			in->op_str);
	cs_free(in, 1);
	return bad;
}
static int rejects(csh h, const uint8_t *code, size_t len)
{
	cs_insn *i = NULL;
	size_t n = cs_disasm(h, code, len, 0, 1, &i);
	if (i)
		cs_free(i, n);
	return n != 0;
}

static int addressing(void)
{
	static const struct {
		cs_mode mode;
		uint8_t code[15], length;
		const char *mnemonic, *operands;
		x86_reg base, index, source;
		int scale, displacement;
		uint8_t address, rex, modoff, dispoff, dispsize, sib;
	} cases[] = {
		{ CS_MODE_64,
		  { 0x64, 0x4f, 0x0f, 0x38, 0xfc, 0x9c, 0xe5, 0xf0, 0xff, 0xff,
		    0xff },
		  11,
		  "aadd",
		  "qword ptr fs:[r13 + r12*8 - 0x10], r11",
		  X86_REG_R13,
		  X86_REG_R12,
		  X86_REG_R11,
		  8,
		  -16,
		  8,
		  0x4f,
		  5,
		  7,
		  4,
		  0xe5 },
		{ CS_MODE_64,
		  { 0x64, 0xc4, 0x02, 0xa9, 0xef, 0x9c, 0xe5, 0xf0, 0xff, 0xff,
		    0xff },
		  11,
		  "cmpnlexadd",
		  "qword ptr fs:[r13 + r12*8 - 0x10], r11, r10",
		  X86_REG_R13,
		  X86_REG_R12,
		  X86_REG_R11,
		  8,
		  -16,
		  8,
		  0,
		  5,
		  7,
		  4,
		  0xe5 },
		{ CS_MODE_64,
		  { 0x0f, 0x38, 0xfc, 0x1d, 0xf0, 0xff, 0xff, 0xff },
		  8,
		  "aadd",
		  "dword ptr [rip - 0x10], ebx",
		  X86_REG_RIP,
		  X86_REG_INVALID,
		  X86_REG_EBX,
		  1,
		  -16,
		  8,
		  0,
		  3,
		  4,
		  4,
		  0 },
		{ CS_MODE_64,
		  { 0x67, 0x0f, 0x38, 0xfc, 0x1d, 0xf0, 0xff, 0xff, 0xff },
		  9,
		  "aadd",
		  "dword ptr [eip - 0x10], ebx",
		  X86_REG_EIP,
		  X86_REG_INVALID,
		  X86_REG_EBX,
		  1,
		  -16,
		  4,
		  0,
		  4,
		  5,
		  4,
		  0 },
		{ CS_MODE_32,
		  { 0x0f, 0x38, 0xfc, 0x1d, 0x10, 0x32, 0x54, 0x76 },
		  8,
		  "aadd",
		  "dword ptr [0x76543210], ebx",
		  X86_REG_INVALID,
		  X86_REG_INVALID,
		  X86_REG_EBX,
		  1,
		  0x76543210,
		  4,
		  0,
		  3,
		  4,
		  4,
		  0 },
		{ CS_MODE_32,
		  { 0x67, 0x0f, 0x38, 0xfc, 0x1e, 0xfe, 0xff },
		  7,
		  "aadd",
		  "dword ptr [0xfffe], ebx",
		  X86_REG_INVALID,
		  X86_REG_INVALID,
		  X86_REG_EBX,
		  1,
		  65534,
		  2,
		  0,
		  4,
		  5,
		  2,
		  0 },
		{ CS_MODE_32,
		  { 0x67, 0x0f, 0x38, 0xfc, 0x9a, 0xfe, 0xff },
		  7,
		  "aadd",
		  "dword ptr [bp + si - 0x2], ebx",
		  X86_REG_BP,
		  X86_REG_SI,
		  X86_REG_EBX,
		  1,
		  -2,
		  2,
		  0,
		  4,
		  5,
		  2,
		  0 },
		/* A legacy prefix discards an earlier REX; the final REX wins. */
		{ CS_MODE_64,
		  { 0x4f, 0x66, 0x0f, 0x38, 0xfc, 0x18 },
		  6,
		  "aand",
		  "dword ptr [rax], ebx",
		  X86_REG_RAX,
		  X86_REG_INVALID,
		  X86_REG_EBX,
		  1,
		  0,
		  8,
		  0,
		  5,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0x4f, 0x48, 0x0f, 0x38, 0xfc, 0x18 },
		  6,
		  "aadd",
		  "qword ptr [rax], rbx",
		  X86_REG_RAX,
		  X86_REG_INVALID,
		  X86_REG_RBX,
		  1,
		  0,
		  8,
		  0x48,
		  5,
		  0,
		  0,
		  0 },
	};
	int bad = 0;
	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		csh h;
		cs_insn *in = NULL;
		if (cs_open(CS_ARCH_X86, cases[i].mode, &h) != CS_ERR_OK)
			return 1;
		cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
		if (cs_disasm(h, cases[i].code, cases[i].length, 0x1000, 1,
			      &in) != 1) {
			fprintf(stderr, "addressing case %u did not decode\n",
				i);
			bad++;
		} else {
			const cs_x86 *x = &in->detail->x86;
			const x86_op_mem *m = &x->operands[0].mem;
			int mismatch =
				in->size != cases[i].length ||
				strcmp(in->mnemonic, cases[i].mnemonic) ||
				strcmp(in->op_str, cases[i].operands) ||
				m->base != cases[i].base ||
				m->index != cases[i].index ||
				m->scale != cases[i].scale ||
				m->disp != cases[i].displacement ||
				x->disp != cases[i].displacement ||
				x->rex != cases[i].rex ||
				x->addr_size != cases[i].address ||
				x->sib != cases[i].sib ||
				x->encoding.modrm_offset != cases[i].modoff ||
				x->encoding.disp_offset != cases[i].dispoff ||
				x->encoding.disp_size != cases[i].dispsize ||
				x->operands[1].reg != cases[i].source;
			if (mismatch)
				fprintf(stderr, "addressing case %u: %s %s\n",
					i, in->mnemonic, in->op_str);
			bad += mismatch;
			cs_free(in, 1);
		}
		cs_close(&h);
	}
	return bad;
}
int main(void)
{
	const unsigned ids[] = { X86_INS_AADD, X86_INS_AAND, X86_INS_AOR,
				 X86_INS_AXOR };
	const uint8_t pp[] = { 0, 0x66, 0xf2, 0xf3 };
	int bad = addressing();
	for (unsigned mode = 0; mode < 3; ++mode) {
		csh h;
		const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
		if (cs_open(CS_ARCH_X86, modes[mode], &h) != CS_ERR_OK)
			return 1;
		cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
		for (unsigned att = 0; att < 2; ++att) {
			cs_option(h, CS_OPT_SYNTAX,
				  att ? CS_OPT_SYNTAX_ATT :
					CS_OPT_SYNTAX_INTEL);
			for (unsigned kind = 0; kind < 4; ++kind)
				for (unsigned narrow = 0; narrow < 2; ++narrow)
					for (unsigned wide = 0;
					     wide < 1 + (mode == 2); ++wide) {
						uint8_t c[15];
						unsigned n = 0;
						c[n++] = 0x64;
						if (narrow)
							c[n++] = 0x67;
						if (pp[kind])
							c[n++] = pp[kind];
						if (wide)
							c[n++] = 0x48;
						c[n++] = 0x0f;
						c[n++] = 0x38;
						c[n++] = 0xfc;
						unsigned mo = n;
						unsigned address =
							mode == 2 ?
								(narrow ? 4 :
									  8) :
							mode == 1 ?
								(narrow ? 2 :
									  4) :
								(narrow ? 4 :
									  2);
						c[n++] = address == 2 ? 0x1f :
									0x18;
						bad += check(
							h, c, n, ids[kind],
							wide ? 8 : 4, address,
							false, att,
							wide ? X86_REG_RBX :
							       X86_REG_EBX,
							X86_REG_INVALID,
							address == 2 ?
								X86_REG_BX :
							address == 4 ?
								X86_REG_EAX :
								X86_REG_RAX,
							mo);
						for (unsigned cut = 0; cut < n;
						     ++cut)
							bad += rejects(h, c,
								       cut);
					}
			if (mode == 2)
				for (unsigned cc = 0; cc < 16; ++cc)
					for (unsigned wide = 0; wide < 2;
					     ++wide)
						for (unsigned narrow = 0;
						     narrow < 2; ++narrow) {
							uint8_t c[8];
							unsigned n = 0;
							c[n++] = 0x64;
							if (narrow)
								c[n++] = 0x67;
							c[n++] = 0xc4;
							c[n++] = 0xe2;
							c[n++] = wide ? 0xe9 :
									0x69;
							c[n++] = 0xe0 + cc;
							unsigned mo = n;
							c[n++] = 0x0b;
							bad += check(
								h, c, n,
								X86_INS_CMPOXADD +
									cc,
								wide ? 8 : 4,
								narrow ? 4 : 8,
								true, att,
								wide ? X86_REG_RCX :
								       X86_REG_ECX,
								wide ? X86_REG_RDX :
								       X86_REG_EDX,
								narrow ?
									X86_REG_EBX :
									X86_REG_RBX,
								mo);
							for (unsigned cut = 0;
							     cut < n; ++cut)
								bad += rejects(
									h, c,
									cut);
							c[n - 3] |= 4;
							bad += rejects(h, c, n);
						}
		}
		const uint8_t lock[] = { 0xf0, 0x0f, 0x38, 0xfc, 0x18 };
		bad += rejects(h, lock, sizeof(lock));
		const uint8_t reg[] = { 0x0f, 0x38, 0xfc, 0xd8 };
		bad += rejects(h, reg, sizeof(reg));
		const uint8_t vex[] = { 0xc4, 0xe2, 0x69, 0xe4, 0x0b };
		if (mode != 2)
			bad += rejects(h, vex, sizeof(vex));
		cs_close(&h);
	}
	return bad ? 1 : 0;
}

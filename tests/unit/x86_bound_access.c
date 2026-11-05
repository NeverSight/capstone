/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>

static bool contains(const cs_regs regs, uint8_t count, x86_reg reg)
{
	for (unsigned i = 0; i < count; ++i)
		if (regs[i] == reg)
			return true;
	return false;
}

static int check(csh h, unsigned mode, unsigned width, unsigned address,
		 unsigned segment, bool iterator)
{
	static const unsigned prefixes[] = { 0,	   0x26, 0x2e, 0x36,
					     0x3e, 0x64, 0x65 };
	static const x86_reg segments[] = { X86_REG_INVALID, X86_REG_ES,
					    X86_REG_CS,	     X86_REG_SS,
					    X86_REG_DS,	     X86_REG_FS,
					    X86_REG_GS };
	uint8_t code[5];
	unsigned n = 0;
	if (width != mode / 8)
		code[n++] = 0x66;
	if (address != mode)
		code[n++] = 0x67;
	if (segment)
		code[n++] = prefixes[segment];
	code[n++] = 0x62;
	code[n++] = 0x0f;
	cs_insn *in = iterator ? cs_malloc(h) : NULL;
	const uint8_t *cursor = code;
	size_t remaining = n;
	uint64_t pc = 0x1000;
	bool decoded = iterator ?
			       cs_disasm_iter(h, &cursor, &remaining, &pc, in) :
			       cs_disasm(h, code, n, pc, 1, &in) == 1;
	if (!decoded) {
		cs_free(in, iterator ? 1 : 0);
		fprintf(stderr, "BOUND failed to decode\n");
		return 1;
	}
	const cs_detail *d = in->detail;
	const cs_x86 *x = &d->x86;
	const cs_x86_op *index = NULL, *bounds = NULL;
	for (unsigned i = 0; i < x->op_count; ++i) {
		if (x->operands[i].type == X86_OP_REG)
			index = &x->operands[i];
		if (x->operands[i].type == X86_OP_MEM)
			bounds = &x->operands[i];
	}
	const x86_reg reg = width == 2 ? X86_REG_CX : X86_REG_ECX;
	const x86_reg base = address == 16 ? X86_REG_BX : X86_REG_EDI;
	cs_regs reads, writes;
	uint8_t nr = 0, nw = 0;
	int bad = in->id != X86_INS_BOUND || in->size != n ||
		  x->op_count != 2 || x->addr_size != address / 8 ||
		  x->eflags || d->regs_read_count || d->regs_write_count ||
		  !index || !bounds ||
		  cs_regs_access(h, in, reads, &nr, writes, &nw) != CS_ERR_OK ||
		  nr != 2 + (segment != 0) || nw || !contains(reads, nr, reg) ||
		  !contains(reads, nr, base);
	if (index && bounds)
		bad |= index->reg != reg || index->size != width ||
		       index->access != CS_AC_READ ||
		       bounds->size != 2 * width ||
		       bounds->access != CS_AC_READ ||
		       bounds->mem.base != base ||
		       bounds->mem.index != X86_REG_INVALID ||
		       bounds->mem.disp ||
		       bounds->mem.segment != segments[segment] ||
		       (segment && !contains(reads, nr, segments[segment]));
	if (iterator)
		bad |= remaining || cursor != code + n || pc != 0x1000 + n;
	if (bad)
		fprintf(stderr,
			"BOUND effects: mode=%u width=%u address=%u segment=%u %s %s reads=%u writes=%u\n",
			mode, width, address, segment, in->mnemonic, in->op_str,
			nr, nw);
	cs_free(in, 1);
	return bad != 0;
}

int main(void)
{
	if (cs_support(CS_SUPPORT_DIET))
		return 77;
	unsigned failures = 0, cases = 0;
	for (unsigned mode = 16; mode <= 32; mode += 16) {
		csh h;
		if (cs_open(CS_ARCH_X86, mode == 16 ? CS_MODE_16 : CS_MODE_32,
			    &h) != CS_ERR_OK)
			return 1;
		cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
		for (unsigned att = 0; att != 2; ++att) {
			cs_option(h, CS_OPT_SYNTAX,
				  att ? CS_OPT_SYNTAX_ATT :
					CS_OPT_SYNTAX_INTEL);
			for (unsigned width = 2; width <= 4; width += 2)
				for (unsigned address = 16; address <= 32;
				     address += 16)
					for (unsigned segment = 0; segment != 7;
					     ++segment)
						for (unsigned iterator = 0;
						     iterator != 2;
						     ++iterator) {
							failures += check(
								h, mode, width,
								address,
								segment,
								iterator != 0);
							++cases;
						}
		}
		cs_close(&h);
	}
	printf("BOUND: %u cases, %u failures\n", cases, failures);
	return failures != 0;
}

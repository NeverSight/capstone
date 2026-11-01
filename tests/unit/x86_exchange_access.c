/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>

typedef struct exchange_case {
	unsigned kind, width, memory, prefix, att, iterator;
	bool long_mode;
} exchange_case;

static bool contains(const cs_regs regs, uint8_t count, x86_reg reg)
{
	for (unsigned i = 0; i < count; ++i)
		if (regs[i] == reg)
			return true;
	return false;
}

static int check(csh h, const exchange_case *test)
{
	const x86_reg accumulators[] = { X86_REG_AL, X86_REG_AX, X86_REG_EAX,
					 X86_REG_RAX };
	const x86_reg sources[] = { X86_REG_CL, X86_REG_CX, X86_REG_ECX,
				    X86_REG_RCX };
	const x86_reg destinations[] = { X86_REG_BL, X86_REG_BX, X86_REG_EBX,
					 X86_REG_RBX };
	const bool pair = test->kind == 2, xadd = test->kind == 0;
	const unsigned width = 1u << test->width;
	const unsigned id =
		pair ? (width == 16 ? X86_INS_CMPXCHG16B : X86_INS_CMPXCHG8B) :
		       (xadd ? X86_INS_XADD : X86_INS_CMPXCHG);
	uint8_t code[15];
	unsigned n = 0;
	if (test->prefix > 1)
		code[n++] = test->prefix == 2 ? 0xf2 : 0xf3;
	if (test->prefix)
		code[n++] = 0xf0;
	if (width == 2)
		code[n++] = 0x66;
	if (pair ? width == 16 : width == 8)
		code[n++] = 0x48;
	code[n++] = 0x0f;
	code[n++] = pair ? 0xc7 : (xadd ? 0xc0 : 0xb0) + (width != 1);
	code[n++] = test->memory ? 0x0f : 0xcb;
	cs_insn *in = test->iterator ? cs_malloc(h) : NULL;
	const uint8_t *cursor = code;
	size_t remaining = n;
	uint64_t address = 0x1000;
	bool decoded =
		test->iterator ?
			cs_disasm_iter(h, &cursor, &remaining, &address, in) :
			cs_disasm(h, code, n, address, 1, &in) == 1;
	if (!decoded) {
		fprintf(stderr, "exchange decode: kind=%u width=%u\n",
			test->kind, width);
		cs_free(in, test->iterator ? 1 : 0);
		return 1;
	}
	const cs_detail *d = in->detail;
	const cs_x86 *x = &d->x86;
	const cs_x86_op *dest = &x->operands[test->att && !pair ? 1 : 0];
	cs_regs reads, writes;
	uint8_t nr = 0, nw = 0;
	int bad = in->id != id || in->size != n ||
		  x->op_count != (pair ? 1 : 2) || dest->size != width ||
		  dest->access != CS_AC_READ_WRITE || d->groups_count ||
		  x->eflags !=
			  (pair ? X86_EFLAGS_MODIFY_ZF :
				  (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
				   X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF |
				   X86_EFLAGS_MODIFY_PF |
				   X86_EFLAGS_MODIFY_CF)) ||
		  cs_regs_access(h, in, reads, &nr, writes, &nw) != CS_ERR_OK ||
		  !contains(writes, nw, X86_REG_EFLAGS);
	if (test->memory) {
		const x86_reg base = test->long_mode ? X86_REG_RDI :
						       X86_REG_EDI;
		bad |= dest->type != X86_OP_MEM || dest->mem.base != base ||
		       !contains(reads, nr, base);
	} else {
		bad |= dest->type != X86_OP_REG ||
		       dest->reg != destinations[test->width] ||
		       !contains(reads, nr, dest->reg) ||
		       !contains(writes, nw, dest->reg);
	}
	if (pair) {
		const x86_reg regs32[] = { X86_REG_EAX, X86_REG_EDX,
					   X86_REG_EBX, X86_REG_ECX };
		const x86_reg regs64[] = { X86_REG_RAX, X86_REG_RDX,
					   X86_REG_RBX, X86_REG_RCX };
		const x86_reg *regs = width == 16 ? regs64 : regs32;
		bad |= d->regs_read_count != 4 || d->regs_write_count != 3 ||
		       nr != 5 || nw != 3;
		for (unsigned i = 0; i < 4; ++i)
			bad |= !contains(reads, nr, regs[i]) ||
			       contains(writes, nw, regs[i]) != (i < 2);
	} else {
		const cs_x86_op *src = &x->operands[test->att ? 0 : 1];
		bad |= src->type != X86_OP_REG ||
		       src->reg != sources[test->width] || src->size != width ||
		       src->access != (xadd ? CS_AC_READ_WRITE : CS_AC_READ) ||
		       !contains(reads, nr, src->reg) ||
		       contains(writes, nw, src->reg) != xadd ||
		       d->regs_read_count != (xadd ? 0 : 1) ||
		       d->regs_write_count != (xadd ? 1 : 2) ||
		       nr != (xadd ? 2 : 3) || nw != (test->memory ? 2 : 3);
		if (!xadd)
			bad |= !contains(reads, nr,
					 accumulators[test->width]) ||
			       !contains(writes, nw, accumulators[test->width]);
	}
	if (test->iterator)
		bad |= remaining != 0 || cursor != code + n ||
		       address != 0x1000 + n;
	if (bad)
		fprintf(stderr,
			"exchange effects: %s %s memory=%u reads=%u writes=%u implicit=%u/%u\n",
			in->mnemonic, in->op_str, dest->access, nr, nw,
			d->regs_read_count, d->regs_write_count);
	cs_free(in, 1);
	return bad != 0;
}

int main(void)
{
	exchange_case test = { 0 };
	int bad = 0;
	for (unsigned mode = 0; mode < 2; ++mode) {
		csh h;
		test.long_mode = mode != 0;
		if (cs_open(CS_ARCH_X86, mode ? CS_MODE_64 : CS_MODE_32, &h) !=
		    CS_ERR_OK)
			return 1;
		cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
		for (test.att = 0; test.att < 2; ++test.att) {
			cs_option(h, CS_OPT_SYNTAX,
				  test.att ? CS_OPT_SYNTAX_ATT :
					     CS_OPT_SYNTAX_INTEL);
			for (test.kind = 0; test.kind < 3; ++test.kind)
				for (test.width = test.kind == 2 ? 3 : 0;
				     test.width <
				     (test.kind == 2 ? 4 : 3) + mode;
				     ++test.width)
					for (test.memory = test.kind == 2;
					     test.memory < 2; ++test.memory)
						for (test.prefix = 0;
						     test.prefix <
						     (test.memory ?
							      (test.width == 4 ?
								       2 :
								       4) :
							      1);
						     ++test.prefix)
							for (test.iterator = 0;
							     test.iterator < 2;
							     ++test.iterator)
								bad += check(
									h,
									&test);
		}
		cs_close(&h);
	}
	return bad != 0;
}

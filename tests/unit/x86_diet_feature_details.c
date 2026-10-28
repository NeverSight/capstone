/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

/* Feature detail construction must not depend on public register names,
 * which are unavailable in DIET. The first case formerly fell through to the
 * generated asmwriter with an out-of-range feature opcode (0x10021).
 */
#include <capstone/capstone.h>
#include <limits.h>
#include <stdio.h>

struct test_case {
	const char *name;
	uint8_t bytes[5];
	uint8_t length;
	unsigned id;
	uint8_t count;
	unsigned regs[3]; /* Architectural Intel order; ATT reverses this. */
	uint8_t widths[3];
	uint8_t accesses[3];
	bool stack;
};

static const struct test_case cases[] = {
	/* Fixed versions of tests/unit/x86_apx_rex2_push_pop.c encodings. */
	{ "push rax",
	  { 0xd5, 0x00, 0x50 },
	  3,
	  X86_INS_PUSH,
	  1,
	  { X86_REG_RAX },
	  { 8 },
	  { CS_AC_READ },
	  true },
	{ "push r16",
	  { 0xd5, 0x10, 0x50 },
	  3,
	  X86_INS_PUSH,
	  1,
	  { X86_REG_R16 },
	  { 8 },
	  { CS_AC_READ },
	  true },
	{ "push r8w",
	  { 0x66, 0xd5, 0x01, 0x50 },
	  4,
	  X86_INS_PUSH,
	  1,
	  { X86_REG_R8W },
	  { 2 },
	  { CS_AC_READ },
	  true },
	{ "pushp r16",
	  { 0xd5, 0x18, 0x50 },
	  3,
	  X86_INS_PUSHP,
	  1,
	  { X86_REG_R16 },
	  { 8 },
	  { CS_AC_READ },
	  true },
	{ "pop r16",
	  { 0xd5, 0x10, 0x58 },
	  3,
	  X86_INS_POP,
	  1,
	  { X86_REG_R16 },
	  { 8 },
	  { CS_AC_WRITE },
	  true },
	{ "popp r16",
	  { 0xd5, 0x18, 0x58 },
	  3,
	  X86_INS_POPP,
	  1,
	  { X86_REG_R16 },
	  { 8 },
	  { CS_AC_WRITE },
	  true },
	/* tests/unit/x86_apx_rex2_alu.c */
	{ "mov bpl, spl",
	  { 0xd5, 0x00, 0x88, 0xe5 },
	  4,
	  X86_INS_MOV,
	  2,
	  { X86_REG_BPL, X86_REG_SPL },
	  { 1, 1 },
	  { CS_AC_WRITE, CS_AC_READ },
	  false },
	{ "mov r16d, eax",
	  { 0xd5, 0x40, 0x8b, 0xc0 },
	  4,
	  X86_INS_MOV,
	  2,
	  { X86_REG_R16D, X86_REG_EAX },
	  { 4, 4 },
	  { CS_AC_WRITE, CS_AC_READ },
	  false },
	/* tests/unit/x86_sha512.c */
	{ "vsha512msg1 ymm2, xmm3",
	  { 0xc4, 0xe2, 0x7f, 0xcc, 0xd3 },
	  5,
	  X86_INS_VSHA512MSG1,
	  2,
	  { X86_REG_YMM2, X86_REG_XMM3 },
	  { 32, 16 },
	  { CS_AC_READ_WRITE, CS_AC_READ },
	  false },
	{ "vsha512msg2 ymm2, ymm3",
	  { 0xc4, 0xe2, 0x7f, 0xcd, 0xd3 },
	  5,
	  X86_INS_VSHA512MSG2,
	  2,
	  { X86_REG_YMM2, X86_REG_YMM3 },
	  { 32, 32 },
	  { CS_AC_READ_WRITE, CS_AC_READ },
	  false },
	{ "vsha512rnds2 ymm2, ymm3, xmm4",
	  { 0xc4, 0xe2, 0x67, 0xcb, 0xd4 },
	  5,
	  X86_INS_VSHA512RNDS2,
	  3,
	  { X86_REG_YMM2, X86_REG_YMM3, X86_REG_XMM4 },
	  { 32, 32, 16 },
	  { CS_AC_READ_WRITE, CS_AC_READ, CS_AC_READ },
	  false },
};

static bool check_names(csh handle, bool diet)
{
	bool ok = cs_reg_name(handle, X86_REG_INVALID) == NULL &&
		  cs_reg_name(handle, X86_REG_ENDING) == NULL &&
		  cs_reg_name(handle, UINT_MAX) == NULL;
	if (!ok)
		fprintf(stderr, "invalid register ID has a public name\n");
	// This covers the contiguous validity range used by the private DIET helper.
	for (unsigned reg = X86_REG_INVALID + 1; reg < X86_REG_ENDING; ++reg) {
		const char *name = cs_reg_name(handle, reg);
		if (diet ? name != NULL : !name || !name[0]) {
			fprintf(stderr,
				"public name contract: diet=%u reg=%u\n", diet,
				reg);
			ok = false;
		}
	}
	return ok;
}

static bool check_case(csh handle, cs_insn *insn, bool att, bool diet,
		       const struct test_case *test)
{
	const uint8_t *cursor = test->bytes;
	size_t remaining = test->length;
	uint64_t address = 0x1000;
	if (!cs_disasm_iter(handle, &cursor, &remaining, &address, insn) ||
	    !insn->detail) {
		fprintf(stderr, "%s: decode/detail failed (att=%u diet=%u)\n",
			test->name, att, diet);
		return false;
	}
	const cs_x86 *x = &insn->detail->x86;
	bool ok = insn->id == test->id && insn->size == test->length &&
		  cursor == test->bytes + test->length && remaining == 0 &&
		  address == 0x1000 + test->length &&
		  x->op_count == test->count;
	if (x->op_count != test->count) {
		fprintf(stderr, "%s: expected %u operands, got %u\n",
			test->name, test->count, x->op_count);
		return false;
	}
	for (unsigned i = 0; i < test->count; ++i) {
		unsigned expected = att ? test->count - 1 - i : i;
		ok &= x->operands[i].type == X86_OP_REG &&
		      x->operands[i].reg == test->regs[expected] &&
		      x->operands[i].size == test->widths[expected];
		// Operand access and implicit registers are not promised in DIET.
		if (!diet)
			ok &= x->operands[i].access == test->accesses[expected];
	}
	if (!diet && test->stack)
		ok &= insn->detail->regs_read_count == 1 &&
		      insn->detail->regs_read[0] == X86_REG_RSP &&
		      insn->detail->regs_write_count == 1 &&
		      insn->detail->regs_write[0] == X86_REG_RSP;
	if (!ok)
		fprintf(stderr,
			"%s: unexpected fields (att=%u diet=%u "
			"id=%u size=%u count=%u)\n",
			test->name, att, diet, insn->id, insn->size,
			x->op_count);
	return ok;
}

int main(void)
{
	bool ok = true;
	bool diet = cs_support(CS_SUPPORT_DIET);
	for (unsigned att = 0; att != 2; ++att) {
		csh handle;
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			return 2;
		if (cs_option(handle, CS_OPT_SYNTAX,
			      att ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL) !=
		    CS_ERR_OK) {
			fprintf(stderr, "syntax %s unavailable\n",
				att ? "att" : "intel");
			cs_close(&handle);
			if (!att)
				return 2;
			continue;
		}
		if (cs_option(handle, CS_OPT_TEXT, CS_OPT_ON) != CS_ERR_OK ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
			cs_close(&handle);
			return 2;
		}
		ok &= check_names(handle, diet);
		cs_insn *insn = cs_malloc(handle);
		if (!insn) {
			cs_close(&handle);
			return 2;
		}
		for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
			ok &= check_case(handle, insn, att != 0, diet,
					 &cases[i]);
		cs_free(insn, 1);
		cs_close(&handle);
	}
	return ok ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	uint32_t bits;
	unsigned id, count;
	cs_mips_op ops[4];
} e2_case;

#define REG(R, A) { .type = MIPS_OP_REG, .access = A, .reg = MIPS_REG_##R }
#define IMM(V) { .type = MIPS_OP_IMM, .access = CS_AC_READ, .imm = V }
#define MEM(R, D, A) \
	{ \
		.type = MIPS_OP_MEM, .access = A, .mem = { MIPS_REG_##R, D } \
	}
#define CS_AC_READ_WRITE (CS_AC_READ | CS_AC_WRITE)
static const e2_case cases[] = {
#define E2_IMM(B, ID, D, S, V) \
	{ B, \
	  MIPS_INS_##ID, \
	  3, \
	  { REG(D, CS_AC_WRITE), REG(S, CS_AC_READ), IMM(V) } },
#define E2_UPPER(B, ID, D, V) \
	{ B, MIPS_INS_##ID, 2, { REG(D, CS_AC_WRITE), IMM(V) } },
#define E2_MEM(B, ID, D, S, V, DA, MA) \
	{ B, MIPS_INS_##ID, 2, { REG(D, DA), MEM(S, V, MA) } },
#define E2_FIELD(B, ID, D, S, P, Z, A) \
	{ B, \
	  MIPS_INS_##ID, \
	  4, \
	  { REG(D, A), REG(S, CS_AC_READ), IMM(P), IMM(Z) } },
#define E2_MOVE(B, ID, D, S, C) \
	{ B, \
	  MIPS_INS_##ID, \
	  3, \
	  { REG(D, CS_AC_READ_WRITE), REG(S, CS_AC_READ), \
	    REG(C, CS_AC_READ) } },
#include "mips16e2_cases.inc"
#undef E2_IMM
#undef E2_UPPER
#undef E2_MEM
#undef E2_FIELD
#undef E2_MOVE
};

static void bytes(uint32_t bits, uint8_t out[4], bool big)
{
	for (unsigned i = 0; i < 2; ++i) {
		uint16_t half = bits >> (i ? 0 : 16);
		out[i * 2] = half >> (big ? 8 : 0);
		out[i * 2 + 1] = half >> (big ? 0 : 8);
	}
}

static bool inspect(csh h, const cs_insn *insn, const e2_case *c,
		    unsigned output)
{
	if (insn->size != 4 || insn->id != c->id)
		return false;
	if (c->count == 3 && c->ops[2].type == MIPS_OP_REG &&
	    c->ops[2].reg == MIPS_REG_T8 &&
	    (insn->alias_id || insn->is_alias || insn->usesAliasDetails))
		return false;
	if (!cs_support(CS_SUPPORT_DIET) && (output & 1) && c->count == 3 &&
	    c->ops[2].type == MIPS_OP_REG && c->ops[2].reg == MIPS_REG_T8) {
		const char *name = c->id == MIPS_INS_MOVZ ? "movtz" : "movtn";
		const char *comma = strchr(insn->op_str, ',');
		if (strcmp(insn->mnemonic, name) || !comma ||
		    strchr(comma + 1, ','))
			return false;
	}
	if (!(output & 2))
		return true;
	const cs_mips *m = &insn->detail->mips;
	if (m->op_count != (output == 3 ? c->count : 0))
		return false;
	for (unsigned n = 0; n < m->op_count; ++n) {
		const cs_mips_op *want = &c->ops[n], *got = &m->operands[n];
		if (got->type != want->type || (!cs_support(CS_SUPPORT_DIET) &&
						got->access != want->access))
			return false;
		if (got->type == MIPS_OP_REG && got->reg != want->reg)
			return false;
		if (got->type == MIPS_OP_IMM && got->imm != want->imm)
			return false;
		if (got->type == MIPS_OP_MEM &&
		    (got->mem.base != want->mem.base ||
		     got->mem.disp != want->mem.disp))
			return false;
	}
	cs_mips_op zero = { 0 };
	for (unsigned n = m->op_count;
	     n < sizeof(m->operands) / sizeof(m->operands[0]); ++n)
		if (memcmp(&m->operands[n], &zero, sizeof(zero)))
			return false;
	if (!cs_support(CS_SUPPORT_DIET) && output == 3 && c->count == 3 &&
	    c->ops[2].type == MIPS_OP_REG && c->ops[2].reg == MIPS_REG_T8) {
		cs_regs read, written;
		uint8_t nr = 0, nw = 0;
		if (cs_regs_access(h, insn, read, &nr, written, &nw))
			return false;
		for (unsigned op = 0; op < 3; ++op) {
			bool found = false;
			for (unsigned r = 0; r < nr; ++r)
				found |= read[r] == c->ops[op].reg;
			if (!found)
				return false;
		}
		if (nw != 1 || written[0] != c->ops[0].reg)
			return false;
	}
	return cs_support(CS_SUPPORT_DIET) ||
	       (cs_insn_group(h, insn, MIPS_FEATURE_INMIPS16MODE) &&
		!cs_insn_group(h, insn, MIPS_FEATURE_HASSTDENC));
}

static unsigned compact(unsigned field)
{
	static const unsigned regs[] = {
#define MIPS_GPR(Name) MIPS_REG_##Name,
#include "mips_gpr_cases.inc"
#undef MIPS_GPR
	};
	return regs[field < 2 ? field + 16 : field];
}

static bool exact(csh h, bool big, const e2_case *c, bool valid)
{
	uint8_t data[4];
	bytes(c->bits, data, big);
	cs_insn *i = NULL;
	size_t n = cs_disasm(h, data, 4, 0x10002, 1, &i);
	bool ok = valid ? n == 1 && inspect(h, i, c, 3) : n == 0;
	if (!ok)
		fprintf(stderr, "field %08x valid=%u count=%zu\n", c->bits,
			valid, n);
	cs_free(i, n);
	return ok;
}

static bool fields(csh h, bool big)
{
	cs_option(h, CS_OPT_TEXT, CS_OPT_ON);
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON | CS_OPT_DETAIL_REAL);
	for (unsigned kind = 0; kind < 8; ++kind)
		for (unsigned x = 0; x < 8; ++x)
			for (unsigned y = 0; y < 8; ++y)
				for (unsigned b = 0; b < 8; ++b) {
					e2_case c = cases[20 + kind];
					bool zero = kind & 1, t = kind >= 4;
					c.bits = (c.bits &
						  ~UINT32_C(0x000707e0)) |
						 (x << 8) | (y << 5) |
						 (b << 16);
					c.ops[0].reg = compact(x);
					c.ops[1].reg = zero ? MIPS_REG_ZERO :
							      compact(b);
					c.ops[2].reg = t ? MIPS_REG_T8 :
							   compact(y);
					if (!exact(h, big, &c,
						   (!zero || !b) && (!t || !y)))
						return false;
				}
	for (unsigned kind = 0; kind < 3; ++kind)
		for (unsigned pos = 0; pos < 32; ++pos)
			for (unsigned limit = 0; limit < 32; ++limit) {
				e2_case c = cases[17 + kind];
				c.bits = (c.bits & ~UINT32_C(0x07df0000)) |
					 (pos << 22) | (limit << 16);
				c.ops[2].imm = pos;
				c.ops[3].imm =
					kind ? (int)limit - (int)pos + 1 :
					       limit + 1;
				if (!exact(h, big, &c,
					   kind ? limit >= pos :
						  pos + limit < 32))
					return false;
			}
	for (unsigned kind = 0; kind < 17; ++kind) {
		const int limits[] = { -32768, -1, 0, 1, 255, 32767 };
		for (unsigned x = 0; x < 8; ++x)
			for (unsigned k = 0;
			     k < sizeof(limits) / sizeof(limits[0]); ++k) {
				e2_case c = cases[kind];
				bool merge = kind >= 13;
				uint16_t imm = merge ? limits[k] & 511 :
						       (uint16_t)limits[k];
				c.bits = merge ? (c.bits &
						  ~UINT32_C(0x01e0071f)) |
							 ((imm & 0x1e0) << 16) :
						 (c.bits &
						  ~UINT32_C(0x07ff071f)) |
							 (((imm & 0x7e0) |
							   (imm >> 11))
							  << 16);
				c.bits |= (x << 8) | (imm & 31);
				c.ops[0].reg = compact(x);
				if (kind > 0 && kind < 4)
					c.ops[1].reg = compact(x);
				if (kind >= 5)
					c.ops[1].mem.disp =
						merge ? (int)(imm ^ 256) - 256 :
							(int16_t)imm;
				else
					c.ops[c.count - 1].imm =
						kind ? imm : (int16_t)imm;
				if (!exact(h, big, &c, true))
					return false;
			}
	}
	const uint32_t reserved[] = {
		0xf00832a6, 0xf01032a6, 0xf04032a6, 0xf08032a6, 0xf10032a6,
		0xf20032a6, 0xf40032a6, 0xf0cb3144, 0xf0cb3244, 0xf0cb3444,
		0xf7e13448, 0xf1ec92ff, 0xf3e492ff, 0xf5e492ff, 0xf00092c0,
		0xf000d280, 0xf000d2a0,
	};
	for (unsigned n = 0; n < sizeof(reserved) / sizeof(reserved[0]); ++n) {
		e2_case c = { .bits = reserved[n] };
		if (!exact(h, big, &c, false))
			return false;
	}
	return true;
}

int main(void)
{
	for (unsigned big = 0; big < 2; ++big) {
		csh h;
		if (cs_open(CS_ARCH_MIPS,
			    CS_MODE_MIPS32 | CS_MODE_MIPS16 |
				    (big ? CS_MODE_BIG_ENDIAN : 0),
			    &h))
			return EXIT_FAILURE;
		for (unsigned output = 0; output < 4; ++output) {
			cs_option(h, CS_OPT_TEXT,
				  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
			cs_option(h, CS_OPT_DETAIL,
				  output & 2 ? CS_OPT_ON : CS_OPT_OFF);
			cs_insn *one = cs_malloc(h);
			for (unsigned syntax = 0; syntax < 4; ++syntax) {
				/* MIPS syntax options accumulate, so use a fresh handle. */
				cs_close(&h);
				if (cs_open(CS_ARCH_MIPS,
					    CS_MODE_MIPS32 | CS_MODE_MIPS16 |
						    (big ? CS_MODE_BIG_ENDIAN :
							   0),
					    &h))
					return EXIT_FAILURE;
				cs_option(h, CS_OPT_TEXT,
					  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
				cs_option(h, CS_OPT_DETAIL,
					  output & 2 ? CS_OPT_ON : CS_OPT_OFF);
				cs_option(
					h, CS_OPT_SYNTAX,
					(syntax & 1 ? CS_OPT_SYNTAX_NOREGNAME :
						      CS_OPT_SYNTAX_DEFAULT) |
						(syntax & 2 ?
							 CS_OPT_SYNTAX_NO_DOLLAR :
							 0));
				for (unsigned n = 0;
				     n < sizeof(cases) / sizeof(cases[0]);
				     ++n) {
					uint8_t data[4];
					bytes(cases[n].bits, data, big);
					for (unsigned api = 0; api < 2; ++api) {
						const uint8_t *cursor = data;
						size_t remaining = 4;
						uint64_t pc = 0x10002;
						cs_insn *all = NULL;
						one->alias_id = UINT64_MAX;
						one->is_alias = true;
						one->usesAliasDetails = true;
						if (output & 2)
							memset(one->detail,
							       0xa5,
							       sizeof(*one->detail));
						size_t count =
							api ? cs_disasm(h, data,
									4, pc,
									1,
									&all) :
							      cs_disasm_iter(
								      h,
								      &cursor,
								      &remaining,
								      &pc, one);
						const cs_insn *got = api ? all :
									   one;
						if (!count ||
						    !inspect(h, got, &cases[n],
							     output)) {
							fprintf(stderr,
								"e2 %08x big=%u output=%u syntax=%u api=%u count=%zu\n",
								cases[n].bits,
								big, output,
								syntax, api,
								count);
							if (count) {
								fprintf(stderr,
									"%u %s %s\n",
									got->id,
									got->mnemonic,
									got->op_str);
								if (got->detail)
									for (unsigned k =
										     0;
									     k <
									     got->detail
										     ->mips
										     .op_count;
									     ++k)
										fprintf(stderr,
											"op%u type=%u access=%u value=%lld\n",
											k,
											got->detail
												->mips
												.operands[k]
												.type,
											got->detail
												->mips
												.operands[k]
												.access,
											(long long)got
												->detail
												->mips
												.operands[k]
												.imm);
							}
							return EXIT_FAILURE;
						}
						if (n >= 24 && (output & 1) &&
						    !cs_support(
							    CS_SUPPORT_DIET)) {
							char want[32];
							const char *prefix =
								syntax & 2 ?
									"" :
									"$";
							const char *dest =
								syntax & 1 ?
									"2" :
									"v0";
							const char *src =
								syntax & 1 ?
									(n & 1 ? "zero" :
										 "4") :
									(n & 1 ? "zero" :
										 "a0");
							snprintf(want,
								 sizeof(want),
								 "%s%s, %s%s",
								 prefix, dest,
								 prefix, src);
							if (strcmp(got->op_str,
								   want)) {
								fprintf(stderr,
									"text syntax=%u got=%s want=%s\n",
									syntax,
									got->op_str,
									want);
								return EXIT_FAILURE;
							}
						}
						cs_free(all, api ? count : 0);
					}
					for (size_t short_size = 0;
					     short_size < 4; ++short_size) {
						const uint8_t *cursor = data;
						uint64_t pc = 0x10002;
						if (cs_disasm_iter(h, &cursor,
								   &short_size,
								   &pc, one))
							return EXIT_FAILURE;
					}
				}
			}
			cs_free(one, 1);
		}
		if (!fields(h, big))
			return EXIT_FAILURE;
		cs_close(&h);
	}
	return EXIT_SUCCESS;
}

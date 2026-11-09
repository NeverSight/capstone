/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static const unsigned registers[] = {
#define MIPS_GPR(Name) MIPS_REG_##Name,
#include "mips_gpr_cases.inc"
#undef MIPS_GPR
};

static bool check(csh h, bool big, unsigned output, unsigned rx, unsigned ry,
		  unsigned kind, unsigned amount, bool extended)
{
	const unsigned ids[] = { MIPS_INS_SLL, MIPS_INS_SRL,  MIPS_INS_SRA,
				 MIPS_INS_NEG, MIPS_INS_MULT, MIPS_INS_MULTU };
	const unsigned functions[] = { 0, 2, 3, 11, 24, 25 };
	unsigned half = (kind < 3 ? 0x3000 : 0xe800) | (rx << 8) | (ry << 5) |
			functions[kind];
	if (kind < 3 && !extended)
		half |= (amount & 7) << 2;
	unsigned first = extended ? 0xf000 | (amount << 6) : half;
	uint8_t bytes[] = { first >> (big ? 8 : 0), first >> (big ? 0 : 8),
			    half >> (big ? 8 : 0), half >> (big ? 0 : 8) };
	size_t size = extended ? 4 : 2;
	cs_insn *i = cs_malloc(h);
	const uint8_t *cursor = bytes;
	size_t left = size;
	uint64_t address = 0x10002;
	bool ok = cs_disasm_iter(h, &cursor, &left, &address, i) &&
		  i->id == ids[kind] && i->size == size && !left &&
		  address == 0x10002 + size && !memcmp(i->bytes, bytes, size);
	if (ok && output == 3) {
		const cs_mips *m = &i->detail->mips;
		ok = m->op_count == (kind < 3 ? 3 : 2) &&
		     m->operands[0].type == MIPS_OP_REG &&
		     m->operands[0].reg == registers[rx < 2 ? rx + 16 : rx] &&
		     m->operands[1].type == MIPS_OP_REG &&
		     m->operands[1].reg == registers[ry < 2 ? ry + 16 : ry];
		if (kind < 3)
			ok &= m->operands[2].type == MIPS_OP_IMM &&
			      m->operands[2].imm == amount;
		if (!cs_support(CS_SUPPORT_DIET)) {
			ok &= m->operands[0].access ==
				      (kind < 4 ? CS_AC_WRITE : CS_AC_READ) &&
			      m->operands[1].access == CS_AC_READ &&
			      cs_insn_group(h, i, MIPS_FEATURE_INMIPS16MODE) &&
			      !cs_insn_group(h, i, MIPS_FEATURE_HASSTDENC);
			if (kind >= 4)
				ok &= cs_reg_write(h, i, MIPS_REG_HI0) &&
				      cs_reg_write(h, i, MIPS_REG_LO0);
		}
	}
	for (size_t n = 0; ok && n < size; ++n) {
		cursor = bytes;
		left = n;
		address = 0x10002;
		ok = !cs_disasm_iter(h, &cursor, &left, &address, i) &&
		     cursor == bytes && left == n && address == 0x10002;
	}
	if (!ok)
		fprintf(stderr,
			"MIPS16 scalar: big=%u output=%u kind=%u rx=%u ry=%u amount=%u ext=%u\n",
			big, output, kind, rx, ry, amount, extended);
	cs_free(i, 1);
	return ok;
}

static bool reserved(csh h, bool big)
{
	// Every reserved bit independently, with an otherwise valid extended SLL.
	for (unsigned bit = 0; bit < 9; ++bit) {
		unsigned first = 0xf7c0 | (bit < 6 ? 1u << bit : 0);
		unsigned half = 0x3280 | (bit >= 6 ? 1u << (bit - 4) : 0);
		uint8_t bytes[] = { first >> (big ? 8 : 0),
				    first >> (big ? 0 : 8),
				    half >> (big ? 8 : 0),
				    half >> (big ? 0 : 8) };
		cs_insn *i = NULL;
		size_t count =
			cs_disasm(h, bytes, sizeof(bytes), 0x10002, 1, &i);
		cs_free(i, count);
		if (count)
			return false;
	}
	const unsigned rejected[][2] = { { 0x3281, 0 },
					 { 0xf000, 0x3281 },
					 { 0xf000, 0xeaab },
					 { 0xf000, 0xecb8 },
					 { 0xf000, 0xecb9 } };
	for (unsigned n = 0; n < sizeof(rejected) / sizeof(rejected[0]); ++n) {
		unsigned first = rejected[n][0], half = rejected[n][1];
		uint8_t bytes[] = { first >> (big ? 8 : 0),
				    first >> (big ? 0 : 8),
				    half >> (big ? 8 : 0),
				    half >> (big ? 0 : 8) };
		cs_insn *i = NULL;
		size_t count =
			cs_disasm(h, bytes, half ? 4 : 2, 0x10002, 1, &i);
		cs_free(i, count);
		if (count)
			return false;
	}
	return true;
}

int main(void)
{
	for (unsigned big = 0; big < 2; ++big)
		for (unsigned output = 0; output < 4; ++output) {
			csh h;
			if (cs_open(CS_ARCH_MIPS,
				    CS_MODE_MIPS32R2 | CS_MODE_MIPS16 |
					    (big ? CS_MODE_BIG_ENDIAN : 0),
				    &h))
				return 1;
			cs_option(h, CS_OPT_TEXT,
				  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
			cs_option(h, CS_OPT_DETAIL,
				  output & 2 ? CS_OPT_ON | CS_OPT_DETAIL_REAL :
					       CS_OPT_OFF);
			for (unsigned kind = 0; kind < 6; ++kind)
				for (unsigned rx = 0; rx < 8; ++rx)
					for (unsigned ry = 0; ry < 8; ++ry) {
						if (kind >= 3) {
							if (!check(h, big,
								   output, rx,
								   ry, kind, 0,
								   false))
								return 1;
							continue;
						}
						for (unsigned sa = 1; sa <= 8;
						     ++sa)
							if (!check(h, big,
								   output, rx,
								   ry, kind, sa,
								   false))
								return 1;
						for (unsigned sa = 0; sa < 32;
						     ++sa)
							if (!check(h, big,
								   output, rx,
								   ry, kind, sa,
								   true))
								return 1;
					}
			if (!reserved(h, big))
				return 1;
			cs_close(&h);
		}
	return 0;
}

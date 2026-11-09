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

static bool check(csh h, bool big, unsigned output, unsigned flags,
		  unsigned frame, unsigned xs, unsigned ar, bool ext)
{
	unsigned first = ext ? 0xf000 | (xs << 8) | (frame & 0xf0) | ar :
			       0x6400 | (flags << 4) | frame;
	unsigned half = 0x6400 | (flags << 4) | (frame & 15);
	uint8_t bytes[] = { first >> (big ? 8 : 0), first >> (big ? 0 : 8),
			    half >> (big ? 8 : 0), half >> (big ? 0 : 8) };
	cs_insn *i = cs_malloc(h);
	const uint8_t *cursor = bytes;
	size_t size = ext ? 4 : 2, left = size;
	uint64_t address = 0x10002;
	bool decoded = cs_disasm_iter(h, &cursor, &left, &address, i);
	bool save = flags & 8;
	bool ok = ext && ar == 15 ?
			  !decoded && cursor == bytes && left == size &&
				  address == 0x10002 :
			  decoded &&
				  i->id == (save ? MIPS_INS_SAVE :
						   MIPS_INS_RESTORE) &&
				  i->size == size && !left &&
				  address == 0x10002 + size &&
				  !memcmp(i->bytes, bytes, size);
	static const unsigned args[] = { 0, 0, 0, 0, 1, 1, 1, 1,
					 2, 2, 2, 0, 3, 3, 4 };
	static const unsigned statics[] = { 0, 1, 2, 3, 0, 1, 2, 3,
					    0, 1, 2, 4, 0, 1, 0 };
	unsigned regs[15], count = 0;
	unsigned arguments = ext && save && ar < 15 ? args[ar] : 0;
	for (unsigned n = 0; n < arguments; ++n)
		regs[count++] = registers[4 + n];
	unsigned imm = count++;
	if (ext && ar < 15)
		for (unsigned n = 8 - statics[ar]; n < 8; ++n)
			regs[count++] = registers[n];
	if (flags & 2)
		regs[count++] = MIPS_REG_S0;
	if (flags & 1)
		regs[count++] = MIPS_REG_S1;
	for (unsigned n = 0; n < xs; ++n)
		regs[count++] = registers[n == 6 ? 30 : 18 + n];
	if (flags & 4)
		regs[count++] = MIPS_REG_RA;
	if (ok && decoded && (output & 2)) {
		const cs_mips *m = &i->detail->mips;
		ok = m->op_count == count;
		for (unsigned n = 0; ok && n < count; ++n) {
			const cs_mips_op *op = &m->operands[n];
			ok = n == imm ? op->type == MIPS_OP_IMM &&
						op->imm == (!ext && !frame ?
								    128 :
								    frame * 8) :
					op->type == MIPS_OP_REG &&
						op->reg == regs[n];
			if (!cs_support(CS_SUPPORT_DIET) && n != imm)
				ok &= op->access ==
				      (save ? CS_AC_READ : CS_AC_WRITE);
		}
		if (!cs_support(CS_SUPPORT_DIET)) {
			cs_regs reads, writes;
			uint8_t nr, nw;
			ok &= cs_regs_access(h, i, reads, &nr, writes, &nw) ==
				      CS_ERR_OK &&
			      nr == (save ? count : 1) &&
			      nw == (save ? 1 : count) &&
			      cs_reg_read(h, i, MIPS_REG_SP) &&
			      cs_reg_write(h, i, MIPS_REG_SP) &&
			      cs_insn_group(h, i, MIPS_FEATURE_INMIPS16MODE);
		}
	}
	if (ok && decoded && (output & 1) && !cs_support(CS_SUPPORT_DIET))
		ok = !strcmp(i->mnemonic, save ? "save" : "restore");
	if (ok && decoded) {
		cs_insn *bulk = NULL;
		size_t n = cs_disasm(h, bytes, size, 0x10002, 1, &bulk);
		ok = n == 1 && bulk->id == i->id && bulk->size == i->size &&
		     !strcmp(bulk->mnemonic, i->mnemonic) &&
		     !strcmp(bulk->op_str, i->op_str);
		if (ok && (output & 2))
			ok = !memcmp(&bulk->detail->mips, &i->detail->mips,
				     sizeof(cs_mips));
		cs_free(bulk, n);
	}
	if (ok && decoded && (output & 1) && !cs_support(CS_SUPPORT_DIET) &&
	    !ext && !frame) {
		if (flags == 8)
			ok = !strcmp(i->op_str, "0x80");
		if (flags == 15)
			ok = !strcmp(i->op_str, "0x80, $s0, $s1, $ra");
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
			"frame big=%u output=%u flags=%u frame=%u xs=%u ar=%u ext=%u\n",
			big, output, flags, frame, xs, ar, ext);
	cs_free(i, 1);
	return ok;
}

int main(void)
{
	for (unsigned big = 0; big < 2; ++big)
		for (unsigned output = 0; output < 4; ++output)
			for (unsigned real = 0; real < 2; ++real) {
				csh h;
				if (cs_open(CS_ARCH_MIPS,
					    CS_MODE_MIPS32R2 | CS_MODE_MIPS16 |
						    (big ? CS_MODE_BIG_ENDIAN :
							   0),
					    &h))
					return 1;
				cs_option(h, CS_OPT_TEXT,
					  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
				cs_option(
					h, CS_OPT_DETAIL,
					output & 2 ?
						CS_OPT_ON |
							(real ? CS_OPT_DETAIL_REAL :
								0) :
						CS_OPT_OFF);
				for (unsigned flags = 0; flags < 16; ++flags) {
					for (unsigned frame = 0; frame < 16;
					     ++frame)
						if (!check(h, big, output,
							   flags, frame, 0, 0,
							   false))
							return 1;
					const unsigned frames[] = {
						0, 1, 15, 16, 128, 255
					};
					for (unsigned f = 0;
					     f <
					     sizeof(frames) / sizeof(frames[0]);
					     ++f)
						for (unsigned xs = 0; xs < 8;
						     ++xs)
							for (unsigned ar = 0;
							     ar < 16; ++ar)
								if (!check(h,
									   big,
									   output,
									   flags,
									   frames[f],
									   xs,
									   ar,
									   true))
									return 1;
				}
				cs_close(&h);
			}
	return 0;
}

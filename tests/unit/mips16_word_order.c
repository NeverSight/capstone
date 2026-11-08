/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static void halfword(uint8_t *bytes, unsigned value, bool big)
{
	bytes[0] = big ? value >> 8 : value;
	bytes[1] = big ? value : value >> 8;
}

static bool instruction(const cs_insn *insn, unsigned size, unsigned reg,
			int immediate, bool detail)
{
	if (insn->id != MIPS_INS_LI || insn->size != size)
		return false;
	if (!detail)
		return true;
	const cs_mips *mips = &insn->detail->mips;
	return mips->op_count == 2 && mips->operands[0].type == MIPS_OP_REG &&
	       mips->operands[0].reg == reg &&
	       mips->operands[1].type == MIPS_OP_IMM &&
	       mips->operands[1].imm == immediate;
}

static bool check(csh handle, bool big, bool detail, unsigned value)
{
	// MIPS16e manual rev 2.63, sections 3.16 and LI (Extended): the EXTEND
	// halfword precedes LI in both byte orders, even across a word boundary.
	uint8_t bytes[8];
	halfword(bytes, 0x6b02, big); // li v1,2
	halfword(bytes + 2, 0xf000 | ((value >> 5) & 63) << 5 | value >> 11,
		 big);
	halfword(bytes + 4, 0x6a00 | (value & 31), big); // extended li v0,value
	halfword(bytes + 6, 0x6c03, big); // li a0,3
	const unsigned sizes[] = { 2, 4, 2 };
	const unsigned regs[] = { MIPS_REG_V1, MIPS_REG_V0, MIPS_REG_A0 };
	const unsigned values[] = { 2, value, 3 };
	cs_insn *result = NULL;
	size_t count =
		cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 0, &result);
	bool ok = count == 3;
	unsigned offset = 0;
	for (unsigned i = 0; ok && i < count; ++i) {
		ok = instruction(&result[i], sizes[i], regs[i], values[i],
				 detail) &&
		     result[i].address == 0x1000 + offset &&
		     !memcmp(result[i].bytes, bytes + offset, sizes[i]);
		offset += sizes[i];
	}
	cs_free(result, count);
	if (!ok)
		return false;
	cs_insn *one = cs_malloc(handle);
	if (!one)
		return false;
	const uint8_t *cursor = bytes;
	size_t left = sizeof(bytes);
	uint64_t address = 0x1000;
	for (unsigned i = 0; ok && i < 3; ++i) {
		const uint64_t start = address;
		ok = cs_disasm_iter(handle, &cursor, &left, &address, one) &&
		     instruction(one, sizes[i], regs[i], values[i], detail) &&
		     one->address == start && address == start + sizes[i] &&
		     !memcmp(one->bytes, bytes + (start - 0x1000), sizes[i]);
	}
	ok &= left == 0 && cursor == bytes + sizeof(bytes);
	// An incomplete prefix/suffix must not turn into a two-byte instruction.
	for (unsigned length = 0; ok && length < 4; ++length) {
		cursor = bytes + 2;
		left = length;
		address = 0x1002;
		ok = !cs_disasm_iter(handle, &cursor, &left, &address, one) &&
		     cursor == bytes + 2 && left == length && address == 0x1002;
		count = cs_disasm(handle, bytes + 2, length, 0x1002, 0,
				  &result);
		ok &= count == 0;
		cs_free(result, count);
	}
	cs_free(one, 1);
	return ok;
}

int main(void)
{
	const unsigned values[] = {
		0, 1, 31, 32, 0x1234, 0x7fff, 0x8000, 0xffff
	};
	for (unsigned big = 0; big < 2; ++big)
		for (unsigned output = 0; output < 4; ++output) {
			csh handle;
			if (cs_open(CS_ARCH_MIPS,
				    CS_MODE_MIPS16 |
					    (big ? CS_MODE_BIG_ENDIAN : 0),
				    &handle) != CS_ERR_OK)
				return 1;
			cs_option(handle, CS_OPT_TEXT,
				  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
			cs_option(handle, CS_OPT_DETAIL,
				  output & 2 ? CS_OPT_ON : CS_OPT_OFF);
			for (unsigned i = 0;
			     i < sizeof(values) / sizeof(values[0]); ++i)
				if (!check(handle, big, output == 3,
					   values[i])) {
					fprintf(stderr,
						"MIPS16 halfword order: big=%u output=%u value=%x\n",
						big, output, values[i]);
					return 1;
				}
			cs_close(&handle);
		}
	return 0;
}

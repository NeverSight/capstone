/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

typedef struct {
	uint16_t opcode;
	unsigned id;
	unsigned bits;
	int scale;
	bool signed_value;
	bool branch;
	unsigned reg;
} immediate_case;

// MIPS16e manual MD00076 revision 2.63, individual instruction definitions.
// These are raw halfwords, independent of an assembler or decoder table.
static const immediate_case cases[] = {
	{ 0x6a00, MIPS_INS_LI, 8, 1, false, false, MIPS_REG_V0 },
	{ 0x6a00, MIPS_INS_LI, 16, 1, false, false, MIPS_REG_V0 },
	{ 0x7200, MIPS_INS_CMPI, 8, 1, false, false, MIPS_REG_V0 },
	{ 0x7200, MIPS_INS_CMPI, 16, 1, false, false, MIPS_REG_V0 },
	{ 0x4a00, MIPS_INS_ADDIU, 8, 1, true, false, MIPS_REG_V0 },
	{ 0x4a00, MIPS_INS_ADDIU, 16, 1, true, false, MIPS_REG_V0 },
	{ 0x6300, MIPS_INS_ADDIU, 8, 8, true, false, MIPS_REG_SP },
	{ 0x6300, MIPS_INS_ADDIU, 16, 1, true, false, MIPS_REG_SP },
	{ 0x1000, MIPS_INS_B, 11, 2, true, true, 0 },
	{ 0x1000, MIPS_INS_B, 16, 2, true, true, 0 },
	{ 0x2200, MIPS_INS_BEQZ, 8, 2, true, true, MIPS_REG_V0 },
	{ 0x2200, MIPS_INS_BEQZ, 16, 2, true, true, MIPS_REG_V0 },
	{ 0x2a00, MIPS_INS_BNEZ, 8, 2, true, true, MIPS_REG_V0 },
	{ 0x2a00, MIPS_INS_BNEZ, 16, 2, true, true, MIPS_REG_V0 },
	{ 0x6000, MIPS_INS_BTEQZ, 8, 2, true, true, 0 },
	{ 0x6000, MIPS_INS_BTEQZ, 16, 2, true, true, 0 },
	{ 0x6100, MIPS_INS_BTNEZ, 8, 2, true, true, 0 },
	{ 0x6100, MIPS_INS_BTNEZ, 16, 2, true, true, 0 },
};

static void halfword(uint8_t *bytes, unsigned value, bool big)
{
	bytes[0] = big ? value >> 8 : value;
	bytes[1] = big ? value : value >> 8;
}

static bool check_insn(csh handle, const cs_insn *insn,
		       const immediate_case *test, const uint8_t *bytes,
		       unsigned size, uint64_t address, int64_t expected,
		       unsigned output)
{
	if (insn->id != test->id || insn->size != size ||
	    insn->address != address || memcmp(insn->bytes, bytes, size))
		return false;
	if (output != 3)
		return true;
	const cs_mips *mips = &insn->detail->mips;
	const unsigned count = test->reg ? 2 : 1;
	if (mips->op_count != count ||
	    mips->operands[count - 1].type != MIPS_OP_IMM ||
	    mips->operands[count - 1].imm != expected ||
	    (test->reg && (mips->operands[0].type != MIPS_OP_REG ||
			   mips->operands[0].reg != test->reg)))
		return false;
	if (cs_support(CS_SUPPORT_DIET))
		return true;
	char value[32];
	if (expected < -9)
		snprintf(value, sizeof(value), "-0x%" PRIx64,
			 (uint64_t)-expected);
	else if (expected > 9)
		snprintf(value, sizeof(value), "0x%" PRIx64,
			 (uint64_t)expected);
	else
		snprintf(value, sizeof(value), "%" PRId64, expected);
	const char *printed = strrchr(insn->op_str, ',');
	printed = printed ? printed + 1 : insn->op_str;
	while (isspace((unsigned char)*printed))
		++printed;
	const size_t length = strlen(value);
	if (strncmp(printed, value, length) ||
	    (printed[length] && !isspace((unsigned char)printed[length])))
		return false;
	if (test->branch &&
	    (!cs_insn_group(handle, insn, MIPS_GRP_JUMP) ||
	     !cs_insn_group(handle, insn, MIPS_GRP_BRANCH_RELATIVE)))
		return false;
	cs_regs reads, writes;
	uint8_t read_count, write_count;
	if (cs_regs_access(handle, insn, reads, &read_count, writes,
			   &write_count) != CS_ERR_OK)
		return false;
	const bool t_branch = test->id == MIPS_INS_BTEQZ ||
			      test->id == MIPS_INS_BTNEZ;
	if (test->branch &&
	    (write_count || read_count != (test->reg || t_branch ? 1 : 0) ||
	     (read_count && reads[0] != (t_branch ? MIPS_REG_T8 : test->reg))))
		return false;
	return true;
}

static bool check(csh handle, const immediate_case *test, unsigned value,
		  bool big, unsigned output, uint64_t address, bool wide)
{
	uint8_t bytes[4];
	const unsigned size = test->bits == 16 ? 4 : 2;
	if (size == 4) {
		halfword(bytes, 0xf000 | ((value >> 5) & 63) << 5 | value >> 11,
			 big);
		halfword(bytes + 2, test->opcode | (value & 31), big);
	} else {
		halfword(bytes, test->opcode | value, big);
	}
	int64_t expected = value;
	if (test->signed_value && (value & (1u << (test->bits - 1))))
		expected -= 1u << test->bits;
	expected *= test->scale;
	if (test->branch) {
		uint64_t target = address + size + (uint64_t)expected;
		expected = wide ? (int64_t)target : (uint32_t)target;
	}
	cs_insn *result = NULL;
	size_t count = cs_disasm(handle, bytes, size, address, 1, &result);
	bool ok = count == 1 && check_insn(handle, result, test, bytes, size,
					   address, expected, output);
	cs_free(result, count);
	cs_insn *one = cs_malloc(handle);
	if (!one)
		return false;
	const uint8_t *cursor = bytes;
	size_t left = size;
	uint64_t pc = address;
	ok &= cs_disasm_iter(handle, &cursor, &left, &pc, one) &&
	      cursor == bytes + size && left == 0 && pc == address + size &&
	      check_insn(handle, one, test, bytes, size, address, expected,
			 output);
	for (unsigned length = 0; length < size; ++length) {
		cursor = bytes;
		left = length;
		pc = address;
		ok &= !cs_disasm_iter(handle, &cursor, &left, &pc, one) &&
		      cursor == bytes && left == length && pc == address;
		count = cs_disasm(handle, bytes, length, address, 0, &result);
		ok &= count == 0;
		cs_free(result, count);
	}
	// EXTEND + I8 leaves suffix bits 7..5 reserved. They must not be
	// reinterpreted as an extended shift, even with a zero prefix immediate.
	if (size == 4 && (test->opcode & 0xf800) == 0x6000) {
		for (unsigned reserved = 1; reserved < 8; ++reserved) {
			halfword(bytes + 2,
				 test->opcode | (value & 31) | (reserved << 5),
				 big);
			count = cs_disasm(handle, bytes, size, address, 1,
					  &result);
			ok &= count == 0;
			cs_free(result, count);
			cursor = bytes;
			left = size;
			pc = address;
			ok &= !cs_disasm_iter(handle, &cursor, &left, &pc,
					      one) &&
			      cursor == bytes && left == size && pc == address;
		}
	}
	cs_free(one, 1);
	return ok;
}

int main(void)
{
	unsigned failures = 0;
	for (unsigned big = 0; big < 2; ++big)
		for (unsigned output = 0; output < 4; ++output) {
			csh handle;
			if (cs_open(CS_ARCH_MIPS,
				    CS_MODE_MIPS16 | CS_MODE_MIPS32R2 |
					    (big ? CS_MODE_BIG_ENDIAN : 0),
				    &handle) != CS_ERR_OK)
				return 1;
			cs_option(handle, CS_OPT_TEXT,
				  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
			cs_option(handle, CS_OPT_DETAIL,
				  output & 2 ? CS_OPT_ON : CS_OPT_OFF);
			for (unsigned i = 0;
			     i < sizeof(cases) / sizeof(cases[0]); ++i) {
				unsigned sign = 1u << (cases[i].bits - 1);
				const unsigned values[] = {
					0,	  1,	31,	  32,
					sign - 1, sign, sign + 1, sign * 2 - 1
				};
				for (unsigned j = 0;
				     j < sizeof(values) / sizeof(values[0]);
				     ++j)
					if (!check(handle, &cases[i], values[j],
						   big, output, 0x10002,
						   false)) {
						fprintf(stderr,
							"MIPS16 immediate: case=%u big=%u output=%u value=%x\n",
							i, big, output,
							values[j]);
						++failures;
					}
			}
			for (unsigned wide = 0; wide < 2; ++wide) {
				cs_option(handle, CS_OPT_MODE,
					  CS_MODE_MIPS16 |
						  (wide ? CS_MODE_MIPS64R2 :
							  CS_MODE_MIPS32R2) |
						  (big ? CS_MODE_BIG_ENDIAN :
							 0));
				const uint64_t addresses[] = { 0, 0xfffffffc,
							       UINT64_MAX - 3 };
				for (unsigned i = 8;
				     i < sizeof(cases) / sizeof(cases[0]); ++i)
					for (unsigned j = 0;
					     j < (wide ? 3u : 2u); ++j)
						for (unsigned negative = 0;
						     negative < 2; ++negative) {
							unsigned value =
								negative ?
									(1u
									 << cases[i].bits) -
										2 :
									1;
							if (!check(handle,
								   &cases[i],
								   value, big,
								   output,
								   addresses[j],
								   wide)) {
								fprintf(stderr,
									"MIPS16 branch wrap: case=%u big=%u output=%u wide=%u address=%" PRIx64
									" value=%x\n",
									i, big,
									output,
									wide,
									addresses[j],
									value);
								++failures;
							}
						}
			}
			cs_close(&handle);
		}
	return failures != 0;
}

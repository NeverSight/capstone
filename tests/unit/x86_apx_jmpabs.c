/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX JMPABS check failed: %s\n", message);
	return condition;
}

static bool contains_group(const cs_detail *detail, uint8_t group)
{
	uint8_t i;

	for (i = 0; i < detail->groups_count; ++i) {
		if (detail->groups[i] == group)
			return true;
	}
	return false;
}

static bool check_valid(csh handle, const uint8_t *code, size_t code_size,
			const char *expected_operands)
{
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (!check(count == 1, "valid instruction decodes"))
		return false;
	success &= check(insn[0].size == code_size,
			 "instruction length includes the absolute target");
	success &= check(insn[0].id == X86_INS_JMPABS,
			 "public instruction ID is exact");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id), "jmpabs") == 0,
			 "public instruction name is exact");
	success &= check(strcmp(insn[0].mnemonic, "jmpabs") == 0,
			 "mnemonic is exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "absolute immediate text is exact");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->opcode[0] == 0xa1,
				 "opcode detail excludes REX2 payload");
		success &= check(x86->encoding.imm_offset == code_size - 8 &&
					 x86->encoding.imm_size == 8,
				 "immediate encoding detail is exact");
		success &= check(x86->op_count == 1 &&
					 x86->operands[0].type == X86_OP_IMM &&
					 x86->operands[0].imm ==
						 (int64_t)0x8877665544332211ULL &&
					 x86->operands[0].size == 8 &&
					 x86->operands[0].access == CS_AC_READ,
				 "immediate operand detail is exact");
		success &= check(contains_group(insn[0].detail, CS_GRP_JUMP),
				 "instruction belongs to the jump group");
	}
	cs_free(insn, count);
	return success;
}

static bool rejects(csh handle, const uint8_t *code, size_t code_size,
		    const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	bool success = check(count == 0, message);

	cs_free(insn, count);
	return success;
}

int main(void)
{
	const uint8_t canonical[] = { 0xd5, 0x00, 0xa1, 0x11, 0x22, 0x33,
				      0x44, 0x55, 0x66, 0x77, 0x88 };
	const uint8_t ignored_payload_bits[] = { 0xd5, 0x77, 0xa1, 0x11,
						  0x22, 0x33, 0x44, 0x55,
						  0x66, 0x77, 0x88 };
	const uint8_t segment_override[] = { 0x64, 0xd5, 0x00, 0xa1,
					     0x11, 0x22, 0x33, 0x44,
					     0x55, 0x66, 0x77, 0x88 };
	const uint8_t invalid_w[] = { 0xd5, 0x08, 0xa1, 0x11, 0x22, 0x33,
				      0x44, 0x55, 0x66, 0x77, 0x88 };
	const uint8_t invalid_map[] = { 0xd5, 0x80, 0xa1, 0x11, 0x22, 0x33,
					0x44, 0x55, 0x66, 0x77, 0x88 };
	const uint8_t invalid_prefix[] = { 0x66, 0xd5, 0x00, 0xa1,
					   0x11, 0x22, 0x33, 0x44,
					   0x55, 0x66, 0x77, 0x88 };
	csh intel = 0;
	csh att = 0;
	bool success = true;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &intel) != CS_ERR_OK ||
	    cs_open(CS_ARCH_X86, CS_MODE_64, &att) != CS_ERR_OK) {
		fprintf(stderr, "failed to open Capstone\n");
		return 1;
	}
	cs_option(intel, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

	success &= check_valid(intel, canonical, sizeof(canonical),
			       "0x8877665544332211");
	success &= check_valid(att, canonical, sizeof(canonical),
			       "0x8877665544332211");
	success &= check_valid(intel, ignored_payload_bits,
			       sizeof(ignored_payload_bits),
			       "0x8877665544332211");
	success &= check_valid(intel, segment_override,
			       sizeof(segment_override),
			       "0x8877665544332211");
	success &= rejects(intel, invalid_w, sizeof(invalid_w),
			   "REX2.W=1 is rejected");
	success &= rejects(intel, invalid_map, sizeof(invalid_map),
			   "REX2.M0=1 is rejected");
	success &= rejects(intel, invalid_prefix, sizeof(invalid_prefix),
			   "forbidden legacy prefix is rejected");
	success &= rejects(intel, canonical, sizeof(canonical) - 1,
			   "truncated absolute target is rejected");

	cs_close(&att);
	cs_close(&intel);
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static const char *const condition_names[16] = {
	"o", "no", "b", "ae", "e", "ne", "be", "a",
	"s", "ns", "p", "np", "l", "ge", "le", "g",
};

static const x86_insn set_ids[16] = {
	X86_INS_SETO,  X86_INS_SETNO, X86_INS_SETB,  X86_INS_SETAE,
	X86_INS_SETE,  X86_INS_SETNE, X86_INS_SETBE, X86_INS_SETA,
	X86_INS_SETS,  X86_INS_SETNS, X86_INS_SETP,  X86_INS_SETNP,
	X86_INS_SETL,  X86_INS_SETGE, X86_INS_SETLE, X86_INS_SETG,
};

static const x86_insn setzu_ids[16] = {
	X86_INS_SETZUO,  X86_INS_SETZUNO, X86_INS_SETZUB,
	X86_INS_SETZUAE, X86_INS_SETZUE,  X86_INS_SETZUNE,
	X86_INS_SETZUBE, X86_INS_SETZUA,  X86_INS_SETZUS,
	X86_INS_SETZUNS, X86_INS_SETZUP,  X86_INS_SETZUNP,
	X86_INS_SETZUL,  X86_INS_SETZUGE, X86_INS_SETZULE,
	X86_INS_SETZUG,
};

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX SETcc check failed: %s\n", message);
	return condition;
}

static x86_reg gpr8(unsigned int number)
{
	static const x86_reg registers[] = {
		X86_REG_AL,   X86_REG_CL,   X86_REG_DL,   X86_REG_BL,
		X86_REG_SPL,  X86_REG_BPL,  X86_REG_SIL,  X86_REG_DIL,
		X86_REG_R8B,  X86_REG_R9B,  X86_REG_R10B, X86_REG_R11B,
		X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B,
		X86_REG_R16B, X86_REG_R17B, X86_REG_R18B, X86_REG_R19B,
		X86_REG_R20B, X86_REG_R21B, X86_REG_R22B, X86_REG_R23B,
		X86_REG_R24B, X86_REG_R25B, X86_REG_R26B, X86_REG_R27B,
		X86_REG_R28B, X86_REG_R29B, X86_REG_R30B, X86_REG_R31B,
	};

	return number < 32 ? registers[number] : X86_REG_INVALID;
}

static void encode_register(uint8_t code[6], unsigned int cc, bool zu,
			    bool w, unsigned int number)
{
	code[0] = 0x62;
	code[1] = 0xd4 | ((number & 8) ? 0 : 0x20) |
		  ((number & 16) ? 0x08 : 0);
	code[2] = (w ? 0x80 : 0) | 0x7f;
	code[3] = (zu ? 0x10 : 0) | 0x08;
	code[4] = 0x40 | (cc & 15);
	code[5] = 0xc0 | (number & 7);
}

static bool has_register(const cs_regs registers, uint8_t count, x86_reg reg)
{
	uint8_t i;

	for (i = 0; i < count; ++i) {
		if (registers[i] == reg)
			return true;
	}
	return false;
}

static bool check_register_case(csh handle, bool att, unsigned int cc,
				bool zu, bool w, unsigned int number)
{
	uint8_t code[6];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	const x86_reg reg = gpr8(number);
	const char *reg_name = cs_reg_name(handle, reg);
	char expected_mnemonic[24];
	char expected_operands[32];
	size_t count;
	bool success = true;

	encode_register(code, cc, zu, w, number);
	if (att)
		snprintf(expected_mnemonic, sizeof(expected_mnemonic),
			 zu ? "setzu%sb" : "set%s", condition_names[cc]);
	else
		snprintf(expected_mnemonic, sizeof(expected_mnemonic),
			 zu ? "setzu%s" : "set%s", condition_names[cc]);
	snprintf(expected_operands, sizeof(expected_operands), att ? "%%%s" : "%s",
		 reg_name);

	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "register form decodes"))
		return false;
	success &= check(insn[0].id == (zu ? setzu_ids[cc] : set_ids[cc]),
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "register mnemonic is exact");
	if (zu) {
		char expected_name[24];

		snprintf(expected_name, sizeof(expected_name), "setzu%s",
			 condition_names[cc]);
		success &= check(cs_insn_name(handle, insn[0].id) != NULL &&
					 strcmp(cs_insn_name(handle, insn[0].id),
						expected_name) == 0,
				 "public instruction name is exact");
	}
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "register text is exact");
	success &= check(insn[0].detail != NULL, "register detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == 1 &&
					 x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == reg &&
					 x86->operands[0].size == 1 &&
					 x86->operands[0].access == CS_AC_WRITE,
				 "register operand detail is exact");
		success &= check(has_register(insn[0].detail->regs_read,
					      insn[0].detail->regs_read_count,
					      X86_REG_EFLAGS),
				 "EFLAGS dependency is explicit");
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
					&regs_read_count, regs_write,
					&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(has_register(regs_read, regs_read_count,
					      X86_REG_EFLAGS) &&
					 has_register(regs_write, regs_write_count, reg),
				 "register accesses are exact");
	}
	cs_free(insn, count);
	return success;
}

static size_t encode_sib_memory(uint8_t code[10], bool address32, bool zu)
{
	size_t cursor = 0;

	code[cursor++] = address32 ? 0x67 : 0x64;
	code[cursor++] = 0x62;
	// Base r20[d], index r29[d]: B4=1, B3=0, X4=1, X3=1.
	code[cursor++] = 0xbc;
	code[cursor++] = 0x7b;
	code[cursor++] = (zu ? 0x10 : 0) | 0x08;
	code[cursor++] = 0x45; // SETNE
	code[cursor++] = 0x44;
	code[cursor++] = 0xac;
	code[cursor++] = 0xf0;
	return cursor;
}

static bool check_memory_case(csh handle, bool att, bool address32, bool zu)
{
	uint8_t code[10] = { 0 };
	cs_insn *insn = NULL;
	const size_t size = encode_sib_memory(code, address32, zu);
	const char *expected_mnemonic = att ?
		(zu ? "setzuneb" : "setne") : (zu ? "setzune" : "setne");
	const char *expected_operands;
	size_t count;
	bool success = true;

	if (address32) {
		expected_operands = att ? "-0x10(%r20d,%r29d,4)" :
					  "byte ptr [r20d + r29d*4 - 0x10]";
	} else {
		expected_operands = att ? "%fs:-0x10(%r20,%r29,4)" :
					  "byte ptr fs:[r20 + r29*4 - 0x10]";
	}

	count = cs_disasm(handle, code, size, 0x1000, 1, &insn);
	if (!check(count == 1, "memory form decodes"))
		return false;
	success &= check(insn[0].id == (zu ? X86_INS_SETZUNE : X86_INS_SETNE),
			 "memory instruction ID preserves ZU encoding");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "memory mnemonic is exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "memory text is exact");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		const x86_reg base = address32 ? X86_REG_R20D : X86_REG_R20;
		const x86_reg index = address32 ? X86_REG_R29D : X86_REG_R29;
		const x86_reg segment = address32 ? X86_REG_INVALID : X86_REG_FS;

		success &= check(x86->addr_size == (address32 ? 4 : 8),
				 "address size is exact");
		success &= check(x86->op_count == 1 &&
					 x86->operands[0].type == X86_OP_MEM &&
					 x86->operands[0].mem.segment == segment &&
					 x86->operands[0].mem.base == base &&
					 x86->operands[0].mem.index == index &&
					 x86->operands[0].mem.scale == 4 &&
					 x86->operands[0].mem.disp == -16 &&
					 x86->operands[0].size == 1 &&
					 x86->operands[0].access == CS_AC_WRITE,
				 "memory operand detail is exact");
		success &= check(x86->encoding.modrm_offset == 6 &&
					 x86->encoding.disp_offset == 8 &&
					 x86->encoding.disp_size == 1,
				 "memory encoding offsets are exact");
	}
	cs_free(insn, count);
	return success;
}

static bool check_addr32_displacement_forms(csh handle)
{
	static const uint8_t relative[] = {
		0x67, 0x62, 0xf4, 0x7b, 0x08, 0x45, 0x05,
		0x34, 0x12, 0x00, 0x00,
	};
	static const uint8_t absolute[] = {
		0x67, 0x62, 0xf4, 0x7b, 0x08, 0x45, 0x04, 0x25,
		0x34, 0x12, 0x00, 0x00,
	};
	const struct {
		const uint8_t *code;
		size_t size;
		x86_reg base;
		uint8_t modrm_offset;
		uint8_t displacement_offset;
		const char *message;
	} cases[] = {
		{ relative, sizeof(relative), X86_REG_EIP, 6, 7,
		  "addr32 ModRM displacement is EIP-relative" },
		{ absolute, sizeof(absolute), X86_REG_INVALID, 6, 8,
		  "addr32 SIB no-base displacement is absolute" },
	};
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		cs_insn *insn = NULL;
		size_t count = cs_disasm(handle, cases[i].code, cases[i].size,
					 0x1000, 1, &insn);

		if (!check(count == 1, cases[i].message))
			return false;
		if (!check(insn[0].detail != NULL,
			   "addr32 displacement detail is available")) {
			cs_free(insn, count);
			return false;
		}
		success &= check(insn[0].detail->x86.addr_size == 4 &&
					 insn[0].detail->x86.op_count == 1 &&
					 insn[0].detail->x86.operands[0].type ==
						 X86_OP_MEM &&
					 insn[0].detail->x86.operands[0].mem.base ==
						 cases[i].base &&
					 insn[0].detail->x86.operands[0].mem.disp ==
						 0x1234,
				 "addr32 displacement operand detail is exact");
		success &= check(
			insn[0].detail->x86.encoding.modrm_offset ==
				cases[i].modrm_offset &&
				insn[0].detail->x86.encoding.disp_offset ==
					cases[i].displacement_offset &&
				insn[0].detail->x86.encoding.disp_size == 4,
			"addr32 displacement encoding offsets are exact");
		cs_free(insn, count);
	}
	return success;
}

static bool rejects(csh handle, const uint8_t *code, size_t size,
		    const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, size, 0x1000, 1, &insn);
	bool success = check(count == 0, message);

	cs_free(insn, count);
	return success;
}

static bool decodes(csh handle, const uint8_t *code, size_t size,
		    const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, size, 0x1000, 1, &insn);
	bool success = check(count == 1, message);

	cs_free(insn, count);
	return success;
}

int main(void)
{
	csh intel = 0;
	csh att = 0;
	csh mode32 = 0;
	uint8_t invalid[7];
	bool success = true;
	unsigned int cc, zu, w, number;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &intel) != CS_ERR_OK ||
	    cs_open(CS_ARCH_X86, CS_MODE_64, &att) != CS_ERR_OK ||
	    cs_open(CS_ARCH_X86, CS_MODE_32, &mode32) != CS_ERR_OK) {
		fprintf(stderr, "failed to open Capstone\n");
		return 1;
	}
	cs_option(intel, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

	for (cc = 0; cc < 16; ++cc) {
		for (zu = 0; zu < 2; ++zu) {
			for (w = 0; w < 2; ++w) {
				for (number = 0; number < 32; ++number) {
					success &= check_register_case(
						intel, false, cc, zu != 0, w != 0,
						number);
					success &= check_register_case(
						att, true, cc, zu != 0, w != 0,
						number);
				}
			}
		}
	}
	success &= check_memory_case(intel, false, false, false);
	success &= check_memory_case(intel, false, false, true);
	success &= check_memory_case(att, true, false, true);
	success &= check_memory_case(intel, false, true, true);
	success &= check_memory_case(att, true, true, true);
	success &= check_addr32_displacement_forms(intel);

	encode_register(invalid, 5, true, false, 29);
	success &= rejects(mode32, invalid, 6, "non-64-bit mode is rejected");
	encode_register(invalid, 5, true, false, 29);
	invalid[2] ^= 0x01;
	success &= rejects(intel, invalid, 6, "non-F2 pp is rejected");
	encode_register(invalid, 5, true, false, 29);
	invalid[2] &= (uint8_t)~0x08;
	success &= rejects(intel, invalid, 6, "nonzero V register is rejected");
	encode_register(invalid, 5, true, false, 29);
	invalid[3] &= (uint8_t)~0x08;
	success &= rejects(intel, invalid, 6, "nonzero V4 is rejected");
	encode_register(invalid, 5, true, false, 29);
	invalid[3] |= 0x04;
	success &= rejects(intel, invalid, 6, "NF is rejected");
	encode_register(invalid, 5, true, false, 29);
	invalid[3] |= 0x80;
	success &= rejects(intel, invalid, 6, "reserved EVEX bits are rejected");
	encode_register(invalid, 5, true, false, 29);
	invalid[2] &= (uint8_t)~0x04;
	success &= rejects(intel, invalid, 6, "register U=0 is rejected");
	encode_register(invalid, 5, true, false, 29);
	invalid[1] ^= 0xd0;
	invalid[5] |= 0x38;
	success &= decodes(intel, invalid, 6,
			   "unused R/X and ModRM.reg fields are ignored");
	encode_register(&invalid[1], 5, true, false, 29);
	invalid[0] = 0x66;
	success &= rejects(intel, invalid, 7, "legacy OSIZE prefix is rejected");
	invalid[0] = 0xf0;
	success &= rejects(intel, invalid, 7, "LOCK prefix is rejected");
	invalid[0] = 0x48;
	success &= rejects(intel, invalid, 7, "REX prefix is rejected");

	cs_close(&mode32);
	cs_close(&att);
	cs_close(&intel);
	return success ? 0 : 1;
}

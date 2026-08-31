/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX REX2 push/pop check failed: %s\n", message);
	return condition;
}

static x86_reg gpr(unsigned int number, uint8_t width)
{
	static const x86_reg registers16[] = {
		X86_REG_AX,   X86_REG_CX,   X86_REG_DX,   X86_REG_BX,
		X86_REG_SP,   X86_REG_BP,   X86_REG_SI,   X86_REG_DI,
		X86_REG_R8W,  X86_REG_R9W,  X86_REG_R10W, X86_REG_R11W,
		X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, X86_REG_R15W,
		X86_REG_R16W, X86_REG_R17W, X86_REG_R18W, X86_REG_R19W,
		X86_REG_R20W, X86_REG_R21W, X86_REG_R22W, X86_REG_R23W,
		X86_REG_R24W, X86_REG_R25W, X86_REG_R26W, X86_REG_R27W,
		X86_REG_R28W, X86_REG_R29W, X86_REG_R30W, X86_REG_R31W,
	};
	static const x86_reg registers64[] = {
		X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
		X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
		X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
		X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
		X86_REG_R16, X86_REG_R17, X86_REG_R18, X86_REG_R19,
		X86_REG_R20, X86_REG_R21, X86_REG_R22, X86_REG_R23,
		X86_REG_R24, X86_REG_R25, X86_REG_R26, X86_REG_R27,
		X86_REG_R28, X86_REG_R29, X86_REG_R30, X86_REG_R31,
	};

	if (number >= 32)
		return X86_REG_INVALID;
	return width == 2 ? registers16[number] : registers64[number];
}

static void encode(uint8_t code[3], bool push, bool hint,
		   unsigned int number)
{
	code[0] = 0xd5;
	code[1] = (hint ? 0x08 : 0) | ((number & 16) ? 0x10 : 0) |
		  ((number & 8) ? 0x01 : 0);
	code[2] = (push ? 0x50 : 0x58) | (number & 7);
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

static bool check_case(csh handle, bool att, bool push, bool hint,
		       bool osize, unsigned int number)
{
	uint8_t raw[3];
	uint8_t code[4];
	const uint8_t *bytes;
	size_t size;
	const uint8_t width = !hint && osize ? 2 : 8;
	const x86_reg reg = gpr(number, width);
	const char *name = cs_reg_name(handle, reg);
	char expected_mnemonic[16];
	char expected_operands[32];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	bool success = true;
	size_t count;

	encode(raw, push, hint, number);
	if (osize) {
		code[0] = 0x66;
		memcpy(&code[1], raw, sizeof(raw));
		bytes = code;
		size = sizeof(code);
	} else {
		bytes = raw;
		size = sizeof(raw);
	}
	if (att) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s%c",
			 push ? "push" : "pop", hint ? "p" : "",
			 width == 2 ? 'w' : 'q');
		snprintf(expected_operands, sizeof(expected_operands), "%%%s", name);
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s",
			 push ? "push" : "pop", hint ? "p" : "");
		snprintf(expected_operands, sizeof(expected_operands), "%s", name);
	}
	count = cs_disasm(handle, bytes, size, 0x1000, 1, &insn);
	if (!check(count == 1, "valid REX2 push/pop decodes"))
		return false;
	success &= check(insn[0].id ==
				 (hint ? (push ? X86_INS_PUSHP : X86_INS_POPP) :
					 (push ? X86_INS_PUSH : X86_INS_POP)),
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "mnemonic and suffix are exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "register text is exact");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		const uint8_t access = push ? CS_AC_READ : CS_AC_WRITE;

		success &= check(x86->op_count == 1 &&
					 x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == reg &&
					 x86->operands[0].size == width &&
					 x86->operands[0].access == access,
				 "explicit operand detail is exact");
		success &= check(insn[0].detail->regs_read_count == 1 &&
					 insn[0].detail->regs_read[0] == X86_REG_RSP &&
					 insn[0].detail->regs_write_count == 1 &&
					 insn[0].detail->regs_write[0] == X86_REG_RSP,
				 "implicit RSP access is exact");
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(has_register(regs_read, regs_read_count,
					      X86_REG_RSP) &&
					 has_register(regs_write, regs_write_count,
					      X86_REG_RSP),
				 "RSP is visible through cs_regs_access");
		success &= check(
			push ? has_register(regs_read, regs_read_count, reg) :
			       has_register(regs_write, regs_write_count, reg),
			"explicit access is visible through cs_regs_access");
	}
	cs_free(insn, count);
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

int main(void)
{
	csh intel = 0;
	csh att = 0;
	uint8_t raw[3];
	uint8_t prefixed[4];
	bool success = true;
	unsigned int push;
	unsigned int hint;
	unsigned int number;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &intel) != CS_ERR_OK ||
	    cs_open(CS_ARCH_X86, CS_MODE_64, &att) != CS_ERR_OK) {
		fprintf(stderr, "failed to open Capstone\n");
		return 1;
	}
	cs_option(intel, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

	for (push = 0; push < 2; ++push) {
		for (hint = 0; hint < 2; ++hint) {
			for (number = 0; number < 32; ++number) {
				success &= check_case(intel, false, push != 0,
						      hint != 0, false, number);
				success &= check_case(att, true, push != 0,
						      hint != 0, false, number);
			}
		}
		for (number = 0; number < 32; ++number) {
			success &= check_case(intel, false, push != 0, false, true,
					      number);
			success &= check_case(intel, false, push != 0, true, true,
					      number);
		}
	}

	encode(raw, true, true, 20);
	prefixed[0] = 0xf0;
	memcpy(&prefixed[1], raw, sizeof(raw));
	success &= rejects(intel, prefixed, sizeof(prefixed),
			   "LOCK is rejected");
	prefixed[0] = 0x48;
	success &= rejects(intel, prefixed, sizeof(prefixed),
			   "REX immediately before REX2 is rejected");
	encode(raw, true, true, 20);
	raw[1] |= 0x80;
	success &= rejects(intel, raw, sizeof(raw), "map 1 is rejected");

	cs_close(&att);
	cs_close(&intel);
	return success ? 0 : 1;
}

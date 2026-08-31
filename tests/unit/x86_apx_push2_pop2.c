/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX PUSH2/POP2 check failed: %s\n", message);
	return condition;
}

static x86_reg gpr64(unsigned int number)
{
	static const x86_reg registers[] = {
		X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
		X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
		X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
		X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
		X86_REG_R16, X86_REG_R17, X86_REG_R18, X86_REG_R19,
		X86_REG_R20, X86_REG_R21, X86_REG_R22, X86_REG_R23,
		X86_REG_R24, X86_REG_R25, X86_REG_R26, X86_REG_R27,
		X86_REG_R28, X86_REG_R29, X86_REG_R30, X86_REG_R31,
	};

	return number < 32 ? registers[number] : X86_REG_INVALID;
}

static void encode(uint8_t code[6], bool push, bool ppx, unsigned int v,
		   unsigned int b)
{
	code[0] = 0x62;
	code[1] = 0x44 | 0x80 | 0x10 | ((b & 8) ? 0 : 0x20) |
		  ((b & 16) ? 0x08 : 0);
	code[2] = (ppx ? 0x80 : 0) | (((~v) & 0xf) << 3) | 0x04;
	code[3] = 0x10 | ((v & 16) ? 0 : 0x08);
	code[4] = push ? 0xff : 0x8f;
	code[5] = 0xc0 | (push ? 0x30 : 0) | (b & 7);
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

static bool check_case(csh handle, bool att, bool push, bool ppx,
		       unsigned int v, unsigned int b)
{
	uint8_t code[6];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	const x86_reg vreg = gpr64(v);
	const x86_reg breg = gpr64(b);
	const char *vname = cs_reg_name(handle, vreg);
	const char *bname = cs_reg_name(handle, breg);
	char mnemonic[16];
	char operands[64];
	bool success = true;
	size_t count;

	encode(code, push, ppx, v, b);
	if (att) {
		snprintf(mnemonic, sizeof(mnemonic), "%s%sq",
			 push ? "push2" : "pop2", ppx ? "p" : "");
		snprintf(operands, sizeof(operands), "%%%s, %%%s", bname,
			 vname);
	} else {
		snprintf(mnemonic, sizeof(mnemonic), "%s%s",
			 push ? "push2" : "pop2", ppx ? "p" : "");
		snprintf(operands, sizeof(operands), "%s, %s", vname, bname);
	}
	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "valid pair instruction decodes"))
		return false;
	success &= check(insn[0].id ==
				 (push ? (ppx ? X86_INS_PUSH2P : X86_INS_PUSH2) :
					 (ppx ? X86_INS_POP2P : X86_INS_POP2)),
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, mnemonic) == 0,
			 "mnemonic and syntax suffix are exact");
	success &= check(strcmp(insn[0].op_str, operands) == 0,
			 "operand order is exact");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		const uint8_t access = push ? CS_AC_READ : CS_AC_WRITE;
		x86_reg first = att ? breg : vreg;
		x86_reg second = att ? vreg : breg;

		success &= check(x86->op_count == 2,
				 "two explicit register operands are exposed");
		success &= check(x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == first &&
					 x86->operands[0].size == 8 &&
					 x86->operands[0].access == access &&
					 x86->operands[1].type == X86_OP_REG &&
					 x86->operands[1].reg == second &&
					 x86->operands[1].size == 8 &&
					 x86->operands[1].access == access,
				 "explicit operand detail is exact");
		success &= check(insn[0].detail->regs_read_count == 1 &&
					 insn[0].detail->regs_read[0] == X86_REG_RSP &&
					 insn[0].detail->regs_write_count == 1 &&
					 insn[0].detail->regs_write[0] == X86_REG_RSP,
				 "implicit stack-pointer access is exact");
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		if (push) {
			success &= check(has_register(regs_read, regs_read_count,
						      vreg) &&
					 has_register(regs_read, regs_read_count,
						      breg),
					 "PUSH2 reads both explicit registers");
		} else {
			success &= check(has_register(regs_write, regs_write_count,
						      vreg) &&
					 has_register(regs_write, regs_write_count,
						      breg),
					 "POP2 writes both explicit registers");
		}
		success &= check(has_register(regs_read, regs_read_count,
					      X86_REG_RSP) &&
					 has_register(regs_write, regs_write_count,
					      X86_REG_RSP),
				 "stack pointer is read and written");
	}
	cs_free(insn, count);
	return success;
}

static bool rejects(csh handle, const uint8_t code[6], const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, 6, 0x1000, 1, &insn);
	bool success = check(count == 0, message);

	cs_free(insn, count);
	return success;
}

static bool decodes(csh handle, const uint8_t code[6], const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, 6, 0x1000, 1, &insn);
	bool success = check(count == 1, message);

	cs_free(insn, count);
	return success;
}

int main(void)
{
	csh intel = 0;
	csh att = 0;
	uint8_t invalid[6];
	bool success = true;
	unsigned int push_index;
	unsigned int ppx_index;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &intel) != CS_ERR_OK ||
	    cs_open(CS_ARCH_X86, CS_MODE_64, &att) != CS_ERR_OK) {
		fprintf(stderr, "failed to open Capstone\n");
		return 1;
	}
	cs_option(intel, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

	for (push_index = 0; push_index < 2; ++push_index) {
		for (ppx_index = 0; ppx_index < 2; ++ppx_index) {
			success &= check_case(intel, false, push_index != 0,
					      ppx_index != 0, 29, 20);
			success &= check_case(att, true, push_index != 0,
					      ppx_index != 0, 29, 20);
		}
	}

	encode(invalid, true, false, 29, 20);
	invalid[1] &= (uint8_t)~0x90;
	success &= decodes(intel, invalid,
			   "unused ModR/M.reg extension bits are ignored");
	encode(invalid, true, false, 29, 20);
	invalid[3] &= (uint8_t)~0x10;
	success &= rejects(intel, invalid, "ND=0 is rejected");
	encode(invalid, true, false, 29, 20);
	invalid[3] |= 0x04;
	success &= rejects(intel, invalid, "NF=1 is rejected");
	encode(invalid, true, false, 29, 20);
	invalid[2] |= 0x01;
	success &= rejects(intel, invalid, "nonzero pp is rejected");
	encode(invalid, true, false, 29, 20);
	invalid[5] &= 0x3f;
	success &= rejects(intel, invalid, "memory form is rejected");
	encode(invalid, true, false, 29, 4);
	success &= rejects(intel, invalid, "PUSH2 with RSP is rejected");
	encode(invalid, false, false, 29, 29);
	success &= rejects(intel, invalid,
			   "POP2 with identical registers is rejected");
	encode(invalid, false, false, 4, 20);
	success &= rejects(intel, invalid, "POP2 with RSP is rejected");

	cs_close(&att);
	cs_close(&intel);
	return success ? 0 : 1;
}

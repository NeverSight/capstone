/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "AMX TILEZERO public API check failed: %s\n",
			message);
	}
	return condition;
}

int main(void)
{
	// tilezero tmm6
	static const uint8_t code[] = { 0xc4, 0xe2, 0x7b, 0x49, 0xf0 };
	csh handle = 0;
	cs_insn *insn = NULL;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "cs_open")) {
		return 1;
	}
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			    CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "instruction decodes")) {
		cs_close(&handle);
		return 1;
	}

	success &= check(insn[0].size == sizeof(code), "instruction size is 5");
	success &= check(insn[0].id == X86_INS_TILEZERO,
			 "instruction has the TILEZERO public ID");
	success &= check(strcmp(insn[0].mnemonic, "tilezero") == 0,
			 "mnemonic is tilezero");
	success &= check(strcmp(insn[0].op_str, "tmm6") == 0,
			 "operand text is tmm6");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id), "tilezero") ==
				 0,
			 "public instruction name is tilezero");
	success &= check(insn[0].detail != NULL, "detail is available");

	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		success &= check(x86->opcode[0] == code[0] &&
					 x86->opcode[1] == code[1] &&
					 x86->opcode[2] == code[2],
				 "VEX bytes are exposed as the opcode");
		success &= check(x86->modrm == code[4], "ModRM is exposed");
		success &= check(x86->encoding.modrm_offset == 4,
				 "ModRM offset is 4");
		success &= check(x86->op_count == 1, "one explicit operand");
		if (x86->op_count == 1) {
			const cs_x86_op *operand = &x86->operands[0];
			success &= check(operand->type == X86_OP_REG,
					 "operand is a register");
			success &= check(operand->reg == X86_REG_TMM6,
					 "operand has the TMM6 public ID");
			success &= check(strcmp(cs_reg_name(handle, operand->reg),
						"tmm6") == 0,
					 "register name is tmm6");
			success &= check(operand->size == 0,
					 "runtime-configured tile size is unknown");
			success &= check(operand->access == CS_AC_WRITE,
					 "tile destination is write-only");
		}

		cs_regs regs_read = { 0 };
		cs_regs regs_write = { 0 };
		uint8_t regs_read_count = 0;
		uint8_t regs_write_count = 0;
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(regs_read_count == 0, "no register is read");
		success &= check(regs_write_count == 1,
				 "one register is written");
		if (regs_write_count == 1) {
			success &= check(strcmp(cs_reg_name(handle, regs_write[0]),
						"tmm6") == 0,
					 "written register is tmm6");
		}
	}

	cs_free(insn, count);
	cs_close(&handle);
	return success ? 0 : 1;
}

#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static const char *const names[] = {
	"cmpoxadd",  "cmpnoxadd", "cmpbxadd",  "cmpnbxadd",
	"cmpzxadd",  "cmpnzxadd", "cmpbexadd", "cmpnbexadd",
	"cmpsxadd",  "cmpnsxadd", "cmppxadd",  "cmpnpxadd",
	"cmplxadd",  "cmpnlxadd", "cmplexadd", "cmpnlexadd",
};

static bool check_case(csh handle, const uint8_t *code, size_t code_size,
		       unsigned int id, const char *mnemonic,
		       const char *operands, x86_reg base, x86_reg index,
		       uint8_t address_size)
{
	const uint64_t flags = X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			       X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF |
			       X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF;
	cs_insn *instruction = NULL;
	bool ok = cs_disasm(handle, code, code_size, 0, 1, &instruction) == 1;

	if (ok) {
		const cs_detail *detail = instruction->detail;
		const cs_x86 *x86 = &detail->x86;
		const cs_x86_op *memory = NULL;
		bool reads_flags = false;
		bool access_ok;

		for (uint8_t operand = 0; operand < x86->op_count; ++operand) {
			if (x86->operands[operand].type == X86_OP_MEM)
				memory = &x86->operands[operand];
		}
		for (uint8_t reg = 0; reg < detail->regs_read_count; ++reg)
			reads_flags |= detail->regs_read[reg] == X86_REG_EFLAGS;
		access_ok =
			(x86->operands[0].access == CS_AC_READ_WRITE &&
			 x86->operands[1].access == CS_AC_READ_WRITE &&
			 x86->operands[2].access == CS_AC_READ) ||
			(x86->operands[2].access == CS_AC_READ_WRITE &&
			 x86->operands[1].access == CS_AC_READ_WRITE &&
			 x86->operands[0].access == CS_AC_READ);
		ok = instruction->id == id &&
		     strcmp(instruction->mnemonic, mnemonic) == 0 &&
		     strcmp(instruction->op_str, operands) == 0 &&
		     x86->op_count == 3 && x86->addr_size == address_size &&
		     access_ok && memory && memory->mem.segment == X86_REG_FS &&
		     memory->mem.base == base && memory->mem.index == index &&
		     memory->mem.scale == 4 && memory->mem.disp == 0x20 &&
		     x86->eflags == flags && !reads_flags &&
		     detail->regs_write_count == 1 &&
		     detail->regs_write[0] == X86_REG_EFLAGS;
	}
	if (instruction)
		cs_free(instruction, 1);
	return ok;
}

static bool rejects(csh handle, const uint8_t *code, size_t code_size)
{
	cs_insn *instruction = NULL;
	bool ok = cs_disasm(handle, code, code_size, 0, 1, &instruction) == 0;

	if (instruction)
		cs_free(instruction, 1);
	return ok;
}

int main(void)
{
	uint8_t code[] = { 0x64, 0x62, 0x0a, 0x75, 0x00,
			   0xe0, 0x54, 0xb5, 0x20 };
	const uint8_t address32[] = { 0x67, 0x64, 0x62, 0x0a, 0x71,
				      0x00, 0xe0, 0x54, 0xa5, 0x20 };
	csh handle;
	bool ok = true;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	for (unsigned int condition = 0; condition < 16; ++condition) {
		code[5] = (uint8_t)(0xe0 + condition);
		ok &= check_case(handle, code, sizeof(code),
				 X86_INS_CMPOXADD + condition, names[condition],
				 "dword ptr fs:[r29 + r14*4 + 0x20], r26d, r17d",
				 X86_REG_R29, X86_REG_R14, 8);
	}

	code[3] = 0xf5;
	code[5] = 0xe6;
	ok &= check_case(handle, code, sizeof(code), X86_INS_CMPBEXADD,
			 "cmpbexadd",
			 "qword ptr fs:[r29 + r14*4 + 0x20], r26, r17",
			 X86_REG_R29, X86_REG_R14, 8);
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	ok &= check_case(handle, code, sizeof(code), X86_INS_CMPBEXADD,
			 "cmpbexaddq", "%r17, %r26, %fs:0x20(%r29,%r14,4)",
			 X86_REG_R29, X86_REG_R14, 8);
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

	code[3] = 0x71;
	code[5] = 0xe0;
	code[7] = 0xa5;
	ok &= check_case(handle, code, sizeof(code), X86_INS_CMPOXADD, "cmpoxadd",
			 "dword ptr fs:[r29 + r28*4 + 0x20], r26d, r17d",
			 X86_REG_R29, X86_REG_R28, 8);
	ok &= check_case(handle, address32, sizeof(address32), X86_INS_CMPOXADD,
			 "cmpoxadd",
			 "dword ptr fs:[r29d + r28d*4 + 0x20], r26d, r17d",
			 X86_REG_R29D, X86_REG_R28D, 4);

	for (unsigned int kind = 0; kind < 4; ++kind) {
		code[4] = (uint8_t[]){ 4, 0x10, 0x20, 0x80 }[kind];
		ok &= rejects(handle, code, sizeof(code));
	}
	code[4] = 0;
	code[3] = 0xf4;
	ok &= rejects(handle, code, sizeof(code));
	code[3] = 0xf5;
	code[6] = 0xd3;
	ok &= rejects(handle, code, 7);

	cs_close(&handle);
	if (!ok)
		fprintf(stderr, "APX CMPCCXADD failure\n");
	return ok ? 0 : 1;
}

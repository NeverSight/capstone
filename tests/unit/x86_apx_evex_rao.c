#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check_case(csh handle, const uint8_t *code, size_t code_size,
		       unsigned int id, const char *mnemonic,
		       const char *operands, x86_reg base, x86_reg index,
		       uint8_t address_size)
{
	cs_insn *instruction = NULL;
	bool ok = cs_disasm(handle, code, code_size, 0, 1, &instruction) == 1;

	if (ok) {
		const cs_detail *detail = instruction->detail;
		const cs_x86 *x86 = &detail->x86;
		const cs_x86_op *memory = x86->operands[0].type == X86_OP_MEM ?
						 &x86->operands[0] :
						 &x86->operands[1];

		ok = instruction->id == id &&
		     strcmp(instruction->mnemonic, mnemonic) == 0 &&
		     strcmp(instruction->op_str, operands) == 0 &&
		     x86->op_count == 2 && x86->addr_size == address_size &&
		     memory->type == X86_OP_MEM &&
		     memory->access == CS_AC_READ_WRITE &&
		     memory->mem.segment == X86_REG_FS &&
		     memory->mem.base == base && memory->mem.index == index &&
		     memory->mem.scale == 4 && memory->mem.disp == 0x20 &&
		     x86->eflags == 0 && detail->regs_read_count == 0 &&
		     detail->regs_write_count == 0;
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
	const uint8_t pp[] = { 0, 1, 3, 2 };
	const unsigned int ids[] = { X86_INS_AADD, X86_INS_AAND,
				     X86_INS_AOR, X86_INS_AXOR };
	const char *mnemonics[] = { "aadd", "aand", "aor", "axor" };
	uint8_t code[] = { 0x64, 0x62, 0x0c, 0x7c, 0x08,
			   0xfc, 0x54, 0xb5, 0x20 };
	const uint8_t address32[] = { 0x67, 0x64, 0x62, 0x0c, 0x78,
				      0x08, 0xfc, 0x54, 0xa5, 0x20 };
	const uint8_t duplicate_segment[] = { 0x64, 0x65, 0x62, 0x0c, 0x7c,
					      0x08, 0xfc, 0x54, 0xb5, 0x20 };
	const uint8_t duplicate_address[] = { 0x67, 0x67, 0x62, 0x0c, 0x7c,
					      0x08, 0xfc, 0x54, 0xb5, 0x20 };
	csh handle;
	bool ok = true;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	for (unsigned int width = 0; width < 2; ++width) {
		for (unsigned int kind = 0; kind < 4; ++kind) {
			char operands[96];
			code[3] = (uint8_t)(0x7c | (width ? 0x80 : 0) |
					  pp[kind]);
			snprintf(operands, sizeof(operands),
				 "%s ptr fs:[r29 + r14*4 + 0x20], r26%s",
				 width ? "qword" : "dword", width ? "" : "d");
			ok &= check_case(handle, code, sizeof(code), ids[kind],
					 mnemonics[kind], operands, X86_REG_R29,
					 X86_REG_R14, 8);
		}
	}

	code[3] = 0xff;
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	ok &= check_case(handle, code, sizeof(code), X86_INS_AOR, "aorq",
			 "%r26, %fs:0x20(%r29,%r14,4)", X86_REG_R29,
			 X86_REG_R14, 8);
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

	code[3] = 0x78;
	code[7] = 0xa5;
	ok &= check_case(handle, code, sizeof(code), X86_INS_AADD, "aadd",
			 "dword ptr fs:[r29 + r28*4 + 0x20], r26d",
			 X86_REG_R29, X86_REG_R28, 8);
	ok &= check_case(handle, address32, sizeof(address32), X86_INS_AADD,
			 "aadd", "dword ptr fs:[r29d + r28d*4 + 0x20], r26d",
			 X86_REG_R29D, X86_REG_R28D, 4);

	code[7] = 0xb5;
	for (unsigned int kind = 0; kind < 4; ++kind) {
		code[4] = (uint8_t[]){ 0, 4, 0x18, 0x28 }[kind];
		ok &= rejects(handle, code, sizeof(code));
	}
	code[4] = 8;
	code[6] = 0xd3;
	ok &= rejects(handle, code, 7);
	code[6] = 0x54;
	code[3] = 0x74;
	ok &= rejects(handle, code, sizeof(code));
	ok &= rejects(handle, duplicate_segment, sizeof(duplicate_segment));
	ok &= rejects(handle, duplicate_address, sizeof(duplicate_address));

	cs_close(&handle);
	if (!ok)
		fprintf(stderr, "APX RAO failure\n");
	return ok ? 0 : 1;
}

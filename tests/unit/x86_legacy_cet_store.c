#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct cet_store_case {
	const char *name;
	cs_mode mode;
	uint8_t code[15];
	size_t code_size;
	unsigned int instruction_id;
	const char *mnemonic;
	const char *operands;
	uint8_t instruction_size;
	uint8_t address_size;
	uint8_t prefixes[4];
	uint8_t rex;
	uint8_t modrm;
	uint8_t sib;
	uint8_t modrm_offset;
	uint8_t displacement_offset;
	uint8_t displacement_size;
	int64_t displacement;
	x86_reg memory_base;
	x86_reg memory_index;
	int memory_scale;
	x86_reg source;
	uint8_t operand_size;
} cet_store_case;

static bool has_register(const uint16_t *registers, uint8_t count,
			 x86_reg expected)
{
	uint8_t index;

	for (index = 0; index < count; ++index) {
		if (registers[index] == expected)
			return true;
	}
	return false;
}

static bool check_case(const cet_store_case *test)
{
	csh handle;
	cs_insn *instructions = NULL;
	cs_regs registers_read, registers_write;
	uint8_t read_count = 0, write_count = 0;
	const cs_x86 *x86;
	const cs_x86_op *memory, *source;
	size_t count;
	bool success;

	if (cs_open(CS_ARCH_X86, test->mode, &handle) != CS_ERR_OK)
		return false;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, test->code, test->code_size, 0, 1,
			  &instructions);
	success = count == 1;
	if (!success) {
		fprintf(stderr, "%s: instruction did not decode\n", test->name);
		cs_close(&handle);
		return false;
	}

	x86 = &instructions[0].detail->x86;
	memory = &x86->operands[0];
	source = &x86->operands[1];
	success = instructions[0].id == test->instruction_id &&
		  strcmp(instructions[0].mnemonic, test->mnemonic) == 0 &&
		  strcmp(instructions[0].op_str, test->operands) == 0 &&
		  instructions[0].size == test->instruction_size &&
		  memcmp(x86->prefix, test->prefixes, sizeof(test->prefixes)) ==
			  0 &&
		  x86->opcode[0] == 0x0f && x86->opcode[1] == 0x38 &&
		  x86->opcode[2] == test->code[test->modrm_offset - 1] &&
		  x86->opcode[3] == 0 && x86->rex == test->rex &&
		  x86->addr_size == test->address_size &&
		  x86->modrm == test->modrm && x86->sib == test->sib &&
		  x86->sib_base ==
			  (test->sib ? test->memory_base : X86_REG_INVALID) &&
		  x86->sib_index ==
			  (test->sib ? test->memory_index : X86_REG_INVALID) &&
		  x86->sib_scale == (test->sib ? test->memory_scale : 0) &&
		  x86->encoding.modrm_offset == test->modrm_offset &&
		  x86->encoding.disp_offset == test->displacement_offset &&
		  x86->encoding.disp_size == test->displacement_size &&
		  x86->disp == test->displacement && x86->op_count == 2 &&
		  memory->type == X86_OP_MEM &&
		  memory->size == test->operand_size &&
		  memory->access == CS_AC_WRITE &&
		  memory->mem.base == test->memory_base &&
		  memory->mem.index == test->memory_index &&
		  memory->mem.scale == test->memory_scale &&
		  memory->mem.segment == (test->prefixes[1] == 0x64 ?
						  X86_REG_FS :
						  X86_REG_INVALID) &&
		  source->type == X86_OP_REG && source->reg == test->source &&
		  source->size == test->operand_size &&
		  source->access == CS_AC_READ && x86->eflags == 0;

	if (cs_regs_access(handle, &instructions[0], registers_read,
			   &read_count, registers_write,
			   &write_count) != CS_ERR_OK) {
		success = false;
	} else {
		success &=
			write_count == 0 &&
			has_register(registers_read, read_count, test->source);
		if (test->memory_base != X86_REG_INVALID)
			success &= has_register(registers_read, read_count,
						test->memory_base);
		if (test->memory_index != X86_REG_INVALID)
			success &= has_register(registers_read, read_count,
						test->memory_index);
		if (memory->mem.segment != X86_REG_INVALID)
			success &= has_register(registers_read, read_count,
						memory->mem.segment);
	}
	if (!success) {
		fprintf(stderr,
			"%s: got %s %s, size=%u, addr=%u, prefix=%02x/%02x/%02x/%02x, rex=%02x\n",
			test->name, instructions[0].mnemonic,
			instructions[0].op_str, instructions[0].size,
			x86->addr_size, x86->prefix[0], x86->prefix[1],
			x86->prefix[2], x86->prefix[3], x86->rex);
	}
	cs_free(instructions, count);
	cs_close(&handle);
	return success;
}

static bool check_rejected(cs_mode mode, const uint8_t *code, size_t code_size,
			   const char *name)
{
	csh handle;
	cs_insn *instructions = NULL;
	size_t count;

	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
		return false;
	count = cs_disasm(handle, code, code_size, 0, 1, &instructions);
	if (instructions)
		cs_free(instructions, count);
	cs_close(&handle);
	if (count != 0)
		fprintf(stderr, "%s: illegal encoding decoded\n", name);
	return count == 0;
}

static bool check_no_qword_form(cs_mode mode, const uint8_t *code,
				size_t code_size, unsigned int forbidden_id,
				const char *name)
{
	csh handle;
	cs_insn *instructions = NULL;
	size_t count, index;
	bool success = true;

	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
		return false;
	count = cs_disasm(handle, code, code_size, 0, 0, &instructions);
	for (index = 0; index < count; ++index)
		success &= instructions[index].id != forbidden_id;
	if (!success)
		fprintf(stderr, "%s: qword form decoded outside 64-bit mode\n",
			name);
	if (instructions)
		cs_free(instructions, count);
	cs_close(&handle);
	return success;
}

int main(void)
{
	static const cet_store_case cases[] = {
		{
			"wrssd-mode16-addr16",
			CS_MODE_16,
			{ 0x0f, 0x38, 0xf6, 0x40, 0x7f },
			5,
			X86_INS_WRSSD,
			"wrssd",
			"dword ptr [bx + si + 0x7f], eax",
			5,
			2,
			{ 0, 0, 0, 0 },
			0,
			0x40,
			0,
			3,
			4,
			1,
			0x7f,
			X86_REG_BX,
			X86_REG_SI,
			1,
			X86_REG_EAX,
			4,
		},
		{
			"wrssd-mode16-addr32",
			CS_MODE_16,
			{ 0x67, 0x0f, 0x38, 0xf6, 0x40, 0x7f },
			6,
			X86_INS_WRSSD,
			"wrssd",
			"dword ptr [eax + 0x7f], eax",
			6,
			4,
			{ 0, 0, 0, 0x67 },
			0,
			0x40,
			0,
			4,
			5,
			1,
			0x7f,
			X86_REG_EAX,
			X86_REG_INVALID,
			1,
			X86_REG_EAX,
			4,
		},
		{
			"wrussd-mode16-addr16",
			CS_MODE_16,
			{ 0x66, 0x0f, 0x38, 0xf5, 0x40, 0x7f },
			6,
			X86_INS_WRUSSD,
			"wrussd",
			"dword ptr [bx + si + 0x7f], eax",
			6,
			2,
			{ 0, 0, 0x66, 0 },
			0,
			0x40,
			0,
			4,
			5,
			1,
			0x7f,
			X86_REG_BX,
			X86_REG_SI,
			1,
			X86_REG_EAX,
			4,
		},
		{
			"wrussd-mode16-addr32",
			CS_MODE_16,
			{ 0x67, 0x66, 0x0f, 0x38, 0xf5, 0x40, 0x7f },
			7,
			X86_INS_WRUSSD,
			"wrussd",
			"dword ptr [eax + 0x7f], eax",
			7,
			4,
			{ 0, 0, 0x66, 0x67 },
			0,
			0x40,
			0,
			5,
			6,
			1,
			0x7f,
			X86_REG_EAX,
			X86_REG_INVALID,
			1,
			X86_REG_EAX,
			4,
		},
		{
			"wrssd-mode32-addr32",
			CS_MODE_32,
			{ 0x0f, 0x38, 0xf6, 0x40, 0x7f },
			5,
			X86_INS_WRSSD,
			"wrssd",
			"dword ptr [eax + 0x7f], eax",
			5,
			4,
			{ 0, 0, 0, 0 },
			0,
			0x40,
			0,
			3,
			4,
			1,
			0x7f,
			X86_REG_EAX,
			X86_REG_INVALID,
			1,
			X86_REG_EAX,
			4,
		},
		{
			"wrussd-mode32-addr16",
			CS_MODE_32,
			{ 0x67, 0x66, 0x0f, 0x38, 0xf5, 0x40, 0x7f },
			7,
			X86_INS_WRUSSD,
			"wrussd",
			"dword ptr [bx + si + 0x7f], eax",
			7,
			2,
			{ 0, 0, 0x66, 0x67 },
			0,
			0x40,
			0,
			5,
			6,
			1,
			0x7f,
			X86_REG_BX,
			X86_REG_SI,
			1,
			X86_REG_EAX,
			4,
		},
		{
			"wrssd-mode64-fs-detail",
			CS_MODE_64,
			{ 0x64, 0x44, 0x0f, 0x38, 0xf6, 0x4c, 0x88, 0x20 },
			8,
			X86_INS_WRSSD,
			"wrssd",
			"dword ptr fs:[rax + rcx*4 + 0x20], r9d",
			8,
			8,
			{ 0, 0x64, 0, 0 },
			0x44,
			0x4c,
			0x88,
			5,
			7,
			1,
			0x20,
			X86_REG_RAX,
			X86_REG_RCX,
			4,
			X86_REG_R9D,
			4,
		},
		{
			"wrussd-mode64-addr32",
			CS_MODE_64,
			{ 0x67, 0x66, 0x0f, 0x38, 0xf5, 0x40, 0x7f },
			7,
			X86_INS_WRUSSD,
			"wrussd",
			"dword ptr [eax + 0x7f], eax",
			7,
			4,
			{ 0, 0, 0x66, 0x67 },
			0,
			0x40,
			0,
			5,
			6,
			1,
			0x7f,
			X86_REG_EAX,
			X86_REG_INVALID,
			1,
			X86_REG_EAX,
			4,
		},
		{
			"wrssq-mode64",
			CS_MODE_64,
			{ 0x48, 0x0f, 0x38, 0xf6, 0x40, 0x7f },
			6,
			X86_INS_WRSSQ,
			"wrssq",
			"qword ptr [rax + 0x7f], rax",
			6,
			8,
			{ 0, 0, 0, 0 },
			0x48,
			0x40,
			0,
			4,
			5,
			1,
			0x7f,
			X86_REG_RAX,
			X86_REG_INVALID,
			1,
			X86_REG_RAX,
			8,
		},
		{
			"wrussq-mode64-addr32",
			CS_MODE_64,
			{ 0x67, 0x66, 0x48, 0x0f, 0x38, 0xf5, 0x40, 0x7f },
			8,
			X86_INS_WRUSSQ,
			"wrussq",
			"qword ptr [eax + 0x7f], rax",
			8,
			4,
			{ 0, 0, 0x66, 0x67 },
			0x48,
			0x40,
			0,
			6,
			7,
			1,
			0x7f,
			X86_REG_EAX,
			X86_REG_INVALID,
			1,
			X86_REG_RAX,
			8,
		},
	};
	static const uint8_t invalid[][8] = {
		{ 0x0f, 0x38, 0xf6, 0xc0 },
		{ 0x48, 0x0f, 0x38, 0xf6, 0xc0 },
		{ 0x66, 0x0f, 0x38, 0xf5, 0xc0 },
		{ 0x66, 0x48, 0x0f, 0x38, 0xf5, 0xc0 },
		{ 0xf0, 0x0f, 0x38, 0xf6, 0x00 },
		{ 0xf0, 0x48, 0x0f, 0x38, 0xf6, 0x00 },
		{ 0xf0, 0x66, 0x0f, 0x38, 0xf5, 0x00 },
		{ 0xf0, 0x66, 0x48, 0x0f, 0x38, 0xf5, 0x00 },
	};
	static const uint8_t invalid_sizes[] = { 4, 5, 5, 6, 5, 6, 6, 7 };
	static const uint8_t wrssq[] = { 0x48, 0x0f, 0x38, 0xf6, 0x00 };
	static const uint8_t wrussq[] = { 0x66, 0x48, 0x0f, 0x38, 0xf5, 0x00 };
	bool success = true;
	size_t index;

	for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index)
		success &= check_case(&cases[index]);
	for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index)
		success &= check_rejected(CS_MODE_64, invalid[index],
					  invalid_sizes[index],
					  "invalid CET store");
	for (index = 0; index < 2; ++index) {
		cs_mode mode = index == 0 ? CS_MODE_16 : CS_MODE_32;

		success &= check_no_qword_form(mode, wrssq, sizeof(wrssq),
					       X86_INS_WRSSQ,
					       "wrssq mode gate");
		success &= check_no_qword_form(mode, wrussq, sizeof(wrussq),
					       X86_INS_WRUSSQ,
					       "wrussq mode gate");
	}
	return success ? 0 : 1;
}

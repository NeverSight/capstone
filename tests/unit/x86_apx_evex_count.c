#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct count_form {
	x86_insn id;
	uint8_t opcode;
	const char *mnemonic;
} count_form;

typedef struct width_form {
	uint8_t size;
	uint8_t p1;
	x86_reg destination;
	x86_reg source;
} width_form;

static const count_form count_forms[] = {
	{ X86_INS_LZCNT, 0xf5, "lzcnt" },
	{ X86_INS_TZCNT, 0xf4, "tzcnt" },
	{ X86_INS_POPCNT, 0x88, "popcnt" },
};

static const width_form width_forms[] = {
	{ 2, 0x7d, X86_REG_R18W, X86_REG_R19W },
	{ 4, 0x7c, X86_REG_R18D, X86_REG_R19D },
	{ 8, 0xfc, X86_REG_R18, X86_REG_R19 },
};

static uint64_t expected_flags(x86_insn id)
{
	if (id == X86_INS_POPCNT) {
		return X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_SF |
		       X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_RESET_AF |
		       X86_EFLAGS_RESET_PF | X86_EFLAGS_RESET_CF;
	}
	return X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF |
	       X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
	       X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF;
}

static bool rejects(csh handle, const uint8_t *code, size_t size)
{
	cs_insn *instruction = NULL;
	size_t count = cs_disasm(handle, code, size, 0, 1, &instruction);

	if (count != 0)
		cs_free(instruction, count);
	return count == 0;
}

static bool check_register_matrix(csh handle)
{
	cs_insn *instruction = NULL;
	bool ok = true;
	unsigned int form_index, width_index, nf;

	for (form_index = 0;
	     form_index < sizeof(count_forms) / sizeof(count_forms[0]);
	     ++form_index) {
		for (width_index = 0;
		     width_index < sizeof(width_forms) / sizeof(width_forms[0]);
		     ++width_index) {
			for (nf = 0; nf < 2; ++nf) {
				const count_form *form = &count_forms[form_index];
				const width_form *width = &width_forms[width_index];
				uint8_t code[] = {
					0x62, 0xec, width->p1,
					(uint8_t)(0x08 | (nf ? 0x04 : 0)),
					form->opcode, 0xd3,
				};
				const size_t count =
					cs_disasm(handle, code, sizeof(code), 0, 1,
						  &instruction);

				if (count != 1) {
					ok = false;
					continue;
				}
				const cs_detail *detail = instruction[0].detail;
				const cs_x86 *x86 = &detail->x86;
				ok &= instruction[0].id == form->id &&
				      (nf || strcmp(instruction[0].mnemonic,
						    form->mnemonic) == 0) &&
				      x86->op_count == 2 &&
				      x86->operands[0].type == X86_OP_REG &&
				      x86->operands[0].reg == width->destination &&
				      x86->operands[0].size == width->size &&
				      x86->operands[0].access == CS_AC_WRITE &&
				      x86->operands[1].type == X86_OP_REG &&
				      x86->operands[1].reg == width->source &&
				      x86->operands[1].size == width->size &&
				      x86->operands[1].access == CS_AC_READ &&
				      x86->eflags ==
					      (nf ? 0 : expected_flags(form->id)) &&
				      detail->regs_read_count == 0 &&
				      detail->regs_write_count == (nf ? 0 : 1) &&
				      (nf || detail->regs_write[0] == X86_REG_EFLAGS);
				cs_free(instruction, count);
				instruction = NULL;
			}
		}
	}
	return ok;
}

static bool check_reserved_register_bits(csh handle)
{
	bool ok = true;
	unsigned int form_index;

	for (form_index = 0;
	     form_index < sizeof(count_forms) / sizeof(count_forms[0]);
	     ++form_index) {
		const uint8_t opcode = count_forms[form_index].opcode;
		const uint8_t bad_vvvv[] = { 0x62, 0xec, 0xf4, 0x08, opcode, 0xd3 };
		const uint8_t bad_v4[] = { 0x62, 0xec, 0xfc, 0x00, opcode, 0xd3 };
		const uint8_t bad_register_u[] = { 0x62, 0xec, 0xf8,
						     0x08, opcode, 0xd3 };
		const uint8_t bad_nd[] = { 0x62, 0xec, 0xfc, 0x18, opcode, 0xd3 };

		ok &= rejects(handle, bad_vvvv, sizeof(bad_vvvv));
		ok &= rejects(handle, bad_v4, sizeof(bad_v4));
		ok &= rejects(handle, bad_register_u, sizeof(bad_register_u));
		ok &= rejects(handle, bad_nd, sizeof(bad_nd));
	}
	return ok;
}

static bool check_memory_x4(csh handle)
{
	static const struct {
		bool address32;
		bool x4;
		bool nf;
		x86_reg base;
		x86_reg index;
	} cases[] = {
		{ false, true, false, X86_REG_R29, X86_REG_R28 },
		{ false, false, true, X86_REG_R29, X86_REG_R12 },
		{ true, true, true, X86_REG_R29D, X86_REG_R28D },
		{ true, false, false, X86_REG_R29D, X86_REG_R12D },
	};
	cs_insn *instruction = NULL;
	bool ok = true;
	unsigned int case_index, form_index;

	for (case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]);
	     ++case_index) {
		for (form_index = 0;
		     form_index < sizeof(count_forms) / sizeof(count_forms[0]);
		     ++form_index) {
			uint8_t code[] = {
				0x67, 0x64, 0x62, 0x8c,
				(uint8_t)(cases[case_index].x4 ? 0xf8 : 0xfc),
				(uint8_t)(0x08 | (cases[case_index].nf ? 0x04 : 0)),
				count_forms[form_index].opcode, 0x54, 0xa5, 0x20,
			};
			const uint8_t *begin = cases[case_index].address32 ? code : code + 1;
			const size_t code_size = sizeof(code) - (begin - code);
			const size_t count = cs_disasm(handle, begin, code_size, 0, 1,
						       &instruction);

			if (count != 1) {
				ok = false;
				continue;
			}
			const cs_detail *detail = instruction[0].detail;
			const cs_x86 *x86 = &detail->x86;
			const cs_x86_op *memory = &x86->operands[1];
			ok &= instruction[0].id == count_forms[form_index].id &&
			      x86->op_count == 2 &&
			      x86->operands[0].reg == X86_REG_R18 &&
			      x86->operands[0].size == 8 &&
			      x86->operands[0].access == CS_AC_WRITE &&
			      memory->type == X86_OP_MEM && memory->size == 8 &&
			      memory->access == CS_AC_READ &&
			      memory->mem.segment == X86_REG_FS &&
			      memory->mem.base == cases[case_index].base &&
			      memory->mem.index == cases[case_index].index &&
			      memory->mem.scale == 4 && memory->mem.disp == 0x20 &&
			      x86->addr_size == (cases[case_index].address32 ? 4 : 8) &&
			      x86->eflags ==
				      (cases[case_index].nf ?
					       0 :
					       expected_flags(count_forms[form_index].id)) &&
			      detail->regs_read_count == 0 &&
			      detail->regs_write_count ==
				      (cases[case_index].nf ? 0 : 1) &&
			      (cases[case_index].nf ||
			       detail->regs_write[0] == X86_REG_EFLAGS);
			cs_free(instruction, count);
			instruction = NULL;
		}
	}
	return ok;
}

static bool check_16_bit_text_and_size(csh handle)
{
	cs_insn *instruction = NULL;
	bool ok = true;
	unsigned int form_index;

	for (form_index = 0;
	     form_index < sizeof(count_forms) / sizeof(count_forms[0]);
	     ++form_index) {
		const count_form *form = &count_forms[form_index];
		uint8_t reg[] = { 0x62, 0xec, 0x7d, 0x08, form->opcode, 0xd3 };
		uint8_t memory[] = { 0x64, 0x62, 0x8c, 0x79, 0x08,
				     form->opcode, 0x54, 0xa5, 0x20 };
		char att_mnemonic[16];
		size_t count;

		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
		count = cs_disasm(handle, reg, sizeof(reg), 0, 1, &instruction);
		if (count != 1) {
			ok = false;
		} else {
			const cs_x86 *x86 = &instruction[0].detail->x86;
			ok &= strcmp(instruction[0].mnemonic, form->mnemonic) == 0 &&
			      strcmp(instruction[0].op_str, "r18w, r19w") == 0 &&
			      x86->operands[0].size == 2 &&
			      x86->operands[1].size == 2;
			cs_free(instruction, count);
			instruction = NULL;
		}
		count = cs_disasm(handle, memory, sizeof(memory), 0, 1,
				  &instruction);
		if (count != 1) {
			ok = false;
		} else {
			const cs_x86 *x86 = &instruction[0].detail->x86;
			ok &= strcmp(instruction[0].mnemonic, form->mnemonic) == 0 &&
			      strcmp(instruction[0].op_str,
				     "r18w, word ptr fs:[r29 + r28*4 + 0x20]") ==
				      0 &&
			      x86->operands[0].size == 2 &&
			      x86->operands[1].size == 2;
			cs_free(instruction, count);
			instruction = NULL;
		}

		snprintf(att_mnemonic, sizeof(att_mnemonic), "%sw",
			 form->mnemonic);
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		count = cs_disasm(handle, reg, sizeof(reg), 0, 1, &instruction);
		if (count != 1) {
			ok = false;
		} else {
			const cs_x86 *x86 = &instruction[0].detail->x86;
			ok &= strcmp(instruction[0].mnemonic, att_mnemonic) == 0 &&
			      strcmp(instruction[0].op_str, "%r19w, %r18w") == 0 &&
			      x86->operands[0].size == 2 &&
			      x86->operands[1].size == 2;
			cs_free(instruction, count);
			instruction = NULL;
		}
		count = cs_disasm(handle, memory, sizeof(memory), 0, 1,
				  &instruction);
		if (count != 1) {
			ok = false;
		} else {
			const cs_x86 *x86 = &instruction[0].detail->x86;
			ok &= strcmp(instruction[0].mnemonic, att_mnemonic) == 0 &&
			      strcmp(instruction[0].op_str,
				     "%fs:0x20(%r29,%r28,4), %r18w") == 0 &&
			      x86->operands[0].size == 2 &&
			      x86->operands[1].size == 2;
			cs_free(instruction, count);
			instruction = NULL;
		}
	}
	return ok;
}

int main(void)
{
	csh handle;
	bool ok;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	ok = check_register_matrix(handle);
	ok &= check_reserved_register_bits(handle);
	ok &= check_memory_x4(handle);
	ok &= check_16_bit_text_and_size(handle);
	cs_close(&handle);
	if (!ok)
		fprintf(stderr, "APX count failure\n");
	return ok ? 0 : 1;
}

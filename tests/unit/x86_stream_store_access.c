/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>

static bool contains(const cs_regs registers, uint8_t count, x86_reg reg)
{
	for (uint8_t i = 0; i < count; ++i)
		if (registers[i] == reg)
			return true;
	return false;
}

static bool check(csh handle, const uint8_t *code, size_t length, bool att,
		  bool iterator, bool text, x86_reg source)
{
	cs_insn *insn = iterator ? cs_malloc(handle) : NULL;
	const uint8_t *cursor = code;
	size_t remaining = length;
	uint64_t address = 0x1000;
	bool decoded = iterator ? cs_disasm_iter(handle, &cursor, &remaining,
						 &address, insn) :
				  cs_disasm(handle, code, length, address, 1,
					    &insn) == 1;
	if (!decoded) {
		fprintf(stderr, "stream store did not decode\n");
		if (insn)
			cs_free(insn, 1);
		return false;
	}
	const cs_x86 *x = &insn->detail->x86;
	if (!text) {
		bool good = insn->id == X86_INS_MOVNTDQ &&
			    insn->size == length && !x->op_count &&
			    !insn->mnemonic[0] && !insn->op_str[0];
		cs_free(insn, 1);
		return good;
	}
	const cs_x86_op *memory = &x->operands[att ? 1 : 0];
	const cs_x86_op *value = &x->operands[att ? 0 : 1];
	cs_regs reads = { 0 }, writes = { 0 };
	uint8_t read_count = 0, write_count = 0;
	bool good = insn->id == X86_INS_MOVNTDQ && insn->size == length &&
		    x->op_count == 2 && !x->eflags &&
		    memory->type == X86_OP_MEM && memory->size == 16 &&
		    memory->access == CS_AC_WRITE &&
		    value->type == X86_OP_REG && value->reg == source &&
		    value->size == 16 && value->access == CS_AC_READ &&
		    cs_regs_access(handle, insn, reads, &read_count, writes,
				   &write_count) == CS_ERR_OK &&
		    write_count == 0 && contains(reads, read_count, source);
	if (memory->mem.base != X86_REG_INVALID)
		good &= contains(reads, read_count, memory->mem.base);
	if (memory->mem.index != X86_REG_INVALID)
		good &= contains(reads, read_count, memory->mem.index);
	if (iterator)
		good &= cursor == code + length && !remaining &&
			address == 0x1000 + length;
	if (!good)
		fprintf(stderr,
			"MOVNTDQ access mismatch: att=%u iterator=%u memory=%u value=%u writes=%u\n",
			att, iterator, memory->access, value->access,
			write_count);
	cs_free(insn, 1);
	return good;
}

int main(void)
{
	const cs_mode modes[] = { CS_MODE_32, CS_MODE_64 };
	const uint8_t plain[] = { 0x66, 0x0f, 0xe7, 0x00 };
	const uint8_t address[] = { 0x67, 0x66, 0x0f, 0xe7, 0x00 };
	const uint8_t extended[] = { 0x66, 0x45, 0x0f, 0xe7, 0x6c, 0x24, 0x10 };
	bool good = true;
	for (size_t mode = 0; mode < sizeof(modes) / sizeof(modes[0]); ++mode) {
		csh handle;
		if (cs_open(CS_ARCH_X86, modes[mode], &handle) != CS_ERR_OK)
			return 1;
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		for (unsigned att = 0; att != 2; ++att) {
			cs_option(handle, CS_OPT_SYNTAX,
				  att ? CS_OPT_SYNTAX_ATT :
					CS_OPT_SYNTAX_INTEL);
			for (unsigned text = 0; text != 2; ++text) {
				cs_option(handle, CS_OPT_TEXT,
					  text ? CS_OPT_ON : CS_OPT_OFF);
				for (unsigned iter = 0; iter != 2; ++iter) {
					good &= check(handle, plain,
						      sizeof(plain), att, iter,
						      text, X86_REG_XMM0);
					good &= check(handle, address,
						      sizeof(address), att,
						      iter, text, X86_REG_XMM0);
					if (modes[mode] == CS_MODE_64)
						good &= check(handle, extended,
							      sizeof(extended),
							      att, iter, text,
							      X86_REG_XMM13);
				}
			}
		}
		cs_close(&handle);
	}
	return !good;
}

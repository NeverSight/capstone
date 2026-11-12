/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_SIMPLE_OUTPUT_H
#define CS_X86_SIMPLE_OUTPUT_H

#include <stddef.h>
#include <string.h>
#include <capstone/capstone.h>

/* The generated records describe the same register operands and implicit
 * effects as the ordinary Intel printer. Only the public x86 prefix of the
 * detail allocation belongs to this decoder. */
struct X86SimpleOperand {
	uint16_t reg;
	uint8_t size;
	uint8_t access;
};

struct X86SimpleOutput {
	unsigned int id;
	char mnemonic[12];
	char operands[20];
	uint64_t flags;
	uint16_t reads[4];
	uint16_t writes[4];
	uint8_t groups[4];
	uint8_t read_count, write_count, group_count, operand_count;
	uint8_t address_size, modrm_offset;
	struct X86SimpleOperand ops[2];
};

struct X86SimpleRegister {
	uint16_t reg;
	uint8_t length;
	char name[8];
};

enum X86SimpleForm {
	X86_SIMPLE_FIXED,
	X86_SIMPLE_RM_REG,
	X86_SIMPLE_REG_RM,
};

static inline void X86_writeSimpleDetail(cs_detail *detail,
					 const struct X86SimpleOutput *row,
					 uint8_t opcode, uint8_t rex,
					 uint8_t modrm, uint16_t first,
					 uint16_t second)
{
	memset(detail, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
	memcpy(detail->regs_read, row->reads, sizeof(row->reads));
	memcpy(detail->regs_write, row->writes, sizeof(row->writes));
	memcpy(detail->groups, row->groups, sizeof(row->groups));
	detail->regs_read_count = row->read_count;
	detail->regs_write_count = row->write_count;
	detail->groups_count = row->group_count;
	cs_x86 *x86 = &detail->x86;
	x86->addr_size = row->address_size;
	x86->opcode[0] = opcode;
	x86->eflags = row->flags;
	x86->rex = rex;
	x86->modrm = modrm;
	x86->encoding.modrm_offset = row->modrm_offset;
	x86->op_count = row->operand_count;
	for (unsigned i = 0; i < x86->op_count; ++i) {
		cs_x86_op *op = &x86->operands[i];
		op->type = X86_OP_REG;
		op->reg = (x86_reg)(i ? second : first);
		op->size = row->ops[i].size;
		op->access = (cs_ac_type)row->ops[i].access;
	}
}

#endif

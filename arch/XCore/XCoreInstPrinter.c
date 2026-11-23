//===-- XCoreInstPrinter.cpp - Convert XCore MCInst to assembly syntax --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an XCore MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_XCORE

#include <stdio.h>
#include <string.h>
#include <capstone/platform.h>

#include "XCoreInstPrinter.h"
#include "../../MCInst.h"
#include "../../utils.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "XCoreMapping.h"

static const char *getRegisterName(unsigned RegNo);

static void set_mem_access(MCInst *MI, bool status, int reg)
{
	if (!MI->csh->detail_opt)
		return;

	cs_xcore *detail = &MI->flat_insn->detail->xcore;
	if (!status) {
		if (MI->csh->doing_mem) {
			if (reg)
				detail->operands[detail->op_count].mem.index = (uint8_t)reg;
			++detail->op_count;
			MI->csh->doing_mem = false;
		}
		return;
	}

	int direction = 1;
	if (reg == 0xffff || reg == -0xffff) {
		/* A register printed before '[' becomes the base of this operand. */
		cs_xcore_op *previous = &detail->operands[--detail->op_count];
		direction = reg > 0 ? 1 : -1;
		reg = previous->reg;
		memset(previous, 0, sizeof(*previous));
	}
	cs_xcore_op *op = &detail->operands[detail->op_count];
	op->type = XCORE_OP_MEM;
	op->mem.base = (uint8_t)reg;
	op->mem.index = XCORE_REG_INVALID;
	op->mem.disp = 0;
	op->mem.direct = direction;
	MI->csh->doing_mem = true;
}

static void add_literal_register(MCInst *MI, xcore_reg reg)
{
	cs_xcore *detail = &MI->flat_insn->detail->xcore;
	cs_xcore_op *op = &detail->operands[detail->op_count++];
	op->type = XCORE_OP_REG;
	op->reg = reg;
}

enum XCoreLiteralKind {
	XCORE_LITERAL_REGISTERS,
	XCORE_LITERAL_OPEN_MEMORY,
	XCORE_LITERAL_FIXED_MEMORY,
};

struct XCoreLiteralOperands {
	uint8_t kind;
	uint8_t first;
	uint8_t second;
	uint8_t displacement;
};

#include "XCoreGenLiteralOperands.inc"

/* An open memory operand receives its remaining fields from printOperand. */
static void add_literal_operands(MCInst *MI, unsigned int opcode)
{
	const uint8_t index = xcore_literal_index[opcode];
	if (!index)
		return;
	const struct XCoreLiteralOperands *literal = &xcore_literal_operands[index];
	if (literal->first)
		add_literal_register(MI, literal->first);
	if (literal->kind == XCORE_LITERAL_REGISTERS) {
		if (literal->second)
			add_literal_register(MI, literal->second);
		return;
	}
	set_mem_access(MI, true, literal->second);
	if (literal->kind == XCORE_LITERAL_FIXED_MEMORY) {
		cs_xcore *detail = &MI->flat_insn->detail->xcore;
		detail->operands[detail->op_count].mem.disp = literal->displacement;
		set_mem_access(MI, false, 0);
	}
}

static void _printOperand(MCInst *MI, MCOperand *MO, SStream *O)
{
	if (MCOperand_isReg(MO)) {
		unsigned reg;

		reg = MCOperand_getReg(MO);
		SStream_concat0(O, getRegisterName(reg));

		if (MI->csh->detail_opt) {
			if (MI->csh->doing_mem) {
				if (MI->flat_insn->detail->xcore
					    .operands[MI->flat_insn->detail
							      ->xcore.op_count]
					    .mem.base == XCORE_REG_INVALID)
					MI->flat_insn->detail->xcore
						.operands[MI->flat_insn->detail
								  ->xcore
								  .op_count]
						.mem.base = (uint8_t)reg;
				else
					MI->flat_insn->detail->xcore
						.operands[MI->flat_insn->detail
								  ->xcore
								  .op_count]
						.mem.index = (uint8_t)reg;
			} else {
				MI->flat_insn->detail->xcore
					.operands[MI->flat_insn->detail->xcore
							  .op_count]
					.type = XCORE_OP_REG;
				MI->flat_insn->detail->xcore
					.operands[MI->flat_insn->detail->xcore
							  .op_count]
					.reg = reg;
				MI->flat_insn->detail->xcore.op_count++;
			}
		}
	} else if (MCOperand_isImm(MO)) {
		int32_t Imm = (int32_t)MCOperand_getImm(MO);

		printInt32(O, Imm);

		if (MI->csh->detail_opt) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->xcore
					.operands[MI->flat_insn->detail->xcore
							  .op_count]
					.mem.disp = Imm;
			} else {
				MI->flat_insn->detail->xcore
					.operands[MI->flat_insn->detail->xcore
							  .op_count]
					.type = XCORE_OP_IMM;
				MI->flat_insn->detail->xcore
					.operands[MI->flat_insn->detail->xcore
							  .op_count]
					.imm = Imm;
				MI->flat_insn->detail->xcore.op_count++;
			}
		}
	}
}

static void printOperand(MCInst *MI, int OpNum, SStream *O)
{
	if (OpNum >= MI->size)
		return;

	_printOperand(MI, MCInst_getOperand(MI, OpNum), O);
}

static void printInlineJT(MCInst *MI, int OpNum, SStream *O)
{
}

static void printInlineJT32(MCInst *MI, int OpNum, SStream *O)
{
}

#define PRINT_ALIAS_INSTR
#include "XCoreGenAsmWriter.inc"

void XCore_printInst(MCInst *MI, SStream *O, void *Info)
{
	printInstruction(MI, O, Info);
	/* Literal instructions already supplied their complete operand list. */
	MI->csh->doing_mem = false;
}

#endif

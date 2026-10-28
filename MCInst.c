/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#include <libkern/libkern.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif
#include <string.h>
#include <assert.h>

#include "MCInstrDesc.h"
#define CS_MCINST_DEFINE_INLINE
#include "MCInst.h"
#undef CS_MCINST_DEFINE_INLINE
#include "utils.h"

#define MCINST_CACHE (ARR_SIZE(mcInst->Operands) - 1)

void MCInst_Init(MCInst *inst, cs_arch arch)
{
	MCInst_InitStorage(inst, arch, true);
}

// does not free @Op
void MCInst_insert0(MCInst *inst, int index, MCOperand *Op)
{
	CS_ASSERT_RET(index < MAX_MC_OPS && inst->size < MAX_MC_OPS);
	int i;

	for (i = inst->size; i > index; i--)
		//memcpy(&(inst->Operands[i]), &(inst->Operands[i-1]), sizeof(MCOperand));
		inst->Operands[i] = inst->Operands[i - 1];

	inst->Operands[index] = *Op;
	inst->size++;
}

// This addOperand2 function doesn't free Op
void MCInst_addOperand2(MCInst *inst, MCOperand *Op)
{
	CS_ASSERT_RET(inst->size < MAX_MC_OPS);
	inst->Operands[inst->size] = *Op;

	inst->size++;
}

bool MCOperand_isValid(const MCOperand *op)
{
	return op->Kind != kInvalid;
}

bool MCOperand_isReg(const MCOperand *op)
{
	return op->Kind == kRegister || op->MachineOperandType == kRegister;
}

bool MCOperand_isImm(const MCOperand *op)
{
	return op->Kind == kImmediate || op->MachineOperandType == kImmediate;
}

bool MCOperand_isFPImm(const MCOperand *op)
{
	return op->Kind == kFPImmediate;
}

bool MCOperand_isDFPImm(const MCOperand *op)
{
	return op->Kind == kDFPImmediate;
}

bool MCOperand_isExpr(const MCOperand *op)
{
	return op->Kind == kExpr;
}

bool MCOperand_isInst(const MCOperand *op)
{
	return op->Kind == kInst;
}

MCOperand *MCOperand_CreateReg1(MCInst *mcInst, unsigned Reg)
{
	MCOperand *op = &(mcInst->Operands[MCINST_CACHE]);

	op->MachineOperandType = kRegister;
	op->Kind = kRegister;
	op->RegVal = Reg;

	return op;
}

MCOperand *MCOperand_CreateImm1(MCInst *mcInst, int64_t Val)
{
	MCOperand *op = &(mcInst->Operands[MCINST_CACHE]);

	op->MachineOperandType = kImmediate;
	op->Kind = kImmediate;
	op->ImmVal = Val;

	return op;
}

/// Check if any operand of the MCInstrDesc is predicable
bool MCInst_isPredicable(const MCInstrDesc *MIDesc)
{
	const MCOperandInfo *OpInfo = MIDesc->OpInfo;
	unsigned NumOps = MIDesc->NumOperands;
	for (unsigned i = 0; i < NumOps; ++i) {
		if (MCOperandInfo_isPredicate(&OpInfo[i])) {
			return true;
		}
	}
	return false;
}

/// Checks if tied operands exist in the instruction and sets
/// - The writeback flag in detail
/// - Saves the indices of the tied destination operands.
void MCInst_handleWriteback(MCInst *MI, const MCInstrDesc *InstDescTable,
			    unsigned tbl_size)
{
	const MCInstrDesc *InstDesc = NULL;
	const MCOperandInfo *OpInfo = NULL;
	unsigned short NumOps = 0;
	InstDesc =
		MCInstrDesc_get(MCInst_getOpcode(MI), InstDescTable, tbl_size);
	OpInfo = InstDesc->OpInfo;
	NumOps = InstDesc->NumOperands;

	for (unsigned i = 0; i < NumOps; ++i) {
		if (MCOperandInfo_isTiedToOp(&OpInfo[i])) {
			int idx = MCOperandInfo_getOperandConstraint(
				InstDesc, i, MCOI_TIED_TO);

			if (idx == -1)
				continue;

			if (i >= MAX_MC_OPS) {
				assert(0 &&
				       "Maximum number of MC operands reached.");
			}
			MI->tied_op_idx[i] = idx;
			if (i >= MI->tied_op_idx_size)
				MI->tied_op_idx_size = i + 1;

			if (MI->flat_insn->detail)
				MI->flat_insn->detail->writeback = true;
		}
	}
}

/// Check if operand with OpNum is tied by another operand
/// (operand is tying destination).
bool MCInst_opIsTied(const MCInst *MI, unsigned OpNum)
{
	assert(OpNum < MAX_MC_OPS && "Maximum number of MC operands exceeded.");
	for (unsigned i = 0; i < MI->tied_op_idx_size; ++i) {
		if (MI->tied_op_idx[i] == OpNum)
			return true;
	}
	return false;
}

/// Check if operand with OpNum is tying another operand
/// (operand is tying src).
bool MCInst_opIsTying(const MCInst *MI, unsigned OpNum)
{
	assert(OpNum < MAX_MC_OPS && "Maximum number of MC operands exceeded.");
	return MI->tied_op_idx[OpNum] != -1;
}

/// Returns the value of the @MCInst operand at index @OpNum.
uint64_t MCInst_getOpVal(MCInst *MI, unsigned OpNum)
{
	assert(OpNum < MAX_MC_OPS);
	MCOperand *op = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isReg(op))
		return MCOperand_getReg(op);
	else if (MCOperand_isImm(op))
		return MCOperand_getImm(op);
	else
		assert(0 && "Operand type not handled in this getter.");
	return MCOperand_getImm(op);
}

void MCInst_setIsAlias(MCInst *MI, bool Flag)
{
	assert(MI);
	MI->isAliasInstr = Flag;
	MI->flat_insn->is_alias = Flag;
}

/// @brief Copies the relevant members of a temporary MCInst to
/// the main MCInst. This is used if TryDecode was run on a temporary MCInst.
/// @param MI The main MCInst
/// @param TmpMI The temporary MCInst.
void MCInst_updateWithTmpMI(MCInst *MI, MCInst *TmpMI)
{
	MI->size = TmpMI->size;
	MI->Opcode = TmpMI->Opcode;
	assert(MI->size < MAX_MC_OPS);
	memcpy(MI->Operands, TmpMI->Operands,
	       sizeof(MI->Operands[0]) * MI->size);
}

/// @brief Sets the softfail/illegal flag in the cs_insn.
/// Setting it indicates the instruction can be decoded, but is invalid
/// due to not allowed operands or an illegal context.
///
/// @param MI The MCInst holding the cs_insn currently decoded.
void MCInst_setSoftFail(MCInst *MI)
{
	assert(MI && MI->flat_insn);
	MI->flat_insn->illegal = true;
}

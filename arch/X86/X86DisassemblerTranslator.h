/*===-- X86DisassemblerTranslator.h - X86 operand translation ------*- C -*-===*
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_X86_DISASSEMBLER_TRANSLATOR_H
#define CS_X86_DISASSEMBLER_TRANSLATOR_H

#include "../../MCInst.h"
#include "X86DisassemblerDecoder.h"
#include "X86FeatureExtension.h"

#define GET_REGINFO_ENUM
#include "X86GenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenInstrInfo_reduce.inc"
#else
#include "X86GenInstrInfo.inc"
#endif

// Fill-ins to make the compiler happy.  These constants are never actually
//   assigned; they are just filler to make an automatically-generated switch
//   statement work.
enum {
	X86_BX_SI = 500,
	X86_BX_DI = 501,
	X86_BP_SI = 502,
	X86_BP_DI = 503,
	X86_sib = 504,
	X86_sib64 = 505
};

//
// Private code that translates from struct InternalInstructions to MCInsts.
//

#if defined(_MSC_VER)
#define X86_TRANSLATE_INLINE static __forceinline
#elif defined(__GNUC__)
#define X86_TRANSLATE_INLINE static inline __attribute__((always_inline))
#else
#define X86_TRANSLATE_INLINE static inline
#endif

/* Suppress stores only: validation and opcode selection run in both modes. */
X86_TRANSLATE_INLINE void createRegisterOperand(MCInst *mcInst, unsigned reg,
						bool emitOperands)
{
	if (emitOperands)
		MCOperand_CreateReg0(mcInst, reg);
}

X86_TRANSLATE_INLINE void createImmediateOperand(MCInst *mcInst, int64_t value,
						 bool emitOperands)
{
	if (emitOperands)
		MCOperand_CreateImm0(mcInst, value);
}

/// translateRegister - Translates an internal register to the appropriate LLVM
///   register, and appends it as an operand to an MCInst.
///
/// @param mcInst     - The MCInst to append to.
/// @param reg        - The Reg to append.
X86_TRANSLATE_INLINE void translateRegister(MCInst *mcInst, Reg reg,
					    bool emitOperands)
{
#define ENTRY(x) X86_##x,
	static const uint16_t llvmRegnums[] = { ALL_REGS 0 };
#undef ENTRY

	uint16_t llvmRegnum = llvmRegnums[reg];
	createRegisterOperand(mcInst, llvmRegnum, emitOperands);
}

X86_TRANSLATE_INLINE uint8_t gprOperandWidth(const InternalInstruction *insn,
					     OperandType type)
{
	switch (type) {
	default:
		return 0;
	case TYPE_R8:
		return 1;
	case TYPE_R16:
		return 2;
	case TYPE_R32:
		return 4;
	case TYPE_R64:
		return 8;
	case TYPE_Rv:
		return insn->registerSize;
	}
}

X86_TRANSLATE_INLINE bool appendFeatureGpr(MCInst *mcInst, unsigned int number,
					   uint8_t width, bool emitOperands)
{
	const unsigned int reg = X86_featureExtensionMCGPR(number, width);

	if (reg == 0)
		return true;
	createRegisterOperand(mcInst, reg, emitOperands);
	return false;
}

static bool rex2ControlRegisterIsValid(unsigned int number)
{
	return number == 0 || number == 2 || number == 3 || number == 4 ||
	       number == 8;
}

static bool rex2DebugRegisterIsValid(unsigned int number)
{
	/* DR4/DR5 retain their architectural alias/CR4.DE behavior. */
	return number <= 7;
}

X86_TRANSLATE_INLINE bool translateRegRegister(MCInst *mcInst,
					       const OperandSpecifier *operand,
					       InternalInstruction *insn,
					       bool emitOperands)
{
	const OperandType type = (OperandType)operand->type;
	unsigned int number;

	if (insn->hasRex2) {
		const uint8_t width = gprOperandWidth(insn, type);
		/* Segment-register selectors remain three bits wide.  Both R4 and
		 * R3 are architecturally ignored for this operand class.  The
		 * generated fixup has already normalized insn->reg to those three
		 * raw ModR/M bits. */
		if (type == TYPE_SEGMENTREG) {
			translateRegister(mcInst, insn->reg, emitOperands);
			return false;
		}
		number = (r4FromREX2(insn->rex2Prefix) << 4) |
			 (r3FromREX2(insn->rex2Prefix) << 3) |
			 regFromModRM(insn->orgModRM);

		if (type == TYPE_CONTROLREG &&
		    !rex2ControlRegisterIsValid(number))
			return true;
		if (type == TYPE_DEBUGREG && !rex2DebugRegisterIsValid(number))
			return true;
		if (width != 0 && r4FromREX2(insn->rex2Prefix))
			return appendFeatureGpr(mcInst, number, width,
						emitOperands);
	}
	translateRegister(mcInst, insn->reg, emitOperands);
	return false;
}

X86_TRANSLATE_INLINE bool
translateOpcodeRegister(MCInst *mcInst, const OperandSpecifier *operand,
			InternalInstruction *insn, bool emitOperands)
{
	if (!insn->hasRex2 || !b4FromREX2(insn->rex2Prefix)) {
		translateRegister(mcInst, insn->opcodeRegister, emitOperands);
		return false;
	}

	uint8_t width = gprOperandWidth(insn, (OperandType)operand->type);

	if (width == 0) {
		switch ((OperandEncoding)operand->encoding) {
		default:
			break;
		case ENCODING_RB:
			width = 1;
			break;
		case ENCODING_RW:
			width = 2;
			break;
		case ENCODING_RD:
			width = 4;
			break;
		case ENCODING_RO:
			width = 8;
			break;
		case ENCODING_Rv:
			width = insn->registerSize;
			break;
		}
	}
	if (width != 0) {
		const unsigned int number =
			16 | (b3FromREX2(insn->rex2Prefix) << 3) |
			(insn->opcode & 7);

		return appendFeatureGpr(mcInst, number, width, emitOperands);
	}
	translateRegister(mcInst, insn->opcodeRegister, emitOperands);
	return false;
}

static const uint8_t segmentRegnums[SEG_OVERRIDE_max] = {
	0, // SEG_OVERRIDE_NONE
	X86_CS, X86_SS, X86_DS, X86_ES, X86_FS, X86_GS
};

/// translateSrcIndex   - Appends a source index operand to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The internal instruction.
static bool translateSrcIndex(MCInst *mcInst, InternalInstruction *insn,
			      bool emitOperands)
{
	unsigned baseRegNo;

	if (insn->mode == MODE_64BIT)
		baseRegNo = insn->hasAdSize ? X86_ESI : X86_RSI;
	else if (insn->mode == MODE_32BIT)
		baseRegNo = insn->hasAdSize ? X86_SI : X86_ESI;
	else {
		// assert(insn->mode == MODE_16BIT);
		baseRegNo = insn->hasAdSize ? X86_ESI : X86_SI;
	}

	createRegisterOperand(mcInst, baseRegNo, emitOperands);

	createRegisterOperand(mcInst, segmentRegnums[insn->segmentOverride],
			      emitOperands);

	return false;
}

/// translateDstIndex   - Appends a destination index operand to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The internal instruction.
static bool translateDstIndex(MCInst *mcInst, InternalInstruction *insn,
			      bool emitOperands)
{
	unsigned baseRegNo;

	if (insn->mode == MODE_64BIT)
		baseRegNo = insn->hasAdSize ? X86_EDI : X86_RDI;
	else if (insn->mode == MODE_32BIT)
		baseRegNo = insn->hasAdSize ? X86_DI : X86_EDI;
	else {
		// assert(insn->mode == MODE_16BIT);
		baseRegNo = insn->hasAdSize ? X86_EDI : X86_DI;
	}

	createRegisterOperand(mcInst, baseRegNo, emitOperands);

	return false;
}

X86_TRANSLATE_INLINE uint64_t
translateRelativeImmediate(uint64_t immediate, const OperandSpecifier *operand,
			   uint8_t displacementSize)
{
	switch (operand->encoding) {
	default:
		break;
	case ENCODING_Iv:
		switch (displacementSize) {
		default:
			break;
		case 1:
			if (immediate & 0x80)
				immediate |= ~(0xffull);
			break;
		case 2:
			if (immediate & 0x8000)
				immediate |= ~(0xffffull);
			break;
		case 4:
			if (immediate & 0x80000000)
				immediate |= ~(0xffffffffull);
			break;
		case 8:
			break;
		}
		break;
	case ENCODING_IB:
		if (immediate & 0x80)
			immediate |= ~(0xffull);
		break;
	case ENCODING_IW:
		if (immediate & 0x8000)
			immediate |= ~(0xffffull);
		break;
	case ENCODING_ID:
		if (immediate & 0x80000000)
			immediate |= ~(0xffffffffull);
		break;
	}
	return immediate;
}

/// translateImmediate  - Appends an immediate operand to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param immediate    - The immediate value to append.
/// @param operand      - The operand, as stored in the descriptor table.
/// @param insn         - The internal instruction.
X86_TRANSLATE_INLINE void translateImmediate(MCInst *mcInst, uint64_t immediate,
					     const OperandSpecifier *operand,
					     InternalInstruction *insn,
					     bool emitOperands)
{
	OperandType type;

	type = (OperandType)operand->type;
	if (type == TYPE_REL) {
		immediate = translateRelativeImmediate(immediate, operand,
						       insn->displacementSize);
	} // By default sign-extend all X86 immediates based on their encoding.
	else if (type == TYPE_IMM) {
		switch (operand->encoding) {
		default:
			break;
		case ENCODING_IB:
			if (immediate & 0x80)
				immediate |= ~(0xffull);
			break;
		case ENCODING_IW:
			if (immediate & 0x8000)
				immediate |= ~(0xffffull);
			break;
		case ENCODING_ID:
			if (immediate & 0x80000000)
				immediate |= ~(0xffffffffull);
			break;
		case ENCODING_IO:
			break;
		}
	} else if (type == TYPE_IMM3) {
#ifndef CAPSTONE_X86_REDUCE
		// Check for immediates that printSSECC can't handle.
		if (immediate >= 8) {
			unsigned NewOpc = 0;

			switch (MCInst_getOpcode(mcInst)) {
			default:
				break; // never reach
			case X86_CMPPDrmi:
				NewOpc = X86_CMPPDrmi_alt;
				break;
			case X86_CMPPDrri:
				NewOpc = X86_CMPPDrri_alt;
				break;
			case X86_CMPPSrmi:
				NewOpc = X86_CMPPSrmi_alt;
				break;
			case X86_CMPPSrri:
				NewOpc = X86_CMPPSrri_alt;
				break;
			case X86_CMPSDrm:
				NewOpc = X86_CMPSDrm_alt;
				break;
			case X86_CMPSDrr:
				NewOpc = X86_CMPSDrr_alt;
				break;
			case X86_CMPSSrm:
				NewOpc = X86_CMPSSrm_alt;
				break;
			case X86_CMPSSrr:
				NewOpc = X86_CMPSSrr_alt;
				break;
			case X86_VPCOMBri:
				NewOpc = X86_VPCOMBri_alt;
				break;
			case X86_VPCOMBmi:
				NewOpc = X86_VPCOMBmi_alt;
				break;
			case X86_VPCOMWri:
				NewOpc = X86_VPCOMWri_alt;
				break;
			case X86_VPCOMWmi:
				NewOpc = X86_VPCOMWmi_alt;
				break;
			case X86_VPCOMDri:
				NewOpc = X86_VPCOMDri_alt;
				break;
			case X86_VPCOMDmi:
				NewOpc = X86_VPCOMDmi_alt;
				break;
			case X86_VPCOMQri:
				NewOpc = X86_VPCOMQri_alt;
				break;
			case X86_VPCOMQmi:
				NewOpc = X86_VPCOMQmi_alt;
				break;
			case X86_VPCOMUBri:
				NewOpc = X86_VPCOMUBri_alt;
				break;
			case X86_VPCOMUBmi:
				NewOpc = X86_VPCOMUBmi_alt;
				break;
			case X86_VPCOMUWri:
				NewOpc = X86_VPCOMUWri_alt;
				break;
			case X86_VPCOMUWmi:
				NewOpc = X86_VPCOMUWmi_alt;
				break;
			case X86_VPCOMUDri:
				NewOpc = X86_VPCOMUDri_alt;
				break;
			case X86_VPCOMUDmi:
				NewOpc = X86_VPCOMUDmi_alt;
				break;
			case X86_VPCOMUQri:
				NewOpc = X86_VPCOMUQri_alt;
				break;
			case X86_VPCOMUQmi:
				NewOpc = X86_VPCOMUQmi_alt;
				break;
			}

			// Switch opcode to the one that doesn't get special printing.
			if (NewOpc != 0) {
				MCInst_setOpcode(mcInst, NewOpc);
			}
		}
#endif
	} else if (type == TYPE_IMM5) {
#ifndef CAPSTONE_X86_REDUCE
		// Check for immediates that printAVXCC can't handle.
		if (immediate >= 32) {
			unsigned NewOpc = 0;

			switch (MCInst_getOpcode(mcInst)) {
			default:
				break; // unexpected opcode
			case X86_VCMPPDrmi:
				NewOpc = X86_VCMPPDrmi_alt;
				break;
			case X86_VCMPPDrri:
				NewOpc = X86_VCMPPDrri_alt;
				break;
			case X86_VCMPPSrmi:
				NewOpc = X86_VCMPPSrmi_alt;
				break;
			case X86_VCMPPSrri:
				NewOpc = X86_VCMPPSrri_alt;
				break;
			case X86_VCMPSDrm:
				NewOpc = X86_VCMPSDrm_alt;
				break;
			case X86_VCMPSDrr:
				NewOpc = X86_VCMPSDrr_alt;
				break;
			case X86_VCMPSSrm:
				NewOpc = X86_VCMPSSrm_alt;
				break;
			case X86_VCMPSSrr:
				NewOpc = X86_VCMPSSrr_alt;
				break;
			case X86_VCMPPDYrmi:
				NewOpc = X86_VCMPPDYrmi_alt;
				break;
			case X86_VCMPPDYrri:
				NewOpc = X86_VCMPPDYrri_alt;
				break;
			case X86_VCMPPSYrmi:
				NewOpc = X86_VCMPPSYrmi_alt;
				break;
			case X86_VCMPPSYrri:
				NewOpc = X86_VCMPPSYrri_alt;
				break;
			case X86_VCMPPDZrmi:
				NewOpc = X86_VCMPPDZrmi_alt;
				break;
			case X86_VCMPPDZrri:
				NewOpc = X86_VCMPPDZrri_alt;
				break;
			case X86_VCMPPDZrrib:
				NewOpc = X86_VCMPPDZrrib_alt;
				break;
			case X86_VCMPPSZrmi:
				NewOpc = X86_VCMPPSZrmi_alt;
				break;
			case X86_VCMPPSZrri:
				NewOpc = X86_VCMPPSZrri_alt;
				break;
			case X86_VCMPPSZrrib:
				NewOpc = X86_VCMPPSZrrib_alt;
				break;
			case X86_VCMPPDZ128rmi:
				NewOpc = X86_VCMPPDZ128rmi_alt;
				break;
			case X86_VCMPPDZ128rri:
				NewOpc = X86_VCMPPDZ128rri_alt;
				break;
			case X86_VCMPPSZ128rmi:
				NewOpc = X86_VCMPPSZ128rmi_alt;
				break;
			case X86_VCMPPSZ128rri:
				NewOpc = X86_VCMPPSZ128rri_alt;
				break;
			case X86_VCMPPDZ256rmi:
				NewOpc = X86_VCMPPDZ256rmi_alt;
				break;
			case X86_VCMPPDZ256rri:
				NewOpc = X86_VCMPPDZ256rri_alt;
				break;
			case X86_VCMPPSZ256rmi:
				NewOpc = X86_VCMPPSZ256rmi_alt;
				break;
			case X86_VCMPPSZ256rri:
				NewOpc = X86_VCMPPSZ256rri_alt;
				break;
			case X86_VCMPSDZrm_Int:
				NewOpc = X86_VCMPSDZrmi_alt;
				break;
			case X86_VCMPSDZrr_Int:
				NewOpc = X86_VCMPSDZrri_alt;
				break;
			case X86_VCMPSDZrrb_Int:
				NewOpc = X86_VCMPSDZrrb_alt;
				break;
			case X86_VCMPSSZrm_Int:
				NewOpc = X86_VCMPSSZrmi_alt;
				break;
			case X86_VCMPSSZrr_Int:
				NewOpc = X86_VCMPSSZrri_alt;
				break;
			case X86_VCMPSSZrrb_Int:
				NewOpc = X86_VCMPSSZrrb_alt;
				break;
			}

			// Switch opcode to the one that doesn't get special printing.
			if (NewOpc != 0) {
				MCInst_setOpcode(mcInst, NewOpc);
			}
		}
#endif
	} else if (type == TYPE_AVX512ICC) {
#ifndef CAPSTONE_X86_REDUCE
		if (immediate >= 8 || ((immediate & 0x3) == 3)) {
			unsigned NewOpc = 0;
			switch (MCInst_getOpcode(mcInst)) {
			default: // llvm_unreachable("unexpected opcode");
			case X86_VPCMPBZ128rmi:
				NewOpc = X86_VPCMPBZ128rmi_alt;
				break;
			case X86_VPCMPBZ128rmik:
				NewOpc = X86_VPCMPBZ128rmik_alt;
				break;
			case X86_VPCMPBZ128rri:
				NewOpc = X86_VPCMPBZ128rri_alt;
				break;
			case X86_VPCMPBZ128rrik:
				NewOpc = X86_VPCMPBZ128rrik_alt;
				break;
			case X86_VPCMPBZ256rmi:
				NewOpc = X86_VPCMPBZ256rmi_alt;
				break;
			case X86_VPCMPBZ256rmik:
				NewOpc = X86_VPCMPBZ256rmik_alt;
				break;
			case X86_VPCMPBZ256rri:
				NewOpc = X86_VPCMPBZ256rri_alt;
				break;
			case X86_VPCMPBZ256rrik:
				NewOpc = X86_VPCMPBZ256rrik_alt;
				break;
			case X86_VPCMPBZrmi:
				NewOpc = X86_VPCMPBZrmi_alt;
				break;
			case X86_VPCMPBZrmik:
				NewOpc = X86_VPCMPBZrmik_alt;
				break;
			case X86_VPCMPBZrri:
				NewOpc = X86_VPCMPBZrri_alt;
				break;
			case X86_VPCMPBZrrik:
				NewOpc = X86_VPCMPBZrrik_alt;
				break;
			case X86_VPCMPDZ128rmi:
				NewOpc = X86_VPCMPDZ128rmi_alt;
				break;
			case X86_VPCMPDZ128rmib:
				NewOpc = X86_VPCMPDZ128rmib_alt;
				break;
			case X86_VPCMPDZ128rmibk:
				NewOpc = X86_VPCMPDZ128rmibk_alt;
				break;
			case X86_VPCMPDZ128rmik:
				NewOpc = X86_VPCMPDZ128rmik_alt;
				break;
			case X86_VPCMPDZ128rri:
				NewOpc = X86_VPCMPDZ128rri_alt;
				break;
			case X86_VPCMPDZ128rrik:
				NewOpc = X86_VPCMPDZ128rrik_alt;
				break;
			case X86_VPCMPDZ256rmi:
				NewOpc = X86_VPCMPDZ256rmi_alt;
				break;
			case X86_VPCMPDZ256rmib:
				NewOpc = X86_VPCMPDZ256rmib_alt;
				break;
			case X86_VPCMPDZ256rmibk:
				NewOpc = X86_VPCMPDZ256rmibk_alt;
				break;
			case X86_VPCMPDZ256rmik:
				NewOpc = X86_VPCMPDZ256rmik_alt;
				break;
			case X86_VPCMPDZ256rri:
				NewOpc = X86_VPCMPDZ256rri_alt;
				break;
			case X86_VPCMPDZ256rrik:
				NewOpc = X86_VPCMPDZ256rrik_alt;
				break;
			case X86_VPCMPDZrmi:
				NewOpc = X86_VPCMPDZrmi_alt;
				break;
			case X86_VPCMPDZrmib:
				NewOpc = X86_VPCMPDZrmib_alt;
				break;
			case X86_VPCMPDZrmibk:
				NewOpc = X86_VPCMPDZrmibk_alt;
				break;
			case X86_VPCMPDZrmik:
				NewOpc = X86_VPCMPDZrmik_alt;
				break;
			case X86_VPCMPDZrri:
				NewOpc = X86_VPCMPDZrri_alt;
				break;
			case X86_VPCMPDZrrik:
				NewOpc = X86_VPCMPDZrrik_alt;
				break;
			case X86_VPCMPQZ128rmi:
				NewOpc = X86_VPCMPQZ128rmi_alt;
				break;
			case X86_VPCMPQZ128rmib:
				NewOpc = X86_VPCMPQZ128rmib_alt;
				break;
			case X86_VPCMPQZ128rmibk:
				NewOpc = X86_VPCMPQZ128rmibk_alt;
				break;
			case X86_VPCMPQZ128rmik:
				NewOpc = X86_VPCMPQZ128rmik_alt;
				break;
			case X86_VPCMPQZ128rri:
				NewOpc = X86_VPCMPQZ128rri_alt;
				break;
			case X86_VPCMPQZ128rrik:
				NewOpc = X86_VPCMPQZ128rrik_alt;
				break;
			case X86_VPCMPQZ256rmi:
				NewOpc = X86_VPCMPQZ256rmi_alt;
				break;
			case X86_VPCMPQZ256rmib:
				NewOpc = X86_VPCMPQZ256rmib_alt;
				break;
			case X86_VPCMPQZ256rmibk:
				NewOpc = X86_VPCMPQZ256rmibk_alt;
				break;
			case X86_VPCMPQZ256rmik:
				NewOpc = X86_VPCMPQZ256rmik_alt;
				break;
			case X86_VPCMPQZ256rri:
				NewOpc = X86_VPCMPQZ256rri_alt;
				break;
			case X86_VPCMPQZ256rrik:
				NewOpc = X86_VPCMPQZ256rrik_alt;
				break;
			case X86_VPCMPQZrmi:
				NewOpc = X86_VPCMPQZrmi_alt;
				break;
			case X86_VPCMPQZrmib:
				NewOpc = X86_VPCMPQZrmib_alt;
				break;
			case X86_VPCMPQZrmibk:
				NewOpc = X86_VPCMPQZrmibk_alt;
				break;
			case X86_VPCMPQZrmik:
				NewOpc = X86_VPCMPQZrmik_alt;
				break;
			case X86_VPCMPQZrri:
				NewOpc = X86_VPCMPQZrri_alt;
				break;
			case X86_VPCMPQZrrik:
				NewOpc = X86_VPCMPQZrrik_alt;
				break;
			case X86_VPCMPUBZ128rmi:
				NewOpc = X86_VPCMPUBZ128rmi_alt;
				break;
			case X86_VPCMPUBZ128rmik:
				NewOpc = X86_VPCMPUBZ128rmik_alt;
				break;
			case X86_VPCMPUBZ128rri:
				NewOpc = X86_VPCMPUBZ128rri_alt;
				break;
			case X86_VPCMPUBZ128rrik:
				NewOpc = X86_VPCMPUBZ128rrik_alt;
				break;
			case X86_VPCMPUBZ256rmi:
				NewOpc = X86_VPCMPUBZ256rmi_alt;
				break;
			case X86_VPCMPUBZ256rmik:
				NewOpc = X86_VPCMPUBZ256rmik_alt;
				break;
			case X86_VPCMPUBZ256rri:
				NewOpc = X86_VPCMPUBZ256rri_alt;
				break;
			case X86_VPCMPUBZ256rrik:
				NewOpc = X86_VPCMPUBZ256rrik_alt;
				break;
			case X86_VPCMPUBZrmi:
				NewOpc = X86_VPCMPUBZrmi_alt;
				break;
			case X86_VPCMPUBZrmik:
				NewOpc = X86_VPCMPUBZrmik_alt;
				break;
			case X86_VPCMPUBZrri:
				NewOpc = X86_VPCMPUBZrri_alt;
				break;
			case X86_VPCMPUBZrrik:
				NewOpc = X86_VPCMPUBZrrik_alt;
				break;
			case X86_VPCMPUDZ128rmi:
				NewOpc = X86_VPCMPUDZ128rmi_alt;
				break;
			case X86_VPCMPUDZ128rmib:
				NewOpc = X86_VPCMPUDZ128rmib_alt;
				break;
			case X86_VPCMPUDZ128rmibk:
				NewOpc = X86_VPCMPUDZ128rmibk_alt;
				break;
			case X86_VPCMPUDZ128rmik:
				NewOpc = X86_VPCMPUDZ128rmik_alt;
				break;
			case X86_VPCMPUDZ128rri:
				NewOpc = X86_VPCMPUDZ128rri_alt;
				break;
			case X86_VPCMPUDZ128rrik:
				NewOpc = X86_VPCMPUDZ128rrik_alt;
				break;
			case X86_VPCMPUDZ256rmi:
				NewOpc = X86_VPCMPUDZ256rmi_alt;
				break;
			case X86_VPCMPUDZ256rmib:
				NewOpc = X86_VPCMPUDZ256rmib_alt;
				break;
			case X86_VPCMPUDZ256rmibk:
				NewOpc = X86_VPCMPUDZ256rmibk_alt;
				break;
			case X86_VPCMPUDZ256rmik:
				NewOpc = X86_VPCMPUDZ256rmik_alt;
				break;
			case X86_VPCMPUDZ256rri:
				NewOpc = X86_VPCMPUDZ256rri_alt;
				break;
			case X86_VPCMPUDZ256rrik:
				NewOpc = X86_VPCMPUDZ256rrik_alt;
				break;
			case X86_VPCMPUDZrmi:
				NewOpc = X86_VPCMPUDZrmi_alt;
				break;
			case X86_VPCMPUDZrmib:
				NewOpc = X86_VPCMPUDZrmib_alt;
				break;
			case X86_VPCMPUDZrmibk:
				NewOpc = X86_VPCMPUDZrmibk_alt;
				break;
			case X86_VPCMPUDZrmik:
				NewOpc = X86_VPCMPUDZrmik_alt;
				break;
			case X86_VPCMPUDZrri:
				NewOpc = X86_VPCMPUDZrri_alt;
				break;
			case X86_VPCMPUDZrrik:
				NewOpc = X86_VPCMPUDZrrik_alt;
				break;
			case X86_VPCMPUQZ128rmi:
				NewOpc = X86_VPCMPUQZ128rmi_alt;
				break;
			case X86_VPCMPUQZ128rmib:
				NewOpc = X86_VPCMPUQZ128rmib_alt;
				break;
			case X86_VPCMPUQZ128rmibk:
				NewOpc = X86_VPCMPUQZ128rmibk_alt;
				break;
			case X86_VPCMPUQZ128rmik:
				NewOpc = X86_VPCMPUQZ128rmik_alt;
				break;
			case X86_VPCMPUQZ128rri:
				NewOpc = X86_VPCMPUQZ128rri_alt;
				break;
			case X86_VPCMPUQZ128rrik:
				NewOpc = X86_VPCMPUQZ128rrik_alt;
				break;
			case X86_VPCMPUQZ256rmi:
				NewOpc = X86_VPCMPUQZ256rmi_alt;
				break;
			case X86_VPCMPUQZ256rmib:
				NewOpc = X86_VPCMPUQZ256rmib_alt;
				break;
			case X86_VPCMPUQZ256rmibk:
				NewOpc = X86_VPCMPUQZ256rmibk_alt;
				break;
			case X86_VPCMPUQZ256rmik:
				NewOpc = X86_VPCMPUQZ256rmik_alt;
				break;
			case X86_VPCMPUQZ256rri:
				NewOpc = X86_VPCMPUQZ256rri_alt;
				break;
			case X86_VPCMPUQZ256rrik:
				NewOpc = X86_VPCMPUQZ256rrik_alt;
				break;
			case X86_VPCMPUQZrmi:
				NewOpc = X86_VPCMPUQZrmi_alt;
				break;
			case X86_VPCMPUQZrmib:
				NewOpc = X86_VPCMPUQZrmib_alt;
				break;
			case X86_VPCMPUQZrmibk:
				NewOpc = X86_VPCMPUQZrmibk_alt;
				break;
			case X86_VPCMPUQZrmik:
				NewOpc = X86_VPCMPUQZrmik_alt;
				break;
			case X86_VPCMPUQZrri:
				NewOpc = X86_VPCMPUQZrri_alt;
				break;
			case X86_VPCMPUQZrrik:
				NewOpc = X86_VPCMPUQZrrik_alt;
				break;
			case X86_VPCMPUWZ128rmi:
				NewOpc = X86_VPCMPUWZ128rmi_alt;
				break;
			case X86_VPCMPUWZ128rmik:
				NewOpc = X86_VPCMPUWZ128rmik_alt;
				break;
			case X86_VPCMPUWZ128rri:
				NewOpc = X86_VPCMPUWZ128rri_alt;
				break;
			case X86_VPCMPUWZ128rrik:
				NewOpc = X86_VPCMPUWZ128rrik_alt;
				break;
			case X86_VPCMPUWZ256rmi:
				NewOpc = X86_VPCMPUWZ256rmi_alt;
				break;
			case X86_VPCMPUWZ256rmik:
				NewOpc = X86_VPCMPUWZ256rmik_alt;
				break;
			case X86_VPCMPUWZ256rri:
				NewOpc = X86_VPCMPUWZ256rri_alt;
				break;
			case X86_VPCMPUWZ256rrik:
				NewOpc = X86_VPCMPUWZ256rrik_alt;
				break;
			case X86_VPCMPUWZrmi:
				NewOpc = X86_VPCMPUWZrmi_alt;
				break;
			case X86_VPCMPUWZrmik:
				NewOpc = X86_VPCMPUWZrmik_alt;
				break;
			case X86_VPCMPUWZrri:
				NewOpc = X86_VPCMPUWZrri_alt;
				break;
			case X86_VPCMPUWZrrik:
				NewOpc = X86_VPCMPUWZrrik_alt;
				break;
			case X86_VPCMPWZ128rmi:
				NewOpc = X86_VPCMPWZ128rmi_alt;
				break;
			case X86_VPCMPWZ128rmik:
				NewOpc = X86_VPCMPWZ128rmik_alt;
				break;
			case X86_VPCMPWZ128rri:
				NewOpc = X86_VPCMPWZ128rri_alt;
				break;
			case X86_VPCMPWZ128rrik:
				NewOpc = X86_VPCMPWZ128rrik_alt;
				break;
			case X86_VPCMPWZ256rmi:
				NewOpc = X86_VPCMPWZ256rmi_alt;
				break;
			case X86_VPCMPWZ256rmik:
				NewOpc = X86_VPCMPWZ256rmik_alt;
				break;
			case X86_VPCMPWZ256rri:
				NewOpc = X86_VPCMPWZ256rri_alt;
				break;
			case X86_VPCMPWZ256rrik:
				NewOpc = X86_VPCMPWZ256rrik_alt;
				break;
			case X86_VPCMPWZrmi:
				NewOpc = X86_VPCMPWZrmi_alt;
				break;
			case X86_VPCMPWZrmik:
				NewOpc = X86_VPCMPWZrmik_alt;
				break;
			case X86_VPCMPWZrri:
				NewOpc = X86_VPCMPWZrri_alt;
				break;
			case X86_VPCMPWZrrik:
				NewOpc = X86_VPCMPWZrrik_alt;
				break;
			}

			// Switch opcode to the one that doesn't get special printing.
			if (NewOpc != 0) {
				MCInst_setOpcode(mcInst, NewOpc);
			}
		}
#endif
	}

	switch (type) {
	case TYPE_XMM:
		createRegisterOperand(mcInst,
				      X86_XMM0 + ((uint32_t)immediate >> 4),
				      emitOperands);
		return;
	case TYPE_YMM:
		createRegisterOperand(mcInst,
				      X86_YMM0 + ((uint32_t)immediate >> 4),
				      emitOperands);
		return;
	case TYPE_ZMM:
		createRegisterOperand(mcInst,
				      X86_ZMM0 + ((uint32_t)immediate >> 4),
				      emitOperands);
		return;
	default:
		// operand is 64 bits wide.  Do nothing.
		break;
	}

	createImmediateOperand(mcInst, immediate, emitOperands);

	if (type == TYPE_MOFFS) {
		createRegisterOperand(mcInst,
				      segmentRegnums[insn->segmentOverride],
				      emitOperands);
	}
}

/// translateRMRegister - Translates a register stored in the R/M field of the
///   ModR/M byte to its LLVM equivalent and appends it to an MCInst.
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The internal instruction to extract the R/M field
///                       from.
/// @return             - 0 on success; -1 otherwise
X86_TRANSLATE_INLINE bool translateRMRegister(MCInst *mcInst,
					      InternalInstruction *insn,
					      OperandType type,
					      bool emitOperands)
{
	if (insn->eaBase == EA_BASE_sib || insn->eaBase == EA_BASE_sib64) {
		//debug("A R/M register operand may not have a SIB byte");
		return true;
	}

	if (insn->hasRex2 || insn->apxEvexB4) {
		const uint8_t width = gprOperandWidth(insn, type);

		if (insn->hasRex2) {
			const unsigned int number =
				(b4FromREX2(insn->rex2Prefix) << 4) |
				(b3FromREX2(insn->rex2Prefix) << 3) |
				rmFromModRM(insn->orgModRM);

			if (type == TYPE_CONTROLREG &&
			    !rex2ControlRegisterIsValid(number))
				return true;
			if (type == TYPE_DEBUGREG &&
			    !rex2DebugRegisterIsValid(number))
				return true;
			if (width != 0 && b4FromREX2(insn->rex2Prefix))
				return appendFeatureGpr(mcInst, number, width,
							emitOperands);
		}
		if (insn->apxEvexB4 && width != 0) {
			const unsigned int number =
				16 |
				(bFromEVEX2of4(insn->vectorExtensionPrefix[1])
				 << 3) |
				(insn->orgModRM & 7);
			const unsigned int reg =
				X86_featureExtensionMCGPR(number, width);

			if (reg == 0)
				return true;
			createRegisterOperand(mcInst, reg, emitOperands);
			return false;
		}
	}

	/* EABase and Reg enumerate their register ranges with ALL_REGS. */
	const unsigned int reg = (unsigned int)insn->eaBase - EA_REG_AL;
	if (reg >= MODRM_REG_max)
		return true;
	translateRegister(mcInst, (Reg)reg, emitOperands);
	return false;
}

/// translateRMMemory - Translates a memory operand stored in the Mod and R/M
///   fields of an internal instruction (and possibly its SIB byte) to a memory
///   operand in LLVM's format, and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The instruction to extract Mod, R/M, and SIB fields
///                       from.
/// @return             - 0 on success; nonzero otherwise
X86_TRANSLATE_INLINE bool translateRMMemoryImpl(MCInst *mcInst,
						InternalInstruction *insn,
						OperandType type,
						bool emitOperands)
{
	// Addresses in an MCInst are represented as five operands:
	//   1. basereg       (register)  The R/M base, or (if there is a SIB) the
	//                                SIB base
	//   2. scaleamount   (immediate) 1, or (if there is a SIB) the specified
	//                                scale amount
	//   3. indexreg      (register)  x86_registerNONE, or (if there is a SIB)
	//                                the index (which is multiplied by the
	//                                scale amount)
	//   4. displacement  (immediate) 0, or the displacement if there is one
	//   5. segmentreg    (register)  x86_registerNONE for now, but could be set
	//                                if we have segment overrides
	int scaleAmount, indexReg;

	if (insn->eaBase == EA_BASE_sib || insn->eaBase == EA_BASE_sib64) {
		if (insn->sibBase != SIB_BASE_NONE) {
			if (insn->apxEvexB4 ||
			    (insn->hasRex2 &&
			     b4FromREX2(insn->rex2Prefix))) {
				const unsigned int extension = insn->hasRex2 ?
					b3FromREX2(insn->rex2Prefix) :
					bFromEVEX2of4(
						insn->vectorExtensionPrefix[1]);
				const unsigned int number =
					16 | (extension << 3) |
					(insn->sib & 7);

				if (appendFeatureGpr(mcInst, number,
						     insn->addressSize,
						     emitOperands))
					return true;
			} else {
				switch (insn->sibBase) {
#define ENTRY(x) \
	case SIB_BASE_##x: \
		createRegisterOperand(mcInst, X86_##x, emitOperands); \
		break;
					ALL_SIB_BASES
#undef ENTRY
				default:
					//debug("Unexpected sibBase");
					return true;
				}
			}
		} else {
			createRegisterOperand(mcInst, 0, emitOperands);
		}

		if (type == TYPE_M &&
		    (insn->apxEvexX4 ||
		     (insn->hasRex2 && x4FromREX2(insn->rex2Prefix)))) {
			const unsigned int extension = insn->hasRex2 ?
				x3FromREX2(insn->rex2Prefix) :
				xFromEVEX2of4(insn->vectorExtensionPrefix[1]);
			const unsigned int number =
				16 | (extension << 3) |
				((insn->sib >> 3) & 7);

			indexReg = (int)X86_featureExtensionMCGPR(
				number, insn->addressSize);
			if (indexReg == 0)
				return true;
			if (!insn->hasRex2)
				insn->apxEvexGprIndex = true;
		} else if (insn->sibIndex != SIB_INDEX_NONE) {
			switch (insn->sibIndex) {
			default:
				//debug("Unexpected sibIndex");
				return true;
#define ENTRY(x) \
	case SIB_INDEX_##x: \
		indexReg = X86_##x; \
		break;
				EA_BASES_32BIT
				EA_BASES_64BIT
				REGS_XMM
				REGS_YMM
				REGS_ZMM
#undef ENTRY
			}
		} else {
			// Use EIZ/RIZ for a few ambiguous cases where the SIB byte is present,
			// but no index is used and modrm alone should have been enough.
			// -No base register in 32-bit mode. In 64-bit mode this is used to
			//  avoid rip-relative addressing.
			// -Any base register used other than ESP/RSP/R12D/R12. Using these as a
			//  base always requires a SIB byte.
			// -A scale other than 1 is used.
			if (insn->sibScale != 1 ||
			    (insn->sibBase == SIB_BASE_NONE &&
			     insn->mode != MODE_64BIT) ||
			    (insn->sibBase != SIB_BASE_NONE &&
			     insn->sibBase != SIB_BASE_ESP &&
			     insn->sibBase != SIB_BASE_RSP &&
			     insn->sibBase != SIB_BASE_R12D &&
			     insn->sibBase != SIB_BASE_R12)) {
				indexReg = insn->addressSize == 4 ? X86_EIZ :
								    X86_RIZ;
			} else
				indexReg = 0;
		}

		scaleAmount = insn->sibScale;
	} else {
		if ((insn->apxEvexB4 ||
		     (insn->hasRex2 && b4FromREX2(insn->rex2Prefix))) &&
		    insn->eaBase != EA_BASE_NONE) {
			const unsigned int extension = insn->hasRex2 ?
				b3FromREX2(insn->rex2Prefix) :
				bFromEVEX2of4(insn->vectorExtensionPrefix[1]);
			const unsigned int number =
				16 | (extension << 3) |
				(insn->orgModRM & 7);

			if (appendFeatureGpr(mcInst, number, insn->addressSize,
					     emitOperands))
				return true;
			indexReg = 0;
		} else {
			switch (insn->eaBase) {
		case EA_BASE_NONE:
			if (insn->eaDisplacement == EA_DISP_NONE) {
				//debug("EA_BASE_NONE and EA_DISP_NONE for ModR/M base");
				return true;
			}
			if (insn->mode == MODE_64BIT) {
				if (insn->prefix3 ==
				    0x67) // address-size prefix overrides RIP relative addressing
					createRegisterOperand(mcInst, X86_EIP,
							      emitOperands);
				else
					// Section 2.2.1.6
					createRegisterOperand(
						mcInst,
						insn->addressSize == 4 ?
							X86_EIP :
							X86_RIP,
						emitOperands);
			} else {
				createRegisterOperand(mcInst, 0, emitOperands);
			}

			indexReg = 0;
			break;
		case EA_BASE_BX_SI:
			createRegisterOperand(mcInst, X86_BX, emitOperands);
			indexReg = X86_SI;
			break;
		case EA_BASE_BX_DI:
			createRegisterOperand(mcInst, X86_BX, emitOperands);
			indexReg = X86_DI;
			break;
		case EA_BASE_BP_SI:
			createRegisterOperand(mcInst, X86_BP, emitOperands);
			indexReg = X86_SI;
			break;
		case EA_BASE_BP_DI:
			createRegisterOperand(mcInst, X86_BP, emitOperands);
			indexReg = X86_DI;
			break;
		default:
			indexReg = 0;
			switch (insn->eaBase) {
			default:
				//debug("Unexpected eaBase");
				return true;
				// Here, we will use the fill-ins defined above.  However,
				//   BX_SI, BX_DI, BP_SI, and BP_DI are all handled above and
				//   sib and sib64 were handled in the top-level if, so they're only
				//   placeholders to keep the compiler happy.
#define ENTRY(x) \
	case EA_BASE_##x: \
		createRegisterOperand(mcInst, X86_##x, emitOperands); \
		break;
				ALL_EA_BASES
#undef ENTRY
#define ENTRY(x) case EA_REG_##x:
				ALL_REGS
#undef ENTRY
				//debug("A R/M memory operand may not be a register; "
				//      "the base field must be a base.");
				return true;
			}
			}
		}

		scaleAmount = 1;
	}

	createImmediateOperand(mcInst, scaleAmount, emitOperands);
	createRegisterOperand(mcInst, indexReg, emitOperands);
	createImmediateOperand(mcInst, insn->displacement, emitOperands);

	createRegisterOperand(mcInst, segmentRegnums[insn->segmentOverride],
			      emitOperands);

	return false;
}

static bool translateRMMemoryFull(MCInst *mcInst, InternalInstruction *insn,
				  OperandType type)
{
	return translateRMMemoryImpl(mcInst, insn, type, true);
}

static bool validateRMMemory(MCInst *mcInst, InternalInstruction *insn,
			     OperandType type)
{
	return translateRMMemoryImpl(mcInst, insn, type, false);
}

X86_TRANSLATE_INLINE bool translateRMMemory(MCInst *mcInst,
					    InternalInstruction *insn,
					    OperandType type, bool emitOperands)
{
	if (emitOperands)
		return translateRMMemoryFull(mcInst, insn, type);
	return validateRMMemory(mcInst, insn, type);
}

/// translateRM - Translates an operand stored in the R/M (and possibly SIB)
///   byte of an instruction to LLVM form, and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param operand      - The operand, as stored in the descriptor table.
/// @param insn         - The instruction to extract Mod, R/M, and SIB fields
///                       from.
/// @return             - 0 on success; nonzero otherwise
X86_TRANSLATE_INLINE bool translateRM(MCInst *mcInst,
				      const OperandSpecifier *operand,
				      InternalInstruction *insn,
				      bool emitOperands)
{
	switch (operand->type) {
	default:
		//debug("Unexpected type for a R/M operand");
		return true;
	case TYPE_R8:
	case TYPE_R16:
	case TYPE_R32:
	case TYPE_R64:
	case TYPE_Rv:
	case TYPE_MM64:
	case TYPE_XMM:
	case TYPE_YMM:
	case TYPE_ZMM:
	case TYPE_VK:
	case TYPE_DEBUGREG:
	case TYPE_CONTROLREG:
	case TYPE_BNDR:
		return translateRMRegister(
			mcInst, insn, (OperandType)operand->type, emitOperands);
	case TYPE_M:
	case TYPE_MVSIBX:
	case TYPE_MVSIBY:
	case TYPE_MVSIBZ:
		return translateRMMemory(
			mcInst, insn, (OperandType)operand->type, emitOperands);
	}
}

/// translateFPRegister - Translates a stack position on the FPU stack to its
///   LLVM form, and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param stackPos     - The stack position to translate.
static void translateFPRegister(MCInst *mcInst, uint8_t stackPos,
				bool emitOperands)
{
	createRegisterOperand(mcInst, X86_ST0 + stackPos, emitOperands);
}

/// translateMaskRegister - Translates a 3-bit mask register number to
///   LLVM form, and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param maskRegNum   - Number of mask register from 0 to 7.
/// @return             - false on success; true otherwise.
X86_TRANSLATE_INLINE bool
translateMaskRegister(MCInst *mcInst, uint8_t maskRegNum, bool emitOperands)
{
	if (maskRegNum >= 8) {
		// debug("Invalid mask register number");
		return true;
	}

	createRegisterOperand(mcInst, X86_K0 + maskRegNum, emitOperands);

	return false;
}

/// translateOperand - Translates an operand stored in an internal instruction
///   to LLVM's format and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param operand      - The operand, as stored in the descriptor table.
/// @param insn         - The internal instruction.
/// @return             - false on success; true otherwise.
static bool translateOperand(MCInst *mcInst, const OperandSpecifier *operand,
			     InternalInstruction *insn, bool emitOperands)
{
	switch (operand->encoding) {
	case ENCODING_REG:
		return translateRegRegister(mcInst, operand, insn,
					    emitOperands);
	case ENCODING_WRITEMASK:
		return translateMaskRegister(mcInst, insn->writemask,
					     emitOperands);
CASE_ENCODING_RM:
CASE_ENCODING_VSIB:
		return translateRM(mcInst, operand, insn, emitOperands);
	case ENCODING_IB:
	case ENCODING_IW:
	case ENCODING_ID:
	case ENCODING_IO:
	case ENCODING_Iv:
	case ENCODING_Ia:
		translateImmediate(
			mcInst,
			insn->immediates[insn->numImmediatesTranslated++],
			operand, insn, emitOperands);
		return false;
	case ENCODING_IRC:
		createImmediateOperand(mcInst, insn->RC, emitOperands);
		return false;
	case ENCODING_SI:
		return translateSrcIndex(mcInst, insn, emitOperands);
	case ENCODING_DI:
		return translateDstIndex(mcInst, insn, emitOperands);
	case ENCODING_RB:
	case ENCODING_RW:
	case ENCODING_RD:
	case ENCODING_RO:
	case ENCODING_Rv:
		return translateOpcodeRegister(mcInst, operand, insn,
					       emitOperands);
	case ENCODING_FP:
		translateFPRegister(mcInst, insn->modRM & 7, emitOperands);
		return false;
	case ENCODING_VVVV:
		translateRegister(mcInst, insn->vvvv, emitOperands);
		return false;
	case ENCODING_DUP:
		return translateOperand(
			mcInst, &insn->operands[operand->type - TYPE_DUP0],
			insn, emitOperands);
	default:
		//debug("Unhandled operand encoding during translation");
		return true;
	}
}

X86_TRANSLATE_INLINE bool beginTranslation(MCInst *mcInst,
					   InternalInstruction *insn)
{
	if (!insn->spec) {
		//debug("Instruction has no specification");
		return true;
	}

	MCInst_clear(mcInst);
	MCInst_setOpcode(mcInst, insn->instructionID);

	// If when reading the prefix bytes we determined the overlapping 0xf2 or 0xf3
	// prefix bytes should be disassembled as xrelease and xacquire then set the
	// opcode to those instead of the rep and repne opcodes.
#ifndef CAPSTONE_X86_REDUCE
	if (insn->xAcquireRelease) {
		if (MCInst_getOpcode(mcInst) == X86_REP_PREFIX)
			MCInst_setOpcode(mcInst, X86_XRELEASE_PREFIX);
		else if (MCInst_getOpcode(mcInst) == X86_REPNE_PREFIX)
			MCInst_setOpcode(mcInst, X86_XACQUIRE_PREFIX);
	}
#endif

	insn->numImmediatesTranslated = 0;

	return false;
}

X86_TRANSLATE_INLINE bool translateInstruction(MCInst *mcInst,
					       InternalInstruction *insn,
					       bool emitOperands)
{
	int index;

	if (beginTranslation(mcInst, insn))
		return true;

	/* UD1 has a runtime operand override; other selected sets use
	 * the same translators with constant descriptors, including duplicates. */
	if (insn->instructionID != X86_UD1) {
#include "X86GenOperandTranslate.inc"
	}

	for (index = 0; index < X86_MAX_OPERANDS &&
			insn->operands[index].encoding != ENCODING_NONE;
	     ++index) {
		if (translateOperand(mcInst, &insn->operands[index], insn,
				     emitOperands))
			return true;
	}

	return false;
}

#undef X86_TRANSLATE_INLINE

#endif

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_ARM_DISASSEMBLER_EXTENSION_H
#define CS_ARM_DISASSEMBLER_EXTENSION_H

#include "../../MCDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "../../cs_priv.h"
#include "ARMAddressingModes.h"
#include "ARMBaseInfo.h"
#include "capstone/capstone.h"

unsigned ARM_AM_getAM5FP16Opc(ARM_AM_AddrOpc Opc, unsigned char Offset);

bool ITBlock_push_back(ARM_ITBlock *it, char v);

bool ITBlock_instrInITBlock(ARM_ITBlock *it);

bool ITBlock_instrLastInITBlock(ARM_ITBlock *it);

unsigned ITBlock_getITCC(ARM_ITBlock *it);

void ITBlock_advanceITState(ARM_ITBlock *it);

void ITBlock_setITState(ARM_ITBlock *it, char Firstcond, char Mask);

bool isValidCoprocessorNumber(MCInst *Inst, unsigned Num);

bool ARM_isVpred(arm_op_type op);

bool isVPTOpcode(int Opc);

bool ARM_isCDECoproc(size_t Coproc, const MCInst *MI);

bool VPTBlock_push_back(ARM_VPTBlock *it, char v);

bool VPTBlock_instrInVPTBlock(ARM_VPTBlock *VPT);

unsigned VPTBlock_getVPTPred(ARM_VPTBlock *VPT);

void VPTBlock_advanceVPTState(ARM_VPTBlock *VPT);

void VPTBlock_setVPTState(ARM_VPTBlock *VPT, char Mask);

/* Keep one body for inline queries and the external definition. */
#ifndef CS_ARM_DEFINE_FEATURE_BITS
static inline
#endif
	bool ARM_getFeatureBits(unsigned int mode, unsigned int feature)
{
	if (feature == ARM_ModeThumb) {
		if (mode & CS_MODE_THUMB)
			return true;
		return false;
	}

	if (feature == ARM_FeatureDFB)
		return false;

	if (feature == ARM_FeatureRAS)
		return false;

	if (feature == ARM_FeatureMClass && (mode & CS_MODE_MCLASS) == 0)
		return false;

	if ((feature == ARM_HasMVEIntegerOps || feature == ARM_HasMVEFloatOps ||
	     feature == ARM_FeatureMVEVectorCostFactor1 ||
	     feature == ARM_FeatureMVEVectorCostFactor2 ||
	     feature == ARM_FeatureMVEVectorCostFactor4) &&
	    (mode & CS_MODE_MCLASS) == 0)
		return false;

	if ((feature == ARM_HasV8Ops || feature == ARM_HasV8_1MMainlineOps ||
	     feature == ARM_HasV8_1aOps || feature == ARM_HasV8_2aOps ||
	     feature == ARM_HasV8_3aOps || feature == ARM_HasV8_4aOps ||
	     feature == ARM_HasV8_5aOps || feature == ARM_HasV8_6aOps ||
	     feature == ARM_HasV8_7aOps || feature == ARM_HasV8_8aOps ||
	     feature == ARM_HasV8_9aOps) &&
	    (mode & CS_MODE_V8) == 0)
		return false;

	if (feature >= ARM_FeatureCoprocCDE0 &&
	    feature <= ARM_FeatureCoprocCDE7)
		// We currently have no way to detect CDE (Custom-Datapath-Extension)
		// coprocessors.
		return false;

	// we support everything
	return true;
}

#endif // CS_ARM_DISASSEMBLER_EXTENSION_H

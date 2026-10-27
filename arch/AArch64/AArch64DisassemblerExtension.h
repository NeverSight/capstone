/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_AARCH64_DISASSEMBLER_EXTENSION_H
#define CS_AARCH64_DISASSEMBLER_EXTENSION_H

#include "../../MCDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "../../cs_priv.h"
#include "AArch64AddressingModes.h"
#include "AArch64BaseInfo.h"
#include "capstone/aarch64.h"
#include "capstone/capstone.h"

/* Keep one body for inline queries and the external definition. */
#ifndef CS_AARCH64_DEFINE_FEATURE_BITS
static inline
#endif
	bool AArch64_getFeatureBits(unsigned int mode, unsigned int feature)
{
	if (feature == AArch64_FeatureAMX || feature == AArch64_FeatureMUL53 ||
	    feature == AArch64_FeatureAppleSys) {
		return mode & CS_MODE_APPLE_PROPRIETARY;
	}
	// we support everything
	return true;
}

bool AArch64_testFeatureList(unsigned int mode, const unsigned int *features);

#endif // CS_AARCH64_DISASSEMBLER_EXTENSION_H

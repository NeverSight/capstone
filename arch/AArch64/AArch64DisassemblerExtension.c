/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#define CS_AARCH64_DEFINE_FEATURE_BITS
#include "AArch64DisassemblerExtension.h"
#undef CS_AARCH64_DEFINE_FEATURE_BITS

/// Tests a NULL terminated array of features if they are enabled.
bool AArch64_testFeatureList(unsigned int mode, const unsigned int *features)
{
	int i = 0;
	while (features[i]) {
		if (!AArch64_getFeatureBits(mode, features[i]))
			return false;
		++i;
	}
	return true;
}

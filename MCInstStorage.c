/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "cs_priv.h"

#if defined(CAPSTONE_MIXED_CONSTRUCTED_OPERANDS) && defined(__clang__)
/* The mixed decoder calls this for ARM, AArch64, PowerPC and RISC-V.
 * Each decoder constructs its active operands before reading them. */
#if defined(__ELF__)
__attribute__((section(".cs_mcinst_storage_text")))
#elif defined(__APPLE__)
__attribute__((section("__TEXT,__cs_mcinst,regular,pure_instructions")))
#endif
CAPSTONE_INTERNAL void MCInst_InitConstructedOperands(MCInst *inst, cs_arch arch)
{
	MCInst_InitStorage(inst, arch, false);
}
#endif

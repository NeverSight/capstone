/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../MCRegisterInfo.h"
#include "../../cs_priv.h"
#include <stdio.h>
#include <stdlib.h>

static bool check(cs_arch arch, cs_mode mode, unsigned end)
{
	if (!cs_support(arch))
		return true;
	csh handle;
	if (cs_open(arch, mode, &handle) != CS_ERR_OK)
		return false;
	const MCRegisterInfo *ri =
		((cs_struct *)(uintptr_t)handle)->printer_info;
	bool ok = ri->NumRegs == end &&
		  MCRegisterInfo_getMatchingSuperReg(ri, end, 0, ri->Classes) ==
			  0;
	if (!ok)
		fprintf(stderr,
			"Architecture %u reports %u register descriptors, expected %u\n",
			(unsigned)arch, ri->NumRegs, end);
	cs_close(&handle);
	return ok;
}

int main(void)
{
	cs_opt_mem mem = { malloc, calloc, realloc, free, vsnprintf };
	if (cs_option(0, CS_OPT_MEM, (size_t)&mem) != CS_ERR_OK)
		return 1;
	bool ok = check(CS_ARCH_ARC, CS_MODE_LITTLE_ENDIAN, ARC_REG_ENDING);
	ok &= check(CS_ARCH_LOONGARCH, CS_MODE_LOONGARCH64,
		    LOONGARCH_REG_ENDING);
	ok &= check(CS_ARCH_MIPS, CS_MODE_MIPS64, MIPS_REG_ENDING);
	ok &= check(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, SPARC_REG_ENDING);
	ok &= check(CS_ARCH_SYSTEMZ, CS_MODE_BIG_ENDIAN, SYSTEMZ_REG_ENDING);
	return ok ? 0 : 1;
}

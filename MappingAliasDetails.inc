/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

CS_ALIAS_DETAIL_LINKAGE bool map_use_alias_details(const MCInst *MI)
{
	assert(MI);
	return (MI->csh->detail_opt & CS_OPT_ON) &&
	       !(MI->csh->detail_opt & CS_OPT_DETAIL_REAL);
}

/* Collect operands only for an instruction with active detail storage. */
CS_ALIAS_DETAIL_LINKAGE void map_set_fill_detail_ops(MCInst *MI, bool Val)
{
	CS_ASSERT_RET(MI);
	if (!detail_is_set(MI)) {
		MI->fillDetailOps = false;
		return;
	}

	MI->fillDetailOps = Val;
}

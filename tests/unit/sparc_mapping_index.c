/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../Mapping.h"
#include "../../arch/Sparc/SparcMapping.h"
#include <limits.h>
#include <stdio.h>

static const insn_map rows[] = {
#include "../../arch/Sparc/SparcGenCSMappingInsn.inc"
};

int main(void)
{
	if (ARR_SIZE(rows) != INSTRUCTION_LIST_END)
		return 1;
	cs_struct handle = { 0 };
	handle.detail_opt = CS_OPT_ON;
	cs_insn record = { 0 };
	MCInst inst = { 0 };
	inst.csh = &handle;
	inst.flat_insn = &record;
	for (unsigned op = 0; op < ARR_SIZE(rows); ++op) {
		MCInst_setOpcode(&inst, op);
		record.id = UINT_MAX;
		record.detail = NULL;
		Sparc_set_instr_map_data(&inst);
		if (rows[op].id != op || record.id != rows[op].mapid) {
			fprintf(stderr, "Wrong SPARC mapping row for opcode %u\n", op);
			return 1;
		}
#ifndef CAPSTONE_DIET
		cs_detail detail = { 0 };
		record.id = UINT_MAX;
		record.detail = &detail;
		Sparc_set_instr_map_data(&inst);
		if (record.id != rows[op].mapid ||
		    detail.sparc.format != rows[op].suppl_info.sparc.form) {
			fprintf(stderr, "Wrong SPARC mapping detail for opcode %u\n", op);
			return 1;
		}
#endif
	}
	return 0;
}

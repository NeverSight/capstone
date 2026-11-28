/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../Mapping.h"
#include "../../utils.h"
#include "../../arch/Alpha/AlphaMapping.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define GET_INSTRINFO_ENUM
#include "../../arch/Alpha/AlphaGenInstrInfo.inc"

int main(void)
{
	if (Alpha_insn_count != INSTRUCTION_LIST_END)
		return 1;
	cs_insn record = { 0 };
	MCInst inst = { 0 };
	inst.flat_insn = &record;
	for (unsigned op = 0; op < Alpha_insn_count; ++op) {
		const insn_map *row = &Alpha_insns[op];
		MCInst_setOpcode(&inst, op);
		record.id = UINT_MAX;
		record.detail = NULL;
		Alpha_set_instr_map_data(&inst);
		if (row->id != op || record.id != row->mapid) {
			fprintf(stderr, "Wrong Alpha mapping row for opcode %u\n", op);
			return 1;
		}
#ifndef CAPSTONE_DIET
		cs_detail detail = { 0 };
		record.detail = &detail;
		record.id = UINT_MAX;
		Alpha_set_instr_map_data(&inst);
		if (record.id != row->mapid ||
		    memcmp(detail.regs_read, row->regs_use, sizeof(row->regs_use)) ||
		    memcmp(detail.regs_write, row->regs_mod, sizeof(row->regs_mod)) ||
		    memcmp(detail.groups, row->groups, sizeof(row->groups)) ||
		    detail.regs_read_count != count_positive(row->regs_use) ||
		    detail.regs_write_count != count_positive(row->regs_mod) ||
		    detail.groups_count != count_positive8(row->groups)) {
			fprintf(stderr, "Wrong Alpha mapping details for opcode %u\n", op);
			return 1;
		}
#endif
	}
	return 0;
}

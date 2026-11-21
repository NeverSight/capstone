/* SPDX-License-Identifier: BSD-3-Clause */
#include <limits.h>
#include <stdio.h>
#include "../../Mapping.h"
#include "../../utils.h"
#include "../../arch/RISCV/RISCVMapping.h"

static bool check_id(cs_struct *handle, unsigned id)
{
	const insn_map *expected = lookup_insn_map(handle, id);
	cs_insn insn = { 0 };
	insn.id = UINT_MAX;
	RISCV_get_insn_id(handle, &insn, id);
	if (insn.id != (expected ? expected->mapid : UINT_MAX)) {
		fprintf(stderr, "RISC-V mapping mismatch for input ID %u\n",
			id);
		return false;
	}
	return true;
}

#ifndef CAPSTONE_DIET
static bool check_alias_names(void)
{
	static const name_map names[] = {
#include "../../arch/RISCV/RISCVGenCSAliasMnemMap.inc"
	};
	cs_struct handle = { 0 };
	cs_insn flat = { 0 };
	MCInst mi = { 0 };
	SStream out = { 0 };
	handle.arch = CS_ARCH_RISCV;
	mi.csh = &handle;
	mi.flat_insn = &flat;
	mi.isAliasInstr = true;
	for (size_t i = 0; i < ARR_SIZE(names); ++i) {
		char *start = out.buffer + 2;
		out.buffer[0] = ' ';
		out.buffer[1] = '\t';
		const size_t len = strlen(names[i].name);
		for (size_t j = 0; j <= len; ++j) {
			for (unsigned c = 0; c <= UCHAR_MAX; ++c) {
				memcpy(start, names[i].name, len + 1);
				start[len + 1] = 0;
				start[j] = (char)c;
				map_set_alias_id(&mi, &out, names, ARR_SIZE(names));
				const uint64_t expected = flat.alias_id;
				RISCV_set_alias_id(&mi, &out);
				if (flat.alias_id != expected)
					return false;
			}
		}
	}
	return true;
}
#endif

int main(void)
{
#ifndef CAPSTONE_DIET
	if (!check_alias_names())
		return 1;
#endif
	for (unsigned i = 0; i < RISCV_insn_count; ++i) {
		if (RISCV_insns[i].id != i) {
			fprintf(stderr,
				"RISC-V mapping is not dense at row %u\n", i);
			return 1;
		}
	}
	const cs_mode modes[] = { CS_MODE_RISCV32, CS_MODE_RISCV64 };
	const unsigned wide_ids[] = { UINT16_MAX + 1U, UINT16_MAX + 2U,
				      UINT16_MAX + RISCV_insn_count, UINT_MAX };
	for (size_t mode = 0; mode < ARR_SIZE(modes); ++mode) {
		csh handle;
		cs_err error = cs_open(CS_ARCH_RISCV, modes[mode], &handle);
		if (error != CS_ERR_OK) {
			fprintf(stderr, "Cannot open RISC-V handle: error %u\n",
				error);
			return 1;
		}
		for (unsigned id = 0; id <= UINT16_MAX; ++id) {
			if (!check_id((cs_struct *)(uintptr_t)handle, id)) {
				cs_close(&handle);
				return 1;
			}
		}
		for (size_t i = 0; i < ARR_SIZE(wide_ids); ++i) {
			if (!check_id((cs_struct *)(uintptr_t)handle,
				      wide_ids[i])) {
				cs_close(&handle);
				return 1;
			}
		}
		cs_close(&handle);
	}
	return 0;
}

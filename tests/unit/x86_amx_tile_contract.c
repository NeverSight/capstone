/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct tile_case {
	const char *name;
	const uint8_t *code;
	size_t code_size;
	x86_insn id;
	const char *mnemonic;
	const char *intel_operands;
	const char *att_operands;
	uint8_t opcode[4];
	uint8_t address_size;
	x86_reg segment;
	bool has_memory;
	bool has_sib;
	x86_reg base;
	x86_reg index;
	int8_t scale;
	int64_t displacement;
	uint8_t memory_size;
	cs_ac_type memory_access;
	x86_reg tile;
	cs_ac_type tile_access;
	bool writes_all_tiles;
	uint8_t modrm_offset;
	uint8_t modrm;
	uint8_t sib;
	uint8_t displacement_offset;
	uint8_t displacement_size;
} tile_case;

static bool check(bool condition, const char *test, const char *message)
{
	if (!condition)
		fprintf(stderr, "AMX tile contract check failed (%s): %s\n",
			test, message);
	return condition;
}

static bool has_register(const cs_regs registers, uint8_t count, x86_reg reg)
{
	for (uint8_t i = 0; i < count; ++i) {
		if (registers[i] == reg)
			return true;
	}
	return false;
}

static uint8_t add_expected_register(x86_reg *registers, uint8_t count,
				     x86_reg reg)
{
	if (reg == X86_REG_INVALID)
		return count;
	for (uint8_t i = 0; i < count; ++i) {
		if (registers[i] == reg)
			return count;
	}
	registers[count] = reg;
	return count + 1;
}

static bool validate_detail(csh handle, const cs_insn *insn,
			    const tile_case *test, bool att_syntax)
{
	const cs_x86 *x86 = &insn->detail->x86;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	x86_reg expected_read[4] = { X86_REG_INVALID };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	uint8_t expected_read_count = 0;
	uint8_t memory_index = 0, tile_index = 0;
	uint8_t expected_op_count = 0;
	bool success = true;

	success &= check(
		x86->prefix[0] == 0 &&
			x86->prefix[1] ==
				(uint8_t)(test->segment == X86_REG_INVALID ?
						  0 :
						  test->code[0]) &&
			x86->prefix[2] == 0 &&
			x86->prefix[3] == (test->address_size == 4 ? 0x67 : 0),
		test->name, "legacy prefix detail is exact");
	success &= check(memcmp(x86->opcode, test->opcode,
				sizeof(test->opcode)) == 0,
			 test->name, "VEX/EVEX prefix detail is exact");
	success &= check(x86->addr_size == test->address_size, test->name,
			 "address size is exact");
	success &=
		check(x86->modrm == test->modrm &&
			      x86->encoding.modrm_offset == test->modrm_offset,
		      test->name, "ModR/M detail is exact");
	success &=
		check(x86->sib == test->sib, test->name, "SIB detail is exact");
	if (test->has_sib) {
		success &= check(x86->sib_base == test->base &&
					 x86->sib_index == test->index &&
					 x86->sib_scale == test->scale,
				 test->name, "SIB address detail is exact");
	}
	success &= check(x86->disp == test->displacement &&
				 x86->encoding.disp_offset ==
					 test->displacement_offset &&
				 x86->encoding.disp_size ==
					 test->displacement_size,
			 test->name, "displacement detail is exact");

	if (test->has_memory)
		++expected_op_count;
	if (test->tile != X86_REG_INVALID)
		++expected_op_count;
	success &= check(x86->op_count == expected_op_count, test->name,
			 "explicit operand count is exact");

	if (test->has_memory && test->tile != X86_REG_INVALID) {
		const bool store = test->id == X86_INS_TILESTORED;

		memory_index = att_syntax == store ? 1 : 0;
		tile_index = memory_index ^ 1;
	}
	if (test->has_memory && x86->op_count > memory_index) {
		const cs_x86_op *memory = &x86->operands[memory_index];

		success &= check(memory->type == X86_OP_MEM &&
					 memory->mem.segment == test->segment &&
					 memory->mem.base == test->base &&
					 memory->mem.index == test->index &&
					 memory->mem.scale == test->scale &&
					 memory->mem.disp == test->displacement,
				 test->name, "public memory address is exact");
		success &= check(memory->size == test->memory_size &&
					 memory->access == test->memory_access,
				 test->name,
				 "public memory size/access is exact");
	}
	if (test->tile != X86_REG_INVALID && x86->op_count > tile_index) {
		const cs_x86_op *tile = &x86->operands[tile_index];

		success &= check(tile->type == X86_OP_REG &&
					 tile->reg == test->tile &&
					 tile->size == 0 &&
					 tile->access == test->tile_access,
				 test->name, "public tile operand is exact");
	}

	/* TILECFG is state, not an addressable register.  The public register
	 * sets therefore expose address registers and architectural TMM effects. */
	if (test->has_memory) {
		expected_read_count = add_expected_register(
			expected_read, expected_read_count, test->segment);
		expected_read_count = add_expected_register(
			expected_read, expected_read_count, test->base);
		expected_read_count = add_expected_register(
			expected_read, expected_read_count, test->index);
	}
	if (test->tile_access & CS_AC_READ) {
		expected_read_count = add_expected_register(
			expected_read, expected_read_count, test->tile);
	}
	success &= check(cs_regs_access(handle, insn, regs_read,
					&regs_read_count, regs_write,
					&regs_write_count) == CS_ERR_OK,
			 test->name, "cs_regs_access succeeds");
	success &= check(regs_read_count == expected_read_count, test->name,
			 "read register count is exact");
	for (uint8_t i = 0; i < expected_read_count; ++i) {
		success &= check(has_register(regs_read, regs_read_count,
					      expected_read[i]),
				 test->name,
				 "expected read register is present");
	}
	if (test->writes_all_tiles) {
		success &= check(regs_write_count == 8, test->name,
				 "all TMM registers are implicit writes");
		for (x86_reg tile = X86_REG_TMM0; tile <= X86_REG_TMM7;
		     ++tile) {
			success &= check(has_register(regs_write,
						      regs_write_count, tile),
					 test->name,
					 "implicit TMM write is present");
		}
	} else if (test->tile_access & CS_AC_WRITE) {
		success &=
			check(regs_write_count == 1 &&
				      has_register(regs_write, regs_write_count,
						   test->tile),
			      test->name, "destination TMM write is exact");
	} else {
		success &=
			check(regs_write_count == 0, test->name,
			      "there are no synthetic state-register writes");
	}
	return success;
}

static bool test_case(csh handle, const tile_case *test, bool att_syntax)
{
	cs_insn *insn = NULL;
	const char *expected_operands = att_syntax ? test->att_operands :
						     test->intel_operands;
	size_t count;
	bool success = true;

	success &=
		check(cs_option(handle, CS_OPT_SYNTAX,
				att_syntax ? CS_OPT_SYNTAX_ATT :
					     CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
		      test->name, "syntax selection succeeds");
	count = cs_disasm(handle, test->code, test->code_size, 0x1000, 1,
			  &insn);
	if (!check(count == 1, test->name, "instruction decodes"))
		return false;
	success &= check(insn[0].size == test->code_size, test->name,
			 "instruction size is exact");
	success &= check(insn[0].id == test->id, test->name,
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, test->mnemonic) == 0,
			 test->name, "mnemonic is exact");
	if (strcmp(insn[0].op_str, expected_operands) != 0) {
		fprintf(stderr,
			"AMX tile contract check failed (%s): expected operands '%s', got '%s'\n",
			test->name, expected_operands, insn[0].op_str);
		success = false;
	}
	success &= check(strcmp(cs_insn_name(handle, insn[0].id),
				test->mnemonic) == 0,
			 test->name, "public instruction name is exact");
	success &= check(insn[0].detail != NULL, test->name,
			 "detail is available");
	if (insn[0].detail)
		success &= validate_detail(handle, &insn[0], test, att_syntax);
	cs_free(insn, count);
	return success;
}

static bool expect_invalid(csh handle, const uint8_t *code, size_t code_size,
			   const char *description)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (count != 0) {
		fprintf(stderr,
			"AMX tile contract check failed (%s): decoded as %s %s\n",
			description, insn[0].mnemonic, insn[0].op_str);
		cs_free(insn, count);
		return false;
	}
	return true;
}

static bool test_invalid_encodings(csh handle)
{
	static const uint8_t legacy_66[] = {
		0x66, 0xc4, 0xe2, 0x78, 0x49, 0x00
	};
	static const uint8_t legacy_lock_evex[] = { 0xf0, 0x62, 0xf2, 0x7c,
						    0x08, 0x49, 0x00 };
	static const uint8_t legacy_rex[] = {
		0x48, 0xc4, 0xe2, 0x78, 0x49, 0x00
	};
	static const uint8_t legacy_f3[] = {
		0xf3, 0xc4, 0xe2, 0x78, 0x49, 0x00
	};
	static const uint8_t vex_bad_vvvv[] = { 0xc4, 0xe2, 0x70, 0x49, 0x00 };
	static const uint8_t vex_bad_l[] = { 0xc4, 0xe2, 0x7c, 0x49, 0x00 };
	static const uint8_t vex_bad_w[] = { 0xc4, 0xe2, 0xf8, 0x49, 0x00 };
	static const uint8_t vex_cfg_reg[] = { 0xc4, 0xe2, 0x78, 0x49, 0x08 };
	static const uint8_t vex_cfg_register[] = { 0xc4, 0xe2, 0x79, 0x49,
						    0xc0 };
	static const uint8_t vex_release_modrm[] = { 0xc4, 0x02, 0x78, 0x49,
						     0xc1 };
	static const uint8_t vex_load_no_sib[] = { 0xc4, 0xe2, 0x7b, 0x4b,
						   0x00 };
	static const uint8_t vex_load_extended_tile[] = { 0xc4, 0x62, 0x7b,
							  0x4b, 0x0c, 0x18 };
	static const uint8_t vex_zero_extended_tile[] = { 0xc4, 0x62, 0x7b,
							  0x49, 0xf0 };
	static const uint8_t evex_bad_w[] = {
		0x62, 0xf2, 0xfc, 0x08, 0x49, 0x00
	};
	static const uint8_t evex_bad_vvvv[] = { 0x62, 0xf2, 0x74,
						 0x08, 0x49, 0x00 };
	static const uint8_t evex_bad_nf[] = { 0x62, 0xf2, 0x7c,
					       0x0c, 0x49, 0x00 };
	static const uint8_t evex_bad_vprime[] = { 0x62, 0xf2, 0x7c,
						   0x00, 0x49, 0x00 };
	static const uint8_t evex_bad_ll[] = { 0x62, 0xf2, 0x7c,
					       0x28, 0x49, 0x00 };
	static const uint8_t evex_bad_z[] = {
		0x62, 0xf2, 0x7c, 0x88, 0x49, 0x00
	};
	static const uint8_t evex_bad_b[] = {
		0x62, 0xf2, 0x7c, 0x18, 0x49, 0x00
	};
	static const uint8_t evex_bad_aaa[] = { 0x62, 0xf2, 0x7c,
						0x09, 0x49, 0x00 };
	static const uint8_t evex_cfg_reg[] = { 0x62, 0xf2, 0x7c,
						0x08, 0x49, 0x08 };
	static const uint8_t evex_cfg_register[] = { 0x62, 0xf2, 0x7d,
						     0x08, 0x49, 0xc0 };
	static const uint8_t evex_load_no_sib[] = { 0x62, 0xf2, 0x7f,
						    0x08, 0x4b, 0x00 };
	static const uint8_t evex_load_r3[] = { 0x62, 0x72, 0x7f, 0x08,
						0x4b, 0x0c, 0x18 };
	static const uint8_t evex_load_r4[] = { 0x62, 0xe2, 0x7f, 0x08,
						0x4b, 0x0c, 0x18 };
	static const uint8_t evex_load_bad_pp[] = { 0x62, 0xf2, 0x7c, 0x08,
						    0x4b, 0x0c, 0x18 };
	static const uint8_t evex_release[] = { 0x62, 0xf2, 0x7c,
						0x08, 0x49, 0xc0 };
	static const uint8_t evex_tilezero[] = { 0x62, 0xf2, 0x7f,
						 0x08, 0x49, 0xf0 };
	static const uint8_t vex_movrs_bad_pp[] = { 0xc4, 0xe2, 0x78,
						    0x4a, 0x0c, 0x18 };
	static const uint8_t evex_movrs_bad_pp[] = { 0x62, 0xf2, 0x7c, 0x08,
						     0x4a, 0x0c, 0x18 };
	static const uint8_t too_long[] = { 0x67, 0x67, 0x67, 0x67, 0x67, 0x67,
					    0x67, 0x67, 0x67, 0x67, 0x67, 0xc4,
					    0xe2, 0x78, 0x49, 0xc0 };
	static const struct {
		const uint8_t *code;
		size_t size;
		const char *description;
	} cases[] = {
		{ legacy_66, sizeof(legacy_66), "legacy 66 before VEX" },
		{ legacy_lock_evex, sizeof(legacy_lock_evex),
		  "LOCK before EVEX" },
		{ legacy_rex, sizeof(legacy_rex), "REX before VEX" },
		{ legacy_f3, sizeof(legacy_f3), "legacy F3 before VEX" },
		{ vex_bad_vvvv, sizeof(vex_bad_vvvv), "VEX.vvvv" },
		{ vex_bad_l, sizeof(vex_bad_l), "VEX.L" },
		{ vex_bad_w, sizeof(vex_bad_w), "VEX.W" },
		{ vex_cfg_reg, sizeof(vex_cfg_reg), "VEX tilecfg /reg" },
		{ vex_cfg_register, sizeof(vex_cfg_register),
		  "VEX tilecfg register form" },
		{ vex_release_modrm, sizeof(vex_release_modrm),
		  "TILERELEASE ModR/M" },
		{ vex_load_no_sib, sizeof(vex_load_no_sib),
		  "VEX tile load without SIB" },
		{ vex_load_extended_tile, sizeof(vex_load_extended_tile),
		  "VEX extended tile register" },
		{ vex_zero_extended_tile, sizeof(vex_zero_extended_tile),
		  "VEX TILEZERO extended tile register" },
		{ evex_bad_w, sizeof(evex_bad_w), "EVEX.W" },
		{ evex_bad_vvvv, sizeof(evex_bad_vvvv), "EVEX.vvvv" },
		{ evex_bad_nf, sizeof(evex_bad_nf), "EVEX.NF" },
		{ evex_bad_vprime, sizeof(evex_bad_vprime), "EVEX.V prime" },
		{ evex_bad_ll, sizeof(evex_bad_ll), "EVEX.LL" },
		{ evex_bad_z, sizeof(evex_bad_z), "EVEX.z" },
		{ evex_bad_b, sizeof(evex_bad_b), "EVEX.b" },
		{ evex_bad_aaa, sizeof(evex_bad_aaa), "EVEX.aaa" },
		{ evex_cfg_reg, sizeof(evex_cfg_reg), "EVEX tilecfg /reg" },
		{ evex_cfg_register, sizeof(evex_cfg_register),
		  "EVEX tilecfg register form" },
		{ evex_load_no_sib, sizeof(evex_load_no_sib),
		  "EVEX tile load without SIB" },
		{ evex_load_r3, sizeof(evex_load_r3),
		  "EVEX.R3 tile extension" },
		{ evex_load_r4, sizeof(evex_load_r4),
		  "EVEX.R4 tile extension" },
		{ evex_load_bad_pp, sizeof(evex_load_bad_pp),
		  "EVEX tile load mandatory prefix" },
		{ evex_release, sizeof(evex_release), "EVEX TILERELEASE" },
		{ evex_tilezero, sizeof(evex_tilezero), "EVEX TILEZERO" },
		{ vex_movrs_bad_pp, sizeof(vex_movrs_bad_pp),
		  "VEX TILELOADDRS mandatory prefix" },
		{ evex_movrs_bad_pp, sizeof(evex_movrs_bad_pp),
		  "EVEX TILELOADDRS mandatory prefix" },
		{ too_long, sizeof(too_long),
		  "instruction longer than 15 bytes" },
	};
	bool success = true;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		success &= expect_invalid(handle, cases[i].code, cases[i].size,
					  cases[i].description);
	}
	return success;
}

static bool test_non64_rejected(void)
{
	static const uint8_t vex[] = { 0xc4, 0xe2, 0x78, 0x49, 0x00 };
	static const uint8_t evex[] = { 0x62, 0xfa, 0x7c, 0x08, 0x49, 0x00 };
	csh handle = 0;
	bool success;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK,
		   "32-bit mode", "handle opens"))
		return false;
	success =
		expect_invalid(handle, vex, sizeof(vex), "VEX in 32-bit mode");
	success &= expect_invalid(handle, evex, sizeof(evex),
				  "EVEX in 32-bit mode");
	cs_close(&handle);
	return success;
}

int main(void)
{
	static const uint8_t release[] = { 0x64, 0x67, 0xc4, 0x02,
					   0x78, 0x49, 0xc0 };
	static const uint8_t zero[] = { 0xc4, 0x82, 0x7b, 0x49, 0xf0 };
	static const uint8_t vex_loadcfg_ignored_r[] = { 0xc4, 0x62, 0x78, 0x49,
							 0x00 };
	static const uint8_t vex_loadcfg_fs[] = { 0x64, 0xc4, 0xc2, 0x78,
						  0x49, 0x84, 0x85, 0x23,
						  0x01, 0x00, 0x00 };
	static const uint8_t vex_storecfg_gs32[] = { 0x65, 0x67, 0xc4, 0xe2,
						     0x79, 0x49, 0x05, 0x20,
						     0x00, 0x00, 0x00 };
	static const uint8_t vex_load_no_index[] = { 0xc4, 0xc2, 0x7b,
						     0x4b, 0x24, 0xe4 };
	static const uint8_t vex_loadt1_fs32[] = { 0x64, 0x67, 0xc4, 0xc2, 0x79,
						   0x4b, 0x54, 0x47, 0xf8 };
	static const uint8_t vex_loadrs_no_index[] = { 0xc4, 0xc2, 0x7b,
						       0x4a, 0x24, 0xe4 };
	static const uint8_t vex_loadrst1_fs32[] = { 0x64, 0x67, 0xc4,
						     0xc2, 0x79, 0x4a,
						     0x54, 0x47, 0xf8 };
	static const uint8_t vex_store_gs_absolute[] = { 0x65, 0xc4, 0xe2, 0x7a,
							 0x4b, 0x3c, 0x9d, 0x20,
							 0x00, 0x00, 0x00 };
	static const uint8_t evex_loadcfg_egpr[] = { 0x62, 0xba, 0x78, 0x08,
						     0x49, 0x44, 0xf8, 0x20 };
	static const uint8_t evex_loadcfg_ignored_r[] = { 0x62, 0x62, 0x7c,
							  0x08, 0x49, 0x00 };
	static const uint8_t evex_storecfg_fs32[] = { 0x64, 0x67, 0x62, 0xda,
						      0x7d, 0x08, 0x49, 0x07 };
	static const uint8_t evex_load_gs[] = { 0x65, 0x62, 0xba, 0x7b, 0x08,
						0x4b, 0x54, 0xb8, 0x20 };
	static const uint8_t evex_loadrs_gs[] = { 0x65, 0x62, 0xba, 0x7b, 0x08,
						  0x4a, 0x54, 0xb8, 0x20 };
	static const uint8_t evex_loadt1_no_index[] = {
		0x64, 0x62, 0xda, 0x7d, 0x08, 0x4b, 0x1c, 0xe7
	};
	static const uint8_t evex_store_gs32[] = {
		0x65, 0x67, 0x62, 0xda, 0x7a, 0x08, 0x4b, 0x7c, 0x47, 0xf8
	};
	static const uint8_t evex_loadrst1_gs32[] = { 0x65, 0x67, 0x62, 0xda,
						      0x79, 0x08, 0x4a, 0x7c,
						      0x47, 0xf8 };
	static const uint8_t evex_loadcfg_eip[] = { 0x64, 0x67, 0x62, 0xf2,
						    0x7c, 0x08, 0x49, 0x05,
						    0x20, 0x00, 0x00, 0x00 };
	static const uint8_t evex_load_absolute[] = { 0x62, 0xb2, 0x7b, 0x08,
						      0x4b, 0x2c, 0x7d, 0x78,
						      0x56, 0x34, 0x12 };
	static const tile_case cases[] = {
		{ "VEX TILERELEASE ignored extensions",
		  release,
		  sizeof(release),
		  X86_INS_TILERELEASE,
		  "tilerelease",
		  "",
		  "",
		  { 0xc4, 0x02, 0x78, 0 },
		  4,
		  X86_REG_FS,
		  false,
		  false,
		  X86_REG_INVALID,
		  X86_REG_INVALID,
		  1,
		  0,
		  0,
		  0,
		  X86_REG_INVALID,
		  0,
		  true,
		  6,
		  0xc0,
		  0,
		  0,
		  0 },
		{ "VEX TILEZERO ignored X/B",
		  zero,
		  sizeof(zero),
		  X86_INS_TILEZERO,
		  "tilezero",
		  "tmm6",
		  "%tmm6",
		  { 0xc4, 0x82, 0x7b, 0 },
		  8,
		  X86_REG_INVALID,
		  false,
		  false,
		  X86_REG_INVALID,
		  X86_REG_INVALID,
		  1,
		  0,
		  0,
		  0,
		  X86_REG_TMM6,
		  CS_AC_WRITE,
		  false,
		  4,
		  0xf0,
		  0,
		  0,
		  0 },
		{ "VEX LDTILECFG ignored R",
		  vex_loadcfg_ignored_r,
		  sizeof(vex_loadcfg_ignored_r),
		  X86_INS_LDTILECFG,
		  "ldtilecfg",
		  "[rax]",
		  "(%rax)",
		  { 0xc4, 0x62, 0x78, 0 },
		  8,
		  X86_REG_INVALID,
		  true,
		  false,
		  X86_REG_RAX,
		  X86_REG_INVALID,
		  1,
		  0,
		  64,
		  CS_AC_READ,
		  X86_REG_INVALID,
		  0,
		  true,
		  4,
		  0x00,
		  0,
		  0,
		  0 },
		{ "VEX LDTILECFG FS",
		  vex_loadcfg_fs,
		  sizeof(vex_loadcfg_fs),
		  X86_INS_LDTILECFG,
		  "ldtilecfg",
		  "fs:[r13 + rax*4 + 0x123]",
		  "%fs:0x123(%r13,%rax,4)",
		  { 0xc4, 0xc2, 0x78, 0 },
		  8,
		  X86_REG_FS,
		  true,
		  true,
		  X86_REG_R13,
		  X86_REG_RAX,
		  4,
		  0x123,
		  64,
		  CS_AC_READ,
		  X86_REG_INVALID,
		  0,
		  true,
		  5,
		  0x84,
		  0x85,
		  7,
		  4 },
		{ "VEX STTILECFG GS addr32",
		  vex_storecfg_gs32,
		  sizeof(vex_storecfg_gs32),
		  X86_INS_STTILECFG,
		  "sttilecfg",
		  "gs:[eip + 0x20]",
		  "%gs:0x20(%eip)",
		  { 0xc4, 0xe2, 0x79, 0 },
		  4,
		  X86_REG_GS,
		  true,
		  false,
		  X86_REG_EIP,
		  X86_REG_INVALID,
		  1,
		  0x20,
		  64,
		  CS_AC_WRITE,
		  X86_REG_INVALID,
		  0,
		  false,
		  6,
		  0x05,
		  0,
		  7,
		  4 },
		{ "VEX TILELOADD zero stride",
		  vex_load_no_index,
		  sizeof(vex_load_no_index),
		  X86_INS_TILELOADD,
		  "tileloadd",
		  "tmm4, [r12]",
		  "(%r12), %tmm4",
		  { 0xc4, 0xc2, 0x7b, 0 },
		  8,
		  X86_REG_INVALID,
		  true,
		  true,
		  X86_REG_R12,
		  X86_REG_INVALID,
		  8,
		  0,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM4,
		  CS_AC_WRITE,
		  false,
		  4,
		  0x24,
		  0xe4,
		  0,
		  0 },
		{ "VEX TILELOADDT1 FS addr32",
		  vex_loadt1_fs32,
		  sizeof(vex_loadt1_fs32),
		  X86_INS_TILELOADDT1,
		  "tileloaddt1",
		  "tmm2, fs:[r15d + eax*2 - 0x8]",
		  "%fs:-0x8(%r15d,%eax,2), %tmm2",
		  { 0xc4, 0xc2, 0x79, 0 },
		  4,
		  X86_REG_FS,
		  true,
		  true,
		  X86_REG_R15D,
		  X86_REG_EAX,
		  2,
		  -8,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM2,
		  CS_AC_WRITE,
		  false,
		  6,
		  0x54,
		  0x47,
		  8,
		  1 },
		{ "VEX TILELOADDRS zero stride",
		  vex_loadrs_no_index,
		  sizeof(vex_loadrs_no_index),
		  X86_INS_TILELOADDRS,
		  "tileloaddrs",
		  "tmm4, [r12]",
		  "(%r12), %tmm4",
		  { 0xc4, 0xc2, 0x7b, 0 },
		  8,
		  X86_REG_INVALID,
		  true,
		  true,
		  X86_REG_R12,
		  X86_REG_INVALID,
		  8,
		  0,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM4,
		  CS_AC_WRITE,
		  false,
		  4,
		  0x24,
		  0xe4,
		  0,
		  0 },
		{ "VEX TILELOADDRST1 FS addr32",
		  vex_loadrst1_fs32,
		  sizeof(vex_loadrst1_fs32),
		  X86_INS_TILELOADDRST1,
		  "tileloaddrst1",
		  "tmm2, fs:[r15d + eax*2 - 0x8]",
		  "%fs:-0x8(%r15d,%eax,2), %tmm2",
		  { 0xc4, 0xc2, 0x79, 0 },
		  4,
		  X86_REG_FS,
		  true,
		  true,
		  X86_REG_R15D,
		  X86_REG_EAX,
		  2,
		  -8,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM2,
		  CS_AC_WRITE,
		  false,
		  6,
		  0x54,
		  0x47,
		  8,
		  1 },
		{ "VEX TILESTORED GS absolute",
		  vex_store_gs_absolute,
		  sizeof(vex_store_gs_absolute),
		  X86_INS_TILESTORED,
		  "tilestored",
		  "gs:[rbx*4 + 0x20], tmm7",
		  "%tmm7, %gs:0x20(,%rbx,4)",
		  { 0xc4, 0xe2, 0x7a, 0 },
		  8,
		  X86_REG_GS,
		  true,
		  true,
		  X86_REG_INVALID,
		  X86_REG_RBX,
		  4,
		  0x20,
		  0,
		  CS_AC_WRITE,
		  X86_REG_TMM7,
		  CS_AC_READ,
		  false,
		  5,
		  0x3c,
		  0x9d,
		  7,
		  4 },
		{ "EVEX LDTILECFG EGPR",
		  evex_loadcfg_egpr,
		  sizeof(evex_loadcfg_egpr),
		  X86_INS_LDTILECFG,
		  "ldtilecfg",
		  "[r16 + r31*8 + 0x20]",
		  "0x20(%r16,%r31,8)",
		  { 0x62, 0xba, 0x78, 0x08 },
		  8,
		  X86_REG_INVALID,
		  true,
		  true,
		  X86_REG_R16,
		  X86_REG_R31,
		  8,
		  0x20,
		  64,
		  CS_AC_READ,
		  X86_REG_INVALID,
		  0,
		  true,
		  5,
		  0x44,
		  0xf8,
		  7,
		  1 },
		{ "EVEX LDTILECFG ignored R3/R4",
		  evex_loadcfg_ignored_r,
		  sizeof(evex_loadcfg_ignored_r),
		  X86_INS_LDTILECFG,
		  "ldtilecfg",
		  "[rax]",
		  "(%rax)",
		  { 0x62, 0x62, 0x7c, 0x08 },
		  8,
		  X86_REG_INVALID,
		  true,
		  false,
		  X86_REG_RAX,
		  X86_REG_INVALID,
		  1,
		  0,
		  64,
		  CS_AC_READ,
		  X86_REG_INVALID,
		  0,
		  true,
		  5,
		  0x00,
		  0,
		  0,
		  0 },
		{ "EVEX STTILECFG FS addr32",
		  evex_storecfg_fs32,
		  sizeof(evex_storecfg_fs32),
		  X86_INS_STTILECFG,
		  "sttilecfg",
		  "fs:[r31d]",
		  "%fs:(%r31d)",
		  { 0x62, 0xda, 0x7d, 0x08 },
		  4,
		  X86_REG_FS,
		  true,
		  false,
		  X86_REG_R31D,
		  X86_REG_INVALID,
		  1,
		  0,
		  64,
		  CS_AC_WRITE,
		  X86_REG_INVALID,
		  0,
		  false,
		  7,
		  0x07,
		  0,
		  0,
		  0 },
		{ "EVEX TILELOADD GS EGPR",
		  evex_load_gs,
		  sizeof(evex_load_gs),
		  X86_INS_TILELOADD,
		  "tileloadd",
		  "tmm2, gs:[r16 + r31*4 + 0x20]",
		  "%gs:0x20(%r16,%r31,4), %tmm2",
		  { 0x62, 0xba, 0x7b, 0x08 },
		  8,
		  X86_REG_GS,
		  true,
		  true,
		  X86_REG_R16,
		  X86_REG_R31,
		  4,
		  0x20,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM2,
		  CS_AC_WRITE,
		  false,
		  6,
		  0x54,
		  0xb8,
		  8,
		  1 },
		{ "EVEX TILELOADDRS GS EGPR",
		  evex_loadrs_gs,
		  sizeof(evex_loadrs_gs),
		  X86_INS_TILELOADDRS,
		  "tileloaddrs",
		  "tmm2, gs:[r16 + r31*4 + 0x20]",
		  "%gs:0x20(%r16,%r31,4), %tmm2",
		  { 0x62, 0xba, 0x7b, 0x08 },
		  8,
		  X86_REG_GS,
		  true,
		  true,
		  X86_REG_R16,
		  X86_REG_R31,
		  4,
		  0x20,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM2,
		  CS_AC_WRITE,
		  false,
		  6,
		  0x54,
		  0xb8,
		  8,
		  1 },
		{ "EVEX TILELOADDT1 zero stride",
		  evex_loadt1_no_index,
		  sizeof(evex_loadt1_no_index),
		  X86_INS_TILELOADDT1,
		  "tileloaddt1",
		  "tmm3, fs:[r31]",
		  "%fs:(%r31), %tmm3",
		  { 0x62, 0xda, 0x7d, 0x08 },
		  8,
		  X86_REG_FS,
		  true,
		  true,
		  X86_REG_R31,
		  X86_REG_INVALID,
		  8,
		  0,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM3,
		  CS_AC_WRITE,
		  false,
		  6,
		  0x1c,
		  0xe7,
		  0,
		  0 },
		{ "EVEX TILESTORED GS addr32",
		  evex_store_gs32,
		  sizeof(evex_store_gs32),
		  X86_INS_TILESTORED,
		  "tilestored",
		  "gs:[r31d + r16d*2 - 0x8], tmm7",
		  "%tmm7, %gs:-0x8(%r31d,%r16d,2)",
		  { 0x62, 0xda, 0x7a, 0x08 },
		  4,
		  X86_REG_GS,
		  true,
		  true,
		  X86_REG_R31D,
		  X86_REG_R16D,
		  2,
		  -8,
		  0,
		  CS_AC_WRITE,
		  X86_REG_TMM7,
		  CS_AC_READ,
		  false,
		  7,
		  0x7c,
		  0x47,
		  9,
		  1 },
		{ "EVEX TILELOADDRST1 GS addr32",
		  evex_loadrst1_gs32,
		  sizeof(evex_loadrst1_gs32),
		  X86_INS_TILELOADDRST1,
		  "tileloaddrst1",
		  "tmm7, gs:[r31d + r16d*2 - 0x8]",
		  "%gs:-0x8(%r31d,%r16d,2), %tmm7",
		  { 0x62, 0xda, 0x79, 0x08 },
		  4,
		  X86_REG_GS,
		  true,
		  true,
		  X86_REG_R31D,
		  X86_REG_R16D,
		  2,
		  -8,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM7,
		  CS_AC_WRITE,
		  false,
		  7,
		  0x7c,
		  0x47,
		  9,
		  1 },
		{ "EVEX LDTILECFG EIP relative",
		  evex_loadcfg_eip,
		  sizeof(evex_loadcfg_eip),
		  X86_INS_LDTILECFG,
		  "ldtilecfg",
		  "fs:[eip + 0x20]",
		  "%fs:0x20(%eip)",
		  { 0x62, 0xf2, 0x7c, 0x08 },
		  4,
		  X86_REG_FS,
		  true,
		  false,
		  X86_REG_EIP,
		  X86_REG_INVALID,
		  1,
		  0x20,
		  64,
		  CS_AC_READ,
		  X86_REG_INVALID,
		  0,
		  true,
		  7,
		  0x05,
		  0,
		  8,
		  4 },
		{ "EVEX TILELOADD absolute EGPR index",
		  evex_load_absolute,
		  sizeof(evex_load_absolute),
		  X86_INS_TILELOADD,
		  "tileloadd",
		  "tmm5, [r31*2 + 0x12345678]",
		  "0x12345678(,%r31,2), %tmm5",
		  { 0x62, 0xb2, 0x7b, 0x08 },
		  8,
		  X86_REG_INVALID,
		  true,
		  true,
		  X86_REG_INVALID,
		  X86_REG_R31,
		  2,
		  0x12345678,
		  0,
		  CS_AC_READ,
		  X86_REG_TMM5,
		  CS_AC_WRITE,
		  false,
		  5,
		  0x2c,
		  0x7d,
		  7,
		  4 },
	};
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "64-bit mode", "handle opens"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "64-bit mode", "detail enables")) {
		cs_close(&handle);
		return 1;
	}
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		success &= test_case(handle, &cases[i], false);
		success &= test_case(handle, &cases[i], true);
	}
	success &= test_invalid_encodings(handle);
	cs_close(&handle);
	success &= test_non64_rejected();
	return success ? 0 : 1;
}

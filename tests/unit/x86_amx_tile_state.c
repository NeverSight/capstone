/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "AMX tile-state public API check failed: %s\n",
			message);
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

typedef struct amx_case {
	const uint8_t *code;
	size_t code_size;
	x86_insn id;
	const char *mnemonic;
	const char *op_str;
	uint8_t op_count;
	int8_t memory_index;
	int8_t tile_index;
	x86_reg base;
	x86_reg index;
	int8_t scale;
	int64_t displacement;
	uint8_t memory_size;
	cs_ac_type memory_access;
	x86_reg tile;
	cs_ac_type tile_access;
	uint8_t modrm_offset;
	uint8_t modrm;
	uint8_t sib;
	uint8_t displacement_offset;
	uint8_t displacement_size;
} amx_case;

static uint8_t expected_register_count(x86_reg first, x86_reg second,
				       x86_reg third)
{
	uint8_t count = 0;

	if (first != X86_REG_INVALID)
		++count;
	if (second != X86_REG_INVALID && second != first)
		++count;
	if (third != X86_REG_INVALID && third != first && third != second)
		++count;
	return count;
}

static bool test_case(csh handle, const amx_case *test)
{
	cs_insn *insn = NULL;
	bool success = true;
	size_t count =
		cs_disasm(handle, test->code, test->code_size, 0x1000, 1, &insn);

	if (!check(count == 1, "instruction decodes"))
		return false;

	success &= check(insn[0].size == test->code_size,
			 "instruction size is exact");
	success &= check(insn[0].id == test->id, "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, test->mnemonic) == 0,
			 "mnemonic is exact");
	if (strcmp(insn[0].op_str, test->op_str) != 0) {
		fprintf(stderr,
			"AMX tile-state public API check failed: %s operands expected '%s', got '%s'\n",
			test->mnemonic, test->op_str, insn[0].op_str);
		success = false;
	}
	success &= check(strcmp(cs_insn_name(handle, insn[0].id), test->mnemonic) ==
				 0,
			 "public instruction name is exact");
	success &= check(insn[0].detail != NULL, "detail is available");

	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		cs_regs regs_read = { 0 };
		cs_regs regs_write = { 0 };
		uint8_t regs_read_count = 0;
		uint8_t regs_write_count = 0;
		x86_reg expected_read_1 = test->base;
		x86_reg expected_read_2 = test->index;
		x86_reg expected_read_3 =
			test->tile_access & CS_AC_READ ? test->tile : X86_REG_INVALID;
		x86_reg expected_write =
			test->tile_access & CS_AC_WRITE ? test->tile : X86_REG_INVALID;
		bool writes_all_tiles = test->id == X86_INS_LDTILECFG ||
					test->id == X86_INS_TILERELEASE;
		uint8_t expected_write_count =
			writes_all_tiles ? 8 :
			(expected_write == X86_REG_INVALID ? 0 : 1);

		success &= check(x86->opcode[0] == test->code[0] &&
					 x86->opcode[1] == test->code[1] &&
					 x86->opcode[2] == test->code[2] &&
					 x86->opcode[3] == 0,
				 "VEX prefix detail is exact");
		success &= check(x86->addr_size == 8, "address size is 64-bit");
		success &= check(x86->modrm == test->modrm,
				 "ModR/M detail is exact");
		success &= check(x86->encoding.modrm_offset == test->modrm_offset,
				 "ModR/M offset is exact");
		success &= check(x86->sib == test->sib, "SIB detail is exact");
		if ((test->modrm & 0xc0) != 0xc0 && (test->modrm & 7) == 4) {
			success &= check(x86->sib_base == test->base &&
						 x86->sib_index == test->index &&
						 x86->sib_scale == test->scale,
					 "decoded SIB address detail is exact");
		}
		success &= check(x86->disp == test->displacement,
				 "displacement detail is exact");
		success &= check(x86->encoding.disp_offset ==
					 test->displacement_offset &&
					 x86->encoding.disp_size ==
						 test->displacement_size,
				 "displacement encoding detail is exact");
		success &= check(x86->op_count == test->op_count,
				 "explicit operand count is exact");

		if (test->memory_index >= 0 &&
		    x86->op_count > (uint8_t)test->memory_index) {
			const cs_x86_op *memory = &x86->operands[test->memory_index];
			success &= check(memory->type == X86_OP_MEM,
					 "memory operand type is exact");
			success &= check(memory->mem.segment == X86_REG_INVALID &&
						 memory->mem.base == test->base &&
						 memory->mem.index == test->index &&
						 memory->mem.scale == test->scale &&
						 memory->mem.disp == test->displacement,
					 "memory address detail is exact");
			success &= check(memory->size == test->memory_size,
					 "memory operand size is exact");
			success &= check(memory->access == test->memory_access,
					 "memory operand access is exact");
		}

		if (test->tile_index >= 0 &&
		    x86->op_count > (uint8_t)test->tile_index) {
			const cs_x86_op *tile = &x86->operands[test->tile_index];
			success &= check(tile->type == X86_OP_REG &&
						 tile->reg == test->tile,
					 "tile operand ID is exact");
			success &= check(tile->size == 0,
					 "runtime-configured tile size is unknown");
			success &= check(tile->access == test->tile_access,
					 "tile operand access is exact");
		}

		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(regs_read_count == expected_register_count(
							 expected_read_1,
							 expected_read_2,
							 expected_read_3),
				 "read register count is exact");
		if (expected_read_1 != X86_REG_INVALID)
			success &= check(has_register(regs_read, regs_read_count,
						      expected_read_1),
					 "base register is read");
		if (expected_read_2 != X86_REG_INVALID)
			success &= check(has_register(regs_read, regs_read_count,
						      expected_read_2),
					 "index register is read");
		if (expected_read_3 != X86_REG_INVALID)
			success &= check(has_register(regs_read, regs_read_count,
						      expected_read_3),
					 "tile register is read");
		success &= check(regs_write_count == expected_write_count,
				 "written register count is exact");
		if (writes_all_tiles) {
			for (x86_reg tile = X86_REG_TMM0; tile <= X86_REG_TMM7;
			     ++tile) {
				success &= check(has_register(regs_write, regs_write_count,
							      tile),
						 "tile-state reset writes every TMM register");
			}
		} else if (expected_write != X86_REG_INVALID) {
			success &= check(has_register(regs_write, regs_write_count,
						      expected_write),
					 "tile register is written");
		}
	}

	cs_free(insn, count);
	return success;
}

static bool test_att_syntax(csh handle)
{
	static const uint8_t load[] = { 0xc4, 0x82, 0x79, 0x4b, 0x14, 0x6c };
	static const uint8_t store[] = { 0xc4, 0x82, 0x7a, 0x4b, 0x3c, 0xbe };
	cs_insn *insn = NULL;
	bool success = true;
	size_t count;

	if (!check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
			   CS_ERR_OK,
		   "select AT&T syntax"))
		return false;

	count = cs_disasm(handle, load, sizeof(load), 0x1000, 1, &insn);
	success &= check(count == 1, "tile load decodes in AT&T syntax");
	if (count == 1) {
		success &= check(strcmp(insn[0].mnemonic, "tileloaddt1") == 0 &&
					 strcmp(insn[0].op_str,
						"(%r12,%r13,2), %tmm2") == 0,
				 "AT&T tile-load text is exact");
		if (insn[0].detail != NULL) {
			const cs_x86 *x86 = &insn[0].detail->x86;
			success &= check(x86->op_count == 2 &&
						 x86->operands[0].type == X86_OP_MEM &&
						 x86->operands[0].access == CS_AC_READ &&
						 x86->operands[1].reg == X86_REG_TMM2 &&
						 x86->operands[1].access == CS_AC_WRITE,
					 "AT&T tile-load detail follows printed order");
		}
	}
	cs_free(insn, count);

	insn = NULL;
	count = cs_disasm(handle, store, sizeof(store), 0x1000, 1, &insn);
	success &= check(count == 1, "tile store decodes in AT&T syntax");
	if (count == 1) {
		success &= check(strcmp(insn[0].mnemonic, "tilestored") == 0 &&
					 strcmp(insn[0].op_str,
						"%tmm7, (%r14,%r15,4)") == 0,
				 "AT&T tile-store text is exact");
		if (insn[0].detail != NULL) {
			const cs_x86 *x86 = &insn[0].detail->x86;
			success &= check(x86->op_count == 2 &&
						 x86->operands[0].reg == X86_REG_TMM7 &&
						 x86->operands[0].access == CS_AC_READ &&
						 x86->operands[1].type == X86_OP_MEM &&
						 x86->operands[1].access == CS_AC_WRITE,
					 "AT&T tile-store detail follows printed order");
		}
	}
	cs_free(insn, count);

	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL) ==
				 CS_ERR_OK,
			 "restore Intel syntax");
	return success;
}

static bool expect_invalid(csh handle, const uint8_t *code, size_t code_size,
			   const char *description)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (count != 0) {
		fprintf(stderr,
			"AMX tile-state public API check failed: %s decoded as %s %s\n",
			description, insn[0].mnemonic, insn[0].op_str);
		cs_free(insn, count);
		return false;
	}
	return true;
}

static bool test_invalid_encodings(csh handle)
{
	static const uint8_t invalid_release_modrm[] = { 0xc4, 0xe2, 0x78, 0x49,
							0xc1 };
	static const uint8_t invalid_release_l[] = { 0xc4, 0xe2, 0x7c, 0x49,
						    0xc0 };
	static const uint8_t invalid_release_w[] = { 0xc4, 0xe2, 0xf8, 0x49,
						    0xc0 };
	static const uint8_t invalid_release_vvvv[] = { 0xc4, 0xe2, 0x70, 0x49,
						       0xc0 };
	static const uint8_t invalid_release_extension[] = { 0xc4, 0xc2, 0x78,
							    0x49, 0xc0 };
	static const uint8_t invalid_cfg_reg[] = { 0xc4, 0xe2, 0x78, 0x49, 0x08 };
	static const uint8_t invalid_cfg_register_form[] = { 0xc4, 0xe2, 0x79,
							    0x49, 0xc0 };
	static const uint8_t invalid_cfg_pp[] = { 0xc4, 0xe2, 0x7a, 0x49, 0x00 };
	static const uint8_t invalid_cfg_r[] = { 0xc4, 0x62, 0x78, 0x49, 0x00 };
	static const uint8_t truncated_cfg_disp[] = { 0xc4, 0xe2, 0x78, 0x49,
						     0x05, 0x01, 0x02 };
	static const uint8_t invalid_load_without_sib[] = { 0xc4, 0xe2, 0x7b,
							   0x4b, 0x00 };
	static const uint8_t invalid_load_register_form[] = { 0xc4, 0xe2, 0x7b,
							     0x4b, 0xc0 };
	static const uint8_t invalid_load_pp[] = { 0xc4, 0xe2, 0x78, 0x4b,
						     0x04, 0x20 };
	static const uint8_t truncated_load_sib[] = { 0xc4, 0xe2, 0x7b, 0x4b,
						     0x04 };
	static const uint8_t invalid_tilezero_rm[] = { 0xc4, 0xe2, 0x7b, 0x49,
						      0xf1 };
	static const uint8_t unsupported_tdpbssd[] = { 0xc4, 0xe2, 0x63, 0x5e,
						      0xca };
	static const uint8_t unsupported_tileloaddrs[] = { 0xc4, 0xe2, 0x7b,
							  0x4a, 0x0c, 0x18 };
	bool success = true;

	success &= expect_invalid(handle, invalid_release_modrm,
				  sizeof(invalid_release_modrm),
				  "reserved TILERELEASE ModR/M");
	success &= expect_invalid(handle, invalid_release_l,
				  sizeof(invalid_release_l),
				  "reserved TILERELEASE VEX.L");
	success &= expect_invalid(handle, invalid_release_w,
				  sizeof(invalid_release_w),
				  "reserved TILERELEASE VEX.W");
	success &= expect_invalid(handle, invalid_release_vvvv,
				  sizeof(invalid_release_vvvv),
				  "reserved TILERELEASE VEX.vvvv");
	success &= expect_invalid(handle, invalid_release_extension,
				  sizeof(invalid_release_extension),
				  "reserved TILERELEASE VEX.X/B");
	success &= expect_invalid(handle, invalid_cfg_reg, sizeof(invalid_cfg_reg),
				  "reserved tilecfg ModR/M.reg");
	success &= expect_invalid(handle, invalid_cfg_register_form,
				  sizeof(invalid_cfg_register_form),
				  "reserved tilecfg register form");
	success &= expect_invalid(handle, invalid_cfg_pp, sizeof(invalid_cfg_pp),
				  "reserved tilecfg mandatory prefix");
	success &= expect_invalid(handle, invalid_cfg_r, sizeof(invalid_cfg_r),
				  "reserved tilecfg VEX.R");
	success &= expect_invalid(handle, truncated_cfg_disp,
				  sizeof(truncated_cfg_disp),
				  "truncated tilecfg displacement");
	success &= expect_invalid(handle, invalid_load_without_sib,
				  sizeof(invalid_load_without_sib),
				  "tile load without required SIB");
	success &= expect_invalid(handle, invalid_load_register_form,
				  sizeof(invalid_load_register_form),
				  "reserved tile-load register form");
	success &= expect_invalid(handle, invalid_load_pp,
				  sizeof(invalid_load_pp),
				  "reserved tile-load mandatory prefix");
	success &= expect_invalid(handle, truncated_load_sib,
				  sizeof(truncated_load_sib),
				  "truncated tile-load SIB");
	success &= expect_invalid(handle, invalid_tilezero_rm,
				  sizeof(invalid_tilezero_rm),
				  "reserved TILEZERO r/m field");
	success &= expect_invalid(handle, unsupported_tdpbssd,
				  sizeof(unsupported_tdpbssd),
				  "unimplemented AMX opcode");
	success &= expect_invalid(handle, unsupported_tileloaddrs,
				  sizeof(unsupported_tileloaddrs),
				  "unimplemented AMX tile-load opcode");
	return success;
}

static bool test_non64_rejected(void)
{
	static const uint8_t release[] = { 0xc4, 0xe2, 0x78, 0x49, 0xc0 };
	csh handle = 0;
	bool success;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK,
		   "open 32-bit mode"))
		return false;
	success = expect_invalid(handle, release, sizeof(release),
				 "AMX is not valid outside 64-bit mode");
	cs_close(&handle);
	return success;
}

int main(void)
{
	static const uint8_t release[] = { 0xc4, 0xe2, 0x78, 0x49, 0xc0 };
	static const uint8_t loadcfg[] = { 0xc4, 0xe2, 0x78, 0x49, 0x00 };
	static const uint8_t storecfg[] = { 0xc4, 0xc2, 0x79, 0x49, 0x07 };
	static const uint8_t loadd[] = { 0xc4, 0xe2, 0x7b, 0x4b, 0x0c, 0x18 };
	static const uint8_t loaddt1[] = { 0xc4, 0x82, 0x79, 0x4b, 0x14, 0x6c };
	static const uint8_t stored[] = { 0xc4, 0x82, 0x7a, 0x4b, 0x3c, 0xbe };
	static const uint8_t rip_cfg[] = { 0xc4, 0xe2, 0x78, 0x49, 0x05,
					   0x20, 0x00, 0x00, 0x00 };
	static const uint8_t sib_cfg[] = { 0xc4, 0xc2, 0x78, 0x49, 0x84,
					   0x80, 0x23, 0x01, 0x00, 0x00 };
	static const uint8_t no_index_load[] = { 0xc4, 0xc2, 0x7b, 0x4b, 0x24,
						0x24 };
	static const uint8_t no_base_load[] = { 0xc4, 0xe2, 0x7b, 0x4b, 0x2c,
					       0x5d, 0x20, 0x00, 0x00, 0x00 };
	static const uint8_t negative_cfg[] = { 0xc4, 0xc2, 0x78, 0x49, 0x45,
						0xf8 };
	static const uint8_t zero[] = { 0xc4, 0xe2, 0x7b, 0x49, 0xf0 };
	static const amx_case cases[] = {
		{ release, sizeof(release), X86_INS_TILERELEASE, "tilerelease", "",
		  0, -1, -1, X86_REG_INVALID, X86_REG_INVALID, 1, 0, 0, 0,
		  X86_REG_INVALID, 0, 4, 0xc0, 0, 0, 0 },
		{ loadcfg, sizeof(loadcfg), X86_INS_LDTILECFG, "ldtilecfg", "[rax]",
		  1, 0, -1, X86_REG_RAX, X86_REG_INVALID, 1, 0, 64,
		  CS_AC_READ, X86_REG_INVALID, 0, 4, 0x00, 0, 0, 0 },
		{ storecfg, sizeof(storecfg), X86_INS_STTILECFG, "sttilecfg",
		  "[r15]", 1, 0, -1, X86_REG_R15, X86_REG_INVALID, 1, 0, 64,
		  CS_AC_WRITE, X86_REG_INVALID, 0, 4, 0x07, 0, 0, 0 },
		{ loadd, sizeof(loadd), X86_INS_TILELOADD, "tileloadd",
		  "tmm1, [rax + rbx]", 2, 1, 0, X86_REG_RAX, X86_REG_RBX, 1,
		  0, 0, CS_AC_READ, X86_REG_TMM1, CS_AC_WRITE, 4, 0x0c, 0x18,
		  0, 0 },
		{ loaddt1, sizeof(loaddt1), X86_INS_TILELOADDT1, "tileloaddt1",
		  "tmm2, [r12 + r13*2]", 2, 1, 0, X86_REG_R12, X86_REG_R13, 2,
		  0, 0, CS_AC_READ, X86_REG_TMM2, CS_AC_WRITE, 4, 0x14, 0x6c,
		  0, 0 },
		{ stored, sizeof(stored), X86_INS_TILESTORED, "tilestored",
		  "[r14 + r15*4], tmm7", 2, 0, 1, X86_REG_R14, X86_REG_R15, 4,
		  0, 0, CS_AC_WRITE, X86_REG_TMM7, CS_AC_READ, 4, 0x3c, 0xbe,
		  0, 0 },
		{ rip_cfg, sizeof(rip_cfg), X86_INS_LDTILECFG, "ldtilecfg",
		  "[rip + 0x20]", 1, 0, -1, X86_REG_RIP, X86_REG_INVALID, 1,
		  0x20, 64, CS_AC_READ, X86_REG_INVALID, 0, 4, 0x05, 0, 5, 4 },
		{ sib_cfg, sizeof(sib_cfg), X86_INS_LDTILECFG, "ldtilecfg",
		  "[r8 + rax*4 + 0x123]", 1, 0, -1, X86_REG_R8, X86_REG_RAX,
		  4, 0x123, 64, CS_AC_READ, X86_REG_INVALID, 0, 4, 0x84, 0x80,
		  6, 4 },
		{ no_index_load, sizeof(no_index_load), X86_INS_TILELOADD,
		  "tileloadd", "tmm4, [r12]", 2, 1, 0, X86_REG_R12,
		  X86_REG_INVALID, 1, 0, 0, CS_AC_READ, X86_REG_TMM4,
		  CS_AC_WRITE, 4, 0x24, 0x24, 0, 0 },
		{ no_base_load, sizeof(no_base_load), X86_INS_TILELOADD, "tileloadd",
		  "tmm5, [rbx*2 + 0x20]", 2, 1, 0, X86_REG_INVALID, X86_REG_RBX,
		  2, 0x20, 0, CS_AC_READ, X86_REG_TMM5, CS_AC_WRITE, 4, 0x2c,
		  0x5d, 6, 4 },
		{ negative_cfg, sizeof(negative_cfg), X86_INS_LDTILECFG, "ldtilecfg",
		  "[r13 - 0x8]", 1, 0, -1, X86_REG_R13, X86_REG_INVALID, 1, -8,
		  64, CS_AC_READ, X86_REG_INVALID, 0, 4, 0x45, 0, 5, 1 },
		{ zero, sizeof(zero), X86_INS_TILEZERO, "tilezero", "tmm6", 1,
		  -1, 0, X86_REG_INVALID, X86_REG_INVALID, 1, 0, 0, 0,
		  X86_REG_TMM6, CS_AC_WRITE, 4, 0xf0, 0, 0, 0 },
	};
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit mode"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			    CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		success &= test_case(handle, &cases[i]);
	success &= test_att_syntax(handle);
	success &= test_invalid_encodings(handle);
	cs_close(&handle);
	success &= test_non64_rejected();
	return success ? 0 : 1;
}

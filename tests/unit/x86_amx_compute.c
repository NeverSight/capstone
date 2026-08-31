/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct compute_case {
	uint8_t code[5];
	x86_insn id;
	const char *mnemonic;
} compute_case;

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "AMX compute check failed: %s\n", message);
	return condition;
}

static bool has_register(const cs_regs registers, uint8_t count, x86_reg reg)
{
	uint8_t i;

	for (i = 0; i < count; ++i) {
		if (registers[i] == reg)
			return true;
	}
	return false;
}

static bool test_case(csh handle, const compute_case *test, bool att_syntax)
{
	static const x86_reg intel_regs[] = {
		X86_REG_TMM1, X86_REG_TMM2, X86_REG_TMM3,
	};
	static const uint8_t intel_access[] = {
		CS_AC_READ | CS_AC_WRITE, CS_AC_READ, CS_AC_READ,
	};
	static const x86_reg att_regs[] = {
		X86_REG_TMM3, X86_REG_TMM2, X86_REG_TMM1,
	};
	static const uint8_t att_access[] = {
		CS_AC_READ, CS_AC_READ, CS_AC_READ | CS_AC_WRITE,
	};
	const x86_reg *expected_regs = att_syntax ? att_regs : intel_regs;
	const uint8_t *expected_access = att_syntax ? att_access : intel_access;
	const char *expected_op_str = att_syntax ? "%tmm3, %tmm2, %tmm1" :
						      "tmm1, tmm2, tmm3";
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	bool success = true;
	size_t count = cs_disasm(handle, test->code, sizeof(test->code),
				 0x1000, 1, &insn);
	const char *name;
	uint8_t i;

	if (!check(count == 1, "legal instruction decodes"))
		return false;
	name = cs_insn_name(handle, insn[0].id);
	success &= check(insn[0].size == sizeof(test->code),
			 "instruction consumes five bytes");
	success &= check(insn[0].id == test->id,
			 "public ID matches the compute operation");
	success &= check(name != NULL && strcmp(name, test->mnemonic) == 0,
			 "public instruction name matches");
	success &= check(strcmp(insn[0].mnemonic, test->mnemonic) == 0,
			 "printed mnemonic matches");
	success &= check(strcmp(insn[0].op_str, expected_op_str) == 0,
			 "operand text follows the selected syntax");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->modrm == 0xca,
				 "ModRM detail is preserved");
		success &= check(x86->encoding.modrm_offset == 4,
				 "ModRM offset is four");
		success &= check(x86->op_count == 3,
				 "three public operands are present");
		if (x86->op_count == 3) {
			for (i = 0; i < 3; ++i) {
				success &= check(x86->operands[i].type ==
							 X86_OP_REG,
						 "compute operand is a register");
				success &= check(x86->operands[i].reg ==
							 expected_regs[i],
						 "compute register order matches syntax");
				success &= check(x86->operands[i].size == 0,
						 "runtime-sized tile reports size zero");
				success &= check(x86->operands[i].access ==
							 expected_access[i],
						 "compute access matches accumulator semantics");
			}
		}
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(has_register(regs_read, regs_read_count,
						      X86_REG_TMM1) &&
				 has_register(regs_read, regs_read_count,
						      X86_REG_TMM2) &&
				 has_register(regs_read, regs_read_count,
						      X86_REG_TMM3),
				 "accumulator and sources are read");
		success &= check(has_register(regs_write, regs_write_count,
						      X86_REG_TMM1),
				 "accumulator is written");
	}
	cs_free(insn, count);
	return success;
}

static bool rejects(csh handle, const uint8_t *code, size_t code_size,
			    const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	bool success = check(count == 0, message);

	if (count != 0)
		cs_free(insn, count);
	return success;
}

static bool is_not_amx_compute(csh handle, const uint8_t *code,
			       size_t code_size, const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	bool success = true;

	if (count != 0) {
		success = check(insn[0].id < X86_INS_TDPBSSD ||
				insn[0].id > X86_INS_TMMULTF32PS, message);
		cs_free(insn, count);
	}
	return success;
}

int main(void)
{
	static const compute_case cases[] = {
		{ { 0xc4, 0xe2, 0x63, 0x5e, 0xca }, X86_INS_TDPBSSD,
		  "tdpbssd" },
		{ { 0xc4, 0xe2, 0x62, 0x5e, 0xca }, X86_INS_TDPBSUD,
		  "tdpbsud" },
		{ { 0xc4, 0xe2, 0x61, 0x5e, 0xca }, X86_INS_TDPBUSD,
		  "tdpbusd" },
		{ { 0xc4, 0xe2, 0x60, 0x5e, 0xca }, X86_INS_TDPBUUD,
		  "tdpbuud" },
		{ { 0xc4, 0xe2, 0x62, 0x5c, 0xca }, X86_INS_TDPBF16PS,
		  "tdpbf16ps" },
		{ { 0xc4, 0xe2, 0x63, 0x5c, 0xca }, X86_INS_TDPFP16PS,
		  "tdpfp16ps" },
		{ { 0xc4, 0xe2, 0x61, 0x6c, 0xca }, X86_INS_TCMMIMFP16PS,
		  "tcmmimfp16ps" },
		{ { 0xc4, 0xe2, 0x60, 0x6c, 0xca }, X86_INS_TCMMRLFP16PS,
		  "tcmmrlfp16ps" },
	};
	static const uint8_t truncated[] = { 0xc4, 0xe2, 0x63, 0x5e };
	static const uint8_t bad_map[] = { 0xc4, 0xe1, 0x63, 0x5e, 0xca };
	static const uint8_t bad_r[] = { 0xc4, 0x62, 0x63, 0x5e, 0xca };
	static const uint8_t x_ignored[] = { 0xc4, 0xa2, 0x63, 0x5e, 0xca };
	static const uint8_t bad_b[] = { 0xc4, 0xc2, 0x63, 0x5e, 0xca };
	static const uint8_t bad_w[] = { 0xc4, 0xe2, 0xe3, 0x5e, 0xca };
	static const uint8_t bad_l[] = { 0xc4, 0xe2, 0x67, 0x5e, 0xca };
	static const uint8_t bad_vvvv[] = { 0xc4, 0xe2, 0x23, 0x5e, 0xca };
	static const uint8_t bad_mod[] = { 0xc4, 0xe2, 0x63, 0x5e, 0x0a };
	static const uint8_t same_dst_src2[] = { 0xc4, 0xe2, 0x63, 0x5e,
						  0xc9 };
	static const uint8_t same_dst_src3[] = { 0xc4, 0xe2, 0x73, 0x5e,
						  0xca };
	static const uint8_t same_sources[] = { 0xc4, 0xe2, 0x6b, 0x5e,
						 0xca };
	static const uint8_t bad_5c_pp[] = { 0xc4, 0xe2, 0x60, 0x5c, 0xca };
	static const uint8_t bad_6c_pp[] = { 0xc4, 0xe2, 0x62, 0x6c, 0xca };
	static const uint8_t bad_tcmmrl_w[] = { 0xc4, 0xe2, 0xe0, 0x6c,
						 0xca };
	csh handle64 = 0;
	csh handle32 = 0;
	bool success = true;
	size_t i;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle64) == CS_ERR_OK,
		   "open 64-bit mode"))
		return 1;
	if (!check(cs_option(handle64, CS_OPT_DETAIL,
			    CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable detail")) {
		cs_close(&handle64);
		return 1;
	}
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		success &= test_case(handle64, &cases[i], false);
	success &= check(cs_option(handle64, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "select AT&T syntax");
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		success &= test_case(handle64, &cases[i], true);
	success &= rejects(handle64, truncated, sizeof(truncated),
			   "truncated compute encoding is rejected");
	success &= is_not_amx_compute(handle64, bad_map, sizeof(bad_map),
				      "wrong opcode map is not classified as AMX");
	success &= rejects(handle64, bad_r, sizeof(bad_r),
			   "extended destination is rejected");
	{
		compute_case x_case = { { 0 }, X86_INS_TDPBSSD, "tdpbssd" };
		memcpy(x_case.code, x_ignored, sizeof(x_case.code));
		success &= test_case(handle64, &x_case, true);
	}
	success &= rejects(handle64, bad_b, sizeof(bad_b),
			   "extended source is rejected");
	success &= rejects(handle64, bad_w, sizeof(bad_w),
			   "fixed W bit is enforced");
	success &= rejects(handle64, bad_l, sizeof(bad_l),
			   "fixed vector length is enforced");
	success &= rejects(handle64, bad_vvvv, sizeof(bad_vvvv),
			   "out-of-range VEX source is rejected");
	success &= rejects(handle64, bad_mod, sizeof(bad_mod),
			   "memory shape is rejected");
	success &= rejects(handle64, same_dst_src2, sizeof(same_dst_src2),
			   "destination and first source must differ");
	success &= rejects(handle64, same_dst_src3, sizeof(same_dst_src3),
			   "destination and second source must differ");
	success &= rejects(handle64, same_sources, sizeof(same_sources),
			   "source tiles must differ");
	success &= rejects(handle64, bad_5c_pp, sizeof(bad_5c_pp),
			   "unassigned 5C prefix is rejected");
	success &= rejects(handle64, bad_6c_pp, sizeof(bad_6c_pp),
			   "unassigned 6C prefix is rejected");

	success &= rejects(handle64, bad_tcmmrl_w, sizeof(bad_tcmmrl_w),
			   "TCMMRLFP16PS enforces the architectural W0 bit");
	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle32) == CS_ERR_OK,
		   "open 32-bit mode")) {
		cs_close(&handle64);
		return 1;
	}
	success &= rejects(handle32, cases[0].code, sizeof(cases[0].code),
			   "AMX compute is 64-bit only");
	cs_close(&handle32);
	cs_close(&handle64);
	return success ? 0 : 1;
}

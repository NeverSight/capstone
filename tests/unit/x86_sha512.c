/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "SHA-512 VEX check failed: %s\n", message);
	return condition;
}

static bool test_vsha512msg1(csh handle)
{
	/* vsha512msg1 ymm2, xmm3 */
	static const uint8_t code[] = { 0xc4, 0xe2, 0x7f, 0xcc, 0xd3 };
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (!check(count == 1, "VSHA512MSG1 decodes"))
		return false;
	success &= check(strcmp(insn[0].mnemonic, "vsha512msg1") == 0,
			 "mnemonic is VSHA512MSG1");
	success &= check(insn[0].id == X86_INS_VSHA512MSG1,
			 "public ID is VSHA512MSG1");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id),
				"vsha512msg1") == 0,
			 "public instruction name is VSHA512MSG1");
	success &= check(strcmp(insn[0].op_str, "ymm2, xmm3") == 0,
			 "Intel operands preserve architectural order");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_detail *detail = insn[0].detail;
		const cs_x86 *x86 = &detail->x86;

		success &= check(insn[0].size == sizeof(code),
				 "instruction size is five bytes");
		success &= check(x86->opcode[0] == 0xc4 &&
					 x86->opcode[1] == 0xe2 &&
					 x86->opcode[2] == 0x7f,
				 "VEX bytes are preserved in opcode detail");
		success &=
			check(x86->rex == 0x40 && x86->addr_size == 8 &&
				      x86->modrm == 0xd3 &&
				      x86->encoding.modrm_offset == 4,
			      "encoding detail matches the five-byte VEX form");
		success &= check(x86->op_count == 2, "two explicit operands");
		if (x86->op_count == 2) {
			success &= check(
				x86->operands[0].type == X86_OP_REG &&
					x86->operands[0].reg == X86_REG_YMM2 &&
					x86->operands[0].size == 32 &&
					x86->operands[0].access ==
						(CS_AC_READ | CS_AC_WRITE),
				"YMM destination is read-write");
			success &= check(
				x86->operands[1].type == X86_OP_REG &&
					x86->operands[1].reg == X86_REG_XMM3 &&
					x86->operands[1].size == 16 &&
					x86->operands[1].access == CS_AC_READ,
				"XMM source is read-only");
		}
		success &= check(cs_insn_group(handle, &insn[0], X86_GRP_SHA),
				 "instruction belongs to the SHA group");
	}

	if (!success) {
		fprintf(stderr, "actual: id=%u mnemonic=%s operands=%s\n",
			insn[0].id, insn[0].mnemonic, insn[0].op_str);
	}
	cs_free(insn, count);
	return success;
}

static bool test_vsha512msg2(csh handle)
{
	/* vsha512msg2 ymm2, ymm3 */
	static const uint8_t code[] = { 0xc4, 0xe2, 0x7f, 0xcd, 0xd3 };
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (!check(count == 1, "VSHA512MSG2 decodes"))
		return false;
	success &= check(strcmp(insn[0].mnemonic, "vsha512msg2") == 0,
			 "mnemonic is VSHA512MSG2");
	success &= check(insn[0].id == X86_INS_VSHA512MSG2,
			 "public ID is VSHA512MSG2");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id),
				"vsha512msg2") == 0,
			 "public instruction name is VSHA512MSG2");
	success &= check(strcmp(insn[0].op_str, "ymm2, ymm3") == 0,
			 "MSG2 operands preserve architectural order");
	success &= check(insn[0].detail != NULL, "MSG2 detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == 2, "MSG2 has two operands");
		if (x86->op_count == 2) {
			success &= check(x86->operands[0].reg == X86_REG_YMM2 &&
						 x86->operands[0].size == 32 &&
						 x86->operands[0].access ==
							 (CS_AC_READ |
							  CS_AC_WRITE),
					 "MSG2 destination is read-write YMM");
			success &= check(x86->operands[1].reg == X86_REG_YMM3 &&
						 x86->operands[1].size == 32 &&
						 x86->operands[1].access ==
							 CS_AC_READ,
					 "MSG2 source is read-only YMM");
		}
		success &= check(cs_insn_group(handle, &insn[0], X86_GRP_SHA),
				 "MSG2 belongs to the SHA group");
	}
	cs_free(insn, count);
	return success;
}

static bool test_vsha512rnds2(csh handle)
{
	/* vsha512rnds2 ymm2, ymm3, xmm4 */
	static const uint8_t code[] = { 0xc4, 0xe2, 0x67, 0xcb, 0xd4 };
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (!check(count == 1, "VSHA512RNDS2 decodes"))
		return false;
	success &= check(strcmp(insn[0].mnemonic, "vsha512rnds2") == 0,
			 "mnemonic is VSHA512RNDS2");
	success &= check(insn[0].id == X86_INS_VSHA512RNDS2,
			 "public ID is VSHA512RNDS2");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id),
				"vsha512rnds2") == 0,
			 "public instruction name is VSHA512RNDS2");
	success &= check(strcmp(insn[0].op_str, "ymm2, ymm3, xmm4") == 0,
			 "RNDS2 operands preserve architectural order");
	success &= check(insn[0].detail != NULL, "RNDS2 detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &=
			check(x86->op_count == 3, "RNDS2 has three operands");
		if (x86->op_count == 3) {
			success &= check(x86->operands[0].reg == X86_REG_YMM2 &&
						 x86->operands[0].size == 32 &&
						 x86->operands[0].access ==
							 (CS_AC_READ |
							  CS_AC_WRITE),
					 "RNDS2 destination is read-write YMM");
			success &= check(x86->operands[1].reg == X86_REG_YMM3 &&
						 x86->operands[1].size == 32 &&
						 x86->operands[1].access ==
							 CS_AC_READ,
					 "RNDS2 first source is read-only YMM");
			success &= check(
				x86->operands[2].reg == X86_REG_XMM4 &&
					x86->operands[2].size == 16 &&
					x86->operands[2].access == CS_AC_READ,
				"RNDS2 second source is read-only XMM");
		}
		success &= check(cs_insn_group(handle, &insn[0], X86_GRP_SHA),
				 "RNDS2 belongs to the SHA group");
	}
	cs_free(insn, count);
	return success;
}

static bool check_render(csh handle, const uint8_t code[5], unsigned int id,
			 const char *mnemonic, const char *operands,
			 uint8_t address_size, uint8_t operand_count,
			 const x86_reg *registers)
{
	cs_insn *insn = NULL;
	bool success;
	size_t count = cs_disasm(handle, code, 5, 0x1000, 1, &insn);
	uint8_t i;

	if (!check(count == 1, "variant decodes"))
		return false;
	success = check(insn[0].id == id, "variant public ID") &&
		  check(strcmp(insn[0].mnemonic, mnemonic) == 0,
			"variant mnemonic") &&
		  check(strcmp(insn[0].op_str, operands) == 0,
			"variant operand order") &&
		  check(insn[0].detail != NULL, "variant detail") &&
		  check(insn[0].detail->x86.addr_size == address_size,
			"variant address size") &&
		  check(insn[0].detail->x86.op_count == operand_count,
			"variant operand count") &&
		  check(cs_insn_group(handle, &insn[0], X86_GRP_SHA),
			"variant SHA group");
	if (insn[0].detail != NULL &&
	    insn[0].detail->x86.op_count == operand_count) {
		for (i = 0; i < operand_count; ++i) {
			success &= check(
				insn[0].detail->x86.operands[i].type ==
						X86_OP_REG &&
					insn[0].detail->x86.operands[i].reg ==
						registers[i],
				"variant detail register order");
		}
	}
	if (!success)
		fprintf(stderr, "actual variant: %s %s\n", insn[0].mnemonic,
			insn[0].op_str);
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

static bool test_64bit_variants(csh handle)
{
	static const uint8_t msg1_high[] = { 0xc4, 0x42, 0x7f, 0xcc, 0xe4 };
	static const uint8_t msg2_high[] = { 0xc4, 0x42, 0x7f, 0xcd, 0xe4 };
	static const uint8_t rnds2_high[] = { 0xc4, 0x42, 0x27, 0xcb, 0xe4 };
	static const uint8_t msg1_x_ignored[] = { 0xc4, 0xa2, 0x7f, 0xcc,
						  0xd3 };
	static const uint8_t msg1[] = { 0xc4, 0xe2, 0x7f, 0xcc, 0xd3 };
	static const uint8_t msg2[] = { 0xc4, 0xe2, 0x7f, 0xcd, 0xd3 };
	static const uint8_t rnds2[] = { 0xc4, 0xe2, 0x67, 0xcb, 0xd4 };
	static const x86_reg msg1_high_intel[] = { X86_REG_YMM12,
						   X86_REG_XMM12 };
	static const x86_reg msg2_high_intel[] = { X86_REG_YMM12,
						   X86_REG_YMM12 };
	static const x86_reg rnds2_high_intel[] = { X86_REG_YMM12,
						    X86_REG_YMM11,
						    X86_REG_XMM12 };
	static const x86_reg msg1_intel[] = { X86_REG_YMM2, X86_REG_XMM3 };
	static const x86_reg msg1_att[] = { X86_REG_XMM3, X86_REG_YMM2 };
	static const x86_reg msg2_att[] = { X86_REG_YMM3, X86_REG_YMM2 };
	static const x86_reg rnds2_att[] = { X86_REG_XMM4, X86_REG_YMM3,
					     X86_REG_YMM2 };
	bool success = true;

	success &= check_render(handle, msg1_high, X86_INS_VSHA512MSG1,
				"vsha512msg1", "ymm12, xmm12", 8, 2,
				msg1_high_intel);
	success &= check_render(handle, msg2_high, X86_INS_VSHA512MSG2,
				"vsha512msg2", "ymm12, ymm12", 8, 2,
				msg2_high_intel);
	success &= check_render(handle, rnds2_high, X86_INS_VSHA512RNDS2,
				"vsha512rnds2", "ymm12, ymm11, xmm12", 8, 3,
				rnds2_high_intel);
	success &= check_render(handle, msg1_x_ignored, X86_INS_VSHA512MSG1,
				"vsha512msg1", "ymm2, xmm3", 8, 2, msg1_intel);

	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "select AT&T syntax");
	success &= check_render(handle, msg1, X86_INS_VSHA512MSG1,
				"vsha512msg1", "%xmm3, %ymm2", 8, 2, msg1_att);
	success &= check_render(handle, msg2, X86_INS_VSHA512MSG2,
				"vsha512msg2", "%ymm3, %ymm2", 8, 2, msg2_att);
	success &= check_render(handle, rnds2, X86_INS_VSHA512RNDS2,
				"vsha512rnds2", "%xmm4, %ymm3, %ymm2", 8, 3,
				rnds2_att);
	success &= check(cs_option(handle, CS_OPT_SYNTAX,
				   CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
			 "restore Intel syntax");
	return success;
}

static bool test_invalid_64bit(csh handle)
{
	static const struct {
		uint8_t code[5];
		size_t size;
		const char *message;
	} cases[] = {
		{ { 0xc4, 0xe2, 0x7f, 0xcc }, 4, "truncated MSG1" },
		{ { 0xc4, 0xe2, 0x7f, 0xcd }, 4, "truncated MSG2" },
		{ { 0xc4, 0xe2, 0x67, 0xcb }, 4, "truncated RNDS2" },
		{ { 0xc4, 0xe2, 0x7b, 0xcc, 0xd3 }, 5, "MSG1 VEX.L=0" },
		{ { 0xc4, 0xe2, 0x7b, 0xcd, 0xd3 }, 5, "MSG2 VEX.L=0" },
		{ { 0xc4, 0xe2, 0x63, 0xcb, 0xd4 }, 5, "RNDS2 VEX.L=0" },
		{ { 0xc4, 0xe2, 0xff, 0xcc, 0xd3 }, 5, "MSG1 VEX.W=1" },
		{ { 0xc4, 0xe2, 0xff, 0xcd, 0xd3 }, 5, "MSG2 VEX.W=1" },
		{ { 0xc4, 0xe2, 0xe7, 0xcb, 0xd4 }, 5, "RNDS2 VEX.W=1" },
		{ { 0xc4, 0xe2, 0x77, 0xcc, 0xd3 },
		  5,
		  "MSG1 reserved VEX.vvvv" },
		{ { 0xc4, 0xe2, 0x77, 0xcd, 0xd3 },
		  5,
		  "MSG2 reserved VEX.vvvv" },
		{ { 0xc4, 0xe2, 0x7f, 0xcc, 0x13 }, 5, "MSG1 memory ModRM" },
		{ { 0xc4, 0xe2, 0x7f, 0xcd, 0x13 }, 5, "MSG2 memory ModRM" },
		{ { 0xc4, 0xe2, 0x67, 0xcb, 0x14 }, 5, "RNDS2 memory ModRM" },
	};
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		success &= rejects(handle, cases[i].code, cases[i].size,
				   cases[i].message);
	return success;
}

static bool test_32bit_and_16bit_modes(void)
{
	static const uint8_t msg1[] = { 0xc4, 0xe2, 0x7f, 0xcc, 0xd3 };
	static const uint8_t msg2[] = { 0xc4, 0xe2, 0x7f, 0xcd, 0xd3 };
	static const uint8_t rnds2[] = { 0xc4, 0xe2, 0x67, 0xcb, 0xd4 };
	static const uint8_t high_destination[] = { 0xc4, 0x62, 0x7f, 0xcc,
						    0xe3 };
	static const uint8_t high_source[] = { 0xc4, 0xc2, 0x7f, 0xcc, 0xd3 };
	static const uint8_t unused_x_extension[] = { 0xc4, 0xa2, 0x7f, 0xcc,
						      0xd3 };
	static const uint8_t high_vvvv[] = { 0xc4, 0xe2, 0x27, 0xcb, 0xd4 };
	static const x86_reg msg1_regs[] = { X86_REG_YMM2, X86_REG_XMM3 };
	static const x86_reg msg2_regs[] = { X86_REG_YMM2, X86_REG_YMM3 };
	static const x86_reg rnds2_regs[] = { X86_REG_YMM2, X86_REG_YMM3,
					      X86_REG_XMM4 };
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK,
		   "open 32-bit mode"))
		return false;
	success &= check(cs_option(handle, CS_OPT_DETAIL,
				   CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
			 "enable 32-bit detail");
	success &= check_render(handle, msg1, X86_INS_VSHA512MSG1,
				"vsha512msg1", "ymm2, xmm3", 4, 2, msg1_regs);
	success &= check_render(handle, msg2, X86_INS_VSHA512MSG2,
				"vsha512msg2", "ymm2, ymm3", 4, 2, msg2_regs);
	success &= check_render(handle, rnds2, X86_INS_VSHA512RNDS2,
				"vsha512rnds2", "ymm2, ymm3, xmm4", 4, 3,
				rnds2_regs);
	success &= rejects(handle, high_destination, 5,
			   "32-bit extended destination");
	success &= rejects(handle, high_source, 5, "32-bit extended source");
	success &= rejects(handle, unused_x_extension, 5,
			   "32-bit VEX.X extension");
	success &= rejects(handle, high_vvvv, 5, "32-bit extended VEX.vvvv");
	cs_close(&handle);

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_16, &handle) == CS_ERR_OK,
		   "open 16-bit mode"))
		return false;
	success &= rejects(handle, msg1, 5, "16-bit MSG1");
	success &= rejects(handle, msg2, 5, "16-bit MSG2");
	success &= rejects(handle, rnds2, 5, "16-bit RNDS2");
	cs_close(&handle);
	return success;
}

int main(void)
{
	csh handle = 0;
	bool success;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit mode"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable real detail")) {
		cs_close(&handle);
		return 1;
	}
	success = test_vsha512msg1(handle);
	success &= test_vsha512msg2(handle);
	success &= test_vsha512rnds2(handle);
	success &= test_64bit_variants(handle);
	success &= test_invalid_64bit(handle);
	cs_close(&handle);
	success &= test_32bit_and_16bit_modes();
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef struct cs_x86_alignment_probe {
	char prefix;
	cs_x86 value;
} cs_x86_alignment_probe;

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX REX2 generated decoder check failed: %s\n",
			message);
	return condition;
}

static bool rejects(csh handle, const uint8_t *code, size_t code_size,
		    const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	bool success = check(count == 0, message);

	cs_free(insn, count);
	return success;
}

static bool test_rex2_tail_abi(void)
{
	const size_t old_end = offsetof(cs_x86, encoding) +
			       sizeof(cs_x86_encoding);
	const size_t alignment = offsetof(cs_x86_alignment_probe, value);
	const size_t old_size =
		(old_end + alignment - 1) / alignment * alignment;
	bool success = true;

	success &= check(offsetof(cs_x86, rex2) == old_end,
			 "REX2 detail is appended after the previous last field");
	success &= check(sizeof(cs_x86) == old_size,
			 "REX2 detail consumes tail padding without an ABI size change");
	return success;
}

static bool test_map0_sib_memory(csh handle)
{
	static const uint8_t code[] = { 0xd5, 0x7f, 0x8b, 0x44, 0xb7, 0xe0 };
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	bool success = true;

	if (!check(count == 1, "MAP0 memory instruction decodes"))
		return false;
	success &= check(insn[0].size == sizeof(code),
			 "MAP0 memory encoding is fully consumed");
	success &= check(insn[0].id == X86_INS_MOV,
			 "MAP0 memory instruction ID is MOV");
	success &= check(insn[0].detail != NULL,
			 "MAP0 memory detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->opcode[0] == 0x8b && x86->opcode[1] == 0,
				 "MAP0 exposes only the main opcode");
		success &= check(x86->rex2 == 0x7f,
				 "MAP0 exposes the raw REX2 payload");
		success &= check(x86->rex == 0,
				 "synthetic legacy REX state is not public");
		success &= check(x86->modrm == 0x44 && x86->sib == 0xb7,
				 "ModR/M and SIB bytes are exact");
		success &= check(x86->sib_base == X86_REG_R31 &&
					 x86->sib_index == X86_REG_R30 &&
					 x86->sib_scale == 4,
				 "SIB detail contains extended base and index");
		success &= check(x86->disp == -0x20,
				 "signed displacement is exact");
		success &= check(x86->encoding.modrm_offset == 3 &&
					 x86->encoding.disp_offset == 5 &&
					 x86->encoding.disp_size == 1,
				 "memory encoding offsets are exact");
		success &= check(x86->op_count == 2 &&
					 x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == X86_REG_R24 &&
					 x86->operands[1].type == X86_OP_MEM &&
					 x86->operands[1].mem.base == X86_REG_R31 &&
					 x86->operands[1].mem.index == X86_REG_R30 &&
					 x86->operands[1].mem.scale == 4 &&
					 x86->operands[1].mem.disp == -0x20,
				 "operands contain R24 and the extended address");
	}
	cs_free(insn, count);
	return success;
}

static bool test_addr32_sib_memory(csh handle)
{
	static const uint8_t code[] = { 0x67, 0xd5, 0x70, 0x8b, 0x84,
					0x61, 0x78, 0x56, 0x34, 0x12 };
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	bool success = true;

	if (!check(count == 1, "address-size override instruction decodes"))
		return false;
	success &= check(insn[0].size == sizeof(code),
			 "address-size override encoding is fully consumed");
	success &= check(insn[0].detail != NULL,
			 "address-size override detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->addr_size == 4 && x86->prefix[3] == 0x67,
				 "address-size detail is 32-bit");
		success &= check(x86->rex2 == 0x70,
				 "addr32 exposes the raw REX2 payload");
		success &= check(x86->sib_base == X86_REG_R17D &&
					 x86->sib_index == X86_REG_R20D &&
					 x86->sib_scale == 2,
				 "addr32 SIB uses extended 32-bit registers");
		success &= check(x86->encoding.modrm_offset == 4 &&
					 x86->encoding.disp_offset == 6 &&
					 x86->encoding.disp_size == 4,
				 "addr32 memory offsets are exact");
		success &= check(x86->op_count == 2 &&
					 x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == X86_REG_R16D &&
					 x86->operands[1].type == X86_OP_MEM &&
					 x86->operands[1].mem.base == X86_REG_R17D &&
					 x86->operands[1].mem.index == X86_REG_R20D &&
					 x86->operands[1].mem.scale == 2 &&
					 x86->operands[1].mem.disp == 0x12345678,
				 "addr32 operands preserve extended registers");
	}
	cs_free(insn, count);
	return success;
}

static bool test_sib_index_extension_matrix(csh handle)
{
	static const uint8_t payloads[] = { 0x00, 0x02, 0x20, 0x22 };
	static const x86_reg indexes[] = { X86_REG_INVALID, X86_REG_R12,
					   X86_REG_R20, X86_REG_R28 };
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(payloads) / sizeof(payloads[0]); ++i) {
		uint8_t code[] = { 0xd5, payloads[i], 0x8b, 0x04, 0x24 };
		cs_insn *insn = NULL;
		size_t count =
			cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

		if (!check(count == 1, "SIB index matrix instruction decodes")) {
			success = false;
			continue;
		}
		success &= check(insn[0].size == sizeof(code) &&
					 insn[0].id == X86_INS_MOV,
				 "SIB index matrix MOV is fully consumed");
		if (insn[0].detail != NULL) {
			const cs_x86 *x86 = &insn[0].detail->x86;

			success &= check(x86->sib_index == indexes[i] &&
						 x86->op_count == 2 &&
						 x86->operands[1].type == X86_OP_MEM &&
						 x86->operands[1].mem.base == X86_REG_RSP &&
						 x86->operands[1].mem.index == indexes[i],
					 "X4:X3 selects none, R12, R20, or R28");
		} else {
			success &= check(false, "SIB index matrix detail is available");
		}
		cs_free(insn, count);
	}
	return success;
}

static bool test_map1_and_opcode_register(csh handle)
{
	static const uint8_t imul[] = { 0xd5, 0xdd, 0xaf, 0xc7 };
	static const uint8_t mov_imm[] = { 0xd5, 0x19, 0xbf, 0x88, 0x77, 0x66,
					  0x55, 0x44, 0x33, 0x22, 0x11 };
	cs_insn *insn = NULL;
	size_t count;
	bool success = true;

	count = cs_disasm(handle, imul, sizeof(imul), 0x1000, 1, &insn);
	if (!check(count == 1, "MAP1 instruction decodes"))
		return false;
	success &= check(insn[0].size == sizeof(imul) &&
				 insn[0].id == X86_INS_IMUL,
			 "MAP1 IMUL is fully consumed and identified");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->opcode[0] == 0xaf && x86->opcode[1] == 0,
				 "MAP1 exposes the direct opcode without 0F");
		success &= check(x86->rex2 == 0xdd,
				 "MAP1 exposes the raw REX2 payload");
		success &= check(x86->encoding.modrm_offset == 3,
				 "MAP1 ModR/M offset is exact");
		success &= check(x86->op_count == 2 &&
					 x86->operands[0].reg == X86_REG_R24 &&
					 x86->operands[1].reg == X86_REG_R31,
				 "MAP1 reg and r/m fields select EGPRs");
	} else {
		success &= check(false, "MAP1 detail is available");
	}
	cs_free(insn, count);

	insn = NULL;
	count = cs_disasm(handle, mov_imm, sizeof(mov_imm), 0x1000, 1,
			  &insn);
	if (!check(count == 1, "opcode-register instruction decodes"))
		return false;
	success &= check(insn[0].size == sizeof(mov_imm) &&
				 insn[0].id == X86_INS_MOVABS,
			 "opcode-register MOVABS is fully consumed and identified");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->opcode[0] == 0xbf &&
					 x86->encoding.imm_offset == 3 &&
					 x86->encoding.imm_size == 8,
				 "opcode-register immediate detail is exact");
		success &= check(x86->op_count == 2 &&
					 x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == X86_REG_R31 &&
					 x86->operands[1].type == X86_OP_IMM &&
					 (uint64_t)x86->operands[1].imm ==
						 0x1122334455667788ULL,
				 "opcode register and immediate are exact");
	} else {
		success &= check(false, "opcode-register detail is available");
	}
	cs_free(insn, count);
	return success;
}

static bool test_map1_direct_opcode_values(csh handle)
{
	static const struct {
		uint8_t code[6];
		size_t size;
		x86_insn instruction;
		uint8_t opcode;
	} cases[] = {
		{ { 0x66, 0xd5, 0x80, 0xc4, 0xc8, 0x00 }, 6,
		  X86_INS_PINSRW, 0xc4 },
		{ { 0x66, 0xd5, 0x80, 0xc5, 0xc1, 0x00 }, 6,
		  X86_INS_PEXTRW, 0xc5 },
		{ { 0x66, 0xd5, 0x80, 0x62, 0xca, 0x00 }, 5,
		  X86_INS_PUNPCKLDQ, 0x62 },
		{ { 0xd5, 0xc0, 0x50, 0xc1, 0x00, 0x00 }, 4,
		  X86_INS_MOVMSKPS, 0x50 },
	};
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		cs_insn *insn = NULL;
		size_t count = cs_disasm(handle, cases[i].code, cases[i].size,
					 0x1000, 1, &insn);

		if (!check(count == 1, "direct MAP1 opcode decodes")) {
			success = false;
			continue;
		}
		success &= check(insn[0].size == cases[i].size &&
					 insn[0].id == cases[i].instruction,
				 "direct MAP1 opcode is fully consumed and identified");
		if (insn[0].detail != NULL) {
			const cs_x86 *x86 = &insn[0].detail->x86;

			success &= check(x86->opcode[0] == cases[i].opcode &&
						 x86->opcode[1] == 0 &&
						 x86->rex2 == cases[i].code[
							 cases[i].code[0] == 0x66 ? 2 : 1],
					 "C4/C5/62/50 remain direct MAP1 opcodes");
		} else {
			success &= check(false, "direct MAP1 detail is available");
		}
		cs_free(insn, count);
	}
	return success;
}

static bool test_control_register_extension(csh handle)
{
	static const uint8_t code[] = { 0xd5, 0x94, 0x20, 0xc0 };
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	bool success = true;

	if (!check(count == 1, "CR8 instruction decodes"))
		return false;
	success &= check(insn[0].size == sizeof(code) &&
				 insn[0].id == X86_INS_MOV,
			 "CR8 MOV is fully consumed and identified");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == 2 &&
					 x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == X86_REG_R16 &&
					 x86->operands[1].type == X86_OP_REG &&
					 x86->operands[1].reg == X86_REG_CR8,
				 "CR8 is validated while B4 selects R16");
	} else {
		success &= check(false, "CR8 detail is available");
	}
	cs_free(insn, count);
	return success;
}

static bool test_opcode_90_extension(csh handle)
{
	static const uint8_t code[] = { 0xd5, 0x10, 0x90 };
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	bool success = true;

	if (!check(count == 1, "extended opcode 90 decodes"))
		return false;
	success &= check(insn[0].size == sizeof(code) &&
				 insn[0].id == X86_INS_XCHG,
			 "REX2.B4 promotes opcode 90 from NOP to XCHG");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		bool has_eax = false, has_r16d = false;
		uint8_t i;

		for (i = 0; i < x86->op_count; ++i) {
			if (x86->operands[i].type != X86_OP_REG)
				continue;
			has_eax |= x86->operands[i].reg == X86_REG_EAX;
			has_r16d |= x86->operands[i].reg == X86_REG_R16D;
		}
		success &= check(x86->op_count == 2 && has_eax && has_r16d,
				 "opcode 90 operands are EAX and R16D");
	} else {
		success &= check(false, "extended opcode 90 detail is available");
	}
	cs_free(insn, count);
	return success;
}

static bool test_specialized_rex2_detail(csh handle)
{
	static const uint8_t push[] = { 0x48, 0x66, 0xd5, 0x10, 0x50 };
	static const uint8_t jmpabs[] = { 0x48, 0x64, 0xd5, 0x77, 0xa1,
					  0x88, 0x77, 0x66, 0x55, 0x44,
					  0x33, 0x22, 0x11 };
	cs_insn *insn = NULL;
	size_t count;
	bool success = true;

	count = cs_disasm(handle, push, sizeof(push), 0x1000, 1, &insn);
	success &= check(count == 1 && insn[0].detail != NULL &&
				 insn[0].detail->x86.rex2 == 0x10,
			 "specialized PUSH ignores a superseded legacy REX");
	cs_free(insn, count);

	insn = NULL;
	count = cs_disasm(handle, jmpabs, sizeof(jmpabs), 0x1000, 1, &insn);
	success &= check(count == 1 && insn[0].detail != NULL &&
				 insn[0].detail->x86.rex2 == 0x77,
			 "specialized JMPABS ignores a superseded legacy REX");
	cs_free(insn, count);
	return success;
}

static bool test_non_gpr_reg_field(csh handle)
{
	static const uint8_t code[] = { 0x66, 0xd5, 0xd0, 0x58, 0x08 };
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	bool success = true;

	if (!check(count == 1, "MAP1 mandatory-prefix vector instruction decodes"))
		return false;
	success &= check(insn[0].size == sizeof(code) &&
				 insn[0].id == X86_INS_ADDPD,
			 "MAP1 mandatory-prefix instruction is identified");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->prefix[2] == 0x66 &&
					 x86->opcode[0] == 0x58,
				 "mandatory prefix and direct MAP1 opcode are exact");
		success &= check(x86->op_count == 2 &&
					 x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == X86_REG_XMM1 &&
					 x86->operands[1].type == X86_OP_MEM &&
					 x86->operands[1].mem.base == X86_REG_R16,
				 "R4 is ignored for XMM while B4 extends memory base");
	} else {
		success &= check(false, "MAP1 vector detail is available");
	}
	cs_free(insn, count);
	return success;
}

static bool test_segment_reg_ignores_extension(csh handle)
{
	static const uint8_t code[] = { 0x66, 0xd5, 0x54, 0x8c, 0xd8 };
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	bool success = true;

	if (!check(count == 1, "segment-register instruction decodes"))
		return false;
	success &= check(insn[0].size == sizeof(code) &&
				 insn[0].id == X86_INS_MOV,
			 "segment-register MOV is fully consumed and identified");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == 2 &&
					 x86->operands[0].type == X86_OP_REG &&
					 x86->operands[0].reg == X86_REG_R16W &&
					 x86->operands[1].type == X86_OP_REG &&
					 x86->operands[1].reg == X86_REG_DS,
				 "R4/R3 are ignored for segment reg while B4 extends GPR");
	} else {
		success &= check(false, "segment-register detail is available");
	}
	cs_free(insn, count);
	return success;
}

static bool test_separated_legacy_rex(csh handle)
{
	static const uint8_t code[] = { 0x48, 0x66, 0xd5, 0x55, 0x8b, 0xc7 };
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	bool success = true;

	if (!check(count == 1, "non-adjacent legacy REX is ignored"))
		return false;
	success &= check(insn[0].size == sizeof(code) &&
				 insn[0].id == X86_INS_MOV,
			 "separated legacy REX encoding is fully consumed");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == 2 &&
					 x86->operands[0].reg == X86_REG_R24W &&
					 x86->operands[1].reg == X86_REG_R31W,
				 "REX2 and operand-size prefix determine the registers");
	} else {
		success &= check(false, "separated legacy REX detail is available");
	}
	cs_free(insn, count);
	return success;
}

static bool test_legality(csh handle)
{
	static const uint8_t truncated[] = { 0xd5 };
	static const uint8_t explicit_0f[] = { 0xd5, 0x00, 0x0f, 0xaf, 0xc0 };
	static const uint8_t reserved_map0[] = { 0xd5, 0x00, 0x40 };
	static const uint8_t reserved_map1_3x[] = { 0xd5, 0x80, 0x30, 0xc0 };
	static const uint8_t reserved_map1_8x[] = { 0xd5, 0x80, 0x80, 0xc0 };
	static const uint8_t prefix_after_rex2[] = { 0xd5, 0x00, 0x66 };
	static const uint8_t vex_after_rex2[] = { 0xd5, 0x00, 0xc4 };
	static const uint8_t evex_after_rex2[] = { 0xd5, 0x00, 0x62 };
	static const uint8_t nested_rex2[] = { 0xd5, 0x00, 0xd5 };
	static const uint8_t legacy_rex[] = { 0x48, 0xd5, 0x08, 0x8b, 0xc0 };
	static const uint8_t duplicate_addr[] = { 0x67, 0x67, 0xd5, 0x08,
						  0x8b, 0xc0 };
	static const uint8_t xsave[] = { 0xd5, 0x80, 0xae, 0x20 };
	static const uint8_t cr16[] = { 0xd5, 0xc0, 0x20, 0xc0 };
	static const uint8_t dr16[] = { 0xd5, 0xc0, 0x21, 0xc0 };
	bool success = true;

	success &= rejects(handle, truncated, sizeof(truncated),
			   "truncated REX2 is rejected in 64-bit mode");
	success &= rejects(handle, explicit_0f, sizeof(explicit_0f),
			   "explicit 0F after REX2 is rejected");
	success &= rejects(handle, reserved_map0, sizeof(reserved_map0),
			   "reserved MAP0 row is rejected");
	success &= rejects(handle, reserved_map1_3x, sizeof(reserved_map1_3x),
			   "reserved MAP1 3x row is rejected");
	success &= rejects(handle, reserved_map1_8x, sizeof(reserved_map1_8x),
			   "reserved MAP1 8x row is rejected");
	success &= rejects(handle, prefix_after_rex2,
			   sizeof(prefix_after_rex2),
			   "legacy prefix after MAP0 REX2 is rejected");
	success &= rejects(handle, vex_after_rex2, sizeof(vex_after_rex2),
			   "VEX after MAP0 REX2 is rejected");
	success &= rejects(handle, evex_after_rex2, sizeof(evex_after_rex2),
			   "EVEX after MAP0 REX2 is rejected");
	success &= rejects(handle, nested_rex2, sizeof(nested_rex2),
			   "a second REX2 prefix is rejected");
	success &= rejects(handle, legacy_rex, sizeof(legacy_rex),
			   "legacy REX immediately before REX2 is rejected");
	success &= rejects(handle, duplicate_addr, sizeof(duplicate_addr),
			   "duplicate address prefix before REX2 is rejected");
	success &= rejects(handle, xsave, sizeof(xsave),
			   "XSAVE family cannot carry REX2");
	success &= rejects(handle, cr16, sizeof(cr16),
			   "extended control register is rejected");
	success &= rejects(handle, dr16, sizeof(dr16),
			   "extended debug register is rejected");
	return success;
}

static bool test_d5_is_aad_outside_64_bit(cs_mode mode)
{
	static const uint8_t code[] = { 0xd5, 0x0a };
	csh handle = 0;
	cs_insn *insn = NULL;
	size_t count;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, mode, &handle) == CS_ERR_OK,
		   "non-64-bit Capstone handle opens"))
		return false;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	success &= check(count == 1 && insn[0].size == sizeof(code) &&
				 insn[0].id == X86_INS_AAD,
			 "D5 remains AAD outside 64-bit mode");
	if (count == 1 && insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == 1 &&
					 x86->operands[0].type == X86_OP_IMM &&
					 x86->operands[0].imm == 0x0a,
				 "AAD immediate is preserved");
	}
	cs_free(insn, count);
	cs_close(&handle);
	return success;
}

int main(void)
{
	csh handle = 0;
	bool success = true;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		fprintf(stderr, "failed to open Capstone\n");
		return 1;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	success &= test_map0_sib_memory(handle);
	success &= test_addr32_sib_memory(handle);
	success &= test_sib_index_extension_matrix(handle);
	success &= test_map1_and_opcode_register(handle);
	success &= test_map1_direct_opcode_values(handle);
	success &= test_control_register_extension(handle);
	success &= test_opcode_90_extension(handle);
	success &= test_specialized_rex2_detail(handle);
	success &= test_non_gpr_reg_field(handle);
	success &= test_segment_reg_ignores_extension(handle);
	success &= test_separated_legacy_rex(handle);
	success &= test_legality(handle);
	cs_close(&handle);

	success &= test_d5_is_aad_outside_64_bit(CS_MODE_16);
	success &= test_d5_is_aad_outside_64_bit(CS_MODE_32);
	success &= test_rex2_tail_abi();
	return success ? 0 : 1;
}

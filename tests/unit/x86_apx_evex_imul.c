/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct decode_anchor {
	const uint8_t *code;
	size_t code_size;
	const char *intel_mnemonic;
	const char *intel_operands;
	const char *att_mnemonic;
	const char *att_operands;
} decode_anchor;

static const uint64_t imul_eflags =
	X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_SF |
	X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF |
	X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF;

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX EVEX IMUL check failed: %s\n", message);
	return condition;
}

static x86_reg register_for(uint8_t width, unsigned int number)
{
	static const x86_reg registers_16[] = {
		X86_REG_AX,   X86_REG_CX,   X86_REG_DX,	  X86_REG_BX,
		X86_REG_SP,   X86_REG_BP,   X86_REG_SI,	  X86_REG_DI,
		X86_REG_R8W,  X86_REG_R9W,  X86_REG_R10W, X86_REG_R11W,
		X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, X86_REG_R15W,
		X86_REG_R16W, X86_REG_R17W, X86_REG_R18W, X86_REG_R19W,
		X86_REG_R20W, X86_REG_R21W, X86_REG_R22W, X86_REG_R23W,
		X86_REG_R24W, X86_REG_R25W, X86_REG_R26W, X86_REG_R27W,
		X86_REG_R28W, X86_REG_R29W, X86_REG_R30W, X86_REG_R31W,
	};
	static const x86_reg registers_32[] = {
		X86_REG_EAX,  X86_REG_ECX,  X86_REG_EDX,  X86_REG_EBX,
		X86_REG_ESP,  X86_REG_EBP,  X86_REG_ESI,  X86_REG_EDI,
		X86_REG_R8D,  X86_REG_R9D,  X86_REG_R10D, X86_REG_R11D,
		X86_REG_R12D, X86_REG_R13D, X86_REG_R14D, X86_REG_R15D,
		X86_REG_R16D, X86_REG_R17D, X86_REG_R18D, X86_REG_R19D,
		X86_REG_R20D, X86_REG_R21D, X86_REG_R22D, X86_REG_R23D,
		X86_REG_R24D, X86_REG_R25D, X86_REG_R26D, X86_REG_R27D,
		X86_REG_R28D, X86_REG_R29D, X86_REG_R30D, X86_REG_R31D,
	};
	static const x86_reg registers_64[] = {
		X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX, X86_REG_RSP,
		X86_REG_RBP, X86_REG_RSI, X86_REG_RDI, X86_REG_R8,  X86_REG_R9,
		X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14,
		X86_REG_R15, X86_REG_R16, X86_REG_R17, X86_REG_R18, X86_REG_R19,
		X86_REG_R20, X86_REG_R21, X86_REG_R22, X86_REG_R23, X86_REG_R24,
		X86_REG_R25, X86_REG_R26, X86_REG_R27, X86_REG_R28, X86_REG_R29,
		X86_REG_R30, X86_REG_R31,
	};

	if (number >= 32)
		return X86_REG_INVALID;
	switch (width) {
	default:
		return X86_REG_INVALID;
	case 2:
		return registers_16[number];
	case 4:
		return registers_32[number];
	case 8:
		return registers_64[number];
	}
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

static char att_suffix(uint8_t width)
{
	return width == 2 ? 'w' : width == 4 ? 'l' : 'q';
}

static const char *memory_size_name(uint8_t width)
{
	return width == 2 ? "word" : width == 4 ? "dword" : "qword";
}

static void encode_register_case(uint8_t code[6], uint8_t width, bool nd,
				 bool nf, unsigned int destination_number,
				 unsigned int source1_number,
				 unsigned int source2_number)
{
	unsigned int ndd_number = nd ? destination_number : 0;
	uint8_t pp = width == 2 ? 1 : 0;
	uint8_t w = width == 8 ? 0x80 : 0;

	code[0] = 0x62;
	code[1] = 0x44 | ((source1_number & 8) ? 0 : 0x80) |
		  ((source2_number & 8) ? 0 : 0x20) |
		  ((source1_number & 16) ? 0 : 0x10) |
		  ((source2_number & 16) ? 0x08 : 0);
	code[2] = w | (((~ndd_number) & 0xf) << 3) | 0x04 | pp;
	code[3] = (nd ? 0x10 : 0) | (nf ? 0x04 : 0) |
		  ((ndd_number & 16) ? 0 : 0x08);
	code[4] = 0xaf;
	code[5] = 0xc0 | ((source1_number & 7) << 3) | (source2_number & 7);
}

static void encode_memory_case(uint8_t code[8], uint8_t width, bool nd, bool nf,
			       unsigned int destination_number,
			       unsigned int source1_number)
{
	unsigned int ndd_number = nd ? destination_number : 0;
	uint8_t pp = width == 2 ? 1 : 0;
	uint8_t w = width == 8 ? 0x80 : 0;

	code[0] = 0x62;
	/* Source two is [r29 + r30*4 + 0x20]. */
	code[1] = 0x0c | ((source1_number & 8) ? 0 : 0x80) |
		  ((source1_number & 16) ? 0 : 0x10);
	code[2] = w | (((~ndd_number) & 0xf) << 3) | pp;
	code[3] = (nd ? 0x10 : 0) | (nf ? 0x04 : 0) |
		  ((ndd_number & 16) ? 0 : 0x08);
	code[4] = 0xaf;
	code[5] = 0x44 | ((source1_number & 7) << 3);
	code[6] = 0xb5;
	code[7] = 0x20;
}

static bool check_flag_detail(const cs_insn *insn, bool nf)
{
	const cs_detail *detail = insn->detail;
	const cs_x86 *x86 = &detail->x86;

	if (nf) {
		return check(x86->eflags == 0 && detail->regs_read_count == 0 &&
				     detail->regs_write_count == 0,
			     "NF suppresses all EFLAGS detail");
	}
	return check(x86->eflags == imul_eflags &&
			     detail->regs_read_count == 0 &&
			     detail->regs_write_count == 1 &&
			     detail->regs_write[0] == X86_REG_EFLAGS,
		     "IMUL EFLAGS detail is exact");
}

static bool check_register_case(csh handle, uint8_t width, bool nd, bool nf,
				unsigned int seed, bool att_syntax)
{
	unsigned int destination_number = seed;
	unsigned int source1_number = nd ? (seed + 11) & 31 : seed;
	unsigned int source2_number = (seed + 23) & 31;
	x86_reg destination = register_for(width, destination_number);
	x86_reg source1 = register_for(width, source1_number);
	x86_reg source2 = register_for(width, source2_number);
	const char *destination_name = cs_reg_name(handle, destination);
	const char *source1_name = cs_reg_name(handle, source1);
	const char *source2_name = cs_reg_name(handle, source2);
	uint8_t code[6];
	char expected_mnemonic[32];
	char expected_operands[128];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	bool success = true;
	size_t count;

	encode_register_case(code, width, nd, nf, destination_number,
			     source1_number, source2_number);
	if (att_syntax) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic),
			 "%simul%c", nf ? "{nf} " : "", att_suffix(width));
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%%%s, %%%s, %%%s", source2_name, source1_name,
				 destination_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%%%s, %%%s", source2_name, source1_name);
		}
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%simul",
			 nf ? "{nf} " : "");
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s, %s", destination_name, source1_name,
				 source2_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s", source1_name, source2_name);
		}
	}

	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "promoted register IMUL decodes"))
		goto failed;
	success &= check(insn[0].id == X86_INS_IMUL,
			 "public IMUL instruction ID is exact");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id), "imul") == 0,
			 "public IMUL instruction name is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "IMUL mnemonic, suffix, and NF decorator are exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "register IMUL operand order is exact");
	success &=
		check(insn[0].detail != NULL, "register detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		x86_reg expected_registers[3];
		uint8_t expected_access[3];
		uint8_t expected_count = nd ? 3 : 2;
		uint8_t i;

		if (att_syntax) {
			expected_registers[0] = source2;
			expected_registers[1] = source1;
			expected_registers[2] = destination;
			expected_access[0] = CS_AC_READ;
			expected_access[1] = nd ? CS_AC_READ :
						  CS_AC_READ | CS_AC_WRITE;
			expected_access[2] = CS_AC_WRITE;
		} else {
			expected_registers[0] = nd ? destination : source1;
			expected_registers[1] = nd ? source1 : source2;
			expected_registers[2] = source2;
			expected_access[0] = nd ? CS_AC_WRITE :
						  CS_AC_READ | CS_AC_WRITE;
			expected_access[1] = CS_AC_READ;
			expected_access[2] = CS_AC_READ;
		}
		success &= check(memcmp(x86->opcode, code, 4) == 0 &&
					 x86->addr_size == 8 &&
					 x86->modrm == code[5] &&
					 x86->encoding.modrm_offset == 5,
				 "register encoding detail is exact");
		success &= check(x86->op_count == expected_count,
				 "register public operand count is exact");
		for (i = 0; i < expected_count; ++i) {
			success &= check(
				x86->operands[i].type == X86_OP_REG &&
					x86->operands[i].reg ==
						expected_registers[i] &&
					x86->operands[i].size == width &&
					x86->operands[i].access ==
						expected_access[i],
				"register operand detail and access are exact");
		}
		success &= check_flag_detail(&insn[0], nf);
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "register cs_regs_access succeeds");
		success &=
			check(regs_read_count == 2 &&
				      has_register(regs_read, regs_read_count,
						   source1) &&
				      has_register(regs_read, regs_read_count,
						   source2),
			      "both register factors are read");
		success &= check(
			regs_write_count == 1 + (nf ? 0 : 1) &&
				has_register(regs_write, regs_write_count,
					     nd ? destination : source1) &&
				(nf ||
				 has_register(regs_write, regs_write_count,
					      X86_REG_EFLAGS)),
			"register destination and EFLAGS writes are exact");
	}

	if (success) {
		cs_free(insn, count);
		return true;
	}
failed:
	fprintf(stderr,
		"register case: width=%u nd=%u nf=%u seed=%u syntax=%s\n",
		width, nd, nf, seed, att_syntax ? "att" : "intel");
	if (count != 0)
		cs_free(insn, count);
	return false;
}

static bool check_memory_case(csh handle, uint8_t width, bool nd, bool nf,
			      bool att_syntax)
{
	const unsigned int destination_number = 31;
	const unsigned int source1_number = 27;
	x86_reg destination = register_for(width, destination_number);
	x86_reg source1 = register_for(width, source1_number);
	const char *destination_name = cs_reg_name(handle, destination);
	const char *source1_name = cs_reg_name(handle, source1);
	const char *size_name = memory_size_name(width);
	uint8_t code[8];
	char expected_mnemonic[32];
	char expected_operands[192];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	bool success = true;
	size_t count;

	encode_memory_case(code, width, nd, nf, destination_number,
			   source1_number);
	if (att_syntax) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic),
			 "%simul%c", nf ? "{nf} " : "", att_suffix(width));
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "0x20(%%r29,%%r30,4), %%%s, %%%s",
				 source1_name, destination_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "0x20(%%r29,%%r30,4), %%%s", source1_name);
		}
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%simul",
			 nf ? "{nf} " : "");
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s, %s ptr [r29 + r30*4 + 0x20]",
				 destination_name, source1_name, size_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s ptr [r29 + r30*4 + 0x20]",
				 source1_name, size_name);
		}
	}

	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "promoted memory IMUL decodes"))
		goto failed;
	success &= check(insn[0].id == X86_INS_IMUL,
			 "memory public IMUL ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "memory IMUL mnemonic is exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "memory IMUL operand order is exact");
	success &= check(insn[0].detail != NULL, "memory detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		uint8_t memory_index = att_syntax ? 0 : (nd ? 2 : 1);
		uint8_t source1_index = att_syntax ? 1 : (nd ? 1 : 0);
		const cs_x86_op *memory_operand = &x86->operands[memory_index];
		const cs_x86_op *source1_operand =
			&x86->operands[source1_index];

		success &= check(memcmp(x86->opcode, code, 4) == 0 &&
					 x86->addr_size == 8 &&
					 x86->modrm == code[5] &&
					 x86->sib == code[6] &&
					 x86->encoding.modrm_offset == 5 &&
					 x86->encoding.disp_offset == 7 &&
					 x86->encoding.disp_size == 1 &&
					 x86->disp == 0x20,
				 "memory encoding detail is exact");
		success &=
			check(x86->sib_base == X86_REG_R29 &&
				      x86->sib_index == X86_REG_R30 &&
				      x86->sib_scale == 4,
			      "memory high address-register detail is exact");
		success &= check(x86->op_count == (nd ? 3 : 2),
				 "memory public operand count is exact");
		success &= check(
			source1_operand->type == X86_OP_REG &&
				source1_operand->reg == source1 &&
				source1_operand->size == width &&
				source1_operand->access ==
					(nd ? CS_AC_READ :
					      (CS_AC_READ | CS_AC_WRITE)),
			"memory first-factor detail and access are exact");
		success &= check(
			memory_operand->type == X86_OP_MEM &&
				memory_operand->size == width &&
				memory_operand->access == CS_AC_READ &&
				memory_operand->mem.segment ==
					X86_REG_INVALID &&
				memory_operand->mem.base == X86_REG_R29 &&
				memory_operand->mem.index == X86_REG_R30 &&
				memory_operand->mem.scale == 4 &&
				memory_operand->mem.disp == 0x20,
			"public memory operand detail and access are exact");
		if (nd) {
			const cs_x86_op *destination_operand =
				&x86->operands[att_syntax ? 2 : 0];

			success &= check(
				destination_operand->type == X86_OP_REG &&
					destination_operand->reg ==
						destination &&
					destination_operand->size == width &&
					destination_operand->access ==
						CS_AC_WRITE,
				"memory NDD destination detail is exact");
		}
		success &= check_flag_detail(&insn[0], nf);
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "memory cs_regs_access succeeds");
		success &=
			check(regs_read_count == 3 &&
				      has_register(regs_read, regs_read_count,
						   source1) &&
				      has_register(regs_read, regs_read_count,
						   X86_REG_R29) &&
				      has_register(regs_read, regs_read_count,
						   X86_REG_R30),
			      "memory factor and address registers are read");
		success &= check(
			regs_write_count == 1 + (nf ? 0 : 1) &&
				has_register(regs_write, regs_write_count,
					     nd ? destination : source1) &&
				(nf ||
				 has_register(regs_write, regs_write_count,
					      X86_REG_EFLAGS)),
			"memory destination and EFLAGS writes are exact");
	}

	if (success) {
		cs_free(insn, count);
		return true;
	}
failed:
	fprintf(stderr, "memory case: width=%u nd=%u nf=%u syntax=%s\n", width,
		nd, nf, att_syntax ? "att" : "intel");
	if (count != 0)
		cs_free(insn, count);
	return false;
}

static bool run_matrix(csh handle, bool att_syntax)
{
	static const uint8_t widths[] = { 2, 4, 8 };
	size_t width_index;
	unsigned int nd, nf, seed;

	if (!check(cs_option(handle, CS_OPT_SYNTAX,
			     att_syntax ? CS_OPT_SYNTAX_ATT :
					  CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
		   "select matrix syntax"))
		return false;
	for (width_index = 0; width_index < sizeof(widths) / sizeof(widths[0]);
	     ++width_index) {
		for (nd = 0; nd < 2; ++nd) {
			for (nf = 0; nf < 2; ++nf) {
				for (seed = 0; seed < 32; ++seed) {
					if (!check_register_case(
						    handle, widths[width_index],
						    nd, nf, seed, att_syntax))
						return false;
				}
				if (!check_memory_case(handle,
						       widths[width_index], nd,
						       nf, att_syntax))
					return false;
			}
		}
	}
	return true;
}

static bool check_anchor(csh handle, const decode_anchor *anchor,
			 bool att_syntax)
{
	cs_insn *insn = NULL;
	size_t count;
	bool success = true;

	if (!check(cs_option(handle, CS_OPT_SYNTAX,
			     att_syntax ? CS_OPT_SYNTAX_ATT :
					  CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
		   "select anchor syntax"))
		return false;
	count = cs_disasm(handle, anchor->code, anchor->code_size, 0x1000, 1,
			  &insn);
	if (!check(count == 1, "current XED IMUL anchor decodes"))
		return false;
	success &= check(insn[0].id == X86_INS_IMUL,
			 "anchor public IMUL ID is exact");
	success &= check(strcmp(insn[0].mnemonic,
				att_syntax ? anchor->att_mnemonic :
					     anchor->intel_mnemonic) == 0,
			 "anchor IMUL mnemonic is exact");
	success &= check(strcmp(insn[0].op_str,
				att_syntax ? anchor->att_operands :
					     anchor->intel_operands) == 0,
			 "anchor IMUL operands are exact");
	cs_free(insn, count);
	return success;
}

static bool test_encoding_anchors(csh handle)
{
	static const uint8_t imul32[] = {
		0x62, 0x4c, 0x7c, 0x08, 0xaf, 0xf5,
	};
	static const uint8_t imul64_nd_nf[] = {
		0x62, 0x4c, 0x84, 0x14, 0xaf, 0xf5,
	};
	static const uint8_t imul32_nd_nf_memory[] = {
		0x62, 0x0c, 0x00, 0x14, 0xaf, 0x74, 0xb5, 0x20,
	};
	static const uint8_t imul64_nf_fs_memory[] = {
		0x64, 0x62, 0x0c, 0xf8, 0x0c, 0xaf, 0x74, 0xb5, 0x20,
	};
	static const uint8_t imul16_nd_address32[] = {
		0x67, 0x62, 0x0c, 0x01, 0x10, 0xaf, 0x74, 0xb5, 0x20,
	};
	static const decode_anchor anchors[] = {
		{ imul32, sizeof(imul32), "imul", "r30d, r29d", "imull",
		  "%r29d, %r30d" },
		{ imul64_nd_nf, sizeof(imul64_nd_nf), "{nf} imul",
		  "r31, r30, r29", "{nf} imulq", "%r29, %r30, %r31" },
		{ imul32_nd_nf_memory, sizeof(imul32_nd_nf_memory), "{nf} imul",
		  "r31d, r30d, dword ptr [r29 + r30*4 + 0x20]", "{nf} imull",
		  "0x20(%r29,%r30,4), %r30d, %r31d" },
		{ imul64_nf_fs_memory, sizeof(imul64_nf_fs_memory), "{nf} imul",
		  "r30, qword ptr fs:[r29 + r30*4 + 0x20]", "{nf} imulq",
		  "%fs:0x20(%r29,%r30,4), %r30" },
		{ imul16_nd_address32, sizeof(imul16_nd_address32), "imul",
		  "r31w, r30w, word ptr [r29d + r30d*4 + 0x20]", "imulw",
		  "0x20(%r29d,%r30d,4), %r30w, %r31w" },
	};
	uint8_t code[8];
	bool success = true;
	size_t i;

	encode_register_case(code, 4, false, false, 30, 30, 29);
	success &= check(memcmp(code, imul32, sizeof(imul32)) == 0,
			 "32-bit IMUL encoding matches current XED");
	encode_register_case(code, 8, true, true, 31, 30, 29);
	success &= check(memcmp(code, imul64_nd_nf, sizeof(imul64_nd_nf)) == 0,
			 "64-bit NDD+NF IMUL encoding matches current XED");
	for (i = 0; i < sizeof(anchors) / sizeof(anchors[0]); ++i) {
		success &= check_anchor(handle, &anchors[i], false);
		success &= check_anchor(handle, &anchors[i], true);
		if (!success)
			return false;
	}
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

static bool decodes_as(csh handle, const uint8_t *code, size_t code_size,
		       const char *mnemonic, const char *operands,
		       const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	bool success = check(count == 1, message);

	if (count == 1) {
		success &=
			check(insn[0].id == X86_INS_IMUL &&
				      strcmp(insn[0].mnemonic, mnemonic) == 0 &&
				      strcmp(insn[0].op_str, operands) == 0,
			      "legal IMUL variant semantics are exact");
		cs_free(insn, count);
	}
	return success;
}

static bool test_legal_variants(csh handle)
{
	static const uint8_t prefixes[] = {
		0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x67,
	};
	uint8_t base[8], code[10];
	bool success = true;
	size_t i;

	success &= check(cs_option(handle, CS_OPT_SYNTAX,
				   CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
			 "select Intel syntax for legal variants");
	encode_register_case(base, 8, true, true, 31, 30, 29);
	base[2] |= 1;
	success &= decodes_as(handle, base, 6, "{nf} imul", "r31, r30, r29",
			      "W=1 takes precedence over pp=66");
	base[1] ^= 0x40;
	success &= decodes_as(handle, base, 6, "{nf} imul", "r31, r30, r29",
			      "unused register-form X extension is ignored");

	encode_register_case(base, 4, false, true, 23, 23, 12);
	for (i = 0; i < sizeof(prefixes); ++i) {
		cs_insn *insn = NULL;
		size_t count;

		code[0] = prefixes[i];
		memcpy(code + 1, base, 6);
		count = cs_disasm(handle, code, 7, 0x1000, 1, &insn);
		success &= check(count == 1,
				 "legal segment/address prefix decodes");
		if (count == 1) {
			const cs_x86 *x86 = &insn[0].detail->x86;

			success &=
				check(insn[0].id == X86_INS_IMUL &&
					      strcmp(insn[0].mnemonic,
						     "{nf} imul") == 0 &&
					      strcmp(insn[0].op_str,
						     "r23d, r12d") == 0,
				      "legal prefix preserves IMUL semantics");
			success &= check(
				x86->encoding.modrm_offset == 6 &&
					x86->addr_size ==
						(prefixes[i] == 0x67 ? 4 : 8) &&
					x86->prefix[prefixes[i] == 0x67 ? 3 :
									  1] ==
						prefixes[i],
				"legal prefix detail and offsets are exact");
			cs_free(insn, count);
		}
	}

	encode_memory_case(base, 4, true, true, 31, 30);
	base[2] |= 0x04;
	success &= decodes_as(handle, base, 8, "{nf} imul",
			      "r31d, r30d, dword ptr [r29 + r14*4 + 0x20]",
			      "memory EVEX.U is the X4 address extension");
	code[0] = 0x67;
	encode_memory_case(code + 1, 2, true, false, 31, 30);
	success &=
		decodes_as(handle, code, 9, "imul",
			   "r31w, r30w, word ptr [r29d + r30d*4 + 0x20]",
			   "address-size override uses 32-bit EGPR addressing");
	return success;
}

static bool rejects(csh handle, const uint8_t *code, size_t code_size,
		    const char *message);
static bool decodes_as(csh handle, const uint8_t *code, size_t code_size,
		       const char *mnemonic, const char *operands,
		       const char *message);

static bool test_immediate_and_one_operand_forms(csh handle)
{
	static const uint8_t imul6b_zu_nf[] = {
		0x62, 0xec, 0x7d, 0x1c, 0x6b, 0xcb, 0xfd,
	};
	static const uint8_t imul69_nf[] = {
		0x62, 0xec, 0xfc, 0x0c, 0x69, 0xcb, 0xfe, 0xff, 0xff, 0xff,
	};
	static const uint8_t imul_f7_nf[] = {
		0x62, 0xfc, 0xfc, 0x0c, 0xf7, 0xeb,
	};
	static const uint8_t imul_f6_ignored_w_nf[] = {
		0x62, 0xf4, 0xfc, 0x0c, 0xf6, 0xeb,
	};
	cs_insn *insn = NULL;
	bool success = true;
	uint8_t invalid[sizeof(imul69_nf)];
	size_t count;

	success &= check(cs_option(handle, CS_OPT_SYNTAX,
				   CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
			 "select Intel syntax for extended IMUL forms");
	count = cs_disasm(handle, imul6b_zu_nf, sizeof(imul6b_zu_nf), 0x1000, 1,
			  &insn);
	success &= check(count == 1, "IMUL 6B ZU+NF decodes");
	if (count == 1) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(
			insn[0].id == X86_INS_IMUL &&
				strcmp(insn[0].mnemonic, "{nf} imul") == 0 &&
				strcmp(insn[0].op_str, "r17w, r19w, -3") == 0,
			"IMUL 6B public identity and operands are exact");
		success &=
			check(x86->op_count == 3 &&
				      x86->operands[0].type == X86_OP_REG &&
				      x86->operands[0].reg == X86_REG_R17W &&
				      x86->operands[0].size == 2 &&
				      x86->operands[0].access == CS_AC_WRITE &&
				      x86->operands[1].type == X86_OP_REG &&
				      x86->operands[1].reg == X86_REG_R19W &&
				      x86->operands[1].size == 2 &&
				      x86->operands[1].access == CS_AC_READ &&
				      x86->operands[2].type == X86_OP_IMM &&
				      x86->operands[2].imm == -3 &&
				      x86->operands[2].size == 2 &&
				      x86->operands[2].access == CS_AC_READ,
			      "IMUL 6B operand detail and access are exact");
		success &= check(x86->encoding.modrm_offset == 5 &&
					 x86->encoding.imm_offset == 6 &&
					 x86->encoding.imm_size == 1 &&
					 x86->eflags == 0 &&
					 insn[0].detail->regs_read_count == 0 &&
					 insn[0].detail->regs_write_count == 0,
				 "IMUL 6B encoding and NF detail are exact");
		cs_free(insn, count);
		insn = NULL;
	}

	count = cs_disasm(handle, imul69_nf, sizeof(imul69_nf), 0x1000, 1,
			  &insn);
	success &= check(count == 1, "IMUL 69 NF decodes");
	if (count == 1) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(
			insn[0].id == X86_INS_IMUL &&
				strcmp(insn[0].mnemonic, "{nf} imul") == 0 &&
				strcmp(insn[0].op_str, "r17, r19, -2") == 0 &&
				x86->op_count == 3 &&
				x86->operands[2].type == X86_OP_IMM &&
				x86->operands[2].imm == -2 &&
				x86->operands[2].size == 8 &&
				x86->encoding.imm_offset == 6 &&
				x86->encoding.imm_size == 4 && x86->eflags == 0,
			"IMUL 69 sign-extended immediate detail is exact");
		cs_free(insn, count);
		insn = NULL;
	}

	count = cs_disasm(handle, imul_f7_nf, sizeof(imul_f7_nf), 0x1000, 1,
			  &insn);
	success &= check(count == 1, "IMUL F7 /5 NF decodes");
	if (count == 1) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(
			insn[0].id == X86_INS_IMUL &&
				strcmp(insn[0].mnemonic, "{nf} imul") == 0 &&
				strcmp(insn[0].op_str, "r19") == 0 &&
				x86->op_count == 1 &&
				x86->operands[0].type == X86_OP_REG &&
				x86->operands[0].reg == X86_REG_R19 &&
				x86->operands[0].size == 8 &&
				x86->operands[0].access == CS_AC_READ &&
				x86->eflags == 0 &&
				insn[0].detail->regs_read_count == 1 &&
				insn[0].detail->regs_read[0] == X86_REG_RAX &&
				insn[0].detail->regs_write_count == 2 &&
				insn[0].detail->regs_write[0] == X86_REG_RAX &&
				insn[0].detail->regs_write[1] == X86_REG_RDX,
			"IMUL F7 implicit registers and NF detail are exact");
		cs_free(insn, count);
		insn = NULL;
	}

	count = cs_disasm(handle, imul_f6_ignored_w_nf,
			  sizeof(imul_f6_ignored_w_nf), 0x1000, 1, &insn);
	success &= check(count == 1, "IMUL F6 /5 accepts ignored W");
	if (count == 1) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(
			insn[0].id == X86_INS_IMUL &&
				strcmp(insn[0].mnemonic, "{nf} imul") == 0 &&
				strcmp(insn[0].op_str, "bl") == 0 &&
				x86->operands[0].reg == X86_REG_BL &&
				x86->operands[0].size == 1 &&
				insn[0].detail->regs_read_count == 1 &&
				insn[0].detail->regs_read[0] == X86_REG_AL &&
				insn[0].detail->regs_write_count == 2 &&
				insn[0].detail->regs_write[0] == X86_REG_AL &&
				insn[0].detail->regs_write[1] == X86_REG_AH,
			"IMUL F6 byte and implicit-register detail are exact");
		cs_free(insn, count);
		insn = NULL;
	}

	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "select AT&T syntax for extended IMUL forms");
	success &= decodes_as(handle, imul6b_zu_nf, sizeof(imul6b_zu_nf),
			      "{nf} imulw", "$-3, %r19w, %r17w",
			      "IMUL 6B AT&T order is exact");
	success &= decodes_as(handle, imul_f7_nf, sizeof(imul_f7_nf),
			      "{nf} imulq", "%r19",
			      "IMUL F7 AT&T form is exact");
	memcpy(invalid, imul6b_zu_nf, sizeof(imul6b_zu_nf));
	invalid[2] ^= 0x08;
	success &= rejects(handle, invalid, sizeof(imul6b_zu_nf),
			   "IMUL 6B rejects nonzero VVVVV");
	memcpy(invalid, imul_f7_nf, sizeof(imul_f7_nf));
	invalid[3] |= 0x10;
	success &= rejects(handle, invalid, sizeof(imul_f7_nf),
			   "IMUL F7 /5 rejects ND");
	return success;
}

static bool test_invalid_encodings(csh handle)
{
	static const uint8_t forbidden_prefixes[] = {
		0x66, 0xf0, 0xf2, 0xf3, 0x40, 0x48,
	};
	static const uint8_t reserved_p2_bits[] = {
		0x80, 0x40, 0x20, 0x02, 0x01,
	};
	uint8_t base[8], code[17];
	bool success = true;
	size_t i;

	success &= check(cs_option(handle, CS_OPT_SYNTAX,
				   CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
			 "select Intel syntax for invalid encodings");
	encode_register_case(base, 4, false, false, 23, 23, 12);
	for (i = 1; i < 6; ++i)
		success &= rejects(handle, base, i,
				   "truncated register IMUL is rejected");
	for (i = 0; i < sizeof(reserved_p2_bits); ++i) {
		memcpy(code, base, 6);
		code[3] |= reserved_p2_bits[i];
		success &= rejects(handle, code, 6,
				   "reserved EVEX P2 bit is rejected");
	}
	memcpy(code, base, 6);
	code[2] &= (uint8_t)~0x04;
	success &= rejects(handle, code, 6,
			   "EVEX.U=0 is rejected for register IMUL");
	memcpy(code, base, 6);
	code[2] &= (uint8_t)~0x08;
	success &= rejects(handle, code, 6,
			   "nonzero low VVVV with ND=0 is rejected");
	memcpy(code, base, 6);
	code[3] &= (uint8_t)~0x08;
	success &= rejects(handle, code, 6, "nonzero V4 with ND=0 is rejected");
	memcpy(code, base, 6);
	code[2] = (code[2] & (uint8_t)~3) | 2;
	success &= rejects(handle, code, 6, "F3 pp is rejected for IMUL AF");
	code[2] = (code[2] & (uint8_t)~3) | 3;
	success &= rejects(handle, code, 6, "F2 pp is rejected for IMUL AF");

	for (i = 0; i < sizeof(forbidden_prefixes); ++i) {
		code[0] = forbidden_prefixes[i];
		memcpy(code + 1, base, 6);
		success &= rejects(handle, code, 7,
				   "forbidden legacy prefix is rejected");
	}

	encode_memory_case(base, 8, true, true, 31, 30);
	for (i = 6; i < 8; ++i)
		success &= rejects(handle, base, i,
				   "truncated memory IMUL is rejected");
	memcpy(code, base, 8);
	code[3] &= (uint8_t)~0x10;
	success &= rejects(handle, code, 8,
			   "memory nonzero VVVV with ND=0 is rejected");

	encode_register_case(base, 4, true, true, 31, 30, 29);
	memset(code, 0x64, 10);
	memcpy(code + 10, base, 6);
	success &= rejects(handle, code, 16,
			   "IMUL longer than 15 bytes is rejected");
	return success;
}

static bool test_wrong_mode(void)
{
	uint8_t code[6];
	csh handle = 0;
	bool success;

	encode_register_case(code, 4, true, true, 31, 30, 29);
	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK,
		   "open 32-bit mode"))
		return false;
	success = rejects(handle, code, sizeof(code),
			  "APX EVEX IMUL is rejected outside 64-bit mode");
	cs_close(&handle);
	return success;
}

int main(void)
{
	csh handle = 0;
	bool success = true;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "open 64-bit mode"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "enable real detail")) {
		cs_close(&handle);
		return 1;
	}
	success &= test_encoding_anchors(handle);
	success &= run_matrix(handle, false);
	success &= run_matrix(handle, true);
	success &= test_legal_variants(handle);
	success &= test_immediate_and_one_operand_forms(handle);
	success &= test_invalid_encodings(handle);
	cs_close(&handle);
	success &= test_wrong_mode();
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct alu_operation {
	x86_insn instruction;
	const char *mnemonic;
	uint8_t base_opcode;
	uint64_t eflags;
} alu_operation;

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX EVEX ALU check failed: %s\n", message);
	return condition;
}

static x86_reg register_for(uint8_t width, unsigned int number)
{
	static const x86_reg registers_8[] = {
		X86_REG_AL,   X86_REG_CL,   X86_REG_DL,	  X86_REG_BL,
		X86_REG_SPL,  X86_REG_BPL,  X86_REG_SIL,  X86_REG_DIL,
		X86_REG_R8B,  X86_REG_R9B,  X86_REG_R10B, X86_REG_R11B,
		X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B,
		X86_REG_R16B, X86_REG_R17B, X86_REG_R18B, X86_REG_R19B,
		X86_REG_R20B, X86_REG_R21B, X86_REG_R22B, X86_REG_R23B,
		X86_REG_R24B, X86_REG_R25B, X86_REG_R26B, X86_REG_R27B,
		X86_REG_R28B, X86_REG_R29B, X86_REG_R30B, X86_REG_R31B,
	};
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
	case 1:
		return registers_8[number];
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

static void encode_case(uint8_t code[6], const alu_operation *operation,
			uint8_t width, bool reverse, bool nd, bool nf,
			unsigned int destination_number,
			unsigned int source1_number,
			unsigned int source2_number)
{
	unsigned int reg_number = reverse ? source1_number : source2_number;
	unsigned int rm_number = reverse ? source2_number : source1_number;
	unsigned int ndd_number = nd ? destination_number : 0;
	uint8_t opcode = operation->base_opcode + (reverse ? 2 : 0) +
			 (width == 1 ? 0 : 1);
	uint8_t pp = width == 2 ? 1 : 0;
	uint8_t w = width == 8 ? 0x80 : 0;

	code[0] = 0x62;
	code[1] = 0x44 | ((reg_number & 8) ? 0 : 0x80) |
		  ((rm_number & 8) ? 0 : 0x20) |
		  ((reg_number & 16) ? 0 : 0x10) |
		  ((rm_number & 16) ? 0x08 : 0);
	code[2] = w | (((~ndd_number) & 0xf) << 3) | 0x04 | pp;
	code[3] = (nd ? 0x10 : 0) | (nf ? 0x04 : 0) |
		  ((ndd_number & 16) ? 0 : 0x08);
	code[4] = opcode;
	code[5] = 0xc0 | ((reg_number & 7) << 3) | (rm_number & 7);
}

static char att_suffix(uint8_t width)
{
	switch (width) {
	default:
		return '?';
	case 1:
		return 'b';
	case 2:
		return 'w';
	case 4:
		return 'l';
	case 8:
		return 'q';
	}
}

static bool check_case(csh handle, const alu_operation *operation,
		       uint8_t width, bool reverse, bool nd, bool nf,
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
	char expected_operands[96];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0;
	uint8_t regs_write_count = 0;
	bool success = true;
	size_t count;

	encode_case(code, operation, width, reverse, nd, nf, destination_number,
		    source1_number, source2_number);
	if (att_syntax) {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s%c",
			 nf ? "{nf} " : "", operation->mnemonic,
			 att_suffix(width));
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%%%s, %%%s, %%%s", source2_name, source1_name,
				 destination_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%%%s, %%%s", source2_name, destination_name);
		}
	} else {
		snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s",
			 nf ? "{nf} " : "", operation->mnemonic);
		if (nd) {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s, %s", destination_name, source1_name,
				 source2_name);
		} else {
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s", destination_name, source2_name);
		}
	}

	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "promoted register ALU instruction decodes"))
		goto failed;
	success &= check(insn[0].id == operation->instruction,
			 "public instruction ID is exact");
	success &= check(strcmp(cs_insn_name(handle, insn[0].id),
				operation->mnemonic) == 0,
			 "public instruction name is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "mnemonic and NF decorator are exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "operand order and register names are exact");
	success &= check(insn[0].detail != NULL, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		x86_reg expected_registers[3];
		uint8_t expected_access[3];
		uint8_t expected_count = nd ? 3 : 2;
		uint8_t i;

		if (att_syntax) {
			expected_registers[0] = source2;
			expected_registers[1] = nd ? source1 : destination;
			expected_registers[2] = destination;
			expected_access[0] = CS_AC_READ;
			expected_access[1] = nd ? CS_AC_READ :
						  CS_AC_READ | CS_AC_WRITE;
			expected_access[2] = CS_AC_WRITE;
		} else {
			expected_registers[0] = destination;
			expected_registers[1] = nd ? source1 : source2;
			expected_registers[2] = source2;
			expected_access[0] = nd ? CS_AC_WRITE :
						  CS_AC_READ | CS_AC_WRITE;
			expected_access[1] = CS_AC_READ;
			expected_access[2] = CS_AC_READ;
		}
		success &= check(memcmp(x86->opcode, code, 4) == 0,
				 "EVEX prefix detail is exact");
		success &= check(x86->addr_size == 8,
				 "default address size is exact");
		success &= check(x86->modrm == code[5] &&
					 x86->encoding.modrm_offset == 5,
				 "ModR/M detail and offset are exact");
		success &= check(x86->op_count == expected_count,
				 "public operand count is exact");
		for (i = 0; i < x86->op_count && i < expected_count; ++i) {
			success &= check(
				x86->operands[i].type == X86_OP_REG &&
					x86->operands[i].reg ==
						expected_registers[i] &&
					x86->operands[i].size == width &&
					x86->operands[i].access ==
						expected_access[i],
				"public register operand detail is exact");
		}
		if (nf) {
			success &= check(
				x86->eflags == 0 &&
					insn[0].detail->regs_write_count == 0,
				"NF suppresses EFLAGS detail");
		} else {
			success &= check(
				x86->eflags == operation->eflags &&
					insn[0].detail->regs_write_count == 1 &&
					insn[0].detail->regs_write[0] ==
						X86_REG_EFLAGS,
				"flag-writing detail is exact");
		}
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
						&regs_read_count, regs_write,
						&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &=
			check(regs_read_count == 2 &&
				      has_register(regs_read, regs_read_count,
						   source1) &&
				      has_register(regs_read, regs_read_count,
						   source2),
			      "both data sources are read");
		success &= check(
			regs_write_count == (nf ? 1 : 2) &&
				has_register(regs_write, regs_write_count,
					     destination) &&
				(nf ||
				 has_register(regs_write, regs_write_count,
					      X86_REG_EFLAGS)),
			"destination and optional EFLAGS writes are exact");
	}

	cs_free(insn, count);
	if (success)
		return true;
failed:
	fprintf(stderr,
		"case: op=%s width=%u reverse=%u nd=%u nf=%u seed=%u syntax=%s\n",
		operation->mnemonic, width, reverse, nd, nf, seed,
		att_syntax ? "att" : "intel");
	if (count != 0)
		cs_free(insn, count);
	return false;
}

static bool run_matrix(csh handle, const alu_operation *operations,
		       size_t operation_count, bool att_syntax)
{
	static const uint8_t widths[] = { 1, 2, 4, 8 };
	bool success = true;
	size_t operation_index;
	uint8_t width_index;
	unsigned int reverse, nd, nf, seed;

	for (operation_index = 0; operation_index < operation_count;
	     ++operation_index) {
		for (width_index = 0;
		     width_index < sizeof(widths) / sizeof(widths[0]);
		     ++width_index) {
			for (reverse = 0; reverse < 2; ++reverse) {
				for (nd = 0; nd < 2; ++nd) {
					for (nf = 0; nf < 2; ++nf) {
						for (seed = 0; seed < 32;
						     ++seed) {
							success &= check_case(
								handle,
								&operations
									[operation_index],
								widths[width_index],
								reverse, nd, nf,
								seed,
								att_syntax);
							if (!success)
								return false;
						}
					}
				}
			}
		}
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

static bool test_encoding_anchors(void)
{
	static const uint64_t arithmetic_flags =
		X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
		X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
		X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
	static const uint64_t logical_flags =
		X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
		X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
		X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
	static const alu_operation add = {
		X86_INS_ADD,
		"add",
		0x00,
		arithmetic_flags,
	};
	static const alu_operation sub = {
		X86_INS_SUB,
		"sub",
		0x28,
		arithmetic_flags,
	};
	static const alu_operation or_op = {
		X86_INS_OR,
		"or",
		0x08,
		logical_flags,
	};
	static const alu_operation and_op = {
		X86_INS_AND,
		"and",
		0x20,
		logical_flags,
	};
	static const alu_operation xor_op = {
		X86_INS_XOR,
		"xor",
		0x30,
		logical_flags,
	};
	static const uint8_t low_add[] = { 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9 };
	static const uint8_t high_ndd_nf_add[] = { 0x62, 0x4c, 0x84,
						   0x14, 0x01, 0xee };
	static const uint8_t high_nf_sub[] = { 0x62, 0xec, 0x7c,
					       0x0c, 0x29, 0xc8 };
	static const uint8_t high_ndd_nf_or[] = { 0x62, 0x4c, 0x04,
						  0x14, 0x08, 0xee };
	static const uint8_t high_ndd_and[] = { 0x62, 0x4c, 0x05,
						0x10, 0x21, 0xee };
	static const uint8_t high_ndd_nf_xor[] = { 0x62, 0x4c, 0x04,
						   0x14, 0x31, 0xee };
	uint8_t code[6];
	bool success = true;

	encode_case(code, &add, 1, false, false, false, 1, 1, 3);
	success &= check(memcmp(code, low_add, sizeof(code)) == 0,
			 "low-register ADD encoding matches LLVM MC");
	encode_case(code, &add, 8, false, true, true, 31, 30, 29);
	success &= check(memcmp(code, high_ndd_nf_add, sizeof(code)) == 0,
			 "high-register NDD+NF ADD encoding matches LLVM MC");
	encode_case(code, &sub, 4, false, false, true, 16, 16, 17);
	success &= check(memcmp(code, high_nf_sub, sizeof(code)) == 0,
			 "high-register NF SUB encoding matches LLVM MC");
	encode_case(code, &or_op, 1, false, true, true, 31, 30, 29);
	success &= check(memcmp(code, high_ndd_nf_or, sizeof(code)) == 0,
			 "high-register NDD+NF OR encoding matches LLVM MC");
	encode_case(code, &and_op, 2, false, true, false, 31, 30, 29);
	success &= check(memcmp(code, high_ndd_and, sizeof(code)) == 0,
			 "high-register NDD AND encoding matches LLVM MC");
	encode_case(code, &xor_op, 4, false, true, true, 31, 30, 29);
	success &= check(memcmp(code, high_ndd_nf_xor, sizeof(code)) == 0,
			 "high-register NDD+NF XOR encoding matches LLVM MC");
	return success;
}

static bool test_allowed_prefixes(csh handle)
{
	static const uint8_t base[] = { 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9 };
	static const uint8_t prefixes[][2] = {
		{ 0x67, 0 }, { 0x26, 0 }, { 0x2e, 0 }, { 0x36, 0 },
		{ 0x3e, 0 }, { 0x64, 0 }, { 0x65, 0 }, { 0x64, 0x67 },
	};
	static const uint8_t prefix_sizes[] = { 1, 1, 1, 1, 1, 1, 1, 2 };
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(prefix_sizes) / sizeof(prefix_sizes[0]); ++i) {
		uint8_t code[8] = { 0 };
		uint8_t prefix_size = prefix_sizes[i];
		uint8_t expected_segment = 0;
		bool expected_address_size = false;
		cs_insn *insn = NULL;
		size_t count;
		uint8_t prefix_index;

		for (prefix_index = 0; prefix_index < prefix_size;
		     ++prefix_index) {
			if (prefixes[i][prefix_index] == 0x67)
				expected_address_size = true;
			else
				expected_segment = prefixes[i][prefix_index];
		}

		memcpy(code, prefixes[i], prefix_size);
		memcpy(code + prefix_size, base, sizeof(base));
		count = cs_disasm(handle, code, prefix_size + sizeof(base),
				  0x1000, 1, &insn);
		success &= check(count == 1,
				 "legal APX segment/address prefix decodes");
		if (count == 1) {
			const cs_x86 *x86 = &insn[0].detail->x86;

			success &= check(
				insn[0].id == X86_INS_ADD &&
					strcmp(insn[0].mnemonic, "add") == 0 &&
					strcmp(insn[0].op_str, "cl, bl") == 0,
				"legal prefix does not change semantics");
			success &= check(
				x86->prefix[1] == expected_segment &&
					x86->prefix[3] ==
						(expected_address_size ? 0x67 :
									 0),
				"legal prefix detail is exact");
			success &= check(
				x86->addr_size == (x86->prefix[3] == 0x67 ?
							   4 :
							   8) &&
					x86->encoding.modrm_offset ==
						prefix_size + 5,
				"legal prefix adjusts detail offsets");
			cs_free(insn, count);
		}
	}
	{
		uint8_t ignored_x[sizeof(base)];
		cs_insn *insn = NULL;
		size_t count;

		memcpy(ignored_x, base, sizeof(base));
		ignored_x[1] &= (uint8_t)~0x40;
		count = cs_disasm(handle, ignored_x, sizeof(ignored_x), 0x1000,
				  1, &insn);
		success &= check(count == 1,
				 "unused EVEX.X3 is ignored for register form");
		if (count != 0)
			cs_free(insn, count);
	}
	{
		uint8_t ignored_w[sizeof(base)];
		uint8_t w_precedes_pp[] = { 0x62, 0xf4, 0xfd, 0x08, 0x01, 0xd9 };
		cs_insn *insn = NULL;
		size_t count;

		memcpy(ignored_w, base, sizeof(base));
		ignored_w[2] |= 0x80;
		count = cs_disasm(handle, ignored_w, sizeof(ignored_w), 0x1000,
				  1, &insn);
		success &= check(count == 1 &&
					 strcmp(insn[0].op_str, "cl, bl") == 0,
				 "W is ignored for the 8-bit form");
		if (count != 0)
			cs_free(insn, count);
		insn = NULL;
		count = cs_disasm(handle, w_precedes_pp, sizeof(w_precedes_pp),
				  0x1000, 1, &insn);
		success &= check(count == 1 && strcmp(insn[0].op_str,
						      "rcx, rbx") == 0,
				 "W=1 takes precedence over pp=66");
		if (count != 0)
			cs_free(insn, count);
	}
	return success;
}

static bool test_invalid_encodings(csh handle)
{
	static const uint8_t base[] = { 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9 };
	static const uint8_t forbidden_prefixes[] = {
		0x66, 0xf0, 0xf2, 0xf3, 0x40, 0x48,
	};
	static const uint8_t reserved_p2_bits[] = {
		0x80, 0x40, 0x20, 0x02, 0x01,
	};
	static const uint8_t unsupported_opcodes[] = {
		0x38,
		0x80,
		0xfc,
	};
	bool success = true;
	size_t i;

	for (i = 1; i < sizeof(base); ++i)
		success &= rejects(handle, base, i,
				   "truncated APX encoding is rejected");
	for (i = 0; i < sizeof(reserved_p2_bits); ++i) {
		uint8_t code[sizeof(base)];

		memcpy(code, base, sizeof(base));
		code[3] |= reserved_p2_bits[i];
		success &= rejects(handle, code, sizeof(code),
				   "reserved EVEX P2 bit is rejected");
	}
	{
		uint8_t code[sizeof(base)];

		memcpy(code, base, sizeof(base));
		code[2] &= (uint8_t)~0x04;
		success &= rejects(handle, code, sizeof(code),
				   "EVEX.U=0 is rejected for Mod=3");
		memcpy(code, base, sizeof(base));
		code[2] &= (uint8_t)~0x08;
		success &= rejects(handle, code, sizeof(code),
				   "nonzero vvvv with ND=0 is rejected");
		memcpy(code, base, sizeof(base));
		code[3] &= (uint8_t)~0x08;
		success &= rejects(handle, code, sizeof(code),
				   "nonzero V4 with ND=0 is rejected");
		memcpy(code, base, sizeof(base));
		code[2] = (code[2] & (uint8_t)~3) | 1;
		success &= rejects(handle, code, sizeof(code),
				   "8-bit form with 66 pp is rejected");
		code[2] = (code[2] & (uint8_t)~3) | 2;
		success &= rejects(handle, code, sizeof(code),
				   "8-bit form with F3 pp is rejected");
		code[2] = (code[2] & (uint8_t)~3) | 3;
		success &= rejects(handle, code, sizeof(code),
				   "8-bit form with F2 pp is rejected");
		memcpy(code, base, sizeof(base));
		code[4] = 0x01;
		code[2] = (code[2] & (uint8_t)~3) | 2;
		success &= rejects(handle, code, sizeof(code),
				   "scalable form with F3 pp is rejected");
		code[2] = (code[2] & (uint8_t)~3) | 3;
		success &= rejects(handle, code, sizeof(code),
				   "scalable form with F2 pp is rejected");
		memcpy(code, base, sizeof(base));
		code[5] &= 0x3f;
		success &= rejects(handle, code, sizeof(code),
				   "memory form remains fail-closed");
	}
	for (i = 0; i < sizeof(unsupported_opcodes); ++i) {
		uint8_t code[sizeof(base)];

		memcpy(code, base, sizeof(base));
		code[4] = unsupported_opcodes[i];
		success &= rejects(handle, code, sizeof(code),
				   "uncovered map4 opcode remains fail-closed");
	}
	for (i = 0; i < sizeof(forbidden_prefixes); ++i) {
		uint8_t code[sizeof(base) + 1];

		code[0] = forbidden_prefixes[i];
		memcpy(code + 1, base, sizeof(base));
		success &= rejects(handle, code, sizeof(code),
				   "forbidden prefix before EVEX is rejected");
	}
	return success;
}

static bool test_wrong_mode(void)
{
	static const uint8_t code[] = { 0x62, 0xf4, 0x7c, 0x08, 0x00, 0xd9 };
	csh handle = 0;
	bool success;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK,
		   "open 32-bit mode"))
		return false;
	success =
		rejects(handle, code, sizeof(code),
			"APX EVEX instruction is rejected outside 64-bit mode");
	cs_close(&handle);
	return success;
}

int main(void)
{
	static const uint64_t arithmetic_flags =
		X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
		X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
		X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
	static const uint64_t logical_flags =
		X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
		X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
		X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
	const alu_operation operations[] = {
		{ X86_INS_ADD, "add", 0x00, arithmetic_flags },
		{ X86_INS_OR, "or", 0x08, logical_flags },
		{ X86_INS_AND, "and", 0x20, logical_flags },
		{ X86_INS_SUB, "sub", 0x28, arithmetic_flags },
		{ X86_INS_XOR, "xor", 0x30, logical_flags },
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

	success &= test_encoding_anchors();
	success &= run_matrix(handle, operations,
			      sizeof(operations) / sizeof(operations[0]),
			      false);
	if (success) {
		success &= check(cs_option(handle, CS_OPT_SYNTAX,
					   CS_OPT_SYNTAX_ATT) == CS_ERR_OK,
				 "select AT&T syntax");
		success &= run_matrix(
			handle, operations,
			sizeof(operations) / sizeof(operations[0]), true);
	}
	if (success) {
		success &= check(cs_option(handle, CS_OPT_SYNTAX,
					   CS_OPT_SYNTAX_INTEL) == CS_ERR_OK,
				 "restore Intel syntax");
		success &= test_allowed_prefixes(handle);
		success &= test_invalid_encodings(handle);
		success &= test_wrong_mode();
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

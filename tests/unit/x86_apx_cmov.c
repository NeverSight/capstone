/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static const char *const condition_names[16] = {
	"o", "no", "b", "ae", "e", "ne", "be", "a",
	"s", "ns", "p", "np", "l", "ge", "le", "g",
};

static const x86_insn cmov_ids[16] = {
	X86_INS_CMOVO,  X86_INS_CMOVNO, X86_INS_CMOVB,  X86_INS_CMOVAE,
	X86_INS_CMOVE,  X86_INS_CMOVNE, X86_INS_CMOVBE, X86_INS_CMOVA,
	X86_INS_CMOVS,  X86_INS_CMOVNS, X86_INS_CMOVP,  X86_INS_CMOVNP,
	X86_INS_CMOVL,  X86_INS_CMOVGE, X86_INS_CMOVLE, X86_INS_CMOVG,
};

static const x86_insn cfcmov_ids[16] = {
	X86_INS_CFCMOVO,  X86_INS_CFCMOVNO, X86_INS_CFCMOVB,
	X86_INS_CFCMOVAE, X86_INS_CFCMOVE,  X86_INS_CFCMOVNE,
	X86_INS_CFCMOVBE, X86_INS_CFCMOVA,  X86_INS_CFCMOVS,
	X86_INS_CFCMOVNS, X86_INS_CFCMOVP,  X86_INS_CFCMOVNP,
	X86_INS_CFCMOVL,  X86_INS_CFCMOVGE, X86_INS_CFCMOVLE,
	X86_INS_CFCMOVG,
};

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "APX CMOV check failed: %s\n", message);
	return condition;
}

static x86_reg gpr(unsigned int number, uint8_t width)
{
	static const x86_reg registers_16[] = {
		X86_REG_AX,   X86_REG_CX,   X86_REG_DX,   X86_REG_BX,
		X86_REG_SP,   X86_REG_BP,   X86_REG_SI,   X86_REG_DI,
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
		X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
		X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
		X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
		X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
		X86_REG_R16, X86_REG_R17, X86_REG_R18, X86_REG_R19,
		X86_REG_R20, X86_REG_R21, X86_REG_R22, X86_REG_R23,
		X86_REG_R24, X86_REG_R25, X86_REG_R26, X86_REG_R27,
		X86_REG_R28, X86_REG_R29, X86_REG_R30, X86_REG_R31,
	};

	if (number >= 32)
		return X86_REG_INVALID;
	if (width == 2)
		return registers_16[number];
	if (width == 4)
		return registers_32[number];
	if (width == 8)
		return registers_64[number];
	return X86_REG_INVALID;
}

static uint8_t scalable_width(bool w, unsigned int pp)
{
	return w ? 8 : pp == 1 ? 2 : 4;
}

static void encode_evex(uint8_t code[6], unsigned int cc, bool nd, bool nf,
			bool w, unsigned int pp, unsigned int ndd,
			unsigned int reg, unsigned int rm)
{
	if (!nd)
		ndd = 0;
	code[0] = 0x62;
	code[1] = 0x44 | ((reg & 8) ? 0 : 0x80) |
		  ((reg & 16) ? 0 : 0x10) | ((rm & 8) ? 0 : 0x20) |
		  ((rm & 16) ? 0x08 : 0);
	code[2] = (w ? 0x80 : 0) | (((~ndd) & 15) << 3) | 0x04 |
		  (pp & 3);
	code[3] = (nd ? 0x10 : 0) | ((ndd & 16) ? 0 : 0x08) |
		  (nf ? 0x04 : 0);
	code[4] = 0x40 | (cc & 15);
	code[5] = 0xc0 | ((reg & 7) << 3) | (rm & 7);
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

static bool has_group(const cs_detail *detail, uint8_t group)
{
	uint8_t i;

	for (i = 0; i < detail->groups_count; ++i) {
		if (detail->groups[i] == group)
			return true;
	}
	return false;
}

static bool check_register_case(csh handle, bool att, unsigned int cc,
				bool nd, bool nf, bool w, unsigned int pp,
				unsigned int number)
{
	const unsigned int ndd_number = number;
	const unsigned int reg_number = (number + 11) & 31;
	const unsigned int rm_number = (number + 23) & 31;
	const uint8_t width = scalable_width(w, pp);
	const bool ordinary_cmov = nd && !nf;
	x86_reg logical[3];
	uint8_t logical_count;
	uint8_t code[6];
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 }, regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	char expected_mnemonic[32], expected_name[32], expected_operands[128];
	const char *names[3];
	size_t count;
	bool success = true;
	uint8_t i;

	encode_evex(code, cc, nd, nf, w, pp, ndd_number, reg_number,
		    rm_number);
	if (nd) {
		logical[0] = gpr(ndd_number, width);
		logical[1] = gpr(reg_number, width);
		logical[2] = gpr(rm_number, width);
		logical_count = 3;
	} else if (nf) {
		logical[0] = gpr(rm_number, width);
		logical[1] = gpr(reg_number, width);
		logical_count = 2;
	} else {
		logical[0] = gpr(reg_number, width);
		logical[1] = gpr(rm_number, width);
		logical_count = 2;
	}
	for (i = 0; i < logical_count; ++i)
		names[i] = cs_reg_name(handle, logical[i]);
	snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s%s",
		 ordinary_cmov ? "cmov" : "cfcmov", condition_names[cc],
		 att ? width == 2 ? "w" : width == 4 ? "l" : "q" : "");
	snprintf(expected_name, sizeof(expected_name), "%s%s",
		 ordinary_cmov ? "cmov" : "cfcmov", condition_names[cc]);
	if (logical_count == 2) {
		snprintf(expected_operands, sizeof(expected_operands),
			 att ? "%%%s, %%%s" : "%s, %s",
			 att ? names[1] : names[0], att ? names[0] : names[1]);
	} else {
		snprintf(expected_operands, sizeof(expected_operands),
			 att ? "%%%s, %%%s, %%%s" : "%s, %s, %s",
			 att ? names[2] : names[0], names[1],
			 att ? names[0] : names[2]);
	}

	count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);
	if (!check(count == 1, "register form decodes"))
		return false;
	success &= check(insn[0].size == sizeof(code),
			 "register instruction size is exact");
	success &= check(insn[0].id == (ordinary_cmov ? cmov_ids[cc] :
						       cfcmov_ids[cc]),
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "register mnemonic is exact");
	success &= check(strcmp(insn[0].op_str, expected_operands) == 0,
			 "register operand text is exact");
	success &= check(cs_insn_name(handle, insn[0].id) != NULL &&
			 strcmp(cs_insn_name(handle, insn[0].id),
				expected_name) == 0,
			 "public instruction name is exact");
	success &= check(insn[0].detail != NULL,
			 "register detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;

		success &= check(x86->op_count == logical_count,
				 "register operand count is exact");
		for (i = 0; i < logical_count; ++i) {
			const uint8_t logical_index = att ? logical_count - 1 - i : i;

			success &= check(x86->operands[i].type == X86_OP_REG &&
					 x86->operands[i].reg == logical[logical_index] &&
					 x86->operands[i].size == width &&
					 x86->operands[i].access ==
						 (logical_index == 0 ? CS_AC_WRITE :
								       CS_AC_READ),
					 "register operand detail is exact");
		}
		success &= check(has_register(insn[0].detail->regs_read,
					      insn[0].detail->regs_read_count,
					      X86_REG_EFLAGS),
				 "EFLAGS dependency is explicit");
		success &= check(has_group(insn[0].detail, X86_GRP_CMOV),
				 "conditional-move group is explicit");
		success &= check(cs_regs_access(handle, &insn[0], regs_read,
					&regs_read_count, regs_write,
					&regs_write_count) == CS_ERR_OK,
				 "cs_regs_access succeeds");
		success &= check(has_register(regs_write, regs_write_count,
					       logical[0]),
				 "destination write is explicit");
		for (i = 1; i < logical_count; ++i)
			success &= check(has_register(regs_read, regs_read_count,
						      logical[i]),
					 "source read is explicit");
	}
	cs_free(insn, count);
	return success;
}

static size_t encode_sib_memory(uint8_t code[11], bool address32,
				bool nd, bool nf, bool w, unsigned int pp,
				unsigned int cc)
{
	const unsigned int ndd = nd ? 30 : 0;
	size_t cursor = 0;

	if (address32)
		code[cursor++] = 0x67;
	code[cursor++] = address32 ? 0x65 : 0x64;
	code[cursor++] = 0x62;
	// ModRM.reg=r17, base=r20[d], index=r29[d].
	code[cursor++] = 0xac;
	code[cursor++] = (w ? 0x80 : 0) | (((~ndd) & 15) << 3) |
			 ((pp & 3));
	code[cursor++] = (nd ? 0x10 : 0) | ((ndd & 16) ? 0 : 0x08) |
			 (nf ? 0x04 : 0);
	code[cursor++] = 0x40 | (cc & 15);
	code[cursor++] = 0x4c;
	code[cursor++] = 0xac;
	code[cursor++] = 0xf0;
	return cursor;
}

static bool check_memory_case(csh handle, bool att, bool address32, bool nd,
			      bool nf, bool w, unsigned int pp,
			      unsigned int cc)
{
	uint8_t code[11] = { 0 };
	const size_t size =
		encode_sib_memory(code, address32, nd, nf, w, pp, cc);
	const uint8_t width = scalable_width(w, pp);
	const bool ordinary_cmov = nd && !nf;
	const x86_reg ndd_reg = gpr(30, width);
	const x86_reg reg = gpr(17, width);
	const x86_reg base = address32 ? X86_REG_R20D : X86_REG_R20;
	const x86_reg index = address32 ? X86_REG_R29D : X86_REG_R29;
	const x86_reg segment = address32 ? X86_REG_GS : X86_REG_FS;
	const char *reg_name = cs_reg_name(handle, reg);
	const char *ndd_name = cs_reg_name(handle, ndd_reg);
	const char *memory_text = address32 ?
		(att ? "%gs:-0x10(%r20d,%r29d,4)" :
		       "word ptr gs:[r20d + r29d*4 - 0x10]") :
		(att ? "%fs:-0x10(%r20,%r29,4)" :
		       "word ptr fs:[r20 + r29*4 - 0x10]");
	char sized_memory[96], expected_mnemonic[32], expected_operands[192];
	cs_insn *insn = NULL;
	size_t count;
	bool success = true;
	const cs_x86 *x86;
	uint8_t memory_index;
	cs_ac_type memory_access;
	uint8_t logical_count, i;
	bool logical_memory[3] = { false, false, false };
	x86_reg logical_regs[3] = { X86_REG_INVALID, X86_REG_INVALID,
				      X86_REG_INVALID };
	cs_ac_type logical_access[3] = { 0, 0, 0 };

	if (!att) {
		const char *width_name =
			width == 2 ? "word" : width == 4 ? "dword" : "qword";
		const char *rest = strstr(memory_text, " ptr");

		snprintf(sized_memory, sizeof(sized_memory), "%s%s", width_name,
			 rest);
		memory_text = sized_memory;
	}
	snprintf(expected_mnemonic, sizeof(expected_mnemonic), "%s%s%s",
		 ordinary_cmov ? "cmov" : "cfcmov", condition_names[cc],
		 att ? width == 2 ? "w" : width == 4 ? "l" : "q" : "");
	if (nd) {
		if (att)
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %%%s, %%%s", memory_text, reg_name,
				 ndd_name);
		else
			snprintf(expected_operands, sizeof(expected_operands),
				 "%s, %s, %s", ndd_name, reg_name, memory_text);
	} else if (nf) {
		snprintf(expected_operands, sizeof(expected_operands),
			 att ? "%%%s, %s" : "%s, %s",
			 att ? reg_name : memory_text,
			 att ? memory_text : reg_name);
	} else {
		snprintf(expected_operands, sizeof(expected_operands),
			 att ? "%s, %%%s" : "%s, %s",
			 att ? memory_text : reg_name,
			 att ? reg_name : memory_text);
	}

	count = cs_disasm(handle, code, size, 0x1000, 1, &insn);
	if (!check(count == 1, "memory form decodes"))
		return false;
	success &= check(insn[0].id == (ordinary_cmov ? cmov_ids[cc] :
						       cfcmov_ids[cc]),
			 "memory public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 "memory mnemonic is exact");
	if (strcmp(insn[0].op_str, expected_operands) != 0) {
		static bool reported;

		if (!reported) {
			fprintf(stderr, "expected `%s`, got `%s`\n",
				expected_operands, insn[0].op_str);
			reported = true;
		}
		success &= check(false, "memory operand text is exact");
	}
	if (!check(insn[0].detail != NULL, "memory detail is available")) {
		cs_free(insn, count);
		return false;
	}
	x86 = &insn[0].detail->x86;
	if (nd) {
		logical_regs[0] = ndd_reg;
		logical_regs[1] = reg;
		logical_memory[2] = true;
		logical_access[0] = CS_AC_WRITE;
		logical_access[1] = CS_AC_READ;
		logical_access[2] = CS_AC_READ;
		logical_count = 3;
	} else if (nf) {
		logical_memory[0] = true;
		logical_regs[1] = reg;
		logical_access[0] = CS_AC_WRITE;
		logical_access[1] = CS_AC_READ;
		logical_count = 2;
	} else {
		logical_regs[0] = reg;
		logical_memory[1] = true;
		logical_access[0] = CS_AC_WRITE;
		logical_access[1] = CS_AC_READ;
		logical_count = 2;
	}
	memory_index = att ? (!nd && nf ? 1 : 0) : nd ? 2 : nf ? 0 : 1;
	memory_access = !nd && nf ? CS_AC_WRITE : CS_AC_READ;
	success &= check(x86->op_count == logical_count &&
			 x86->addr_size == (address32 ? 4 : 8) &&
			 x86->operands[memory_index].type == X86_OP_MEM &&
			 x86->operands[memory_index].mem.segment == segment &&
			 x86->operands[memory_index].mem.base == base &&
			 x86->operands[memory_index].mem.index == index &&
			 x86->operands[memory_index].mem.scale == 4 &&
			 x86->operands[memory_index].mem.disp == -16 &&
			 x86->operands[memory_index].size == width &&
			 x86->operands[memory_index].access == memory_access,
			 "memory operand detail is exact");
	for (i = 0; i < logical_count; ++i) {
		const uint8_t logical_index = att ? logical_count - 1 - i : i;

		if (logical_memory[logical_index]) {
			success &= check(x86->operands[i].type == X86_OP_MEM &&
					 x86->operands[i].access ==
						 logical_access[logical_index],
					 "memory access direction is exact");
		} else {
			success &= check(x86->operands[i].type == X86_OP_REG &&
					 x86->operands[i].reg ==
						 logical_regs[logical_index] &&
					 x86->operands[i].size == width &&
					 x86->operands[i].access ==
						 logical_access[logical_index],
					 "memory-form register detail is exact");
		}
	}
	success &= check(has_register(insn[0].detail->regs_read,
				      insn[0].detail->regs_read_count,
				      X86_REG_EFLAGS) &&
			 has_group(insn[0].detail, X86_GRP_CMOV),
			 "memory-form implicit detail is exact");
	success &= check(x86->encoding.modrm_offset ==
					(address32 ? 7 : 6) &&
			 x86->encoding.disp_offset == (address32 ? 9 : 8) &&
			 x86->encoding.disp_size == 1,
			 "memory encoding offsets are exact");
	cs_free(insn, count);
	return success;
}

static bool check_displacement_forms(csh handle)
{
	static const uint8_t rip_relative[] = {
		0x62, 0xf4, 0x7c, 0x08, 0x44, 0x05,
		0x34, 0x12, 0x00, 0x00,
	};
	static const uint8_t eip_relative[] = {
		0x67, 0x62, 0xf4, 0x7c, 0x08, 0x44, 0x05,
		0x34, 0x12, 0x00, 0x00,
	};
	static const uint8_t absolute[] = {
		0x67, 0x62, 0xf4, 0x7c, 0x08, 0x44, 0x04, 0x25,
		0x34, 0x12, 0x00, 0x00,
	};
	const struct {
		const uint8_t *code;
		size_t size;
		x86_reg base;
		x86_reg index;
		uint8_t address_size;
		uint8_t modrm_offset;
		uint8_t displacement_offset;
	} cases[] = {
		{ rip_relative, sizeof(rip_relative), X86_REG_RIP,
		  X86_REG_INVALID, 8, 5, 6 },
		{ eip_relative, sizeof(eip_relative), X86_REG_EIP,
		  X86_REG_INVALID, 4, 6, 7 },
		{ absolute, sizeof(absolute), X86_REG_INVALID,
		  X86_REG_INVALID, 4, 6, 8 },
	};
	bool success = true;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		cs_insn *insn = NULL;
		size_t count = cs_disasm(handle, cases[i].code, cases[i].size,
					 0x1000, 1, &insn);

		if (!check(count == 1, "displacement form decodes"))
			return false;
		success &= check(insn[0].detail != NULL &&
					 insn[0].detail->x86.addr_size ==
						 cases[i].address_size &&
					 insn[0].detail->x86.op_count == 2 &&
					 insn[0].detail->x86.operands[1].type ==
						 X86_OP_MEM &&
					 insn[0].detail->x86.operands[1].mem.base ==
						 cases[i].base &&
					 insn[0].detail->x86.operands[1].mem.index ==
						 cases[i].index &&
					 insn[0].detail->x86.operands[1].mem.disp ==
						 0x1234,
				 "displacement operand detail is exact");
		success &= check(insn[0].detail->x86.encoding.modrm_offset ==
						 cases[i].modrm_offset &&
					 insn[0].detail->x86.encoding.disp_offset ==
						 cases[i].displacement_offset &&
					 insn[0].detail->x86.encoding.disp_size == 4,
				 "displacement encoding detail is exact");
		cs_free(insn, count);
	}
	return success;
}

static bool rejects(csh handle, const uint8_t *code, size_t size,
		    const char *message)
{
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, size, 0x1000, 1, &insn);
	bool success = check(count == 0, message);

	cs_free(insn, count);
	return success;
}

static bool check_invalid_forms(csh intel, csh mode32)
{
	static const uint8_t valid_setcc[] = {
		0x62, 0xf4, 0x7f, 0x08, 0x45, 0xc0,
	};
	uint8_t invalid[20] = { 0 };
	bool success = true;
	cs_insn *setcc = NULL;
	size_t count;

	count = cs_disasm(intel, valid_setcc, sizeof(valid_setcc), 0x1000, 1,
			  &setcc);
	success &= check(count == 1 && setcc[0].id == X86_INS_SETNE,
			 "F2 opcode sharing still selects promoted SETcc");
	cs_free(setcc, count);

	encode_evex(invalid, 5, true, false, false, 0, 29, 17, 3);
	success &= rejects(mode32, invalid, 6, "non-64-bit mode is rejected");
	encode_evex(invalid, 5, true, false, false, 2, 29, 17, 3);
	success &= rejects(intel, invalid, 6, "F3 pp is rejected");
	encode_evex(invalid, 5, false, false, false, 0, 0, 17, 3);
	invalid[2] &= (uint8_t)~0x08;
	success &= rejects(intel, invalid, 6,
			 "ND=0 with a nonzero V register is rejected");
	encode_evex(invalid, 5, false, true, false, 0, 0, 17, 3);
	invalid[3] &= (uint8_t)~0x08;
	success &= rejects(intel, invalid, 6,
			 "ND=0 with a nonzero V4 bit is rejected");
	encode_evex(invalid, 5, true, true, false, 0, 29, 17, 3);
	invalid[3] |= 0x80;
	success &= rejects(intel, invalid, 6, "nonzero LL bit is rejected");
	encode_evex(invalid, 5, true, true, false, 0, 29, 17, 3);
	invalid[3] |= 0x01;
	success &= rejects(intel, invalid, 6,
			 "reserved EVEX payload bit is rejected");
	encode_evex(invalid, 5, true, true, false, 0, 29, 17, 3);
	invalid[2] &= (uint8_t)~0x04;
	success &= rejects(intel, invalid, 6,
			 "register U/X4=0 is rejected");
	encode_evex(&invalid[1], 5, true, true, false, 0, 29, 17, 3);
	invalid[0] = 0x66;
	success &= rejects(intel, invalid, 7,
			 "legacy OSIZE prefix is rejected");
	invalid[0] = 0xf2;
	success &= rejects(intel, invalid, 7, "legacy REP prefix is rejected");
	invalid[0] = 0xf0;
	success &= rejects(intel, invalid, 7, "LOCK prefix is rejected");
	invalid[0] = 0x48;
	success &= rejects(intel, invalid, 7, "REX prefix is rejected");
	memset(invalid, 0x67, 10);
	encode_evex(&invalid[10], 5, true, true, false, 0, 29, 17, 3);
	success &= rejects(intel, invalid, 16,
			 "instruction longer than 15 bytes is rejected");
	return success;
}

int main(void)
{
	csh intel = 0, att = 0, mode32 = 0;
	bool success = true;
	unsigned int cc, nd, nf, w, pp, number;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &intel) != CS_ERR_OK ||
	    cs_open(CS_ARCH_X86, CS_MODE_64, &att) != CS_ERR_OK ||
	    cs_open(CS_ARCH_X86, CS_MODE_32, &mode32) != CS_ERR_OK) {
		fprintf(stderr, "failed to open Capstone\n");
		return 1;
	}
	cs_option(intel, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(att, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

	for (cc = 0; cc < 16; ++cc) {
		for (nd = 0; nd < 2; ++nd) {
			for (nf = 0; nf < 2; ++nf) {
				for (w = 0; w < 2; ++w) {
					for (pp = 0; pp < 2; ++pp) {
						for (number = 0; number < 32;
						     ++number) {
							success &= check_register_case(
								intel, false, cc, nd != 0,
								nf != 0, w != 0, pp,
								number);
							success &= check_register_case(
								att, true, cc, nd != 0,
								nf != 0, w != 0, pp,
								number);
						}
						success &= check_memory_case(
							intel, false, false, nd != 0,
							nf != 0, w != 0, pp, cc);
						success &= check_memory_case(
							att, true, true, nd != 0,
							nf != 0, w != 0, pp, cc);
					}
				}
			}
		}
	}
	success &= check_displacement_forms(intel);
	success &= check_invalid_forms(intel, mode32);

	cs_close(&mode32);
	cs_close(&att);
	cs_close(&intel);
	return success ? 0 : 1;
}

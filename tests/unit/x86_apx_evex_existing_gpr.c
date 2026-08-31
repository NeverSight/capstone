/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool check(bool condition, const char *name, const char *message)
{
	if (!condition)
		fprintf(stderr, "%s: %s\n", name, message);
	return condition;
}

static bool has_register(const cs_regs registers, uint8_t count, x86_reg reg)
{
	uint8_t index;

	for (index = 0; index < count; ++index) {
		if (registers[index] == reg)
			return true;
	}
	return false;
}

static bool check_memory(csh handle, const char *name, const uint8_t *code,
			 size_t code_size, x86_insn expected_id,
			 const char *expected_mnemonic,
			 const char *expected_operands, x86_reg base,
			 x86_reg index, int scale, int64_t displacement)
{
	cs_insn *insn = NULL;
	cs_regs regs_read = { 0 };
	cs_regs regs_write = { 0 };
	uint8_t regs_read_count = 0, regs_write_count = 0;
	const cs_x86_op *memory = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);

	if (!check(count == 1, name, "instruction decodes"))
		return false;
	success &= check(insn[0].id == expected_id, name,
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 name, "mnemonic is exact");
	if (strcmp(insn[0].op_str, expected_operands) != 0) {
		fprintf(stderr, "%s: operands were '%s', expected '%s'\n", name,
			insn[0].op_str, expected_operands);
		success = false;
	}
	success &= check(insn[0].detail != NULL, name, "detail is available");
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		uint8_t operand_index;

		for (operand_index = 0; operand_index < x86->op_count;
		     ++operand_index) {
			if (x86->operands[operand_index].type == X86_OP_MEM) {
				memory = &x86->operands[operand_index];
				break;
			}
		}
		success &= check(memory != NULL, name,
				 "memory detail is present");
		if (memory != NULL) {
			success &= check(memory->mem.base == base, name,
					 "extended base is exact");
			success &= check(memory->mem.index == index, name,
					 "index is exact");
			success &= check(memory->mem.scale == scale, name,
					 "scale is exact");
			success &= check(memory->mem.disp == displacement, name,
					 "displacement is exact");
		}
		if ((x86->modrm & 0xc0) != 0xc0 &&
		    (x86->modrm & 7) == 4 &&
		    (index < X86_REG_XMM0 || index > X86_REG_ZMM31)) {
			success &= check(x86->sib_base == base, name,
					 "SIB base detail is exact");
			success &= check(x86->sib_index == index, name,
					 "SIB index detail is exact");
		}
		success &= check(
			x86->opcode[0] == code[0] && x86->opcode[1] == code[1] &&
				x86->opcode[2] == code[2] &&
				x86->opcode[3] == code[3],
			name, "raw EVEX payload is preserved");
		success &= check(
			cs_regs_access(handle, &insn[0], regs_read,
				       &regs_read_count, regs_write,
				       &regs_write_count) == CS_ERR_OK,
			name, "register access query succeeds");
		success &= check(has_register(regs_read, regs_read_count, base),
				 name, "base is reported read");
		if (index != X86_REG_INVALID)
			success &= check(
				has_register(regs_read, regs_read_count, index), name,
				"index is reported read");
	}
	cs_free(insn, count);
	return success;
}

static bool check_gpr_source(csh handle, bool att_syntax)
{
	static const uint8_t code[] = {
		0x62, 0xd9, 0x6e, 0x08, 0x2a, 0xcd
	};
	const char *name = att_syntax ? "gpr-source-att" : "gpr-source-intel";
	const char *expected_mnemonic = att_syntax ? "vcvtsi2ssl" :
						    "vcvtsi2ss";
	const char *expected_operands = att_syntax ? "%r29d, %xmm2, %xmm1" :
						    "xmm1, xmm2, r29d";
	cs_insn *insn = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (!check(count == 1, name, "instruction decodes"))
		return false;
	success &= check(insn[0].id == X86_INS_VCVTSI2SS, name,
			 "public instruction ID is exact");
	success &= check(strcmp(insn[0].mnemonic, expected_mnemonic) == 0,
			 name, "mnemonic is exact");
	if (strcmp(insn[0].op_str, expected_operands) != 0) {
		fprintf(stderr, "%s: operands were '%s', expected '%s'\n", name,
			insn[0].op_str, expected_operands);
		success = false;
	}
	if (insn[0].detail != NULL) {
		const cs_x86 *x86 = &insn[0].detail->x86;
		bool found_source = false;
		uint8_t operand_index;

		for (operand_index = 0; operand_index < x86->op_count;
		     ++operand_index) {
			const cs_x86_op *operand = &x86->operands[operand_index];

			if (operand->type == X86_OP_REG &&
			    operand->reg == X86_REG_R29D && operand->size == 4 &&
			    operand->access == CS_AC_READ)
				found_source = true;
		}
		success &= check(found_source, name,
				 "extended GPR source detail is exact");
		success &= check(x86->opcode[1] == code[1], name,
				 "B4 remains visible in raw detail");
	} else {
		success &= check(false, name, "detail is available");
	}
	cs_free(insn, count);
	return success;
}

static bool rejects_outside_64_bit(const uint8_t *code, size_t code_size)
{
	csh handle = 0;
	cs_insn *insn = NULL;
	size_t count;
	bool success;

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return false;
	count = cs_disasm(handle, code, code_size, 0x1000, 1, &insn);
	success = check(count == 0, "outside-64-bit",
			"APX extended EVEX is rejected");
	cs_free(insn, count);
	cs_close(&handle);
	return success;
}

int main(void)
{
	static const uint8_t sib_memory[] = {
		0x62, 0x99, 0x7a, 0xcb, 0x6f, 0x4c, 0xb5, 0x01
	};
	static const uint8_t no_sib_memory[] = {
		0x62, 0xd9, 0x7e, 0xcb, 0x6f, 0x4d, 0x01
	};
	static const uint8_t map3_memory[] = {
		0x62, 0x9b, 0x59, 0x4f, 0x1f, 0x74, 0xf5, 0x01, 0x02
	};
	static const uint8_t vsib_memory[] = {
		0x62, 0x9a, 0x79, 0x42, 0x90, 0x4c, 0xb5, 0x00
	};
	static const uint8_t ignored_bits[] = {
		0x62, 0xf9, 0x60, 0x4d, 0x58, 0xd4
	};
	static const uint8_t gpr_source[] = {
		0x62, 0xd9, 0x6e, 0x08, 0x2a, 0xcd
	};
	csh handle = 0;
	cs_insn *insn = NULL;
	bool success = true;
	size_t count;

	if (!check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
		   "setup", "open x86-64 handle"))
		return 1;
	if (!check(cs_option(handle, CS_OPT_DETAIL,
			     CS_OPT_ON | CS_OPT_DETAIL_REAL) == CS_ERR_OK,
		   "setup", "enable detail")) {
		cs_close(&handle);
		return 1;
	}

	success &= check_memory(
		handle, "sib-intel", sib_memory, sizeof(sib_memory),
		X86_INS_VMOVDQU32, "vmovdqu32",
		"zmm1 {k3} {z}, zmmword ptr [r29 + r30*4 + 0x40]",
		X86_REG_R29, X86_REG_R30, 4, 0x40);
	success &= check_memory(
		handle, "no-sib-intel", no_sib_memory, sizeof(no_sib_memory),
		X86_INS_VMOVDQU32, "vmovdqu32",
		"zmm1 {k3} {z}, zmmword ptr [r29 + 0x40]", X86_REG_R29,
		X86_REG_INVALID, 1, 0x40);
	success &= check_memory(
		handle, "map3-intel", map3_memory, sizeof(map3_memory),
		X86_INS_VPCMPD, "vpcmpled",
		"k6 {k7}, zmm4, zmmword ptr [r29 + r30*8 + 0x40]",
		X86_REG_R29, X86_REG_R30, 8, 0x40);
	success &= check_gpr_source(handle, false);

	count = cs_disasm(handle, ignored_bits, sizeof(ignored_bits), 0x1000, 1,
			  &insn);
	success &= check(count == 1 && insn[0].id == X86_INS_VADDPS,
			 "ignored-register-bits",
			 "unused B4 and U do not alter vector operands");
	if (count == 1)
		success &= check(strcmp(insn[0].op_str,
					"zmm2 {k5}, zmm3, zmm4") == 0,
				 "ignored-register-bits", "vector text is exact");
	cs_free(insn, count);

	success &= check_memory(
		handle, "vsib-intel", vsib_memory, sizeof(vsib_memory),
		X86_INS_VPGATHERDD, "vpgatherdd",
		"zmm1 {k2}, zmmword ptr [r29 + zmm30*4]", X86_REG_R29,
		X86_REG_ZMM30, 4, 0);

	success &= check(cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) ==
				 CS_ERR_OK,
			 "setup", "select AT&T syntax");
	success &= check_memory(
		handle, "sib-att", sib_memory, sizeof(sib_memory),
		X86_INS_VMOVDQU32, "vmovdqu32",
		"0x40(%r29, %r30, 4), %zmm1 {%k3} {z}", X86_REG_R29,
		X86_REG_R30, 4, 0x40);
	success &= check_gpr_source(handle, true);

	success &= rejects_outside_64_bit(gpr_source, sizeof(gpr_source));
	cs_close(&handle);
	return success ? 0 : 1;
}

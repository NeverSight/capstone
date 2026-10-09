/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct address_case {
	uint8_t modrm;
	x86_reg base;
	x86_reg index;
	int64_t displacement;
	uint8_t bytes[2];
	size_t size;
} address_case;

static bool contains_reg(const cs_regs regs, uint8_t count, x86_reg reg)
{
	uint8_t i;

	for (i = 0; i < count; ++i)
		if (regs[i] == reg)
			return true;
	return false;
}

static bool check_memory(cs_mode mode, const uint8_t *code, size_t size,
			 unsigned int id, x86_reg destination,
			 uint8_t destination_size, uint8_t source_size,
			 uint8_t address_size, x86_reg base, x86_reg index,
			 int64_t displacement, x86_reg segment)
{
	csh handle;
	cs_insn *insn = NULL;
	cs_x86 *x86;
	cs_regs read, written;
	uint8_t read_count, written_count;
	uint8_t reference_code[5];
	size_t reference_size = 0;
	cs_insn *reference = NULL;
	size_t count;
	bool ok = false;

	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
		return false;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		goto done;
	count = cs_disasm(handle, code, size, 0x1000, 1, &insn);
	if (count != 1 || insn->size != size || insn->id != id || !insn->detail)
		goto free_insn;
	x86 = &insn->detail->x86;
	if (x86->addr_size != address_size || x86->op_count != 2 ||
	    x86->operands[0].type != X86_OP_REG ||
	    x86->operands[0].reg != destination ||
	    x86->operands[0].size != destination_size ||
	    x86->operands[0].access != CS_AC_WRITE ||
	    x86->operands[1].type != X86_OP_MEM ||
	    x86->operands[1].size != source_size ||
	    x86->operands[1].access != CS_AC_READ ||
	    x86->operands[1].mem.base != base ||
	    x86->operands[1].mem.index != index ||
	    x86->operands[1].mem.scale != 1 ||
	    x86->operands[1].mem.disp != displacement ||
	    x86->operands[1].mem.segment != segment)
		goto free_insn;
	if (cs_regs_access(handle, insn, read, &read_count, written,
			   &written_count) != CS_ERR_OK ||
	    !contains_reg(written, written_count, destination) ||
	    (base != X86_REG_INVALID &&
	     !contains_reg(read, read_count, base)) ||
	    (index != X86_REG_INVALID &&
	     !contains_reg(read, read_count, index)))
		goto free_insn;
	reference_code[reference_size++] = source_size == 8 ? 0xf2 : 0xf3;
	if (destination_size == 8)
		reference_code[reference_size++] = 0x48;
	reference_code[reference_size++] = 0x0f;
	reference_code[reference_size++] =
		id == X86_INS_CVTTSD2SI || id == X86_INS_CVTTSS2SI ? 0x2c :
								     0x2d;
	reference_code[reference_size++] = 0x00;
	if (cs_disasm(handle, reference_code, reference_size, 0x1000, 1,
		      &reference) != 1 ||
	    reference->detail->groups_count != insn->detail->groups_count ||
	    memcmp(reference->detail->groups, insn->detail->groups,
		   insn->detail->groups_count) != 0)
		goto free_insn;
	ok = true;
free_insn:
	if (!ok) {
		size_t i;
		fprintf(stderr, "mode %u:", (unsigned int)mode);
		for (i = 0; i < size; ++i)
			fprintf(stderr, " %02x", code[i]);
		fprintf(stderr,
			" decoded as %s %s; id/address/operand/access mismatch\n",
			count ? insn->mnemonic : "<invalid>",
			count ? insn->op_str : "");
	}
	cs_free(insn, count);
	cs_free(reference, reference ? 1 : 0);
done:
	cs_close(&handle);
	return ok;
}

static bool check_conversions(void)
{
	static const unsigned int ids[2][2] = {
		{ X86_INS_CVTSD2SI, X86_INS_CVTTSD2SI },
		{ X86_INS_CVTSS2SI, X86_INS_CVTTSS2SI },
	};
	static const address_case addresses[] = {
		{ 0x00, X86_REG_BX, X86_REG_SI, 0, { 0 }, 0 },
		{ 0x01, X86_REG_BX, X86_REG_DI, 0, { 0 }, 0 },
		{ 0x02, X86_REG_BP, X86_REG_SI, 0, { 0 }, 0 },
		{ 0x03, X86_REG_BP, X86_REG_DI, 0, { 0 }, 0 },
		{ 0x04, X86_REG_SI, X86_REG_INVALID, 0, { 0 }, 0 },
		{ 0x05, X86_REG_DI, X86_REG_INVALID, 0, { 0 }, 0 },
		{ 0x06,
		  X86_REG_INVALID,
		  X86_REG_INVALID,
		  0x1234,
		  { 0x34, 0x12 },
		  2 },
		{ 0x07, X86_REG_BX, X86_REG_INVALID, 0, { 0 }, 0 },
		{ 0x40, X86_REG_BX, X86_REG_SI, -16, { 0xf0 }, 1 },
		{ 0x86, X86_REG_BP, X86_REG_INVALID, -128, { 0x80, 0xff }, 2 },
	};
	bool ok = true;
	size_t source, truncate, order, i;

	for (source = 0; source < 2; ++source) {
		for (truncate = 0; truncate < 2; ++truncate) {
			uint8_t prefix = source ? 0xf3 : 0xf2;
			uint8_t opcode = truncate ? 0x2c : 0x2d;
			uint8_t width = source ? 4 : 8;
			unsigned int id = ids[source][truncate];
			uint8_t plain[] = { prefix, 0x0f, opcode, 0x00 };
			uint8_t addr[] = { 0x67, prefix, 0x0f, opcode, 0x00 };
			uint8_t wide[] = { 0x67, prefix, 0x48,
					   0x0f, opcode, 0x00 };

			ok &= check_memory(CS_MODE_16, plain, sizeof(plain), id,
					   X86_REG_EAX, 4, width, 2, X86_REG_BX,
					   X86_REG_SI, 0, X86_REG_INVALID);
			ok &= check_memory(CS_MODE_32, plain, sizeof(plain), id,
					   X86_REG_EAX, 4, width, 4,
					   X86_REG_EAX, X86_REG_INVALID, 0,
					   X86_REG_INVALID);
			ok &= check_memory(CS_MODE_64, plain, sizeof(plain), id,
					   X86_REG_EAX, 4, width, 8,
					   X86_REG_RAX, X86_REG_INVALID, 0,
					   X86_REG_INVALID);
			ok &= check_memory(CS_MODE_64, wide, sizeof(wide), id,
					   X86_REG_RAX, 8, width, 4,
					   X86_REG_EAX, X86_REG_INVALID, 0,
					   X86_REG_INVALID);
			for (order = 0; order < 2; ++order) {
				addr[0] = order ? prefix : 0x67;
				addr[1] = order ? 0x67 : prefix;
				ok &= check_memory(CS_MODE_16, addr,
						   sizeof(addr), id,
						   X86_REG_EAX, 4, width, 4,
						   X86_REG_EAX, X86_REG_INVALID,
						   0, X86_REG_INVALID);
				ok &= check_memory(CS_MODE_64, addr,
						   sizeof(addr), id,
						   X86_REG_EAX, 4, width, 4,
						   X86_REG_EAX, X86_REG_INVALID,
						   0, X86_REG_INVALID);
				for (i = 0; i < sizeof(addresses) /
							sizeof(addresses[0]);
				     ++i) {
					uint8_t code[7];
					memcpy(code, addr, sizeof(addr));
					code[4] = addresses[i].modrm;
					memcpy(code + 5, addresses[i].bytes,
					       addresses[i].size);
					ok &= check_memory(
						CS_MODE_32, code,
						5 + addresses[i].size, id,
						X86_REG_EAX, 4, width, 2,
						addresses[i].base,
						addresses[i].index,
						addresses[i].displacement,
						X86_REG_INVALID);
				}
			}
		}
	}
	return ok;
}

static bool check_other_opcodes(void)
{
	static const struct {
		cs_mode mode;
		uint8_t code[9];
		size_t size;
		unsigned int id;
		const char *text;
	} cases[] = {
		{ CS_MODE_32,
		  { 0x67, 0xf2, 0x0f, 0x10, 0x00 },
		  5,
		  X86_INS_MOVSD,
		  "movsd xmm0, qword ptr [bx + si]" },
		{ CS_MODE_32,
		  { 0xf3, 0x67, 0x0f, 0x10, 0x00 },
		  5,
		  X86_INS_MOVSS,
		  "movss xmm0, dword ptr [bx + si]" },
		{ CS_MODE_32,
		  { 0x67, 0xf2, 0x0f, 0x58, 0x00 },
		  5,
		  X86_INS_ADDSD,
		  "addsd xmm0, qword ptr [bx + si]" },
		{ CS_MODE_32,
		  { 0xf3, 0x67, 0x0f, 0x58, 0x00 },
		  5,
		  X86_INS_ADDSS,
		  "addss xmm0, dword ptr [bx + si]" },
		{ CS_MODE_32,
		  { 0x66, 0x67, 0xf2, 0x0f, 0x38, 0xf1, 0x00 },
		  7,
		  X86_INS_CRC32,
		  "crc32 eax, word ptr [bx + si]" },
		{ CS_MODE_32, { 0x67, 0xf3, 0x90 }, 3, X86_INS_PAUSE, "pause " },
		{ CS_MODE_32,
		  { 0x67, 0xe3, 0x01 },
		  3,
		  X86_INS_JCXZ,
		  "jcxz 0x1004" },
		{ CS_MODE_16,
		  { 0x67, 0xe3, 0x01 },
		  3,
		  X86_INS_JECXZ,
		  "jecxz 0x1004" },
		{ CS_MODE_32,
		  { 0x67, 0xf3, 0x0f, 0xae, 0xf0 },
		  5,
		  X86_INS_UMONITOR,
		  "umonitor ax" },
		{ CS_MODE_64,
		  { 0xf3, 0x67, 0x0f, 0xae, 0xf0 },
		  5,
		  X86_INS_UMONITOR,
		  "umonitor eax" },
	};
	bool ok = true;
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		csh handle;
		cs_insn *insn = NULL;
		size_t count;
		char text[sizeof(insn->mnemonic) + sizeof(insn->op_str) + 1] =
			"";
		if (cs_open(CS_ARCH_X86, cases[i].mode, &handle) != CS_ERR_OK)
			return false;
		count = cs_disasm(handle, cases[i].code, cases[i].size, 0x1000,
				  1, &insn);
		if (count == 1)
			snprintf(text, sizeof(text), "%s %s", insn->mnemonic,
				 insn->op_str);
		if (count != 1 || insn->size != cases[i].size ||
		    insn->id != cases[i].id ||
		    strcmp(text, cases[i].text) != 0) {
			fprintf(stderr, "expected %s; decoded %s\n",
				cases[i].text, text);
			ok = false;
		}
		cs_free(insn, count);
		cs_close(&handle);
	}
	return ok;
}

int main(void)
{
	bool ok = check_conversions();
	ok &= check_other_opcodes();
	return ok ? 0 : 1;
}

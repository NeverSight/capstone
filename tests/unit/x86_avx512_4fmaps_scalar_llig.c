#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool valid(csh handle, uint8_t opcode, uint8_t p2, unsigned int id,
		  const char *mnemonic)
{
	uint8_t code[] = { 0x62, 0xf2, 0x5f, p2, opcode, 0x08 };
	cs_insn *instruction = NULL;
	bool ok = cs_disasm(handle, code, sizeof(code), 0, 1, &instruction) == 1;
	if (ok) {
		const cs_x86 *x86 = &instruction->detail->x86;
		const bool masked = (p2 & 7) != 0;
		const unsigned int source = masked ? 2 : 1;
		const unsigned int memory = masked ? 3 : 2;
		ok = instruction->id == id &&
		     strcmp(instruction->mnemonic, mnemonic) == 0 &&
		     x86->op_count == (masked ? 4 : 3) &&
		     x86->operands[0].type == X86_OP_REG &&
		     x86->operands[0].reg == X86_REG_XMM1 &&
		     x86->operands[source].type == X86_OP_REG &&
		     x86->operands[source].reg == X86_REG_XMM4 &&
		     x86->operands[memory].type == X86_OP_MEM &&
		     x86->operands[memory].size == 16 &&
		     (!masked || x86->operands[1].reg == X86_REG_K3) &&
		     (strstr(instruction->op_str, "{z}") != NULL) ==
			     ((p2 & 0x80) != 0);
		if (!ok)
			fprintf(stderr, "unexpected detail: %s %s (%u operands: %u/%u %u/%u %u/%u %u/%u)\n",
				instruction->mnemonic, instruction->op_str,
				x86->op_count, x86->operands[0].type,
				x86->operands[0].reg, x86->operands[1].type,
				x86->operands[1].reg, x86->operands[2].type,
				x86->operands[2].reg, x86->operands[3].type,
				x86->operands[3].reg);
	}
	else
		fprintf(stderr, "valid scalar rejected: op=%02x p2=%02x\n",
			opcode, p2);
	if (instruction)
		cs_free(instruction, 1);
	return ok;
}

static bool invalid(csh handle, const uint8_t code[6])
{
	cs_insn *instruction = NULL;
	bool ok = cs_disasm(handle, code, 6, 0, 1, &instruction) == 0;
	if (!ok)
		fprintf(stderr, "invalid accepted: %s %s\n", instruction->mnemonic,
			instruction->op_str);
	if (instruction)
		cs_free(instruction, 1);
	return ok;
}

static bool valid_prefixed(csh handle, const uint8_t *prefixes,
			   size_t prefix_count, uint8_t opcode, uint8_t p2,
			   unsigned int id, x86_reg segment, uint8_t address_size)
{
	uint8_t code[10] = { 0 };
	cs_insn *instruction = NULL;
	bool ok;
	memcpy(code, prefixes, prefix_count);
	code[prefix_count + 0] = 0x62;
	code[prefix_count + 1] = 0xf2;
	code[prefix_count + 2] = 0x5f;
	code[prefix_count + 3] = p2;
	code[prefix_count + 4] = opcode;
	code[prefix_count + 5] = 0x08;
	ok = cs_disasm(handle, code, prefix_count + 6, 0, 1, &instruction) == 1;
	if (ok) {
		const cs_x86 *x86 = &instruction->detail->x86;
		const cs_x86_op *memory = &x86->operands[x86->op_count - 1];
		ok = instruction->id == id &&
		     instruction->size == prefix_count + 6 &&
		     instruction->bytes[prefix_count + 3] == p2 &&
		     x86->encoding.modrm_offset == prefix_count + 5 &&
		     x86->addr_size == address_size &&
		     memory->type == X86_OP_MEM && memory->mem.segment == segment &&
		     memory->mem.base ==
			     (address_size == 4 ? X86_REG_EAX : X86_REG_RAX);
	}
	if (instruction)
		cs_free(instruction, 1);
	return ok;
}

int main(void)
{
	csh handle;
	bool ok = true;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	for (unsigned int ll = 0; ll != 4; ++ll) {
		ok &= valid(handle, 0x9b, (uint8_t)(0x08 | (ll << 5)),
			    X86_INS_V4FMADDSS, "v4fmaddss");
		ok &= valid(handle, 0xab, (uint8_t)(0x08 | (ll << 5)),
			    X86_INS_V4FNMADDSS, "v4fnmaddss");
		ok &= valid(handle, 0x9b, (uint8_t)(0x0b | (ll << 5)),
			    X86_INS_V4FMADDSS, "v4fmaddss");
		ok &= valid(handle, 0xab, (uint8_t)(0x8b | (ll << 5)),
			    X86_INS_V4FNMADDSS, "v4fnmaddss");
	}
	{
		const uint8_t fs[] = { 0x64 };
		const uint8_t address32[] = { 0x67 };
		const uint8_t fs_address32[] = { 0x64, 0x67 };
		ok &= valid_prefixed(handle, fs, sizeof(fs), 0x9b, 0x68,
				     X86_INS_V4FMADDSS, X86_REG_FS, 8);
		ok &= valid_prefixed(handle, address32, sizeof(address32), 0xab,
				     0x48, X86_INS_V4FNMADDSS,
				     X86_REG_INVALID, 4);
		ok &= valid_prefixed(handle, fs_address32, sizeof(fs_address32),
				     0x9b, 0x68, X86_INS_V4FMADDSS,
				     X86_REG_FS, 4);
	}
	{
		const uint8_t duplicate_segment[] =
			{ 0x64, 0x65, 0x62, 0xf2, 0x5f, 0x68, 0x9b, 0x08 };
		const uint8_t duplicate_address[] =
			{ 0x67, 0x67, 0x62, 0xf2, 0x5f, 0x68, 0xab, 0x08 };
		const uint8_t illegal_prefix[] =
			{ 0x66, 0x62, 0xf2, 0x5f, 0x68, 0x9b, 0x08 };
		cs_insn *instruction = NULL;
		ok &= cs_disasm(handle, duplicate_segment,
				sizeof(duplicate_segment), 0, 1, &instruction) == 0;
		if (instruction) {
			cs_free(instruction, 1);
			instruction = NULL;
		}
		ok &= cs_disasm(handle, duplicate_address,
				sizeof(duplicate_address), 0, 1, &instruction) == 0;
		if (instruction) {
			cs_free(instruction, 1);
			instruction = NULL;
		}
		ok &= cs_disasm(handle, illegal_prefix, sizeof(illegal_prefix), 0, 1,
				&instruction) == 0;
		if (instruction)
			cs_free(instruction, 1);
	}
	{
		const uint8_t b[] = { 0x62, 0xf2, 0x5f, 0x18, 0x9b, 0x08 };
		const uint8_t z_without_mask[] =
			{ 0x62, 0xf2, 0x5f, 0x88, 0xab, 0x08 };
		const uint8_t reserved_w[] =
			{ 0x62, 0xf2, 0xdf, 0x08, 0x9b, 0x08 };
		ok &= invalid(handle, b) && invalid(handle, z_without_mask) &&
		      invalid(handle, reserved_w);
	}
	/* Packed forms remain VL=512 and are not made LLIG by this repair. */
	{
		const uint8_t packed_ll0[] =
			{ 0x62, 0xf2, 0x5f, 0x08, 0x9a, 0x08 };
		const uint8_t packed_ll2[] =
			{ 0x62, 0xf2, 0x5f, 0x48, 0x9a, 0x08 };
		cs_insn *instruction = NULL;
		ok &= invalid(handle, packed_ll0);
		ok &= cs_disasm(handle, packed_ll2, sizeof(packed_ll2), 0, 1,
				&instruction) == 1 &&
		      instruction && instruction->id == X86_INS_V4FMADDPS;
		if (instruction)
			cs_free(instruction, 1);
	}
	cs_close(&handle);
	if (!ok)
		fprintf(stderr, "AVX512_4FMAPS scalar LLIG failure\n");
	return ok ? 0 : 1;
}

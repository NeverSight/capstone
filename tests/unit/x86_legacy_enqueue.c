#include <capstone/capstone.h>

#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint64_t expected_eflags =
	X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_RESET_CF | X86_EFLAGS_RESET_PF |
	X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_SF | X86_EFLAGS_RESET_AF;

static bool check_common(const cs_insn *insn, const uint8_t *bytes,
			 size_t length, unsigned int id, const char *mnemonic,
			 const char *operands, uint8_t register_size)
{
	const cs_x86 *x86 = &insn->detail->x86;
	const cs_x86_op *reg = &x86->operands[0];
	const cs_x86_op *memory = &x86->operands[1];

	return insn->size == length &&
	       memcmp(insn->bytes, bytes, length) == 0 && insn->id == id &&
	       strcmp(insn->mnemonic, mnemonic) == 0 &&
	       strcmp(insn->op_str, operands) == 0 && x86->op_count == 2 &&
	       reg->type == X86_OP_REG && reg->size == register_size &&
	       reg->access == CS_AC_READ && memory->type == X86_OP_MEM &&
	       memory->size == 64 && memory->access == CS_AC_READ &&
	       x86->eflags == expected_eflags &&
	       insn->detail->regs_write_count == 1 &&
	       insn->detail->regs_write[0] == X86_REG_EFLAGS;
}

static bool check_fs_sib(csh handle)
{
	const uint8_t bytes[] = {
		0x64, 0xf2, 0x0f, 0x38, 0xf8, 0x44, 0x8b, 0x20
	};
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 1, &insn) ==
		  1;

	if (ok) {
		const cs_x86 *x86 = &insn->detail->x86;
		const cs_x86_op *reg = &x86->operands[0];
		const cs_x86_op *memory = &x86->operands[1];

		ok = check_common(insn, bytes, sizeof(bytes), X86_INS_ENQCMD,
				  "enqcmd",
				  "rax, zmmword ptr fs:[rbx + rcx*4 + 0x20]",
				  8) &&
		     x86->prefix[0] == 0xf2 && x86->prefix[1] == 0x64 &&
		     x86->prefix[2] == 0 && x86->prefix[3] == 0 &&
		     x86->rex == 0 && x86->opcode[0] == 0x0f &&
		     x86->opcode[1] == 0x38 && x86->opcode[2] == 0xf8 &&
		     x86->addr_size == 8 && x86->modrm == 0x44 &&
		     x86->sib == 0x8b && x86->sib_base == X86_REG_RBX &&
		     x86->sib_index == X86_REG_RCX && x86->sib_scale == 4 &&
		     x86->disp == 0x20 && x86->encoding.modrm_offset == 5 &&
		     x86->encoding.disp_offset == 7 &&
		     x86->encoding.disp_size == 1 && reg->reg == X86_REG_RAX &&
		     memory->mem.segment == X86_REG_FS &&
		     memory->mem.base == X86_REG_RBX &&
		     memory->mem.index == X86_REG_RCX &&
		     memory->mem.scale == 4 && memory->mem.disp == 0x20;
	}
	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_gs_rex(csh handle)
{
	const uint8_t bytes[] = { 0x65, 0xf3, 0x47, 0x0f, 0x38,
				  0xf8, 0x44, 0xd1, 0x80 };
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, sizeof(bytes), 0x2000, 1, &insn) ==
		  1;

	if (ok) {
		const cs_x86 *x86 = &insn->detail->x86;
		const cs_x86_op *reg = &x86->operands[0];
		const cs_x86_op *memory = &x86->operands[1];

		ok = check_common(insn, bytes, sizeof(bytes), X86_INS_ENQCMDS,
				  "enqcmds",
				  "r8, zmmword ptr gs:[r9 + r10*8 - 0x80]",
				  8) &&
		     x86->prefix[0] == 0xf3 && x86->prefix[1] == 0x65 &&
		     x86->rex == 0x47 && x86->addr_size == 8 &&
		     x86->modrm == 0x44 && x86->sib == 0xd1 &&
		     x86->sib_base == X86_REG_R9 &&
		     x86->sib_index == X86_REG_R10 && x86->sib_scale == 8 &&
		     x86->disp == -0x80 && x86->encoding.modrm_offset == 6 &&
		     x86->encoding.disp_offset == 8 &&
		     x86->encoding.disp_size == 1 && reg->reg == X86_REG_R8 &&
		     memory->mem.segment == X86_REG_GS &&
		     memory->mem.base == X86_REG_R9 &&
		     memory->mem.index == X86_REG_R10 &&
		     memory->mem.scale == 8 && memory->mem.disp == -0x80;
	}
	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_address32(csh handle)
{
	const uint8_t bytes[] = { 0x67, 0x64, 0xf2, 0x0f, 0x38,
				  0xf8, 0x44, 0x8b, 0x20 };
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, sizeof(bytes), 0x3000, 1, &insn) ==
		  1;

	if (ok) {
		const cs_x86 *x86 = &insn->detail->x86;
		const cs_x86_op *memory = &x86->operands[1];

		ok = check_common(insn, bytes, sizeof(bytes), X86_INS_ENQCMD,
				  "enqcmd",
				  "eax, zmmword ptr fs:[ebx + ecx*4 + 0x20]",
				  4) &&
		     x86->prefix[0] == 0xf2 && x86->prefix[1] == 0x64 &&
		     x86->prefix[3] == 0x67 && x86->addr_size == 4 &&
		     x86->encoding.modrm_offset == 6 &&
		     x86->encoding.disp_offset == 8 &&
		     x86->encoding.disp_size == 1 &&
		     x86->operands[0].reg == X86_REG_EAX &&
		     memory->mem.segment == X86_REG_FS &&
		     memory->mem.base == X86_REG_EBX &&
		     memory->mem.index == X86_REG_ECX &&
		     memory->mem.scale == 4 && memory->mem.disp == 0x20;
	}
	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_address32_ip_relative(csh handle)
{
	const uint8_t bytes[] = { 0x67, 0xf2, 0x0f, 0x38, 0xf8,
				  0x05, 0x20, 0x00, 0x00, 0x00 };
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, sizeof(bytes), 0x3000, 1, &insn) ==
		  1;

	if (ok) {
		const cs_x86 *x86 = &insn->detail->x86;
		const cs_x86_op *memory = &x86->operands[1];

		ok = check_common(insn, bytes, sizeof(bytes), X86_INS_ENQCMD,
				  "enqcmd", "eax, zmmword ptr [eip + 0x20]",
				  4) &&
		     x86->prefix[0] == 0xf2 && x86->prefix[3] == 0x67 &&
		     x86->addr_size == 4 && x86->encoding.modrm_offset == 5 &&
		     x86->encoding.disp_offset == 6 &&
		     x86->encoding.disp_size == 4 &&
		     memory->mem.base == X86_REG_EIP &&
		     memory->mem.index == X86_REG_INVALID &&
		     memory->mem.disp == 0x20;
	}
	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_apx_address32(csh handle)
{
	const uint8_t bytes[] = { 0x67, 0x64, 0x62, 0x0c, 0x7f,
				  0x08, 0xf8, 0x54, 0xb5, 0x20 };
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, sizeof(bytes), 0x4000, 1, &insn) ==
		  1;

	if (ok) {
		const cs_x86 *x86 = &insn->detail->x86;
		const cs_x86_op *memory = &x86->operands[1];

		ok = check_common(insn, bytes, sizeof(bytes), X86_INS_ENQCMD,
				  "enqcmd",
				  "r26d, zmmword ptr fs:[r29d + r14d*4 + 0x20]",
				  4) &&
		     x86->prefix[1] == 0x64 && x86->prefix[3] == 0x67 &&
		     x86->addr_size == 4 && x86->encoding.modrm_offset == 7 &&
		     x86->encoding.disp_offset == 9 &&
		     x86->encoding.disp_size == 1 &&
		     x86->operands[0].reg == X86_REG_R26D &&
		     memory->mem.segment == X86_REG_FS &&
		     memory->mem.base == X86_REG_R29D &&
		     memory->mem.index == X86_REG_R14D &&
		     memory->mem.scale == 4 && memory->mem.disp == 0x20;
	}
	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_att(csh handle)
{
	const uint8_t bytes[] = {
		0x64, 0xf2, 0x0f, 0x38, 0xf8, 0x44, 0x8b, 0x20
	};
	cs_insn *insn = NULL;
	bool ok;

	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	ok = cs_disasm(handle, bytes, sizeof(bytes), 0, 1, &insn) == 1;
	if (ok)
		ok = strcmp(insn->mnemonic, "enqcmd") == 0 &&
		     strcmp(insn->op_str, "%fs:0x20(%rbx,%rcx,4), %rax") == 0;
	if (insn)
		cs_free(insn, 1);
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	return ok;
}

static bool rejects(csh handle, const uint8_t *bytes, size_t length)
{
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, length, 0, 1, &insn) == 0;

	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_invalid_encodings(csh handle)
{
	static const uint8_t register_source[] = { 0xf2, 0x0f, 0x38, 0xf8,
						   0xc0 };
	static const uint8_t lock[] = { 0xf0, 0xf2, 0x0f, 0x38, 0xf8, 0x00 };
	static const uint8_t repeated_mandatory[] = { 0xf2, 0xf2, 0x0f,
						      0x38, 0xf8, 0x00 };
	static const uint8_t conflicting_mandatory[] = { 0xf2, 0xf3, 0x0f,
							 0x38, 0xf8, 0x00 };
	static const uint8_t repeated_segment[] = { 0x64, 0x65, 0xf2, 0x0f,
						    0x38, 0xf8, 0x00 };
	static const uint8_t repeated_address[] = { 0x67, 0x67, 0xf2, 0x0f,
						    0x38, 0xf8, 0x00 };
	static const uint8_t truncated_disp32[] = { 0xf2, 0x0f, 0x38, 0xf8,
						    0x80, 0x01, 0x02 };

	return rejects(handle, register_source, sizeof(register_source)) &&
	       rejects(handle, lock, sizeof(lock)) &&
	       rejects(handle, repeated_mandatory,
		       sizeof(repeated_mandatory)) &&
	       rejects(handle, conflicting_mandatory,
		       sizeof(conflicting_mandatory)) &&
	       rejects(handle, repeated_segment, sizeof(repeated_segment)) &&
	       rejects(handle, repeated_address, sizeof(repeated_address)) &&
	       rejects(handle, truncated_disp32, sizeof(truncated_disp32));
}

static bool check_prefix_case(csh handle, const uint8_t *bytes, size_t length,
			      const char *operands, x86_reg destination,
			      x86_reg base, uint8_t register_size,
			      uint8_t address_size, uint8_t operand_size_prefix,
			      uint8_t rex, uint8_t modrm_offset)
{
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, length, 0, 1, &insn) == 1;

	if (ok) {
		const cs_x86 *x86 = &insn->detail->x86;
		ok = check_common(insn, bytes, length, X86_INS_ENQCMD, "enqcmd",
				  operands, register_size) &&
		     x86->prefix[0] == 0xf2 &&
		     x86->prefix[2] == operand_size_prefix && x86->rex == rex &&
		     x86->addr_size == address_size && x86->opcode[0] == 0x0f &&
		     x86->opcode[1] == 0x38 && x86->opcode[2] == 0xf8 &&
		     x86->encoding.modrm_offset == modrm_offset &&
		     x86->operands[0].reg == destination &&
		     x86->operands[1].mem.base == base;
	}
	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_ignored_and_effective_prefixes(csh handle)
{
	const uint8_t operand_size_before_rep[] = { 0x66, 0xf2, 0x0f,
						    0x38, 0xf8, 0x00 };
	const uint8_t operand_size_after_rep[] = { 0xf2, 0x66, 0x0f,
						   0x38, 0xf8, 0x00 };
	const uint8_t ignored_rex[] = { 0x44, 0xf2, 0x0f, 0x38, 0xf8, 0x00 };
	const uint8_t last_rex_wins[] = { 0xf2, 0x40, 0x44, 0x0f,
					  0x38, 0xf8, 0x00 };
	const uint8_t address32_rex_r[] = { 0x67, 0xf2, 0x44, 0x0f,
					    0x38, 0xf8, 0x00 };

	return check_prefix_case(handle, operand_size_before_rep,
				 sizeof(operand_size_before_rep),
				 "rax, zmmword ptr [rax]", X86_REG_RAX,
				 X86_REG_RAX, 8, 8, 0x66, 0, 5) &&
	       check_prefix_case(handle, operand_size_after_rep,
				 sizeof(operand_size_after_rep),
				 "rax, zmmword ptr [rax]", X86_REG_RAX,
				 X86_REG_RAX, 8, 8, 0x66, 0, 5) &&
	       check_prefix_case(handle, ignored_rex, sizeof(ignored_rex),
				 "rax, zmmword ptr [rax]", X86_REG_RAX,
				 X86_REG_RAX, 8, 8, 0, 0, 5) &&
	       check_prefix_case(handle, last_rex_wins, sizeof(last_rex_wins),
				 "r8, zmmword ptr [rax]", X86_REG_R8,
				 X86_REG_RAX, 8, 8, 0, 0x44, 6) &&
	       check_prefix_case(handle, address32_rex_r,
				 sizeof(address32_rex_r),
				 "r8d, zmmword ptr [eax]", X86_REG_R8D,
				 X86_REG_EAX, 4, 4, 0, 0x44, 6);
}

static bool check_movdir64b_remains_generated(csh handle)
{
	const uint8_t bytes[] = { 0x66, 0x0f, 0x38, 0xf8, 0x00 };
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, sizeof(bytes), 0, 1, &insn) == 1;

	if (ok)
		ok = insn->id == X86_INS_MOVDIR64B;
	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_legacy_mode(const char *label, csh handle,
			      const uint8_t *bytes, size_t length,
			      unsigned int id, const char *mnemonic,
			      const char *operands, uint8_t register_size,
			      uint8_t address_size, x86_reg base, x86_reg index,
			      int64_t displacement, uint8_t modrm_offset,
			      uint8_t displacement_offset,
			      uint8_t displacement_size)
{
	cs_insn *insn = NULL;
	bool ok = cs_disasm(handle, bytes, length, 0x5000, 1, &insn) == 1;

	if (ok) {
		const cs_x86 *x86 = &insn->detail->x86;
		const cs_x86_op *memory = &x86->operands[1];

		ok = check_common(insn, bytes, length, id, mnemonic, operands,
				  register_size) &&
		     x86->opcode[0] == 0x0f && x86->opcode[1] == 0x38 &&
		     x86->opcode[2] == 0xf8 && x86->addr_size == address_size &&
		     x86->encoding.modrm_offset == modrm_offset &&
		     x86->encoding.disp_offset == displacement_offset &&
		     x86->encoding.disp_size == displacement_size &&
		     memory->mem.base == base && memory->mem.index == index &&
		     memory->mem.disp == displacement &&
		     insn->detail->regs_read_count == 1 &&
		     insn->detail->regs_read[0] == X86_REG_ES;
		if (!ok) {
			fprintf(stderr,
				"%s: %s %s, reg=%u/%u addr=%u base=%u index=%u "
				"disp=%" PRId64 " modrm=%u dispmeta=%u/%u\n",
				label, insn->mnemonic, insn->op_str,
				x86->operands[0].reg, x86->operands[0].size,
				x86->addr_size, memory->mem.base,
				memory->mem.index, memory->mem.disp,
				x86->encoding.modrm_offset,
				x86->encoding.disp_offset,
				x86->encoding.disp_size);
		}
	} else {
		fprintf(stderr, "%s: did not decode\n", label);
	}
	if (insn)
		cs_free(insn, 1);
	return ok;
}

static bool check_legacy_16_and_32_bit_modes(void)
{
	const uint8_t mode32_default[] = { 0xf2, 0x0f, 0x38, 0xf8,
					   0x44, 0x8b, 0x20 };
	const uint8_t mode32_address16[] = { 0x67, 0xf3, 0x0f, 0x38,
					     0xf8, 0x40, 0x7f };
	const uint8_t mode32_absolute32[] = { 0xf2, 0x0f, 0x38, 0xf8, 0x05,
					      0x78, 0x56, 0x34, 0x12 };
	const uint8_t mode32_absolute16[] = { 0x67, 0xf3, 0x0f, 0x38,
					      0xf8, 0x06, 0x34, 0x12 };
	const uint8_t mode16_default[] = { 0xf2, 0x0f, 0x38, 0xf8, 0x40, 0x80 };
	const uint8_t mode16_address32[] = { 0x67, 0xf3, 0x0f, 0x38,
					     0xf8, 0x44, 0x8b, 0x20 };
	const uint8_t mode16_absolute16[] = { 0xf2, 0x0f, 0x38, 0xf8,
					      0x06, 0x34, 0x12 };
	const uint8_t mode16_absolute32[] = { 0x67, 0xf3, 0x0f, 0x38, 0xf8,
					      0x05, 0x78, 0x56, 0x34, 0x12 };
	csh handle;
	bool ok;

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return false;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	ok = check_legacy_mode("mode32-default", handle, mode32_default,
			       sizeof(mode32_default), X86_INS_ENQCMD, "enqcmd",
			       "eax, zmmword ptr [ebx + ecx*4 + 0x20]", 4, 4,
			       X86_REG_EBX, X86_REG_ECX, 0x20, 4, 6, 1) &&
	     check_legacy_mode("mode32-addr16", handle, mode32_address16,
			       sizeof(mode32_address16), X86_INS_ENQCMDS,
			       "enqcmds", "ax, zmmword ptr [bx + si + 0x7f]", 2,
			       2, X86_REG_BX, X86_REG_SI, 0x7f, 5, 6, 1) &&
	     check_legacy_mode("mode32-absolute32", handle, mode32_absolute32,
			       sizeof(mode32_absolute32), X86_INS_ENQCMD,
			       "enqcmd", "eax, zmmword ptr [0x12345678]", 4, 4,
			       X86_REG_INVALID, X86_REG_INVALID, 0x12345678, 4,
			       5, 4) &&
	     check_legacy_mode("mode32-absolute16", handle, mode32_absolute16,
			       sizeof(mode32_absolute16), X86_INS_ENQCMDS,
			       "enqcmds", "ax, zmmword ptr [0x1234]", 2, 2,
			       X86_REG_INVALID, X86_REG_INVALID, 0x1234, 5, 6,
			       2);
	cs_close(&handle);
	if (!ok)
		return false;

	if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK)
		return false;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	ok = check_legacy_mode("mode16-default", handle, mode16_default,
			       sizeof(mode16_default), X86_INS_ENQCMD, "enqcmd",
			       "ax, zmmword ptr [bx + si - 0x80]", 2, 2,
			       X86_REG_BX, X86_REG_SI, -0x80, 4, 5, 1) &&
	     check_legacy_mode("mode16-addr32", handle, mode16_address32,
			       sizeof(mode16_address32), X86_INS_ENQCMDS,
			       "enqcmds",
			       "eax, zmmword ptr [ebx + ecx*4 + 0x20]", 4, 4,
			       X86_REG_EBX, X86_REG_ECX, 0x20, 5, 7, 1) &&
	     check_legacy_mode("mode16-absolute16", handle, mode16_absolute16,
			       sizeof(mode16_absolute16), X86_INS_ENQCMD,
			       "enqcmd", "ax, zmmword ptr [0x1234]", 2, 2,
			       X86_REG_INVALID, X86_REG_INVALID, 0x1234, 4, 5,
			       2) &&
	     check_legacy_mode("mode16-absolute32", handle, mode16_absolute32,
			       sizeof(mode16_absolute32), X86_INS_ENQCMDS,
			       "enqcmds", "eax, zmmword ptr [0x12345678]", 4, 4,
			       X86_REG_INVALID, X86_REG_INVALID, 0x12345678, 5,
			       6, 4);
	cs_close(&handle);
	return ok;
}

int main(void)
{
	csh handle;
	bool ok;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	ok = true;
	if (!check_fs_sib(handle)) {
		fprintf(stderr, "legacy enqueue fs/sib contract failure\n");
		ok = false;
	}
	if (!check_gs_rex(handle)) {
		fprintf(stderr, "legacy enqueue gs/rex contract failure\n");
		ok = false;
	}
	if (!check_address32(handle)) {
		fprintf(stderr, "legacy enqueue addr32 contract failure\n");
		ok = false;
	}
	if (!check_address32_ip_relative(handle)) {
		fprintf(stderr, "legacy enqueue addr32 EIP-relative failure\n");
		ok = false;
	}
	if (!check_apx_address32(handle)) {
		fprintf(stderr, "APX enqueue addr32 contract failure\n");
		ok = false;
	}
	if (!check_att(handle)) {
		fprintf(stderr, "legacy enqueue AT&T contract failure\n");
		ok = false;
	}
	if (!check_invalid_encodings(handle)) {
		fprintf(stderr,
			"legacy enqueue invalid-encoding contract failure\n");
		ok = false;
	}
	if (!check_ignored_and_effective_prefixes(handle)) {
		fprintf(stderr,
			"legacy enqueue ignored-prefix contract failure\n");
		ok = false;
	}
	if (!check_movdir64b_remains_generated(handle)) {
		fprintf(stderr, "legacy enqueue MOVDIR64B routing failure\n");
		ok = false;
	}
	cs_close(&handle);
	if (ok && !check_legacy_16_and_32_bit_modes()) {
		fprintf(stderr, "legacy enqueue 16/32-bit contract failure\n");
		ok = false;
	}
	return ok ? 0 : 1;
}

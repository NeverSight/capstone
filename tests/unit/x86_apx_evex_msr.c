#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct msr_case {
	const uint8_t *bytes;
	size_t size;
	unsigned int id;
	const char *mnemonic;
	const char *intel;
	const char *att;
	bool privileged;
	bool register_write;
	unsigned int register_reads;
	bool immediate;
	uint8_t modrm_offset;
	uint8_t immediate_offset;
} msr_case;

static bool check_case(csh handle, const msr_case *test, bool att)
{
	cs_insn *instruction = NULL;
	bool ok = cs_disasm(handle, test->bytes, test->size, 0, 1,
			    &instruction) == 1;
	unsigned int immediate_count = 0, register_read_count = 0;
	unsigned int register_write_count = 0;
	unsigned int i;

	if (!ok)
		return false;
	ok = instruction->id == test->id &&
	     strcmp(instruction->mnemonic, test->mnemonic) == 0 &&
	     strcmp(instruction->op_str, att ? test->att : test->intel) == 0 &&
	     strcmp(cs_insn_name(handle, instruction->id), test->mnemonic) == 0 &&
	     instruction->size == test->size &&
	     instruction->detail && instruction->detail->x86.op_count == 2;
	if (ok) {
		const cs_x86 *x86 = &instruction->detail->x86;
		for (i = 0; i < x86->op_count; ++i) {
			immediate_count += x86->operands[i].type == X86_OP_IMM;
			register_read_count +=
				x86->operands[i].type == X86_OP_REG &&
				(x86->operands[i].access & CS_AC_READ) != 0;
			register_write_count +=
				x86->operands[i].type == X86_OP_REG &&
				(x86->operands[i].access & CS_AC_WRITE) != 0;
			ok &= x86->operands[i].size ==
			      (x86->operands[i].type == X86_OP_IMM ? 4 : 8);
		}
		ok = immediate_count == (unsigned int)test->immediate &&
		     register_read_count == test->register_reads &&
		     register_write_count ==
			     (unsigned int)test->register_write &&
		     x86->encoding.modrm_offset == test->modrm_offset &&
		     x86->encoding.imm_offset == test->immediate_offset &&
		     x86->encoding.imm_size == (test->immediate ? 4 : 0) &&
		     (instruction->detail->groups_count == 1) ==
			     test->privileged &&
		     (!test->privileged ||
		      instruction->detail->groups[0] == X86_GRP_PRIVILEGE);
	}
	if (!ok)
		fprintf(stderr, "%s %s\n", instruction->mnemonic,
			instruction->op_str);
	cs_free(instruction, 1);
	return ok;
}

static bool rejects(csh handle, const uint8_t *bytes, size_t size)
{
	cs_insn *instruction = NULL;
	bool ok = cs_disasm(handle, bytes, size, 0, 1, &instruction) == 0;
	cs_free(instruction, 1);
	return ok;
}

int main(void)
{
	static const uint8_t rd_imm[] = {
		0x62, 0xff, 0xff, 0x08, 0xf6, 0xc1, 0x78, 0x56, 0x34, 0x12
	};
	static const uint8_t wr_imm[] = {
		0x62, 0xff, 0xfe, 0x08, 0xf6, 0xc2, 0x78, 0x56, 0x34, 0x12
	};
	static const uint8_t urd_imm[] = {
		0x62, 0xff, 0x7f, 0x08, 0xf8, 0xc3, 0x00, 0x1b, 0x00, 0x00
	};
	static const uint8_t uwr_imm[] = {
		0x62, 0xff, 0x7e, 0x08, 0xf8, 0xc4, 0x01, 0x1b, 0x00, 0x00
	};
	static const uint8_t urd_reg[] = {
		0x62, 0xec, 0x7f, 0x08, 0xf8, 0xf5
	};
	static const uint8_t uwr_reg[] = {
		0x62, 0xcc, 0x7e, 0x08, 0xf8, 0xf8
	};
	static const uint8_t legacy_urd_reg[] = {
		0xf2, 0x45, 0x0f, 0x38, 0xf8, 0xc7
	};
	static const uint8_t legacy_uwr_reg[] = {
		0xf3, 0x45, 0x0f, 0x38, 0xf8, 0xc7
	};
	static const uint8_t vex_urd_imm[] = {
		0xc4, 0x07, 0x7b, 0xf8, 0xc7, 0x00, 0x1b, 0x00, 0x00
	};
	static const uint8_t vex_uwr_imm[] = {
		0xc4, 0x07, 0x7a, 0xf8, 0xc7, 0x01, 0x1b, 0x00, 0x00
	};
	static const msr_case tests[] = {
		{ rd_imm, sizeof(rd_imm), X86_INS_RDMSR, "rdmsr",
		  "r17, 0x12345678", "$0x12345678, %r17", true, true, 0,
		  true, 5, 6 },
		{ wr_imm, sizeof(wr_imm), X86_INS_WRMSRNS, "wrmsrns",
		  "0x12345678, r18", "%r18, $0x12345678", true, false, 1,
		  true, 5, 6 },
		{ urd_imm, sizeof(urd_imm), X86_INS_URDMSR, "urdmsr",
		  "r19, 0x1b00", "$0x1b00, %r19", false, true, 0, true, 5,
		  6 },
		{ uwr_imm, sizeof(uwr_imm), X86_INS_UWRMSR, "uwrmsr",
		  "0x1b01, r20", "%r20, $0x1b01", false, false, 1, true,
		  5, 6 },
		{ urd_reg, sizeof(urd_reg), X86_INS_URDMSR, "urdmsr",
		  "r21, r22", "%r22, %r21", false, true, 1, false, 5, 0 },
		{ uwr_reg, sizeof(uwr_reg), X86_INS_UWRMSR, "uwrmsr",
		  "r23, r24", "%r24, %r23", false, false, 2, false, 5, 0 },
		{ legacy_urd_reg, sizeof(legacy_urd_reg), X86_INS_URDMSR,
		  "urdmsr", "r15, r8", "%r8, %r15", false, true, 1, false,
		  5, 0 },
		{ legacy_uwr_reg, sizeof(legacy_uwr_reg), X86_INS_UWRMSR,
		  "uwrmsr", "r8, r15", "%r15, %r8", false, false, 2, false,
		  5, 0 },
		{ vex_urd_imm, sizeof(vex_urd_imm), X86_INS_URDMSR, "urdmsr",
		  "r15, 0x1b00", "$0x1b00, %r15", false, true, 0, true, 4,
		  5 },
		{ vex_uwr_imm, sizeof(vex_uwr_imm), X86_INS_UWRMSR, "uwrmsr",
		  "0x1b01, r15", "%r15, $0x1b01", false, false, 1, true,
		  4, 5 },
	};
	csh handle;
	bool ok;
	unsigned int syntax, i;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	ok = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
	for (syntax = 0; syntax < 2; ++syntax) {
		ok &= cs_option(handle, CS_OPT_SYNTAX,
				syntax ? CS_OPT_SYNTAX_ATT :
					 CS_OPT_SYNTAX_INTEL) == CS_ERR_OK;
		for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
			ok &= check_case(handle, &tests[i], syntax != 0);
	}
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	{
		uint8_t w_ignored[sizeof(rd_imm)];
		msr_case w_ignored_case = tests[0];

		memcpy(w_ignored, rd_imm, sizeof(w_ignored));
		w_ignored[2] &= (uint8_t)~0x80;
		w_ignored_case.bytes = w_ignored;
		ok &= check_case(handle, &w_ignored_case, false);
	}
	{
		uint8_t invalid[sizeof(urd_imm)];
		memcpy(invalid, urd_imm, sizeof(invalid));
		invalid[2] |= 0x80; /* W=1 is reserved for USER_MSR. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, urd_imm, sizeof(invalid));
		invalid[2] &= (uint8_t)~0x04; /* EVEX.U must be one. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, urd_imm, sizeof(invalid));
		invalid[2] &= (uint8_t)~0x08; /* EVEX.vvvv is reserved. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, urd_imm, sizeof(invalid));
		invalid[3] |= 0x20; /* Non-zero vector length. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, urd_imm, sizeof(invalid));
		invalid[3] |= 0x04; /* NF is reserved. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, urd_imm, sizeof(invalid));
		invalid[5] = 0xcb; /* MAP7 requires ModRM.reg=/0. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, urd_imm, sizeof(invalid));
		invalid[5] = 0x03; /* All forms require register ModRM. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		ok &= rejects(handle, urd_imm, sizeof(urd_imm) - 1);
	}
	{
		uint8_t invalid[sizeof(urd_reg)];
		memcpy(invalid, urd_reg, sizeof(invalid));
		invalid[2] |= 0x80; /* W=1 is reserved for USER_MSR. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, urd_reg, sizeof(invalid));
		invalid[3] |= 0x10; /* ND is reserved. */
		ok &= rejects(handle, invalid, sizeof(invalid));
	}
	{
		uint8_t invalid[sizeof(vex_urd_imm)];
		memcpy(invalid, vex_urd_imm, sizeof(invalid));
		invalid[2] |= 0x80; /* VEX.W must be zero. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, vex_urd_imm, sizeof(invalid));
		invalid[2] |= 0x04; /* VEX.L must be zero. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, vex_urd_imm, sizeof(invalid));
		invalid[2] &= (uint8_t)~0x08; /* VEX.vvvv is reserved. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		memcpy(invalid, vex_urd_imm, sizeof(invalid));
		invalid[4] = 0xc8; /* VEX MAP7 requires ModRM.reg=/0. */
		ok &= rejects(handle, invalid, sizeof(invalid));
		ok &= rejects(handle, vex_urd_imm, sizeof(vex_urd_imm) - 1);
	}
	{
		uint8_t prefixed[sizeof(rd_imm) + 1];
		prefixed[0] = 0x66;
		memcpy(&prefixed[1], rd_imm, sizeof(rd_imm));
		ok &= rejects(handle, prefixed, sizeof(prefixed));
	}
	cs_close(&handle);

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return 1;
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
		ok &= rejects(handle, tests[i].bytes, tests[i].size);
	cs_close(&handle);
	return ok ? 0 : 1;
}

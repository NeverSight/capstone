/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct broadcast_case {
	const char *name;
	uint8_t p1;
	uint8_t opcode;
	x86_insn instruction;
	uint8_t element_size;
} broadcast_case;

static bool check_case(csh handle, const broadcast_case *test_case,
		       bool register_source)
{
	const uint8_t code[] = {
		0x62,
		register_source ? 0x02 : 0x62,
		test_case->p1,
		register_source ? 0x4f : 0xcf,
		test_case->opcode,
		register_source ? 0xf5 : 0x30,
	};
	const uint8_t expected_mask_size =
		(uint8_t)(((64 / test_case->element_size) + 7) / 8);
	cs_insn *insn = NULL;
	const cs_x86_op *mask = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (count != 1) {
		fprintf(stderr, "%s %s did not decode\n", test_case->name,
			register_source ? "register" : "memory");
		return false;
	}
	if (insn[0].id != test_case->instruction || insn[0].detail == NULL) {
		fprintf(stderr, "%s %s decoded with wrong id/detail\n",
			test_case->name,
			register_source ? "register" : "memory");
		success = false;
		goto done;
	}
	for (uint8_t i = 0; i < insn[0].detail->x86.op_count; ++i) {
		const cs_x86_op *operand = &insn[0].detail->x86.operands[i];

		if (operand->type == X86_OP_REG && operand->reg == X86_REG_K7) {
			mask = operand;
			break;
		}
	}
	if (mask == NULL || mask->size != expected_mask_size) {
		fprintf(stderr,
			"%s %s mask size was %u, expected %u\n",
			test_case->name,
			register_source ? "register" : "memory",
			mask ? mask->size : 0, expected_mask_size);
		success = false;
	}

done:
	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const broadcast_case cases[] = {
		{ "vbroadcastss", 0x7d, 0x18, X86_INS_VBROADCASTSS, 4 },
		{ "vbroadcastsd", 0xfd, 0x19, X86_INS_VBROADCASTSD, 8 },
		{ "vpbroadcastb", 0x7d, 0x78, X86_INS_VPBROADCASTB, 1 },
		{ "vpbroadcastw", 0x7d, 0x79, X86_INS_VPBROADCASTW, 2 },
		{ "vpbroadcastd", 0x7d, 0x58, X86_INS_VPBROADCASTD, 4 },
		{ "vpbroadcastq", 0xfd, 0x59, X86_INS_VPBROADCASTQ, 8 },
	};
	csh handle = 0;
	bool success = true;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON | CS_OPT_DETAIL_REAL) !=
	    CS_ERR_OK) {
		cs_close(&handle);
		return 1;
	}

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		success &= check_case(handle, &cases[i], false);
		success &= check_case(handle, &cases[i], true);
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

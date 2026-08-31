/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct f16c_case {
	const char *name;
	const uint8_t *code;
	size_t code_size;
	x86_insn id;
	uint8_t expected_mask_size;
} f16c_case;

static bool check_case(csh handle, const f16c_case *test)
{
	cs_insn *insn = NULL;
	const cs_x86_op *mask = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, test->code, test->code_size, 0x1000, 1,
				 &insn);

	if (count != 1) {
		fprintf(stderr, "%s did not decode\n", test->name);
		return false;
	}
	if (insn[0].id != test->id || insn[0].detail == NULL) {
		fprintf(stderr, "%s has wrong id/detail\n", test->name);
		success = false;
		goto done;
	}
	for (uint8_t i = 0; i < insn[0].detail->x86.op_count; ++i) {
		const cs_x86_op *operand = &insn[0].detail->x86.operands[i];

		if (operand->type == X86_OP_REG && operand->reg == X86_REG_K3) {
			mask = operand;
			break;
		}
	}
	if (mask == NULL || mask->size != test->expected_mask_size ||
	    (mask->access & CS_AC_READ) == 0) {
		fprintf(stderr,
			"%s mask size/access was %u/%u, expected %u/read\n",
			test->name, mask ? mask->size : 0,
			mask ? mask->access : 0, test->expected_mask_size);
		success = false;
	}

done:
	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const uint8_t widen_memory[] = {
		0x62, 0xf2, 0x7d, 0xcb, 0x13, 0x08
	};
	static const uint8_t widen_register[] = {
		0x62, 0xb2, 0x7d, 0xcb, 0x13, 0xcb
	};
	static const uint8_t narrow_memory_128[] = {
		0x62, 0xe3, 0x7d, 0x0b, 0x1d, 0x18, 0x04
	};
	static const uint8_t narrow_memory_512[] = {
		0x62, 0xe3, 0x7d, 0x4b, 0x1d, 0x18, 0x02
	};
	static const uint8_t narrow_register_512[] = {
		0x62, 0xe3, 0x7d, 0xcb, 0x1d, 0xd9, 0x02
	};
	static const f16c_case cases[] = {
		{ "widen-memory-512", widen_memory, sizeof(widen_memory),
		  X86_INS_VCVTPH2PS, 2 },
		{ "widen-register-512", widen_register,
		  sizeof(widen_register), X86_INS_VCVTPH2PS, 2 },
		{ "narrow-memory-128", narrow_memory_128,
		  sizeof(narrow_memory_128), X86_INS_VCVTPS2PH, 1 },
		{ "narrow-memory-512", narrow_memory_512,
		  sizeof(narrow_memory_512), X86_INS_VCVTPS2PH, 2 },
		{ "narrow-register-512", narrow_register_512,
		  sizeof(narrow_register_512), X86_INS_VCVTPS2PH, 2 },
	};
	csh handle = 0;
	bool success = true;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	if (cs_option(handle, CS_OPT_DETAIL,
		      CS_OPT_ON | CS_OPT_DETAIL_REAL) != CS_ERR_OK) {
		cs_close(&handle);
		return 1;
	}
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		success &= check_case(handle, &cases[i]);
	cs_close(&handle);
	return success ? 0 : 1;
}

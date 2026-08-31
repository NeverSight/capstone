/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct convert_family {
	const char *name;
	x86_insn id;
	uint8_t p1;
	uint8_t opcode;
	uint8_t wide_element_size;
} convert_family;

static uint8_t normalized_mask_size(unsigned int lanes)
{
	unsigned int bytes = (lanes + 7) / 8;

	if (bytes <= 1)
		return 1;
	if (bytes <= 2)
		return 2;
	if (bytes <= 4)
		return 4;
	return 8;
}

static bool check_mask_size(csh handle, const convert_family *family,
			    uint8_t vector_size, bool memory_source)
{
	const uint8_t length = vector_size == 16 ? 0 :
			       vector_size == 32 ? 0x20 :
						   0x40;
	const uint8_t expected_mask_size =
		normalized_mask_size(vector_size / family->wide_element_size);
	const uint8_t code[] = {
		0x62,		0xf1,
		family->p1,	(uint8_t)(0x09 | length),
		family->opcode, (uint8_t)(memory_source ? 0x00 : 0xc1)
	};
	cs_insn *insn = NULL;
	const cs_x86_op *mask = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (count != 1) {
		fprintf(stderr, "%s %u-bit %s did not decode\n", family->name,
			vector_size * 8, memory_source ? "memory" : "register");
		return false;
	}
	if (insn[0].id != family->id || insn[0].detail == NULL) {
		fprintf(stderr, "%s %u-bit %s has wrong id/detail\n",
			family->name, vector_size * 8,
			memory_source ? "memory" : "register");
		success = false;
		goto done;
	}
	for (uint8_t i = 0; i < insn[0].detail->x86.op_count; ++i) {
		const cs_x86_op *operand = &insn[0].detail->x86.operands[i];

		if (operand->type == X86_OP_REG && operand->reg == X86_REG_K1) {
			mask = operand;
			break;
		}
	}
	if (mask == NULL || mask->size != expected_mask_size ||
	    (mask->access & CS_AC_READ) == 0) {
		fprintf(stderr,
			"%s %u-bit %s mask size/access was %u/%u, expected %u/read\n",
			family->name, vector_size * 8,
			memory_source ? "memory" : "register",
			mask ? mask->size : 0, mask ? mask->access : 0,
			expected_mask_size);
		success = false;
	}

done:
	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const convert_family families[] = {
		{ "vcvtps2dq", X86_INS_VCVTPS2DQ, 0x7d, 0x5b, 4 },
		{ "vcvtps2udq", X86_INS_VCVTPS2UDQ, 0x7c, 0x79, 4 },
		{ "vcvttps2dq", X86_INS_VCVTTPS2DQ, 0x7e, 0x5b, 4 },
		{ "vcvttps2udq", X86_INS_VCVTTPS2UDQ, 0x7c, 0x78, 4 },
		{ "vcvtpd2ps", X86_INS_VCVTPD2PS, 0xfd, 0x5a, 8 },
		{ "vcvtps2pd", X86_INS_VCVTPS2PD, 0x7c, 0x5a, 8 },
	};
	static const uint8_t vector_sizes[] = { 16, 32, 64 };
	csh handle = 0;
	bool success = true;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON | CS_OPT_DETAIL_REAL) !=
	    CS_ERR_OK) {
		cs_close(&handle);
		return 1;
	}

	for (size_t family_index = 0;
	     family_index < sizeof(families) / sizeof(families[0]);
	     ++family_index) {
		for (size_t size_index = 0;
		     size_index <
		     sizeof(vector_sizes) / sizeof(vector_sizes[0]);
		     ++size_index) {
			success &= check_mask_size(handle,
						   &families[family_index],
						   vector_sizes[size_index],
						   false);
			success &=
				check_mask_size(handle, &families[family_index],
						vector_sizes[size_index], true);
		}
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

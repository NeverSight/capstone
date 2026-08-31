/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct dot_product_family {
	const char *name;
	x86_insn id;
	uint8_t opcode;
} dot_product_family;

static bool check_mask_size(csh handle, const dot_product_family *family,
			    uint8_t vector_size)
{
	const uint8_t length = vector_size == 16 ? 0x18 :
			       vector_size == 32 ? 0x38 :
						   0x58;
	const uint8_t expected_mask_size =
		(uint8_t)(((vector_size / 4) + 7) / 8);
	const uint8_t code[] = { 0x62, 0xf2, 0x6d,
				 (uint8_t)(length | 3), family->opcode, 0x08 };
	cs_insn *insn = NULL;
	const cs_x86_op *mask = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (count != 1) {
		fprintf(stderr, "%s %u-bit did not decode\n", family->name,
			vector_size * 8);
		return false;
	}
	if (insn[0].id != family->id || insn[0].detail == NULL) {
		fprintf(stderr, "%s %u-bit decoded with wrong id/detail\n",
			family->name, vector_size * 8);
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
	if (mask == NULL || mask->size != expected_mask_size) {
		fprintf(stderr, "%s %u-bit mask size was %u, expected %u\n",
			family->name, vector_size * 8,
			mask ? mask->size : 0, expected_mask_size);
		success = false;
	}

done:
	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const dot_product_family families[] = {
		{ "vpdpbusd", X86_INS_VPDPBUSD, 0x50 },
		{ "vpdpbusds", X86_INS_VPDPBUSDS, 0x51 },
		{ "vpdpwssd", X86_INS_VPDPWSSD, 0x52 },
		{ "vpdpwssds", X86_INS_VPDPWSSDS, 0x53 },
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
		     size_index < sizeof(vector_sizes) / sizeof(vector_sizes[0]);
		     ++size_index) {
			success &= check_mask_size(handle, &families[family_index],
						   vector_sizes[size_index]);
		}
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

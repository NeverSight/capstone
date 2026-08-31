/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct unpack_family {
	const char *name;
	x86_insn low_id;
	x86_insn high_id;
	uint8_t low_opcode;
	uint8_t high_opcode;
	uint8_t element_size;
	bool w;
} unpack_family;

static bool check_mask_size(csh handle, const unpack_family *family, bool high,
			    uint8_t vector_size)
{
	const uint8_t p1 = (family->w ? 0x80 : 0) | 0x75;
	const uint8_t length = vector_size == 16 ? 0x08 :
			       vector_size == 32 ? 0x28 :
						   0x48;
	const uint8_t opcode = high ? family->high_opcode : family->low_opcode;
	const x86_insn expected_id = high ? family->high_id : family->low_id;
	const uint8_t expected_mask_size =
		(uint8_t)(((vector_size / family->element_size) + 7) / 8);
	const uint8_t code[] = { 0x62,	 0xf1, p1, (uint8_t)(length | 1),
				 opcode, 0x18 };
	cs_insn *insn = NULL;
	const cs_x86_op *mask = NULL;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (count != 1) {
		fprintf(stderr, "%s%s %u-bit did not decode\n", family->name,
			high ? "-high" : "-low", vector_size * 8);
		return false;
	}
	if (insn[0].id != expected_id || insn[0].detail == NULL) {
		fprintf(stderr, "%s%s %u-bit decoded with wrong id/detail\n",
			family->name, high ? "-high" : "-low", vector_size * 8);
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
	if (mask == NULL || mask->size != expected_mask_size) {
		fprintf(stderr, "%s%s %u-bit mask size was %u, expected %u\n",
			family->name, high ? "-high" : "-low", vector_size * 8,
			mask ? mask->size : 0, expected_mask_size);
		success = false;
	}

done:
	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const unpack_family families[] = {
		{ "byte", X86_INS_VPUNPCKLBW, X86_INS_VPUNPCKHBW, 0x60, 0x68, 1,
		  false },
		{ "word", X86_INS_VPUNPCKLWD, X86_INS_VPUNPCKHWD, 0x61, 0x69, 2,
		  false },
		{ "dword", X86_INS_VPUNPCKLDQ, X86_INS_VPUNPCKHDQ, 0x62, 0x6a,
		  4, false },
		{ "qword", X86_INS_VPUNPCKLQDQ, X86_INS_VPUNPCKHQDQ, 0x6c, 0x6d,
		  8, true },
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
			for (unsigned high = 0; high != 2; ++high)
				success &= check_mask_size(
					handle, &families[family_index],
					high != 0, vector_sizes[size_index]);
		}
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

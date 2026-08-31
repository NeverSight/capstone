/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct narrow_family {
	const char *name;
	x86_insn id;
	uint8_t opcode;
	uint8_t source_element_size;
	uint8_t destination_element_size;
} narrow_family;

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

static bool check_form(csh handle, const narrow_family *family,
		       uint8_t source_size, bool memory_destination)
{
	const uint8_t length = source_size == 16 ? 0 :
			       source_size == 32 ? 0x20 : 0x40;
	const uint8_t modrm = memory_destination ? 0x18 : 0xd9;
	const uint8_t code[] = { 0x62, 0xf2, 0x7e,
				 (uint8_t)(0x0a | length), family->opcode,
				 modrm };
	const uint8_t expected_mask_size = normalized_mask_size(
		source_size / family->source_element_size);
	const uint8_t active_destination_size =
		(uint8_t)((source_size / family->source_element_size) *
			  family->destination_element_size);
	const uint8_t expected_destination_size =
		memory_destination || active_destination_size >= 16 ?
			active_destination_size :
			16;
	cs_insn *insn = NULL;
	const cs_x86_op *destination;
	const cs_x86_op *mask;
	const cs_x86_op *source;
	bool success = true;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 1, &insn);

	if (count != 1) {
		fprintf(stderr, "%s %u-bit %s form did not decode\n",
			family->name, source_size * 8,
			memory_destination ? "memory" : "register");
		return false;
	}
	if (insn[0].id != family->id || insn[0].detail == NULL ||
	    insn[0].detail->x86.op_count != 3) {
		fprintf(stderr, "%s %u-bit %s form has wrong id/detail\n",
			family->name, source_size * 8,
			memory_destination ? "memory" : "register");
		success = false;
		goto done;
	}
	destination = &insn[0].detail->x86.operands[0];
	mask = &insn[0].detail->x86.operands[1];
	source = &insn[0].detail->x86.operands[2];
	if ((memory_destination && destination->type != X86_OP_MEM) ||
	    (!memory_destination && destination->type != X86_OP_REG) ||
	    destination->size != expected_destination_size ||
	    (destination->access & CS_AC_WRITE) == 0 ||
	    mask->type != X86_OP_REG || mask->reg != X86_REG_K2 ||
	    mask->size != expected_mask_size ||
	    (mask->access & CS_AC_READ) == 0 || source->type != X86_OP_REG ||
	    (source->access & CS_AC_READ) == 0 ||
	    source->size != source_size) {
		fprintf(stderr,
			"%s %u-bit %s sizes dst=%u mask=%u src=%u; expected %u/%u/%u\n",
			family->name, source_size * 8,
			memory_destination ? "memory" : "register",
			destination->size, mask->size, source->size,
			expected_destination_size, expected_mask_size, source_size);
		success = false;
	}

done:
	cs_free(insn, count);
	return success;
}

int main(void)
{
	static const narrow_family families[] = {
		{ "vpmovwb", X86_INS_VPMOVWB, 0x30, 2, 1 },
		{ "vpmovdb", X86_INS_VPMOVDB, 0x31, 4, 1 },
		{ "vpmovqb", X86_INS_VPMOVQB, 0x32, 8, 1 },
		{ "vpmovdw", X86_INS_VPMOVDW, 0x33, 4, 2 },
		{ "vpmovqw", X86_INS_VPMOVQW, 0x34, 8, 2 },
		{ "vpmovqd", X86_INS_VPMOVQD, 0x35, 8, 4 },
		{ "vpmovswb", X86_INS_VPMOVSWB, 0x20, 2, 1 },
		{ "vpmovsdb", X86_INS_VPMOVSDB, 0x21, 4, 1 },
		{ "vpmovsqb", X86_INS_VPMOVSQB, 0x22, 8, 1 },
		{ "vpmovsdw", X86_INS_VPMOVSDW, 0x23, 4, 2 },
		{ "vpmovsqw", X86_INS_VPMOVSQW, 0x24, 8, 2 },
		{ "vpmovsqd", X86_INS_VPMOVSQD, 0x25, 8, 4 },
		{ "vpmovuswb", X86_INS_VPMOVUSWB, 0x10, 2, 1 },
		{ "vpmovusdb", X86_INS_VPMOVUSDB, 0x11, 4, 1 },
		{ "vpmovusqb", X86_INS_VPMOVUSQB, 0x12, 8, 1 },
		{ "vpmovusdw", X86_INS_VPMOVUSDW, 0x13, 4, 2 },
		{ "vpmovusqw", X86_INS_VPMOVUSQW, 0x14, 8, 2 },
		{ "vpmovusqd", X86_INS_VPMOVUSQD, 0x15, 8, 4 },
	};
	static const uint8_t source_sizes[] = { 16, 32, 64 };
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
		     size_index < sizeof(source_sizes) / sizeof(source_sizes[0]);
		     ++size_index) {
			success &= check_form(handle, &families[family_index],
					      source_sizes[size_index], false);
			success &= check_form(handle, &families[family_index],
					      source_sizes[size_index], true);
		}
	}

	cs_close(&handle);
	return success ? 0 : 1;
}

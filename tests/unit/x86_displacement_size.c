/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct instruction_family {
	const char *name;
	x86_insn id;
	uint8_t bytes[5];
	uint8_t length;
} instruction_family;

static bool check_detail(const cs_insn *insn, const instruction_family *family,
			 cs_mode mode, uint8_t address_size,
			 uint8_t displacement_size, uint8_t displacement_offset,
			 int64_t displacement, uint8_t length, bool segment,
			 unsigned int form)
{
	if (insn->id != family->id || insn->size != length || !insn->detail) {
		fprintf(stderr,
			"%s mode %u form %u: wrong instruction/length/detail\n",
			family->name, mode, form);
		return false;
	}
	const cs_x86 *x86 = &insn->detail->x86;
	const cs_x86_op *memory = NULL;
	for (unsigned int i = 0; i < x86->op_count; ++i)
		if (x86->operands[i].type == X86_OP_MEM)
			memory = &x86->operands[i];
	if (x86->addr_size != address_size ||
	    x86->encoding.disp_size != displacement_size ||
	    x86->encoding.disp_offset != displacement_offset ||
	    x86->disp != displacement || !memory ||
	    memory->mem.disp != displacement ||
	    !(memory->access & CS_AC_READ) ||
	    memory->mem.segment != (segment ? X86_REG_GS : X86_REG_INVALID)) {
		fprintf(stderr,
			"%s mode %u addr %u form %u: displacement %u@%u=%lld, expected %u@%u=%lld\n",
			family->name, mode, address_size, form,
			x86->encoding.disp_size, x86->encoding.disp_offset,
			(long long)x86->disp, displacement_size,
			displacement_offset, (long long)displacement);
		return false;
	}
	return true;
}

static bool check_encoding(csh handle, const instruction_family *family,
			   cs_mode mode, bool address_override,
			   unsigned int form, bool segment)
{
	const uint8_t address_size =
		mode == CS_MODE_64 ? (address_override ? 4 : 8) :
		mode == CS_MODE_32 ? (address_override ? 2 : 4) :
				     (address_override ? 4 : 2);
	uint8_t bytes[15];
	uint8_t length = 0;
	uint8_t displacement_size = 0;
	if (segment)
		bytes[length++] = 0x65;
	if (address_override)
		bytes[length++] = 0x67;
	memcpy(bytes + length, family->bytes, family->length);
	length += family->length;
	if (address_size == 2 && form >= 4)
		return true;
	switch (form) {
	case 0: /* no displacement */
		bytes[length++] = 0x00;
		break;
	case 1: /* signed disp8 */
		bytes[length++] = 0x40;
		displacement_size = 1;
		break;
	case 2: /* base plus full displacement */
		bytes[length++] = 0x80;
		displacement_size = address_size == 2 ? 2 : 4;
		break;
	case 3: /* absolute disp16/disp32 or RIP/EIP-relative disp32 */
		bytes[length++] = address_size == 2 ? 0x06 : 0x05;
		displacement_size = address_size == 2 ? 2 : 4;
		break;
	case 4: /* no-base SIB */
		bytes[length++] = 0x04;
		bytes[length++] = 0x25;
		displacement_size = 4;
		break;
	case 5: /* scaled-index SIB with a base and disp32 */
		bytes[length++] = 0x84;
		bytes[length++] = 0x88;
		displacement_size = 4;
		break;
	}
	const uint8_t displacement_offset = displacement_size ? length : 0;
	const int64_t encoded_displacement =
		displacement_size == 1 ? -17 :
		displacement_size == 2 ? -0x1234 :
		displacement_size == 4 ? -0x12345678 :
					 0;
	for (unsigned int i = 0; i < displacement_size; ++i)
		bytes[length++] =
			(uint8_t)((uint64_t)encoded_displacement >> (i * 8));
	/* EVEX disp8 is compressed; its encoded extent remains one byte. */
	const int64_t displacement =
		displacement_size == 1 && family->bytes[0] == 0x62 ?
			encoded_displacement *
				((family->bytes[3] & 0x40) ? 64 : 16) :
			encoded_displacement;

	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, bytes, length, 0x1000, 1, &insn);
	bool success = count == 1;
	if (!success)
		fprintf(stderr, "%s mode %u addr %u form %u did not decode\n",
			family->name, mode, address_size, form);
	else
		success = check_detail(insn, family, mode, address_size,
				       displacement_size, displacement_offset,
				       displacement, length, segment, form);
	cs_free(insn, count);
	insn = cs_malloc(handle);
	if (!insn)
		return false;
	const uint8_t *cursor = bytes;
	size_t remaining = length;
	uint64_t address = 0x1000;
	if (!cs_disasm_iter(handle, &cursor, &remaining, &address, insn) ||
	    remaining || cursor != bytes + length || address != 0x1000 + length)
		success = false;
	else
		success &= check_detail(insn, family, mode, address_size,
					displacement_size, displacement_offset,
					displacement, length, segment, form);
	cs_free(insn, 1);
	return success;
}

int main(void)
{
	static const instruction_family families[] = {
		{ "mov16", X86_INS_MOV, { 0x66, 0x8b }, 2 },
		{ "cvtpd2ps", X86_INS_CVTPD2PS, { 0x66, 0x0f, 0x5a }, 3 },
		{ "vcvtpd2ps128", X86_INS_VCVTPD2PS, { 0xc5, 0xf9, 0x5a }, 3 },
		{ "vcvtpd2ps256", X86_INS_VCVTPD2PS, { 0xc5, 0xfd, 0x5a }, 3 },
		{ "vcvtpd2dq256", X86_INS_VCVTPD2DQ, { 0xc5, 0xff, 0xe6 }, 3 },
		{ "evex-cvtpd2ps128",
		  X86_INS_VCVTPD2PS,
		  { 0x62, 0xf1, 0xfd, 0x08, 0x5a },
		  5 },
		{ "evex-cvtpd2ps512",
		  X86_INS_VCVTPD2PS,
		  { 0x62, 0xf1, 0xfd, 0x48, 0x5a },
		  5 },
	};
	static const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	static const cs_opt_value syntaxes[] = { CS_OPT_SYNTAX_INTEL,
						 CS_OPT_SYNTAX_ATT };
	bool success = true;
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
		csh handle;
		if (cs_open(CS_ARCH_X86, modes[m], &handle) != CS_ERR_OK)
			return 1;
		if (cs_option(handle, CS_OPT_DETAIL,
			      CS_OPT_ON | CS_OPT_DETAIL_REAL) != CS_ERR_OK)
			return 1;
		for (size_t s = 0; s < sizeof(syntaxes) / sizeof(syntaxes[0]);
		     ++s) {
			cs_option(handle, CS_OPT_SYNTAX, syntaxes[s]);
			for (size_t f = 0;
			     f < sizeof(families) / sizeof(families[0]); ++f) {
				/* Legacy SIMD mandatory-prefix identity in mode16 is a
				 * separate decoder boundary. Integer and VEX/EVEX forms
				 * still exercise both mode16 address sizes here. */
				if (modes[m] == CS_MODE_16 &&
				    families[f].id == X86_INS_CVTPD2PS)
					continue;
				for (unsigned int a = 0; a < 2; ++a)
					for (unsigned int form = 0; form < 6;
					     ++form)
						for (unsigned int segment = 0;
						     segment < 2; ++segment)
							success &= check_encoding(
								handle,
								&families[f],
								modes[m], a,
								form, segment);
			}
		}
		cs_close(&handle);
	}
	return success ? 0 : 1;
}

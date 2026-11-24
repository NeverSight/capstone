/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>

struct move {
	uint8_t bytes[6], length, width;
	x86_insn id;
	bool store, wide_only;
};

static const struct move moves[] = {
	{ { 0x0f, 0x6e, 0x0b }, 3, 4, X86_INS_MOVD, false, false },
	{ { 0x0f, 0x7e, 0x0b }, 3, 4, X86_INS_MOVD, true, false },
	{ { 0x0f, 0x6f, 0x0b }, 3, 8, X86_INS_MOVQ, false, false },
	{ { 0x0f, 0x7f, 0x0b }, 3, 8, X86_INS_MOVQ, true, false },
	{ { 0x48, 0x0f, 0x6e, 0x0b }, 4, 8, X86_INS_MOVQ, false, true },
	{ { 0x48, 0x0f, 0x7e, 0x0b }, 4, 8, X86_INS_MOVQ, true, true },
	{ { 0x66, 0x0f, 0x6e, 0x0b }, 4, 4, X86_INS_MOVD, false, false },
	{ { 0x66, 0x0f, 0x7e, 0x0b }, 4, 4, X86_INS_MOVD, true, false },
	{ { 0x66, 0x48, 0x0f, 0x6e, 0x0b }, 5, 8, X86_INS_MOVQ, false, true },
	{ { 0x66, 0x48, 0x0f, 0x7e, 0x0b }, 5, 8, X86_INS_MOVQ, true, true },
	{ { 0xf3, 0x0f, 0x7e, 0x0b }, 4, 8, X86_INS_MOVQ, false, false },
	{ { 0x66, 0x0f, 0xd6, 0x0b }, 4, 8, X86_INS_MOVQ, true, false },
	{ { 0xc5, 0xf9, 0x6e, 0x0b }, 4, 4, X86_INS_VMOVD, false, false },
	{ { 0xc5, 0xf9, 0x7e, 0x0b }, 4, 4, X86_INS_VMOVD, true, false },
	{ { 0xc5, 0xfa, 0x7e, 0x0b }, 4, 8, X86_INS_VMOVQ, false, false },
	{ { 0xc5, 0xf9, 0xd6, 0x0b }, 4, 8, X86_INS_VMOVQ, true, false },
	{ { 0xc4, 0xe1, 0x79, 0x6e, 0x0b }, 5, 4, X86_INS_VMOVD, false, false },
	{ { 0xc4, 0xe1, 0x79, 0x7e, 0x0b }, 5, 4, X86_INS_VMOVD, true, false },
	{ { 0xc4, 0xe1, 0xf9, 0x6e, 0x0b }, 5, 8, X86_INS_VMOVQ, false, true },
	{ { 0xc4, 0xe1, 0xf9, 0x7e, 0x0b }, 5, 8, X86_INS_VMOVQ, true, true },
	{ { 0xc4, 0xe1, 0x7a, 0x7e, 0x0b }, 5, 8, X86_INS_VMOVQ, false, false },
	{ { 0xc4, 0xe1, 0x79, 0xd6, 0x0b }, 5, 8, X86_INS_VMOVQ, true, false },
	{ { 0x62, 0xf1, 0x7d, 0x08, 0x6e, 0x0b },
	  6,
	  4,
	  X86_INS_VMOVD,
	  false,
	  false },
	{ { 0x62, 0xf1, 0x7d, 0x08, 0x7e, 0x0b },
	  6,
	  4,
	  X86_INS_VMOVD,
	  true,
	  false },
	{ { 0x62, 0xf1, 0xfd, 0x08, 0x6e, 0x0b },
	  6,
	  8,
	  X86_INS_VMOVQ,
	  false,
	  true },
	{ { 0x62, 0xf1, 0xfd, 0x08, 0x7e, 0x0b },
	  6,
	  8,
	  X86_INS_VMOVQ,
	  true,
	  true },
	{ { 0x62, 0xf1, 0xfe, 0x08, 0x7e, 0x0b },
	  6,
	  8,
	  X86_INS_VMOVQ,
	  false,
	  false },
	{ { 0x62, 0xf1, 0xfd, 0x08, 0xd6, 0x0b },
	  6,
	  8,
	  X86_INS_VMOVQ,
	  true,
	  false },
};

static bool check_moves(csh handle, bool wide, bool att)
{
	for (size_t i = 0; i < sizeof(moves) / sizeof(moves[0]); ++i) {
		const struct move *move = &moves[i];
		if (move->wide_only && !wide)
			continue;
		cs_insn *insn;
		if (cs_disasm(handle, move->bytes, move->length, 0x1000, 1,
			      &insn) != 1)
			return false;
		const cs_x86 *x86 = &insn->detail->x86;
		const unsigned memory_index = att == move->store;
		const cs_x86_op *memory = &x86->operands[memory_index];
		const cs_x86_op *reg = &x86->operands[1 - memory_index];
		bool ok = insn->size == move->length && insn->id == move->id &&
			  x86->op_count == 2 && memory->type == X86_OP_MEM &&
			  memory->size == move->width &&
			  reg->type == X86_OP_REG &&
			  memory->access ==
				  (move->store ? CS_AC_WRITE : CS_AC_READ) &&
			  reg->access ==
				  (move->store ? CS_AC_READ : CS_AC_WRITE);
		if (!ok)
			fprintf(stderr, "%s %s (case %zu)\n", insn->mnemonic,
				insn->op_str, i);
		cs_free(insn, 1);
		if (!ok)
			return false;
	}
	return true;
}

int main(void)
{
	const cs_mode modes[] = { CS_MODE_32, CS_MODE_64 };
	for (unsigned i = 0; i < 2; ++i) {
		csh handle;
		if (cs_open(CS_ARCH_X86, modes[i], &handle))
			return 1;
		bool ok = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) ==
			  CS_ERR_OK;
		for (unsigned att = 0; att < 2 && ok; ++att) {
			cs_err err = cs_option(handle, CS_OPT_SYNTAX,
					       att ? CS_OPT_SYNTAX_ATT :
						     CS_OPT_SYNTAX_INTEL);
			if (att && err == CS_ERR_X86_ATT)
				continue;
			ok = err == CS_ERR_OK &&
			     check_moves(handle, i != 0, att != 0);
		}
		cs_close(&handle);
		if (!ok)
			return 1;
	}
	return 0;
}

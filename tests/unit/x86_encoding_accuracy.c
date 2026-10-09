/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool decode(csh handle, const uint8_t *bytes, size_t size, unsigned id,
		   size_t length)
{
	cs_insn *batch = NULL, *iter = cs_malloc(handle);
	const uint8_t *cursor = bytes;
	size_t remaining = size;
	uint64_t address = 0x1000;
	size_t count = cs_disasm(handle, bytes, size, address, 1, &batch);
	bool ok = iter != NULL;
	if (iter) {
		bool decoded = cs_disasm_iter(handle, &cursor, &remaining,
					      &address, iter);
		ok &= decoded == (length != 0);
		if (decoded)
			ok &= iter->id == id && iter->size == length &&
			      cursor == bytes + length &&
			      remaining == size - length &&
			      address == 0x1000 + length;
		else
			ok &= cursor == bytes && remaining == size &&
			      address == 0x1000;
	}
	if (length)
		ok &= count == 1 && batch->id == id && batch->size == length &&
		      memcmp(batch->bytes, bytes, length) == 0;
	else
		ok &= count == 0;
	if (!ok) {
		fprintf(stderr, "decode: expected id=%u size=%zu for", id,
			length);
		for (size_t i = 0; i < size; ++i)
			fprintf(stderr, " %02x", bytes[i]);
		fprintf(stderr, "\n");
	}
	cs_free(batch, count);
	cs_free(iter, iter ? 1 : 0);
	return ok;
}

static bool check_lock(csh handle, cs_mode mode)
{
	static const struct {
		uint8_t opcode;
		unsigned id;
	} arithmetic[] = { { 0x00, X86_INS_ADD }, { 0x08, X86_INS_OR },
			   { 0x10, X86_INS_ADC }, { 0x18, X86_INS_SBB },
			   { 0x20, X86_INS_AND }, { 0x28, X86_INS_SUB },
			   { 0x30, X86_INS_XOR } };
	static const struct {
		uint8_t bytes[3];
		size_t size;
	} prefixes[] = { { { 0xf0 }, 1 },	{ { 0x66, 0xf0 }, 2 },
			 { { 0x67, 0xf0 }, 2 }, { { 0x64, 0xf0 }, 2 },
			 { { 0xf2, 0xf0 }, 2 }, { { 0xf0, 0xf2 }, 2 },
			 { { 0xf3, 0xf0 }, 2 }, { { 0xf0, 0xf3 }, 2 } };
	static const struct {
		uint8_t bytes[5];
		size_t size;
		unsigned id;
	} forms[] = {
		{ { 0xf0, 0x89, 0x02 }, 3, X86_INS_INVALID },
		{ { 0xf0, 0x39, 0x02 }, 3, X86_INS_INVALID },
		{ { 0xf0, 0x0f, 0xa3, 0x02 }, 4, X86_INS_INVALID },
		{ { 0xf0, 0x90 }, 2, X86_INS_INVALID },
		{ { 0xf0, 0x0f, 0x1f, 0x00 }, 4, X86_INS_INVALID },
		{ { 0x66, 0xf0, 0x0f, 0x1f, 0x00 }, 5, X86_INS_INVALID },
		{ { 0xf0, 0x0f, 0xab, 0x02 }, 4, X86_INS_BTS },
		{ { 0xf0, 0x0f, 0xb3, 0x02 }, 4, X86_INS_BTR },
		{ { 0xf0, 0x0f, 0xbb, 0x02 }, 4, X86_INS_BTC },
		{ { 0xf0, 0x0f, 0xb1, 0x02 }, 4, X86_INS_CMPXCHG },
		{ { 0xf0, 0x0f, 0xc7, 0x0a }, 4, X86_INS_CMPXCHG8B },
		{ { 0xf0, 0x0f, 0xc1, 0x02 }, 4, X86_INS_XADD },
		{ { 0xf0, 0x87, 0x02 }, 3, X86_INS_XCHG },
		{ { 0xf0, 0xff, 0x02 }, 3, X86_INS_INC },
		{ { 0xf0, 0xff, 0x0a }, 3, X86_INS_DEC },
		{ { 0xf0, 0xf7, 0x12 }, 3, X86_INS_NOT },
		{ { 0xf0, 0xf7, 0x1a }, 3, X86_INS_NEG },
	};
	bool ok = true;
	for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); ++p)
		for (size_t a = 0;
		     a < sizeof(arithmetic) / sizeof(arithmetic[0]); ++a)
			for (unsigned form = 0; form != 4; ++form)
				for (unsigned reg = 0; reg != 2; ++reg) {
					uint8_t bytes[5];
					size_t n = prefixes[p].size;
					memcpy(bytes, prefixes[p].bytes, n);
					bytes[n++] =
						arithmetic[a].opcode + form;
					bytes[n++] = reg ? 0xc2 : 0x02;
					bool valid = form < 2 && !reg;
					ok &= decode(handle, bytes, n,
						     arithmetic[a].id,
						     valid ? n : 0);
				}
	for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i)
		ok &= decode(handle, forms[i].bytes, forms[i].size, forms[i].id,
			     forms[i].id ? forms[i].size : 0);
	if (mode == CS_MODE_64) {
		const uint8_t valid[] = { 0xf0, 0xd5, 0x58, 0x31, 0x02 };
		const uint8_t invalid[] = { 0xf0, 0xd5, 0x58, 0x33, 0x02 };
		const uint8_t wide[] = { 0xf0, 0x48, 0x0f, 0xc7, 0x0a };
		ok &= decode(handle, valid, sizeof(valid), X86_INS_XOR,
			     sizeof(valid));
		ok &= decode(handle, invalid, sizeof(invalid), X86_INS_INVALID,
			     0);
		ok &= decode(handle, wide, sizeof(wide), X86_INS_CMPXCHG16B,
			     sizeof(wide));
	}
	return ok;
}

static bool check_segments(csh handle, cs_mode mode)
{
	bool ok = true;
	const uint8_t prefixes[] = { 0x00, 0x66, 0x67, 0x48, 0x4c };
	for (size_t p = 0; p < sizeof(prefixes); ++p) {
		if (p >= 3 && mode != CS_MODE_64)
			continue;
		for (unsigned reg = 0; reg != 2; ++reg) {
			uint8_t bytes[3];
			size_t n = 0;
			if (prefixes[p])
				bytes[n++] = prefixes[p];
			bytes[n++] = 0x8e;
			bytes[n++] = reg ? 0xc8 : 0x0a;
			ok &= decode(handle, bytes, n, X86_INS_INVALID, 0);
			bytes[n - 2] = 0x8c;
			ok &= decode(handle, bytes, n, X86_INS_MOV, n);
			bytes[n - 2] = 0x8e;
			bytes[n - 1] = reg ? 0xe0 : 0x22;
			ok &= decode(handle, bytes, n, X86_INS_MOV, n);
		}
	}
	if (mode == CS_MODE_64) {
		uint8_t rex2[] = { 0xd5, 0x44, 0x8e, 0xc8 };
		ok &= decode(handle, rex2, sizeof(rex2), X86_INS_INVALID, 0);
		rex2[2] = 0x8c;
		ok &= decode(handle, rex2, sizeof(rex2), X86_INS_MOV,
			     sizeof(rex2));
	}
	return ok;
}

struct ud1_case {
	cs_mode mode;
	uint8_t bytes[16];
	size_t size;
	uint8_t address_size, modrm_offset, disp_offset, disp_size;
	x86_reg reg, base, index;
	int scale;
	int64_t displacement;
};

static bool check_ud1(csh handle, const struct ud1_case *test, unsigned syntax,
		      bool detail, bool text)
{
	bool ok = true;
	cs_insn *insn = NULL;
	uint8_t stream[17];
	for (size_t n = 0; n < test->size; ++n)
		ok &= decode(handle, test->bytes, n, X86_INS_INVALID, 0);
	memcpy(stream, test->bytes, test->size);
	stream[test->size] = 0x90;
	ok &= decode(handle, stream, test->size + 1, X86_INS_UD1, test->size);
	size_t count =
		cs_disasm(handle, stream, test->size + 1, 0x1000, 0, &insn);
	ok &= count == 2 && insn[0].id == X86_INS_UD1 &&
	      insn[1].id == X86_INS_NOP &&
	      insn[1].address == 0x1000 + test->size;
	if (count && detail && text && !cs_support(CS_SUPPORT_DIET)) {
		const cs_x86 *x = &insn[0].detail->x86;
		bool memory = (test->bytes[test->modrm_offset] >> 6) != 3;
		unsigned first = syntax == CS_OPT_SYNTAX_ATT ? 1 : 0;
		const cs_x86_op *reg = &x->operands[first];
		const cs_x86_op *rm = &x->operands[1 - first];
		ok &= x->op_count == 2 && reg->type == X86_OP_REG &&
		      reg->reg == test->reg && reg->size == 4 &&
		      rm->size == 4 && x->addr_size == test->address_size &&
		      x->modrm == test->bytes[test->modrm_offset] &&
		      x->encoding.modrm_offset == test->modrm_offset &&
		      x->encoding.disp_offset == test->disp_offset &&
		      x->encoding.disp_size == test->disp_size &&
		      x->disp == test->displacement && !x->encoding.imm_size &&
		      !x->encoding.imm_offset;
		if (memory)
			ok &= rm->type == X86_OP_MEM &&
			      rm->mem.base == test->base &&
			      rm->mem.index == test->index &&
			      rm->mem.scale == test->scale &&
			      rm->mem.disp == test->displacement;
		else
			ok &= rm->type == X86_OP_REG && rm->reg == test->base;
		if (!cs_support(CS_SUPPORT_DIET)) {
			cs_regs reads, writes;
			uint8_t read_count = 0, write_count = 0;
			ok &= reg->access == CS_AC_READ &&
			      rm->access == CS_AC_READ && x->eflags == 0 &&
			      cs_regs_access(handle, &insn[0], reads,
					     &read_count, writes,
					     &write_count) == CS_ERR_OK &&
			      read_count > 0 && write_count == 0 &&
			      strcmp(insn[0].mnemonic, "ud1") == 0 &&
			      insn[0].op_str[0] != '\0';
		}
	}
	cs_free(insn, count);
	if (!ok)
		fprintf(stderr,
			"UD1 detail/boundary: mode=%u size=%zu syntax=%u detail=%d text=%d\n",
			(unsigned)test->mode, test->size, syntax, detail, text);
	return ok;
}

int main(void)
{
	/* UD1's encoded operands are r32/rm32 even with 66 or REX.W.  The
	 * address-size prefix still selects the complete addressing extent. */
	static const struct ud1_case ud1[] = {
		{ CS_MODE_16,
		  { 0x0f, 0xb9, 0xc1 },
		  3,
		  2,
		  2,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_32,
		  { 0x0f, 0xb9, 0xc1 },
		  3,
		  4,
		  2,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0xc1 },
		  3,
		  8,
		  2,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_16,
		  { 0x0f, 0xb9, 0x06, 0x34, 0x12 },
		  5,
		  2,
		  2,
		  3,
		  2,
		  X86_REG_EAX,
		  0,
		  0,
		  1,
		  0x1234 },
		{ CS_MODE_32,
		  { 0x67, 0x0f, 0xb9, 0x46, 0x80 },
		  5,
		  2,
		  3,
		  4,
		  1,
		  X86_REG_EAX,
		  X86_REG_BP,
		  0,
		  1,
		  -128 },
		{ CS_MODE_32,
		  { 0x67, 0x0f, 0xb9, 0x86, 0x34, 0x92 },
		  6,
		  2,
		  3,
		  4,
		  2,
		  X86_REG_EAX,
		  X86_REG_BP,
		  0,
		  1,
		  -28108 },
		{ CS_MODE_16,
		  { 0x67, 0x0f, 0xb9, 0x4c, 0x9a, 0x80 },
		  6,
		  4,
		  3,
		  5,
		  1,
		  X86_REG_ECX,
		  X86_REG_EDX,
		  X86_REG_EBX,
		  4,
		  -128 },
		{ CS_MODE_32,
		  { 0x0f, 0xb9, 0x4c, 0x9a, 0x80 },
		  5,
		  4,
		  2,
		  4,
		  1,
		  X86_REG_ECX,
		  X86_REG_EDX,
		  X86_REG_EBX,
		  4,
		  -128 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0x4c, 0x9a, 0x80 },
		  5,
		  8,
		  2,
		  4,
		  1,
		  X86_REG_ECX,
		  X86_REG_RDX,
		  X86_REG_RBX,
		  4,
		  -128 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0x9c, 0xf6, 0xdd, 0xcc, 0xbb, 0xaa },
		  8,
		  8,
		  2,
		  4,
		  4,
		  X86_REG_EBX,
		  X86_REG_RSI,
		  X86_REG_RSI,
		  8,
		  -1430532899 },
		{ CS_MODE_64,
		  { 0x66, 0x0f, 0xb9, 0x9c, 0xf6, 0xdd, 0xcc, 0xbb, 0xaa },
		  9,
		  8,
		  3,
		  5,
		  4,
		  X86_REG_EBX,
		  X86_REG_RSI,
		  X86_REG_RSI,
		  8,
		  -1430532899 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0x05, 1, 2, 3, 4 },
		  7,
		  8,
		  2,
		  3,
		  4,
		  X86_REG_EAX,
		  X86_REG_RIP,
		  0,
		  1,
		  0x04030201 },
		{ CS_MODE_64,
		  { 0x67, 0x0f, 0xb9, 0x05, 1, 2, 3, 4 },
		  8,
		  4,
		  3,
		  4,
		  4,
		  X86_REG_EAX,
		  X86_REG_EIP,
		  0,
		  1,
		  0x04030201 },
		{ CS_MODE_64,
		  { 0x0f, 0xb9, 0x04, 0x25, 1, 2, 3, 4 },
		  8,
		  8,
		  2,
		  4,
		  4,
		  X86_REG_EAX,
		  0,
		  0,
		  1,
		  0x04030201 },
		{ CS_MODE_64,
		  { 0x66, 0x0f, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0x48, 0x0f, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0xd5, 0x80, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0xd5, 0xc0, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_R16D,
		  X86_REG_ECX,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0xd5, 0x98, 0xb9, 0xc1 },
		  4,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_R17D,
		  0,
		  0,
		  0 },
		{ CS_MODE_64,
		  { 0xd5, 0xa0, 0xb9, 0x04, 0x50 },
		  5,
		  8,
		  3,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_RAX,
		  X86_REG_R18,
		  2,
		  0 },
		{ CS_MODE_64,
		  { 0x67, 0xd5, 0xa0, 0xb9, 0x04, 0x50 },
		  6,
		  4,
		  4,
		  0,
		  0,
		  X86_REG_EAX,
		  X86_REG_EAX,
		  X86_REG_R18D,
		  2,
		  0 },
	};
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	const unsigned syntaxes[] = { CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT };
	bool ok = true;
	for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m)
		for (size_t s = 0; s < sizeof(syntaxes) / sizeof(syntaxes[0]);
		     ++s)
			for (unsigned detail = 0; detail != 2; ++detail)
				for (unsigned text = 0; text != 2; ++text) {
					csh handle;
					if (cs_open(CS_ARCH_X86, modes[m],
						    &handle) != CS_ERR_OK)
						return 1;
					cs_err err = cs_option(handle,
							       CS_OPT_SYNTAX,
							       syntaxes[s]);
					if (syntaxes[s] == CS_OPT_SYNTAX_ATT &&
					    (err == CS_ERR_X86_ATT ||
					     err == CS_ERR_DIET)) {
						cs_close(&handle);
						continue;
					}
					ok &= err == CS_ERR_OK;
					ok &= cs_option(handle, CS_OPT_DETAIL,
							detail) == CS_ERR_OK;
					ok &= cs_option(handle, CS_OPT_TEXT,
							text) == CS_ERR_OK;
					ok &= check_lock(handle, modes[m]);
					ok &= check_segments(handle, modes[m]);
					const uint8_t ud0[] = { 0x0f, 0xff };
					const uint8_t ud2[] = { 0x0f, 0x0b };
					ok &= decode(handle, ud0, sizeof(ud0),
						     X86_INS_UD0, 2);
					ok &= decode(handle, ud2, sizeof(ud2),
						     X86_INS_UD2, 2);
					for (size_t i = 0;
					     i < sizeof(ud1) / sizeof(ud1[0]);
					     ++i)
						if (ud1[i].mode == modes[m])
							ok &= check_ud1(
								handle, &ud1[i],
								syntaxes[s],
								detail, text);
					uint8_t maximum[16];
					memset(maximum, 0x66, sizeof(maximum));
					memcpy(maximum + 12, "\x0f\xb9\xc0", 3);
					ok &= decode(handle, maximum, 15,
						     X86_INS_UD1, 15);
					memcpy(maximum + 13, "\x0f\xb9\xc0", 3);
					maximum[12] = 0x66;
					ok &= decode(handle, maximum, 16,
						     X86_INS_INVALID, 0);
					cs_close(&handle);
				}
	return ok ? 0 : 1;
}

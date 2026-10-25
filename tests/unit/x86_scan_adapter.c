/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <string.h>
#include "../../arch/X86/X86ScanAdapter.h"

typedef struct {
	unsigned calls;
	uint32_t result;
} adapter_state;

static uint32_t scan(void *opaque, const uint8_t *code, size_t size)
{
	(void)code;
	(void)size;
	adapter_state *state = opaque;
	++state->calls;
	return state->result;
}

#define CHECK(condition) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "line %u: %s\n", __LINE__, \
				#condition); \
			return 1; \
		} \
	} while (0)

int main(void)
{
	static const uint8_t code[] = { 0x62, 0xf1, 0x7c, 0x48, 0x28, 0x00 };
	csh handle = 0;
	CHECK(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK);
	adapter_state state = { 0, (X86_INS_VMOVAPS << 8) | sizeof(code) };
	CHECK(!X86_setScanAdapter(0, CS_MODE_64, scan, &state));
	CHECK(!X86_setScanAdapter(handle, CS_MODE_32, scan, &state));
	CHECK(X86_setScanAdapter(handle, CS_MODE_64, scan, &state));
	cs_insn *insn = cs_malloc(handle);
	CHECK(insn);
	/* Text/detail gates precede adapter dispatch. */
	for (unsigned detail = 0; detail < 2; ++detail) {
		cs_free(insn, 1);
		CHECK(cs_option(handle, CS_OPT_DETAIL,
				detail ? CS_OPT_ON : CS_OPT_OFF) == CS_ERR_OK);
		insn = cs_malloc(handle);
		CHECK(insn);
		for (unsigned text = 0; text < 2; ++text) {
			CHECK(cs_option(handle, CS_OPT_TEXT,
					text ? CS_OPT_ON : CS_OPT_OFF) ==
			      CS_ERR_OK);
			state.calls = 0;
			const uint8_t *p = code;
			size_t left = sizeof(code);
			uint64_t address = 0x1000;
			CHECK(cs_disasm_iter(handle, &p, &left, &address,
					     insn));
			CHECK(state.calls == (!detail && !text));
			CHECK(insn->id == X86_INS_VMOVAPS &&
			      insn->size == sizeof(code));
			CHECK(p == code + sizeof(code) && !left &&
			      address == 0x1000 + sizeof(code));
			CHECK(!memcmp(insn->bytes, code, sizeof(code)));
		}
	}
	CHECK(cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF) == CS_ERR_OK);
	CHECK(cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF) == CS_ERR_OK);
	/* Empty/invalid adapter output retains the normal decoder. */
	const uint32_t results[] = { 0,
				     X86_INS_VMOVAPS << 8,
				     (X86_INS_VMOVAPS << 8) | 16,
				     (X86_INS_VMOVAPS << 8) | 7,
				     (X86_INS_ENDING << 8) | 6,
				     6,
				     (X86_INS_VMOVAPS << 8) | sizeof(code) };
	for (unsigned i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
		state.result = results[i];
		state.calls = 0;
		cs_insn *batch = NULL;
		CHECK(cs_disasm(handle, code, sizeof(code), 0x1000, 1,
				&batch) == 1);
		CHECK(state.calls == 1);
		CHECK(batch->id == X86_INS_VMOVAPS &&
		      batch->size == sizeof(code));
		CHECK(!batch->mnemonic[0] && !batch->op_str[0]);
		cs_free(batch, 1);
	}
	/* Changing bitness disables the old profile until explicitly rebound. */
	CHECK(cs_option(handle, CS_OPT_MODE, CS_MODE_32) == CS_ERR_OK);
	state.calls = 0;
	cs_insn *batch = NULL;
	CHECK(cs_disasm(handle, code, sizeof(code), 0, 1, &batch) == 1);
	CHECK(!state.calls);
	cs_free(batch, 1);
	CHECK(X86_setScanAdapter(handle, CS_MODE_32, scan, &state));
	/* A compact scalar instruction never calls the registered adapter. */
	const uint8_t nop = 0x90;
	CHECK(cs_disasm(handle, &nop, 1, 0, 1, &batch) == 1);
	CHECK(!state.calls && batch->id == X86_INS_NOP);
	cs_free(batch, 1);
	CHECK(X86_setScanAdapter(handle, 0, NULL, NULL));
	CHECK(cs_disasm(handle, code, sizeof(code), 0, 1, &batch) == 1);
	CHECK(!state.calls);
	cs_free(batch, 1);
	cs_free(insn, 1);
	CHECK(cs_close(&handle) == CS_ERR_OK);
	return 0;
}

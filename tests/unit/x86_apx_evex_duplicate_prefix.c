#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool rejects(csh handle, const uint8_t *code, size_t size)
{
	cs_insn *instruction = NULL;
	bool rejected = cs_disasm(handle, code, size, 0, 1, &instruction) == 0;
	if (instruction)
		cs_free(instruction, 1);
	return rejected;
}

static bool decodes(csh handle, const uint8_t *code, size_t size,
		    uint16_t length, const char *text)
{
	cs_insn *instruction = NULL;
	size_t count = cs_disasm(handle, code, size, 0, 1, &instruction);
	char actual[sizeof(instruction->mnemonic) + sizeof(instruction->op_str)] = "";
	bool ok;

	if (count == 1)
		snprintf(actual, sizeof(actual), "%s %s", instruction->mnemonic,
			 instruction->op_str);
	ok = count == 1 && instruction->size == length &&
	     strcmp(actual, text) == 0;
	if (!ok)
		fprintf(stderr, "decoded as \"%s\", expected \"%s\"\n", actual,
			text);
	cs_free(instruction, count);
	return ok;
}

int main(void)
{
	// Representative memory-RMW, conditional, ordinary promoted ALU/BMI,
	// load-hint, and privileged decode-only topologies.  The common feature
	// entry must reject duplicates before any family can normalize them.
	static const uint8_t cases[][16] = {
		{ 0x64, 0x65, 0x62, 0x0c, 0x7c, 0x08, 0xfc, 0x54, 0xb5, 0x20 },
		{ 0x67, 0x67, 0x62, 0x0a, 0x75, 0x00, 0xe0, 0x54, 0xb5, 0x20 },
		{ 0x64, 0x65, 0x62, 0x6c, 0x2c, 0x02, 0x39, 0x11 },
		{ 0x67, 0x67, 0x62, 0xea, 0xf4, 0x00, 0xf2, 0xd3 },
		{ 0x64, 0x65, 0x62, 0xec, 0x7c, 0x08, 0x8b, 0x11 },
		{ 0x67, 0x67, 0x62, 0xec, 0x7e, 0x08, 0xf0, 0x11 },
		{ 0x64, 0x65, 0xd5, 0x5d, 0x01, 0xc7 },
		{ 0x67, 0x67, 0xd5, 0x00, 0xa1, 0x11, 0x22, 0x33, 0x44, 0x55,
		  0x66, 0x77, 0x88 },
	};
	static const size_t sizes[] = { 10, 10, 8, 8, 8, 8, 6, 13 };
	csh handle;
	bool ok = true;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
		ok &= rejects(handle, cases[i], sizes[i]);

	/* Legacy instructions keep the generated decoder's reading of repeated
	 * prefixes, also when the byte after their opcode has the value of an
	 * EVEX or REX2 escape, and the last FS or GS override takes effect, as
	 * in XED. */
	{
		static const uint8_t mov_cs_cs[] = { 0x2e, 0x2e, 0x8b, 0xd5 };
		static const uint8_t mov_addr32_addr32[] = { 0x67, 0x67, 0x8b,
							     0xd5 };
		static const uint8_t add_es_es[] = { 0x26, 0x26, 0x00, 0x62,
						     0xf4, 0x7c, 0x08, 0x80,
						     0xd1, 0x05 };
		static const uint8_t add_fs_gs[] = { 0x64, 0x65, 0x00, 0x62,
						     0xf4 };
		static const uint8_t mov_gs_fs[] = { 0x65, 0x64, 0x8b, 0x00 };
		static const uint8_t mov_gs_cs[] = { 0x65, 0x2e, 0x8b, 0x00 };

		ok &= decodes(handle, mov_cs_cs, sizeof(mov_cs_cs), 4,
			      "mov edx, ebp");
		ok &= decodes(handle, mov_addr32_addr32,
			      sizeof(mov_addr32_addr32), 4, "mov edx, ebp");
		ok &= decodes(handle, add_es_es, sizeof(add_es_es), 5,
			      "add byte ptr [rdx - 0xc], ah");
		ok &= decodes(handle, add_fs_gs, sizeof(add_fs_gs), 5,
			      "add byte ptr gs:[rdx - 0xc], ah");
		ok &= decodes(handle, mov_gs_fs, sizeof(mov_gs_fs), 4,
			      "mov eax, dword ptr fs:[rax]");
		ok &= decodes(handle, mov_gs_cs, sizeof(mov_gs_cs), 4,
			      "mov eax, dword ptr gs:[rax]");
	}
	cs_close(&handle);
	if (!ok)
		fprintf(stderr, "APX duplicate-prefix rejection failure\n");
	return ok ? 0 : 1;
}

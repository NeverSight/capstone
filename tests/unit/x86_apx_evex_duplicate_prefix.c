#include <capstone/capstone.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static bool rejects(csh handle, const uint8_t *code, size_t size)
{
	cs_insn *instruction = NULL;
	bool rejected = cs_disasm(handle, code, size, 0, 1, &instruction) == 0;
	if (instruction)
		cs_free(instruction, 1);
	return rejected;
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
	cs_close(&handle);
	if (!ok)
		fprintf(stderr, "APX duplicate-prefix rejection failure\n");
	return ok ? 0 : 1;
}

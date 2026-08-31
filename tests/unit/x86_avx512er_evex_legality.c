#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>

static bool decoded(csh h, uint8_t opcode, uint8_t p2, uint8_t modrm,
		    cs_insn **insn)
{
	uint8_t code[] = { 0x62, 0xf2, 0x7d, p2, opcode, modrm };
	if (opcode == 0xcb || opcode == 0xcd)
		code[2] = 0x4d;
	return cs_disasm(h, code, sizeof(code), 0, 1, insn) == 1;
}

int main(void)
{
	static const uint8_t packed[] = { 0xc8, 0xca, 0xcc };
	static const uint8_t scalar[] = { 0xcb, 0xcd };
	csh h;
	cs_insn *insn = NULL;
	bool ok = true;
	unsigned i, ll, b, memory;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK)
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	for (i = 0; i < sizeof(packed); ++i)
		for (memory = 0; memory < 2; ++memory)
			for (b = 0; b < 2; ++b)
				for (ll = 0; ll < 4; ++ll) {
					const bool valid =
						b && !memory ? true : ll == 2;
					const uint8_t p2 = 8 | (b << 4) |
							   (ll << 5);
					const bool got = decoded(
						h, packed[i], p2,
						memory ? 8 : 0xca, &insn);
					ok &= got == valid;
					if (insn) {
						const cs_x86 *x =
							&insn->detail->x86;
						if (got && b)
							ok &= memory ?
								      x->operands[x->op_count -
										  1]
										      .avx_bcast !=
									      X86_AVX_BCAST_INVALID :
								      x->avx_sae;
						cs_free(insn, 1);
						insn = NULL;
					}
				}
	for (i = 0; i < sizeof(scalar); ++i)
		for (memory = 0; memory < 2; ++memory)
			for (b = 0; b < 2; ++b)
				for (ll = 0; ll < 4; ++ll) {
					const bool valid =
						memory ? !b && ll < 3 :
						b      ? true :
							 ll < 3;
					const uint8_t p2 = 8 | (b << 4) |
							   (ll << 5);
					const bool got = decoded(
						h, scalar[i], p2,
						memory ? 0x28 : 0xef, &insn);
					ok &= got == valid;
					if (insn) {
						if (got && b)
							ok &= insn->detail->x86
								      .avx_sae;
						cs_free(insn, 1);
						insn = NULL;
					}
				}
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "AVX512ER EVEX legality/detail mismatch\n");
	return ok ? 0 : 1;
}

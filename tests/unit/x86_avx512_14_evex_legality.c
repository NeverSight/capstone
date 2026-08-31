#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
int main(void)
{
	static const uint8_t ops[] = { 0x4c, 0x4d, 0x4e, 0x4f };
	csh h;
	cs_insn *i = NULL;
	bool ok = true;
	unsigned o, w, m, b, ll;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK)
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	for (o = 0; o < 4; o++)
		for (w = 0; w < 2; w++)
			for (m = 0; m < 2; m++)
				for (b = 0; b < 2; b++)
					for (ll = 0; ll < 4; ll++) {
						uint8_t c[] = {
							0x62,
							0xf2,
							(uint8_t)(0x7d |
								  (w << 7)),
							(uint8_t)(8 | (b << 4) |
								  (ll << 5)),
							ops[o],
							(uint8_t)(m ? 8 : 0xca)
						};
						bool scalar = (ops[o] & 1) != 0,
						     valid = ll < 3 &&
							     (!b ||
							      (m && !scalar));
						bool got = cs_disasm(h, c, 6, 0,
								     1,
								     &i) == 1;
						ok &= got == valid;
						if (i) {
							if (got && b)
								ok &= i->detail
									      ->x86
									      .operands
										      [i->detail
											       ->x86
											       .op_count -
										       1]
									      .avx_bcast !=
								      X86_AVX_BCAST_INVALID;
							cs_free(i, 1);
							i = NULL;
						}
					}
	cs_close(&h);
	if (!ok)
		fprintf(stderr, "EVEX 14 legality/detail mismatch\n");
	return ok ? 0 : 1;
}

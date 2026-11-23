/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <string.h>

int main(void)
{
	static const unsigned ids[] = {
		RISCV_INS_AUIPC, RISCV_INS_LUI, RISCV_INS_JAL,
	};
	static const uint8_t majors[] = { 0x17, 0x37, 0x6f };
	csh h;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &h) != CS_ERR_OK)
		return 1;
	cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn *insn = cs_malloc(h);
	if (!insn)
		return 1;
	unsigned ok = 1;
	for (unsigned phase = 0; phase < 4 && ok; ++phase) {
		const bool scan = phase == 0 || phase == 2;
		cs_option(h, CS_OPT_TEXT, scan ? CS_OPT_OFF : CS_OPT_ON);
		cs_option(h, CS_OPT_DETAIL, scan ? CS_OPT_OFF : CS_OPT_ON);
		for (unsigned e = 0; e < 2; ++e) {
			cs_option(h, CS_OPT_MODE, CS_MODE_RISCV64 |
							(e ? CS_MODE_RISCV_E : 0));
			for (unsigned m = 0; m < 3; ++m) {
				for (unsigned reg = 0; reg < 32; ++reg) {
					const uint8_t raw[] = {
						(uint8_t)(majors[m] | (reg << 7)),
						(uint8_t)(0xc0 | (reg >> 1)),
						0x81, 0xfe,
					};
					const uint8_t *p = raw;
					size_t n = sizeof(raw);
					uint64_t ip = 0x1000;
					const bool valid = !e || reg < 16;
					const bool got =
						cs_disasm_iter(h, &p, &n, &ip, insn);
					if (got != valid ||
					    (got && (insn->id != ids[m] || n ||
						     p != raw + 4 || ip != 0x1004 ||
						     memcmp(insn->bytes, raw, 4))))
						ok = 0;
#ifndef CAPSTONE_DIET
					if (got && !scan && !insn->mnemonic[0])
						ok = 0;
#endif
				}
			}
		}
	}
	cs_free(insn, 1);
	cs_close(&h);
	return ok ? 0 : 1;
}

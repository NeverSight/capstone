/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <string.h>

/* Disable the scan specialization on the reference handle by requesting
 * detail. Compare instruction identity and boundaries for every halfword. */
static bool checkCompressed(cs_mode mode)
{
	csh scan, reference;
	if (cs_open(CS_ARCH_RISCV, mode, &scan) != CS_ERR_OK)
		return false;
	if (cs_open(CS_ARCH_RISCV, mode, &reference) != CS_ERR_OK) {
		cs_close(&scan);
		return false;
	}
	cs_option(scan, CS_OPT_TEXT, CS_OPT_OFF);
	cs_option(reference, CS_OPT_TEXT, CS_OPT_OFF);
	cs_option(reference, CS_OPT_DETAIL, CS_OPT_ON);
	cs_insn *a = cs_malloc(scan), *b = cs_malloc(reference);
	bool ok = a && b;
	for (unsigned bits = 0; ok && bits <= UINT16_MAX; ++bits) {
		if ((bits & 3) == 3)
			continue;
		const uint8_t raw[] = { (uint8_t)bits, (uint8_t)(bits >> 8) };
		const uint8_t *p = raw, *q = raw;
		size_t n = 2, m = 2;
		uint64_t pc = 0xfffe, ip = pc;
		const bool x = cs_disasm_iter(scan, &p, &n, &pc, a);
		const bool y = cs_disasm_iter(reference, &q, &m, &ip, b);
		ok = x == y && n == m && p == q && pc == ip &&
		     (!x || (a->id == b->id && a->size == b->size &&
			     memcmp(a->bytes, b->bytes, 2) == 0));
	}
	if (a)
		cs_free(a, 1);
	if (b)
		cs_free(b, 1);
	cs_close(&scan);
	cs_close(&reference);
	return ok;
}

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
	const unsigned extensions = CS_MODE_RISCV_C | CS_MODE_RISCV_FD |
				    CS_MODE_RISCV_ZICFISS | CS_MODE_RISCV_ZCMP_ZCMT_ZCE;
	ok &= checkCompressed((cs_mode)(CS_MODE_RISCV32 | extensions));
	ok &= checkCompressed((cs_mode)(CS_MODE_RISCV64 | extensions));
	cs_free(insn, 1);
	cs_close(&h);
	return ok ? 0 : 1;
}

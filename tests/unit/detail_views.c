/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

struct sample {
	cs_arch arch;
	cs_mode mode;
	uint8_t bytes[4];
	size_t length;
};

static bool decode_view(csh handle, const struct sample *sample,
			size_t flags, cs_insn *insn, cs_detail *detail)
{
	const uint8_t *code = sample->bytes;
	size_t size = sample->length;
	uint64_t address = 0x1000;

	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF) != CS_ERR_OK ||
	    cs_option(handle, CS_OPT_DETAIL, flags) != CS_ERR_OK)
		return false;
	memset(insn, 0, sizeof(*insn));
	memset(detail, 0, sizeof(*detail));
	insn->detail = detail;
	return cs_disasm_iter(handle, &code, &size, &address, insn) &&
	       size == 0 && address == 0x1000 + sample->length;
}

int main(void)
{
	static const struct sample samples[] = {
		{ CS_ARCH_ARM, CS_MODE_ARM, { 0x10, 0x40, 0x2d, 0xe9 }, 4 },
		{ CS_ARCH_ARM, CS_MODE_THUMB, { 0x10, 0xb5 }, 2 },
		{ CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN,
		  { 0xe0, 0x03, 0x01, 0xaa }, 4 },
		{ CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN,
		  { 0x7c, 0x64, 0x1b, 0x78 }, 4 },
		{ CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV_C,
		  { 0x85, 0x00 }, 2 },
	};
	static const cs_opt_value views[] = { CS_OPT_DETAIL_REAL,
					      CS_OPT_DETAIL_UNCOMPRESSED_REAL,
					      CS_OPT_DETAIL_ALIAS };
	for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
		const struct sample *sample = &samples[i];
		if (!cs_support(sample->arch))
			continue;
		csh handle;
		if (cs_open(sample->arch, sample->mode, &handle) != CS_ERR_OK)
			return 1;
		for (size_t j = 0; j < sizeof(views) / sizeof(views[0]); ++j) {
			cs_insn implicit, explicit_on;
			cs_detail first, second;
			bool ok = decode_view(handle, sample, views[j],
					      &implicit, &first) &&
				  decode_view(handle, sample, views[j] | CS_OPT_ON,
					      &explicit_on, &second);
			if (!ok || implicit.id != explicit_on.id ||
			    implicit.alias_id != explicit_on.alias_id ||
			    implicit.usesAliasDetails != explicit_on.usesAliasDetails ||
			    strcmp(implicit.mnemonic, explicit_on.mnemonic) ||
			    strcmp(implicit.op_str, explicit_on.op_str) ||
			    memcmp(&first, &second, sizeof(first))) {
				fprintf(stderr, "detail view %u differs on architecture %u, mode %u\n",
					(unsigned)views[j], (unsigned)sample->arch,
					(unsigned)sample->mode);
				cs_close(&handle);
				return 1;
			}
		}
		cs_close(&handle);
	}
	return 0;
}

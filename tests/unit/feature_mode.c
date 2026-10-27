/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>

struct FeatureCase {
	cs_arch arch;
	cs_mode mode;
	cs_mode feature;
	unsigned int id;
	uint8_t bytes[4];
};

static const struct FeatureCase cases[] = {
	{ CS_ARCH_AARCH64,
	  CS_MODE_BIG_ENDIAN,
	  CS_MODE_APPLE_PROPRIETARY,
	  AARCH64_INS_LDX,
	  { 0x00, 0x20, 0x10, 0x00 } },
	{ CS_ARCH_ARM,
	  CS_MODE_ARM,
	  CS_MODE_V8,
	  ARM_INS_CRC32B,
	  { 0x42, 0x00, 0x01, 0xe1 } },
	{ CS_ARCH_ARM,
	  CS_MODE_THUMB,
	  CS_MODE_V8,
	  ARM_INS_CRC32B,
	  { 0xc1, 0xfa, 0x82, 0xf0 } },
	{ CS_ARCH_RISCV,
	  CS_MODE_RISCV32,
	  CS_MODE_RISCV_FD,
	  RISCV_INS_FADD_S,
	  { 0x53, 0xfd, 0xcd, 0x01 } },
	{ CS_ARCH_RISCV,
	  CS_MODE_RISCV64,
	  CS_MODE_RISCV_FD,
	  RISCV_INS_FADD_S,
	  { 0x53, 0xfd, 0xcd, 0x01 } },
	{ CS_ARCH_RISCV,
	  CS_MODE_RISCV32,
	  CS_MODE_RISCV_A,
	  RISCV_INS_AMOSWAP_W,
	  { 0x2f, 0x27, 0x14, 0x08 } },
};

int main(void)
{
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		const struct FeatureCase *test = &cases[i];
		if (!cs_support(test->arch))
			continue;
		for (unsigned output = 0; output < 4; ++output) {
			csh handle;
			if (cs_open(test->arch, test->mode, &handle) !=
			    CS_ERR_OK)
				return 1;
			cs_option(handle, CS_OPT_TEXT,
				  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
			cs_option(handle, CS_OPT_DETAIL,
				  output & 2 ? CS_OPT_ON : CS_OPT_OFF);
			cs_insn *insn = cs_malloc(handle);
			if (!insn)
				return 1;
			// RISC-V replaces its mode; ARM backends currently add mode bits.
			// Reopen those handles to test a disabled feature again.
			for (unsigned attempt = 0; attempt < 4; ++attempt) {
				if (attempt == 2 &&
				    test->arch != CS_ARCH_RISCV) {
					cs_free(insn, 1);
					cs_close(&handle);
					if (cs_open(test->arch, test->mode,
						    &handle) != CS_ERR_OK)
						return 1;
					cs_option(handle, CS_OPT_TEXT,
						  output & 1 ? CS_OPT_ON :
							       CS_OPT_OFF);
					cs_option(handle, CS_OPT_DETAIL,
						  output & 2 ? CS_OPT_ON :
							       CS_OPT_OFF);
					insn = cs_malloc(handle);
					if (!insn)
						return 1;
				}
				bool enabled = (attempt & 1) != 0;
				cs_mode mode = test->mode |
					       (enabled ? test->feature : 0);
				if (cs_option(handle, CS_OPT_MODE, mode) !=
				    CS_ERR_OK)
					return 1;
				const uint8_t *code = test->bytes;
				size_t size = sizeof(test->bytes);
				uint64_t address = 0x1000;
				bool decoded = cs_disasm_iter(
					handle, &code, &size, &address, insn);
				if (decoded != enabled ||
				    (decoded &&
				     (insn->id != test->id || size != 0 ||
				      address != 0x1004)) ||
				    (!decoded &&
				     (code != test->bytes || size != 4 ||
				      address != 0x1000))) {
					fprintf(stderr,
						"feature mode case %zu output %u attempt %u failed\n",
						i, output, attempt);
					return 1;
				}
			}
			cs_free(insn, 1);
			cs_close(&handle);
		}
	}
	return 0;
}

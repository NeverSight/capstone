/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static bool check_implicit_copies(csh handle)
{
	for (unsigned reads = 0; reads <= MAX_IMPL_R_REGS; ++reads) {
		for (unsigned writes = 0; writes <= MAX_IMPL_W_REGS; ++writes) {
			for (unsigned overlap = 0; overlap < 3; ++overlap) {
				cs_detail detail = { 0 }, before;
				cs_insn insn = { 0 };
				insn.id = X86_INS_MOV;
				insn.detail = &detail;
				detail.regs_read_count = reads;
				detail.regs_write_count = writes;
				for (unsigned i = 0; i < reads; ++i)
					detail.regs_read[i] =
						(uint16_t)(i * 73 + 1);
				for (unsigned i = 0; i < writes; ++i)
					detail.regs_write[i] =
						(uint16_t)(65535 - i * 91);
				memcpy(&before, &detail, sizeof(detail));
				uint16_t actual[129], expected[129];
				memset(actual, 0xa5, sizeof(actual));
				memcpy(expected, actual, sizeof(actual));
				size_t write_offset =
					overlap == 0 ? 64 : overlap - 1;
				for (unsigned i = 0; i < reads; ++i)
					expected[i] = detail.regs_read[i];
				for (unsigned i = 0; i < writes; ++i)
					expected[write_offset + i] =
						detail.regs_write[i];
				uint8_t read_count = 0xa5, write_count = 0xa5;
				if (cs_regs_access(handle, &insn, actual,
						   &read_count,
						   actual + write_offset,
						   &write_count) != CS_ERR_OK ||
				    read_count != reads ||
				    write_count != writes ||
				    memcmp(actual, expected, sizeof(actual)) ||
				    memcmp(&detail, &before, sizeof(detail))) {
					fprintf(stderr,
						"implicit register copy: read=%u write=%u overlap=%u\n",
						reads, writes, overlap);
					return false;
				}
			}
		}
	}
	return true;
}

int main(void)
{
	if (cs_support(CS_SUPPORT_DIET))
		return 0;
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		cs_close(&handle);
		return 1;
	}
	bool success = check_implicit_copies(handle);
	cs_close(&handle);
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>

static bool check(csh handle, bool big)
{
	cs_insn *insn = cs_malloc(handle);
	if (!insn)
		return false;
	bool ok = true;
	for (unsigned n = 8; ok && n < 32; ++n) {
		for (unsigned read = 0; read < 2; ++read) {
			uint32_t word = read ? 0x787e0099u | (n << 11) :
					       0x783e2819u | (n << 6);
			uint8_t bytes[4];
			for (unsigned i = 0; i < 4; ++i)
				bytes[i] = word >> (8 * (big ? 3 - i : i));
			const uint8_t *cursor = bytes;
			size_t left = sizeof(bytes);
			uint64_t pc = 0x1000;
			if (!cs_disasm_iter(handle, &cursor, &left, &pc,
					    insn) ||
			    left || pc != 0x1004 || insn->size != 4 ||
			    insn->id != (read ? MIPS_INS_CFCMSA :
						MIPS_INS_CTCMSA)) {
				ok = false;
				break;
			}
			const cs_mips *detail = &insn->detail->mips;
			const cs_mips_op *op = &detail->operands[read];
			if (detail->op_count != 2 || op->type != MIPS_OP_REG ||
			    op->reg != MIPS_REG_MSA8 + n - 8) {
				ok = false;
				break;
			}
		}
	}
	cs_free(insn, 1);
	return ok;
}

int main(void)
{
	for (unsigned big = 0; big < 2; ++big) {
		csh handle;
		if (cs_open(CS_ARCH_MIPS,
			    CS_MODE_MIPS32R5 | (big ? CS_MODE_BIG_ENDIAN :
						      CS_MODE_LITTLE_ENDIAN),
			    &handle))
			return 1;
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		bool ok = check(handle, big);
		cs_close(&handle);
		if (!ok) {
			fprintf(stderr,
				"failed to decode reserved MSA control register (big=%u)\n",
				big);
			return 1;
		}
	}
	return 0;
}

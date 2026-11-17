/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static bool check_access(csh handle, cs_insn *insn, uint32_t word,
			 const uint16_t *expected, unsigned count)
{
	cs_regs reads, writes;
	uint8_t read_count = 0, write_count = 0;
	cs_detail before;
	memcpy(&before, insn->detail, sizeof(before));
	memset(reads, 0xa5, sizeof(reads));
	memset(writes, 0xa5, sizeof(writes));
	if (cs_regs_access(handle, insn, reads, &read_count, writes,
			   &write_count) != CS_ERR_OK ||
	    read_count != count || write_count != 1 ||
	    memcmp(reads, expected, count * sizeof(*reads)) ||
	    writes[0] != ARM_REG_R0 ||
	    memcmp(&before, insn->detail, sizeof(before))) {
		fprintf(stderr, "ARM register access mismatch for %08x: reads",
			(unsigned)word);
		for (unsigned i = 0; i < read_count; ++i)
			fprintf(stderr, " %u", reads[i]);
		fputc('\n', stderr);
		return false;
	}
	for (unsigned i = count; i < sizeof(reads) / sizeof(*reads); ++i)
		if (reads[i] != 0xa5a5)
			return false;
	for (unsigned i = 1; i < sizeof(writes) / sizeof(*writes); ++i)
		if (writes[i] != 0xa5a5)
			return false;
	return true;
}

static bool check_word(csh handle, cs_insn *slot, uint32_t word,
		       bool big_endian, const uint16_t *expected,
		       unsigned count)
{
	uint8_t bytes[4];
	for (unsigned i = 0; i < 4; ++i)
		bytes[big_endian ? 3 - i : i] = (uint8_t)(word >> (8 * i));
	const uint8_t *cursor = bytes;
	size_t left = sizeof(bytes);
	uint64_t address = 0x1000;
	if (!cs_disasm_iter(handle, &cursor, &left, &address, slot) || left ||
	    !check_access(handle, slot, word, expected, count))
		return false;
	cs_insn *allocated = NULL;
	size_t decoded =
		cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 1, &allocated);
	bool ok = decoded == 1 &&
		  check_access(handle, allocated, word, expected, count);
	cs_free(allocated, decoded);
	return ok;
}

static bool check_mode(bool big_endian, bool real)
{
	csh handle;
	cs_mode mode = big_endian ? CS_MODE_ARM | CS_MODE_BIG_ENDIAN :
				    CS_MODE_ARM;
	if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK)
		return false;
	bool ok = cs_option(handle, CS_OPT_DETAIL,
			    CS_OPT_ON | (real ? CS_OPT_DETAIL_REAL : 0)) ==
		  CS_ERR_OK;
	cs_insn *slot = cs_malloc(handle);
	if (!slot)
		ok = false;
	for (unsigned shift = 0; ok && shift < 4; ++shift) {
		for (unsigned conditional = 0; ok && conditional < 2;
		     ++conditional) {
			for (unsigned rs = 0; ok && rs < 4; ++rs) {
				uint16_t expected[4];
				unsigned count = 0;
				if (conditional)
					expected[count++] = ARM_REG_CPSR;
				expected[count++] = ARM_REG_R1;
				expected[count++] = ARM_REG_R2;
				if (rs == 0 || rs == 3)
					expected[count++] =
						(uint16_t)(ARM_REG_R0 + rs);
				/* ADD{EQ} r0, r1, r2, <shift> r0..r3. */
				uint32_t word = 0x00810012 | (shift << 5) |
						(rs << 8);
				if (!conditional)
					word |= 0xe0000000;
				ok = check_word(handle, slot, word, big_endian,
						expected, count);
			}
		}
		const uint16_t pair[] = { ARM_REG_R1, ARM_REG_R2 };
		/* Immediate shifts add no register. MOV shift aliases already
		 * expose the shift register as a separate operand in alias detail. */
		ok = ok &&
		     check_word(handle, slot, 0xe0810182 | (shift << 5),
				big_endian, pair, 2) &&
		     check_word(handle, slot, 0xe1a00211 | (shift << 5),
				big_endian, pair, 2);
	}
	cs_free(slot, slot ? 1 : 0);
	cs_close(&handle);
	return ok;
}

int main(void)
{
	for (unsigned big_endian = 0; big_endian < 2; ++big_endian)
		for (unsigned real = 0; real < 2; ++real)
			if (!check_mode(big_endian, real))
				return 1;
	return 0;
}

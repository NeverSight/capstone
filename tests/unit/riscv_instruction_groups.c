/* RISC-V privileged instruction groups must not depend on stale output bytes.
 * Encodings come from tests/MC/RISCV and LLVM RISCVInstrInfo.td. */
#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

struct group_case {
	uint32_t word;
	unsigned id;
	bool privileged;
	bool rv64_only;
};

static const struct group_case cases[] = {
	{ 0x10200073, RISCV_INS_SRET, true, false },
	{ 0x30200073, RISCV_INS_MRET, true, false },
	{ 0x10500073, RISCV_INS_WFI, true, false },
	{ 0x12000073, RISCV_INS_SFENCE_VMA, true, false },
	{ 0x12b50073, RISCV_INS_SFENCE_VMA, true, false },
	{ 0x16000073, RISCV_INS_SINVAL_VMA, true, false },
	{ 0x16b50073, RISCV_INS_SINVAL_VMA, true, false },
	{ 0x18000073, RISCV_INS_SFENCE_W_INVAL, true, false },
	{ 0x18100073, RISCV_INS_SFENCE_INVAL_IR, true, false },
	{ 0x22000073, RISCV_INS_HFENCE_VVMA, true, false },
	{ 0x22b50073, RISCV_INS_HFENCE_VVMA, true, false },
	{ 0x62000073, RISCV_INS_HFENCE_GVMA, true, false },
	{ 0x62b50073, RISCV_INS_HFENCE_GVMA, true, false },
	{ 0x6005c573, RISCV_INS_HLV_B, true, false },
	{ 0x6015c573, RISCV_INS_HLV_BU, true, false },
	{ 0x640645f3, RISCV_INS_HLV_H, true, false },
	{ 0x6415c5f3, RISCV_INS_HLV_HU, true, false },
	{ 0x643645f3, RISCV_INS_HLVX_HU, true, false },
	{ 0x68064673, RISCV_INS_HLV_W, true, false },
	{ 0x6836c673, RISCV_INS_HLVX_WU, true, false },
	{ 0x62a5c073, RISCV_INS_HSV_B, true, false },
	{ 0x66a5c073, RISCV_INS_HSV_H, true, false },
	{ 0x6aa5c073, RISCV_INS_HSV_W, true, false },
	{ 0x6815c573, RISCV_INS_HLV_WU, true, true },
	{ 0x6c05c573, RISCV_INS_HLV_D, true, true },
	{ 0x6ea5c073, RISCV_INS_HSV_D, true, true },
	{ 0x7b200073, RISCV_INS_DRET, true, false },
	{ 0x00d00073, RISCV_INS_WRS_NTO, false, false },
	{ 0x01d00073, RISCV_INS_WRS_STO, false, false },
	{ 0x81c5c673, RISCV_INS_MOP_R_0, false, false },
	{ 0xcdf5c673, RISCV_INS_MOP_R_31, false, false },
	{ 0x82b646f3, RISCV_INS_MOP_RR_0, false, false },
	{ 0xceb646f3, RISCV_INS_MOP_RR_7, false, false },
	{ 0xcdc0c073, RISCV_INS_SSPOPCHK, false, false },
	{ 0xcdc2c073, RISCV_INS_SSPOPCHK, false, false },
	{ 0xce104073, RISCV_INS_SSPUSH, false, false },
	{ 0xce504073, RISCV_INS_SSPUSH, false, false },
	{ 0xcdc040f3, RISCV_INS_SSRDP, false, false },
	{ 0x26000073, RISCV_INS_HINVAL_VVMA, true, false },
	{ 0x66000073, RISCV_INS_HINVAL_GVMA, true, false },
	{ 0x00000073, RISCV_INS_ECALL, false, false },
	{ 0x00100073, RISCV_INS_EBREAK, false, false },
	{ 0xc0001073, RISCV_INS_UNIMP, false, false },
	{ 0x00158513, RISCV_INS_ADDI, false, false },
};

static void put_word(uint8_t *bytes, uint32_t word)
{
	for (unsigned i = 0; i < 4; ++i)
		bytes[i] = (uint8_t)(word >> (8 * i));
}

static unsigned count_group(const cs_insn *insn, unsigned group)
{
	unsigned count = 0;
	for (unsigned i = 0; i < insn->detail->groups_count; ++i)
		count += insn->detail->groups[i] == group;
	return count;
}

static bool check_groups(csh handle, const cs_insn *insn,
			 const struct group_case *test)
{
	uint8_t bytes[4];
	put_word(bytes, test->word);
	const bool groups_enabled = !cs_support(CS_SUPPORT_DIET);
	if (insn->id != test->id || insn->size != 4 || !insn->detail ||
	    memcmp(insn->bytes, bytes, sizeof(bytes)) ||
	    count_group(insn, RISCV_GRP_PRIVILEGE) !=
		    (groups_enabled && test->privileged) ||
	    count_group(insn, RISCV_GRP_IRET) !=
		    (groups_enabled && (test->id == RISCV_INS_MRET ||
					test->id == RISCV_INS_SRET)) ||
	    count_group(insn, RISCV_GRP_INT) !=
		    (groups_enabled && (test->id == RISCV_INS_ECALL ||
					test->id == RISCV_INS_EBREAK))) {
		fprintf(stderr,
			"RISC-V groups mismatch for %08" PRIx32 " (id %u)\n",
			test->word, insn->id);
		return false;
	}
	if (groups_enabled &&
	    cs_insn_group(handle, insn, RISCV_GRP_PRIVILEGE) !=
		    test->privileged)
		return false;

	return true;
}

static bool check_iterator(csh handle, cs_insn *insn,
			   const struct group_case *test, unsigned poison)
{
	uint8_t bytes[4];
	put_word(bytes, test->word);
	/* Alternate unrelated bytes and a stale privileged instruction. A mask
	 * correction alone would still incorrectly classify this output buffer. */
	memset(insn->bytes, poison & 1 ? 0xa5 : 0, sizeof(insn->bytes));
	if (!(poison & 1))
		put_word(insn->bytes, 0x30200073);
	const uint8_t *cursor = bytes;
	size_t remaining = sizeof(bytes);
	uint64_t address = 0x1000;
	if (!cs_disasm_iter(handle, &cursor, &remaining, &address, insn) ||
	    remaining != 0 || cursor != bytes + sizeof(bytes) ||
	    address != 0x1004) {
		fprintf(stderr, "RISC-V failed to decode %08" PRIx32 "\n",
			test->word);
		return false;
	}
	return check_groups(handle, insn, test);
}

static bool check_fixed_cases(csh handle, cs_insn *insn, bool rv64)
{
	uint8_t bytes[sizeof(cases) / sizeof(cases[0]) * 4];
	const struct group_case *expected[sizeof(cases) / sizeof(cases[0])];
	for (unsigned reverse = 0; reverse < 2; ++reverse) {
		size_t count = 0;
		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
			size_t index =
				reverse ? sizeof(cases) / sizeof(cases[0]) - 1 -
						  i :
					  i;
			const struct group_case *test = &cases[index];
			if (test->rv64_only && !rv64)
				continue;
			if (!check_iterator(handle, insn, test,
					    (unsigned)i + reverse))
				return false;
			put_word(bytes + count * 4, test->word);
			expected[count++] = test;
		}
		cs_insn *batch = NULL;
		size_t decoded =
			cs_disasm(handle, bytes, count * 4, 0x1000, 0, &batch);
		bool ok = decoded == count;
		for (size_t i = 0; ok && i < decoded; ++i)
			ok = check_groups(handle, &batch[i], expected[i]);
		cs_free(batch, decoded);
		if (!ok)
			return false;
	}
	return true;
}

static bool check_csr_space(csh handle, cs_insn *insn)
{
	static const struct {
		unsigned funct3;
		unsigned id;
	} forms[] = {
		{ 1, RISCV_INS_CSRRW },	 { 2, RISCV_INS_CSRRS },
		{ 3, RISCV_INS_CSRRC },	 { 5, RISCV_INS_CSRRWI },
		{ 6, RISCV_INS_CSRRSI }, { 7, RISCV_INS_CSRRCI },
	};
	static const unsigned registers[][2] = {
		{ 0, 0 },
		{ 5, 0 },
		{ 0, 7 },
		{ 5, 31 },
	};
	for (unsigned csr = 0; csr < 4096; ++csr) {
		/* Unprivileged CSR address ranges from the architecture's allocation
		 * table. Existence and runtime access controls are not disassembler
		 * legality checks; all syntactically valid CSR operands are covered. */
		bool user_csr = csr <= 0x0ff ||
				(csr >= 0x400 && csr <= 0x4ff) ||
				(csr >= 0x800 && csr <= 0x8ff) ||
				(csr >= 0xc00 && csr <= 0xcff);
		for (size_t f = 0; f < sizeof(forms) / sizeof(forms[0]); ++f) {
			for (size_t k = 0;
			     k < sizeof(registers) / sizeof(registers[0]);
			     ++k) {
				struct group_case test = {
					(csr << 20) | (registers[k][1] << 15) |
						(forms[f].funct3 << 12) |
						(registers[k][0] << 7) | 0x73,
					forms[f].id,
					!user_csr,
					false,
				};
				/* The decoder gives this deliberate read-only CSR write
				 * its established UNIMP identity in both syntaxes. */
				if (test.word == 0xc0001073)
					test.id = RISCV_INS_UNIMP;
				if (!check_iterator(handle, insn, &test,
						    csr + (unsigned)k))
					return false;
			}
		}
	}
	return true;
}

int main(void)
{
	for (unsigned rv64 = 0; rv64 < 2; ++rv64) {
		csh handle;
		cs_mode mode = (rv64 ? CS_MODE_RISCV64 : CS_MODE_RISCV32) |
			       CS_MODE_RISCV_A | CS_MODE_RISCV_ZICFISS;
		if (cs_open(CS_ARCH_RISCV, mode, &handle) != CS_ERR_OK)
			return 1;
		if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
			cs_close(&handle);
			return 1;
		}
		cs_insn *insn = cs_malloc(handle);
		bool ok = insn != NULL;
		for (unsigned real = 0; ok && real < 2; ++real) {
			ok = cs_option(handle, CS_OPT_SYNTAX,
				       real ? CS_OPT_SYNTAX_REAL :
					      CS_OPT_SYNTAX_DEFAULT) ==
				     CS_ERR_OK &&
			     check_fixed_cases(handle, insn, rv64) &&
			     check_csr_space(handle, insn);
		}
		cs_free(insn, 1);
		cs_close(&handle);
		if (!ok)
			return 1;
	}
	return 0;
}

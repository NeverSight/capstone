#include "unit_test.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

// c.addi sp, -16 (2 ops) -> addi a0, a1, 1 (3 ops) -> c.addi sp, -16 (2 ops)
// Without RISCV_init_cs_detail(), op_count accumulates: 2, 5, 7
static bool test_riscv_op_count_no_stale()
{
	printf("Test test_riscv_op_count_no_stale\n");
	static const uint8_t code[] = {
		0x41, 0x11, // c.addi sp, -16
		0x13, 0x85, 0x15, 0x00, // addi a0, a1, 1
		0x41, 0x11, // c.addi sp, -16
	};
	static const int32_t expected_op_counts[] = { 2, 3, 2 };

	csh handle;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV_C,
		    &handle) != CS_ERR_OK) {
		return false;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON | CS_OPT_DETAIL_REAL);
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_REAL);
	cs_insn *insn = cs_malloc(handle);

	const uint8_t *start = code;
	size_t size = sizeof(code);
	uint64_t address = 0;
	size_t i = 0;

	while (cs_disasm_iter(handle, &start, &size, &address, insn)) {
		CHECK_INT_EQUAL_RET_FALSE((size_t)insn->detail->riscv.op_count,
					  expected_op_counts[i]);
		++i;
	}

	cs_free(insn, 1);
	cs_close(&handle);
	return true;
}

static size_t decode_view(cs_opt_value syntax, cs_opt_value detail, cs_insn **insns)
{
	static const uint8_t code[] = {
		0x41, 0x11,             /* c.addi sp, -16 */
		0x13, 0x85, 0x15, 0x00, /* addi a0, a1, 1 */
		0x13, 0x85, 0x05, 0x00, /* mv a0, a1 */
	};
	csh handle;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV_C,
		    &handle) != CS_ERR_OK)
		return 0;
	/* RISC-V syntax flags accumulate within a handle. */
	size_t count = 0;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON | detail) == CS_ERR_OK &&
	    cs_option(handle, CS_OPT_SYNTAX, syntax) == CS_ERR_OK)
		count = cs_disasm(handle, code, sizeof(code), 0, 0, insns);
	cs_close(&handle);
	return count;
}

/* Both the compressed and uncompressed operand views must survive a change
 * of text syntax, including when the printer emits an alias. */
static bool check_detail_syntax(cs_opt_value detail, cs_opt_value reference)
{
	cs_insn *canonical = NULL;
	size_t count = decode_view(reference, detail, &canonical);
	bool ok = count == 3;
	const cs_opt_value syntaxes[] = { CS_OPT_SYNTAX_ALIAS, CS_OPT_SYNTAX_REAL,
					 CS_OPT_SYNTAX_UNCOMPRESSED_REAL };
	for (size_t k = 0; ok && k < sizeof(syntaxes) / sizeof(syntaxes[0]); ++k) {
		cs_insn *other = NULL;
		size_t n = decode_view(syntaxes[k], detail, &other);
		ok = n == count;
		for (size_t i = 0; ok && i < n; ++i) {
			const cs_riscv *x = &canonical[i].detail->riscv;
			const cs_riscv *y = &other[i].detail->riscv;
			ok = x->op_count == y->op_count &&
			     !memcmp(x->operands, y->operands,
				     x->op_count * sizeof(*x->operands));
		}
		cs_free(other, n);
	}
	cs_free(canonical, count);
	return ok;
}

int main(void)
{
	bool ret = true;
	ret &= test_riscv_op_count_no_stale();
	ret &= check_detail_syntax(CS_OPT_DETAIL_REAL, CS_OPT_SYNTAX_REAL);
	ret &= check_detail_syntax(CS_OPT_DETAIL_UNCOMPRESSED_REAL,
				   CS_OPT_SYNTAX_UNCOMPRESSED_REAL);
	return ret ? 0 : -1;
}

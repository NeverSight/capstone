/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static cs_insn *active;
static unsigned calls;

static int format_with_unused_operand(char *out, size_t size, const char *fmt,
				      va_list ap)
{
	if (active) {
		/* The LDR below has two operands. A spare slot must never be
		 * interpreted as a post-index displacement. */
		cs_arm_op *unused = &active->detail->arm.operands[2];
		unused->type = ARM_OP_IMM;
		unused->imm = 23;
		++calls;
	}
	return vsnprintf(out, size, fmt, ap);
}

static bool check_load(csh handle, cs_insn *insn, const uint8_t *code,
		       bool post_index, int displacement)
{
	size_t size = 4;
	uint64_t address = 0x1000;
	if (!cs_disasm_iter(handle, &code, &size, &address, insn))
		return false;
	const cs_arm *arm = &insn->detail->arm;
	return insn->id == ARM_INS_LDR && arm->op_count == 2 &&
	       arm->post_index == post_index &&
	       insn->detail->writeback == post_index &&
	       arm->operands[1].type == ARM_OP_MEM &&
	       arm->operands[1].mem.disp == displacement;
}

int main(void)
{
	const uint8_t base_only[] = { 0x00, 0x00, 0x91, 0xe5 };
	const uint8_t indexed[] = { 0x04, 0x00, 0x91, 0xe4 };
	cs_opt_mem mem = { malloc, calloc, realloc, free,
			   format_with_unused_operand };
	csh handle;
	if (cs_option(0, CS_OPT_MEM, (size_t)&mem) != CS_ERR_OK ||
	    cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
		return 1;
	bool ok = false;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK) {
		cs_insn *insn = cs_malloc(handle);
		if (insn) {
			active = insn;
			ok = check_load(handle, insn, base_only, false, 0);
			active = NULL;
			ok = ok && calls && check_load(handle, insn, indexed, true, 4);
			cs_free(insn, 1);
		}
	}
	cs_close(&handle);
	if (!ok)
		fputs("ARM post-index operand extent or displacement mismatch\n", stderr);
	return ok ? 0 : 1;
}

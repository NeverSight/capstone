/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_vex_immediate_text" rodata = \
	".cs_x86_vex_immediate_rodata"
#endif
#include "X86OutputOptions.h"
#include "X86SimpleOutput.h"
#include "X86UnsignedImmediate.h"
#include "X86VectorRegisterWriter.h"

struct VexRegisterImmediateRow {
	struct VectorOutputRow instruction;
	/* Each register selects ModR/M.reg, vvvv or ModR/M.r/m, then
     * XMM, YMM, a 32-bit GPR or a 64-bit GPR. */
	uint8_t operands[3], register_count;
	bool uses_vvvv;
};
#include "X86GenVexRegisterImmediates.inc"

/* Both iterators have identified C4 in their fixed address mode. */
bool X86_writeVexRegisterImmediate(cs_struct *handle, const uint8_t *code,
				   size_t size, cs_insn *insn,
				   uint16_t *insn_size,
				   const struct X86SimpleRegister regs[4][16],
				   bool wide)
{
	if (size < 6 || (code[1] & 31) != 3 || code[4] < 0xc0)
		return false;
	const unsigned flags = code[2];
	const unsigned src = (~flags >> 3) & 15;
	if (!wide && (code[1] != 0xe3 || src >= 8))
		return false;
	const unsigned form = vex_immediate_opcodes[wide][code[3]];
	const unsigned key = ((flags >> 4) & 8) | (flags & 7);
	const unsigned index = vex_immediate_prefixes[form][key];
	if (!index)
		return false;
	const struct VexRegisterImmediateRow *row =
		&vex_immediate_rows[index - 1];
	if ((!row->uses_vvvv && src) || X86_OUTPUT_UNSUPPORTED(handle, false))
		return false;
	const struct VectorOutputRow *record = &row->instruction;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	const unsigned mr = code[4];
	const unsigned numbers[] = { ((mr >> 3) & 7) | ((rxb & 4) << 1), src,
				     (mr & 7) | ((rxb & 1) << 3) };
	insn->id = record->id;
	*insn_size = insn->size = 6;
	memcpy(insn->bytes, code, 6);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, record->mnemonic, sizeof(record->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	cs_x86 *x = NULL;
	if (insn->detail) {
		cs_detail *detail = insn->detail;
		memset(detail, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		detail->groups_count = record->group_count;
		memcpy(detail->groups, record->groups, sizeof(record->groups));
		x = &detail->x86;
		memcpy(x->opcode, code, 3);
		x->rex = wide ? (uint8_t)(0x40 | ((flags >> 4) & 8) | rxb) : 0;
		x->addr_size = wide ? 8 : 4;
		x->modrm = (uint8_t)mr;
		x->encoding.modrm_offset = 4;
		x->encoding.imm_offset = 5;
		x->encoding.imm_size = 1;
		x->op_count = row->register_count + 1;
		cs_x86_op *imm = &x->operands[row->register_count];
		imm->type = X86_OP_IMM;
		imm->imm = code[5];
		imm->size = 1;
		imm->access = (cs_ac_type)record->access[row->register_count];
	}
	char *out = insn->op_str;
	for (unsigned i = 0; i < row->register_count; ++i) {
		const unsigned operand = row->operands[i], bank = operand & 3;
		const unsigned number = numbers[operand >> 2];
		x86_reg reg;
		if (bank < 2) {
			out = writeVectorRegister(out, bank, number);
			reg = (x86_reg)((bank ? X86_REG_YMM0 : X86_REG_XMM0) +
					number);
		} else {
			const struct X86SimpleRegister *gpr =
				&regs[bank][number];
			memcpy(out, gpr->name, sizeof(gpr->name));
			out += gpr->length;
			reg = (x86_reg)gpr->reg;
		}
		if (x) {
			static const uint8_t widths[] = { 16, 32, 4, 8 };
			cs_x86_op *op = &x->operands[i];
			op->type = X86_OP_REG;
			op->reg = reg;
			op->size = widths[bank];
			op->access = (cs_ac_type)record->access[i];
		}
		memcpy(out, ", ", 2);
		out += 2;
	}
	writeUnsignedImmediate(out, code[5]);
	return true;
}
#endif
#endif

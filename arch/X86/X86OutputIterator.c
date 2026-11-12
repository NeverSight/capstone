/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#include "X86ScanAdapter.h"

#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86Disassembler.h"
#include "X86InstPrinter.h"
#include "X86InstPrinterCommon.h"
#include "../../utils.h"
#include "X86Mapping.h"
#include "X86SimpleOutput.h"
#include "X86GenSimpleOutput.inc"

/* A leading legacy prefix or a memory ModR/M encoding goes through the full
 * decoder. The register rows distinguish the high byte registers from SPL,
 * BPL, SIL and DIL as soon as any REX prefix is present. */
#ifdef CAPSTONE_X86_DEDICATED_OUTPUT
CAPSTONE_INTERNAL
#else
static
#endif
bool X86_trySimpleOutput(cs_struct *handle, const uint8_t *code, size_t size,
			 cs_insn *insn, uint16_t *insn_size)
{
	const bool wide = handle->mode == CS_MODE_64;
	const bool has_rex = wide && (code[0] & 0xf0) == 0x40;
	const uint8_t rex = has_rex ? code[0] : 0;
	const bool escaped = code[0] == 0x0f;
	const unsigned lead = has_rex || escaped;
	if (size <= lead)
		return false;
	const uint8_t opcode = code[lead];
	const unsigned prefix_class = escaped ? 3 :
				      has_rex ? ((rex & 8) ? 2 : 1) :
						0;
	const unsigned plan = x86_simple_plans[wide][prefix_class][opcode];
	if (!plan)
		return false;
	const unsigned form = plan & 3;
	uint8_t modrm = 0;
	if (form == X86_SIMPLE_RM_REG || form == X86_SIMPLE_REG_RM) {
		if (size < 2u + has_rex)
			return false;
		modrm = code[1 + has_rex];
		if (modrm < 0xc0)
			return false;
	}
	if ((!wide && handle->mode != CS_MODE_32) || handle->no_text ||
	    handle->imm_unsigned || handle->mnem_list || handle->doing_mem ||
	    (handle->syntax != CS_OPT_SYNTAX_INTEL &&
	     handle->syntax != CS_OPT_SYNTAX_DEFAULT) ||
	    handle->disasm != X86_getInstruction ||
	    handle->insn_id != X86_get_insn_id ||
	    handle->printer != X86_Intel_printInst ||
	    handle->post_printer != X86_postprinter ||
	    cs_vsnprintf != cs_default_vsnprintf)
		return false;

	const struct X86SimpleOutput *row = &x86_simple_outputs[plan >> 2];
	const bool relative = form == X86_SIMPLE_RELATIVE;
	if (relative && size < (size_t)row->imm_offset + row->imm_size)
		return false;
	uint64_t target = 0;
	uint16_t first = row->ops[0].reg, second = row->ops[1].reg;
	insn->id = row->id;
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	insn->bytes[0] = code[0];
	if (form == X86_SIMPLE_FIXED) {
		memcpy(insn->op_str, row->operands, sizeof(row->operands));
		*insn_size = insn->size = 1;
	} else if (relative) {
		const uint8_t *bytes = code + row->imm_offset;
		int64_t delta;
		if (row->imm_size == 1) {
			delta = (int8_t)bytes[0];
		} else {
			uint32_t raw = (uint32_t)bytes[0] |
				       ((uint32_t)bytes[1] << 8) |
				       ((uint32_t)bytes[2] << 16) |
				       ((uint32_t)bytes[3] << 24);
			delta = (int32_t)raw;
		}
		const uint16_t length = row->imm_offset + row->imm_size;
		target = X86_relativeBranchTarget(handle->mode, insn->address,
						  length, delta, row->imm_size);
		if (target <= HEX_THRESHOLD) {
			insn->op_str[0] = (char)('0' + target);
		} else {
			char digits[16];
			char *end = digits + sizeof(digits);
			char *p = end;
			uint64_t value = target;
			do {
				*--p = "0123456789abcdef"[value & 15];
				value >>= 4;
			} while (value);
			insn->op_str[0] = '0';
			insn->op_str[1] = 'x';
			memcpy(insn->op_str + 2, p, (size_t)(end - p));
		}
		memcpy(insn->bytes, code, length);
		*insn_size = insn->size = length;
	} else {
		const unsigned width = (opcode & 1) ? ((rex & 8) ? 3 : 2) :
						      has_rex;
		const unsigned reg = ((rex & 4) << 1) | ((modrm >> 3) & 7);
		const unsigned rm = ((rex & 1) << 3) | (modrm & 7);
		const struct X86SimpleRegister *regs =
			x86_simple_registers[width];
		const struct X86SimpleRegister *a =
			&regs[form == X86_SIMPLE_REG_RM ? reg : rm];
		const struct X86SimpleRegister *b =
			&regs[form == X86_SIMPLE_REG_RM ? rm : reg];
		memcpy(insn->op_str, a->name, sizeof(a->name));
		char *separator = insn->op_str + a->length;
		separator[0] = ',';
		separator[1] = ' ';
		memcpy(separator + 2, b->name, sizeof(b->name));
		first = a->reg;
		second = b->reg;
		insn->bytes[1] = code[1];
		if (has_rex)
			insn->bytes[2] = code[2];
		*insn_size = insn->size = 2 + has_rex;
	}
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, opcode, rex, modrm,
				      first, second);
		if (relative) {
			cs_x86 *x = &insn->detail->x86;
			if (escaped) {
				x->opcode[0] = 0x0f;
				x->opcode[1] = opcode;
			}
			x->operands[0].type = X86_OP_IMM;
			x->operands[0].imm = (int64_t)target;
		}
	}
	return true;
}

#ifndef CAPSTONE_X86_DEDICATED_OUTPUT
#define CS_DECODE_TRY_OUTPUT X86_trySimpleOutput
#endif
#endif
#include "../../cs_disasm_internal.h"

CAPSTONE_INTERNAL bool X86_disasmIter(csh ud, const uint8_t **code,
				      size_t *size, uint64_t *address,
				      cs_insn *insn)
{
#ifdef CS_DECODE_TRY_OUTPUT
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (handle && handle->arch == CS_ARCH_X86 && !handle->no_text)
		return cs_disasm_iter_core(ud, code, size, address, insn);
#endif
	return cs_disasm_iter(ud, code, size, address, insn);
}
#endif

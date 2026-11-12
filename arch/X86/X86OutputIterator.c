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

/* The admitted MOV forms share the register/register row's access and widths.
 * The ModR/M byte selects an integer base without SIB, RIP or a disp32. */
static void X86_writeBaseMov(cs_insn *insn, const struct X86SimpleOutput *row,
			     const uint8_t *code, uint8_t opcode, uint8_t rex,
			     uint8_t modrm, bool load, bool wide,
			     uint16_t *insn_size)
{
	const bool has_disp = (modrm >> 6) == 1;
	const unsigned offset = 2 + (rex != 0);
	const int displacement = has_disp ? (int8_t)code[offset] : 0;
	const unsigned reg_width = (opcode & 1) ? ((rex & 8) ? 3 : 2) :
						  rex != 0;
	const unsigned reg_index = ((rex & 4) << 1) | ((modrm >> 3) & 7);
	const unsigned rm = ((rex & 1) << 3) | (modrm & 7);
	const struct X86SimpleRegister *reg =
		&x86_simple_registers[reg_width][reg_index];
	const struct X86SimpleRegister *base =
		&x86_simple_registers[wide ? 3 : 2][rm];

	char *out = insn->op_str;
	if (load) {
		memcpy(out, reg->name, sizeof(reg->name));
		out += reg->length;
		memcpy(out, ", ", 2);
		out += 2;
	}
	if (row->ops[0].size == 1) {
		memcpy(out, "byte ptr [", 10);
		out += 10;
	} else {
		memcpy(out,
		       row->ops[0].size == 8 ? "qword ptr [" : "dword ptr [",
		       11);
		out += 11;
	}
	memcpy(out, base->name, sizeof(base->name));
	out += base->length;
	if (displacement) {
		const unsigned magnitude = displacement < 0 ? -displacement :
							      displacement;
		memcpy(out, displacement < 0 ? " - " : " + ", 3);
		out += 3;
		if (magnitude <= HEX_THRESHOLD) {
			*out++ = (char)('0' + magnitude);
		} else {
			static const char digits[] = "0123456789abcdef";
			memcpy(out, "0x", 2);
			out += 2;
			if (magnitude >= 16)
				*out++ = digits[magnitude >> 4];
			*out++ = digits[magnitude & 15];
		}
	}
	*out++ = ']';
	if (!load) {
		memcpy(out, ", ", 2);
		memcpy(out + 2, reg->name, sizeof(reg->name));
	}
	*insn_size = insn->size = (uint16_t)(offset + has_disp);
	memcpy(insn->bytes, code, insn->size);
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, opcode, rex, modrm,
				      load ? reg->reg : 0, load ? 0 : reg->reg);
		cs_x86 *x = &insn->detail->x86;
		x->disp = displacement;
		if (has_disp) {
			x->encoding.disp_offset = (uint8_t)offset;
			x->encoding.disp_size = 1;
		}
		cs_x86_op *op = &x->operands[load ? 1 : 0];
		op->type = X86_OP_MEM;
		op->mem.base = (x86_reg)base->reg;
		op->mem.scale = 1;
		op->mem.disp = displacement;
	}
}

/* The /digit selects the same flags and register access as the corresponding
 * ALU register pair. The immediate's public width follows the destination. */
static void writeGroup1Immediate(cs_insn *insn,
				 const struct X86SimpleOutput *row,
				 const uint8_t *code, uint8_t rex,
				 uint8_t modrm, uint16_t *insn_size)
{
	const unsigned offset = 2 + (rex != 0);
	const int immediate = (int8_t)code[offset];
	const unsigned group = (modrm >> 3) & 7;
	const bool logical = group == 1 || group == 4 || group == 6;
	const bool wide = (rex & 8) != 0;
	const bool negative = !logical && immediate < 0;
	const uint64_t value =
		logical ? (wide ? (uint64_t)(int64_t)immediate :
				  (uint32_t)immediate) :
			  (uint64_t)(negative ? -immediate : immediate);
	const unsigned id = ((rex & 1) << 3) | (modrm & 7);
	const struct X86SimpleRegister *reg =
		&x86_simple_registers[wide ? 3 : 2][id];
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)(offset + 1);
	memcpy(insn->bytes, code, insn->size);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	memcpy(insn->op_str, reg->name, sizeof(reg->name));
	char *out = insn->op_str + reg->length;
	memcpy(out, ", ", 2);
	out += 2;
	if (negative)
		*out++ = '-';
	if (value <= HEX_THRESHOLD) {
		*out = (char)('0' + value);
	} else {
		static const char digits[] = "0123456789abcdef";
		char temp[16], *end = temp + sizeof(temp), *start = end;
		uint64_t n = value;
		do {
			*--start = digits[n & 15];
			n >>= 4;
		} while (n);
		memcpy(out, "0x", 2);
		memcpy(out + 2, start, end - start);
	}
	if (insn->detail) {
		X86_writeSimpleDetail(insn->detail, row, 0x83, rex, modrm,
				      reg->reg, 0);
		cs_x86 *x = &insn->detail->x86;
		x->operands[1].type = X86_OP_IMM;
		x->operands[1].imm = logical && !wide ?
					     (int64_t)(uint32_t)immediate :
					     immediate;
		x->operands[1].access = 0;
		x->encoding.imm_offset = (uint8_t)offset;
		x->encoding.imm_size = 1;
	}
}

/* The register rows distinguish AH..BH from SPL..DIL when a REX prefix is
 * present. Memory admission below is limited to MOV with a base or base+disp8. */
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
	bool base_memory = false;
	if (form == X86_SIMPLE_RM_REG || form == X86_SIMPLE_REG_RM) {
		if (size < 2u + has_rex)
			return false;
		modrm = code[1 + has_rex];
		if (modrm < 0xc0) {
			unsigned rm = modrm & 7;
			if ((opcode & 0xfc) != 0x88 || modrm >= 0x80 ||
			    rm == 4 || (modrm < 0x40 && rm == 5) ||
			    (modrm >= 0x40 && size < 3u + has_rex))
				return false;
			base_memory = true;
		}
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

	if (plan == X86_PLAN_GROUP1_IMM8) {
		if (size < 3u + has_rex)
			return false;
		unsigned reg_plan =
			x86_simple_plans[wide][prefix_class][(modrm & 0x38) | 1];
		if (!reg_plan)
			return false;
		writeGroup1Immediate(insn, &x86_simple_outputs[reg_plan >> 2],
				     code, rex, modrm, insn_size);
		return true;
	}
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
	if (base_memory) {
		X86_writeBaseMov(insn, row, code, opcode, rex, modrm,
				 form == X86_SIMPLE_REG_RM, wide, insn_size);
		return true;
	}
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

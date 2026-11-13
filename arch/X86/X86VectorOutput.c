/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86SimpleOutput.h"
#include "X86GenVectorOutput.inc"
static char *writeVectorRegister(char *out, unsigned length_code,
				 unsigned number)
{
	*out++ = "xyz"[length_code];
	*out++ = 'm';
	*out++ = 'm';
	if (number >= 10)
		*out++ = (char)('0' + number / 10);
	*out++ = (char)('0' + number % 10);
	return out;
}

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static bool writeEvexRegisterOutput(const uint8_t *code, size_t size,
				    cs_insn *insn, uint16_t *insn_size)
{
	if (size < 6 || (code[2] & 7) != 5 || (code[3] & 0x97) ||
	    (code[3] & 0x60) == 0x60 || code[5] < 0xc0)
		return false;
	const unsigned ll = code[3] >> 5;
	const unsigned w = code[2] >> 7;
	const struct VectorOutputRow *row =
		evexOutputRow(((code[1] & 15) << 8) | code[4], w, ll);
	if (!row || (row->immediate && size < 7))
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	const unsigned regs[] = { ((code[5] >> 3) & 7) | ((rxb & 4) << 1) |
					  (~(unsigned)code[1] & 16),
				  ((~(unsigned)code[2] >> 3) & 15) |
					  ((~(unsigned)code[3] & 8) << 1),
				  (code[5] & 7) | ((rxb & 3) << 3) };
	const unsigned len = 6 + row->immediate;
	*insn_size = insn->size = (uint16_t)len;
	insn->id = row->id;
	memcpy(insn->bytes, code, len);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, ll, regs[0]);
	for (unsigned n = 1; n != 3; ++n) {
		memcpy(out, ", ", 2);
		out = writeVectorRegister(out + 2, ll, regs[n]);
	}
	if (row->immediate) {
		const unsigned value = code[6];
		memcpy(out, ", ", 2);
		out += 2;
		if (value <= HEX_THRESHOLD) {
			*out = (char)('0' + value);
		} else {
			static const char digits[] = "0123456789abcdef";
			memcpy(out, "0x", 2);
			out += 2;
			if (value >= 16)
				*out++ = digits[value >> 4];
			*out = digits[value & 15];
		}
	}
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		memcpy(d->groups, row->groups, sizeof(row->groups));
		d->groups_count = row->group_count;
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, sizeof(x->opcode));
		x->addr_size = 8;
		x->rex = (uint8_t)(0x40 | (w << 3) | rxb);
		x->modrm = code[5];
		x->encoding.modrm_offset = 5;
		x->op_count = 3 + row->immediate;
		static const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0,
						 X86_REG_ZMM0 };
		for (unsigned n = 0; n != 3; ++n) {
			cs_x86_op *op = &x->operands[n];
			op->type = X86_OP_REG;
			op->reg = (x86_reg)(bases[ll] + regs[n]);
			op->access = (cs_ac_type)row->access[n];
			op->size = (uint8_t)(16 << ll);
		}
		if (row->immediate) {
			x->operands[3].type = X86_OP_IMM;
			x->operands[3].imm = code[6];
			x->operands[3].access = (cs_ac_type)row->access[3];
			x->operands[3].size = 1;
			x->encoding.imm_offset = 6;
			x->encoding.imm_size = 1;
		}
	}
	return true;
}

/* VEX packed loads and FMA with an ordinary base, index and optional disp8.
 * Prefix, ModR/M and SIB also supply all register IDs used in detail. */
#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static bool writeVexIndexedOutput(const uint8_t *code, size_t size,
				  cs_insn *insn, uint16_t *insn_size,
				  const struct X86SimpleRegister *regs)
{
	const bool fma = code[0] == 0xc4;
	const unsigned prefix = fma ? 3 : 2;
	if (size < prefix + 3)
		return false;
	const uint8_t flags = code[prefix - 1];
	if (fma) {
		if ((code[1] & 0x1f) != 2 || (flags & 0x83) != 1 ||
		    code[prefix] != 0xa8)
			return false;
	} else if ((flags & 0x7b) != 0x78 || code[prefix] != 0x28) {
		return false;
	}
	const unsigned modrm = code[prefix + 1];
	const unsigned sib = code[prefix + 2];
	const bool has_disp = (modrm & 0x40) != 0;
	const unsigned len = prefix + 3 + has_disp;
	if ((modrm & 0x87) != 4 || len > size || (!has_disp && (sib & 7) == 5))
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & (fma ? 7 : 4);
	const unsigned index = ((rxb & 2) << 2) | ((sib >> 3) & 7);
	if (index == 4)
		return false;
	const unsigned base = ((rxb & 1) << 3) | (sib & 7);
	const unsigned scale = 1u << (sib >> 6);
	const int disp = has_disp ? (int8_t)code[len - 1] : 0;
	const unsigned ll = (flags >> 2) & 1;
	const unsigned dst = ((rxb & 4) << 1) | ((modrm >> 3) & 7);
	const unsigned src = (~(unsigned)flags >> 3) & 15;
	const struct VectorOutputRow *row = &vex_indexed_rows[fma][ll];
	*insn_size = insn->size = (uint16_t)len;
	insn->id = row->id;
	memcpy(insn->bytes, code, len);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, ll, dst);
	if (fma) {
		memcpy(out, ", ", 2);
		out = writeVectorRegister(out + 2, ll, src);
	}
	memcpy(out, ", xmmword ptr [", 15);
	out[2] = "xy"[ll];
	out += 15;
	memcpy(out, regs[base].name, sizeof(regs[base].name));
	out += regs[base].length;
	memcpy(out, " + ", 3);
	out += 3;
	memcpy(out, regs[index].name, sizeof(regs[index].name));
	out += regs[index].length;
	if (scale != 1) {
		*out++ = '*';
		*out++ = (char)('0' + scale);
	}
	out = X86_writeDisp8(out, disp);
	*out = ']';
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		memcpy(d->groups, row->groups, sizeof(row->groups));
		d->groups_count = row->group_count;
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, prefix);
		x->addr_size = 8;
		x->rex = (uint8_t)(0x40 | rxb);
		x->modrm = (uint8_t)modrm;
		x->sib = (uint8_t)sib;
		x->sib_base = (x86_reg)regs[base].reg;
		x->sib_index = (x86_reg)regs[index].reg;
		x->sib_scale = (int8_t)scale;
		x->disp = disp;
		x->encoding.modrm_offset = (uint8_t)(prefix + 1);
		if (has_disp) {
			x->encoding.disp_offset = (uint8_t)(len - 1);
			x->encoding.disp_size = 1;
		}
		x->op_count = (uint8_t)(2 + fma);
		const x86_reg first = ll ? X86_REG_YMM0 : X86_REG_XMM0;
		const unsigned reg_count = 1u + fma;
		for (unsigned i = 0; i < reg_count; ++i) {
			cs_x86_op *op = &x->operands[i];
			op->type = X86_OP_REG;
			op->reg = (x86_reg)(first + (i ? src : dst));
			op->size = (uint8_t)(16u << ll);
			op->access = (cs_ac_type)row->access[i];
		}
		cs_x86_op *op = &x->operands[reg_count];
		op->type = X86_OP_MEM;
		op->mem.base = x->sib_base;
		op->mem.index = x->sib_index;
		op->mem.scale = (int)scale;
		op->mem.disp = disp;
		op->size = (uint8_t)(16u << ll);
		op->access = (cs_ac_type)row->access[reg_count];
	}
	return true;
}

static bool writeLegacyRegisterOutput(const uint8_t *code, size_t size,
				      cs_insn *insn, uint16_t *insn_size,
				      bool wide)
{
	if (size < 4)
		return false;
	const bool has_rex = wide && (code[1] & 0xf0) == 0x40;
	const unsigned length = 4 + has_rex;
	if (size < length || code[1 + has_rex] != 0x0f)
		return false;
	const uint8_t opcode = code[2 + has_rex];
	const unsigned plan = legacy_register_plans[opcode];
	const uint8_t modrm = code[3 + has_rex];
	if (!plan || modrm < 0xc0)
		return false;

	const struct VectorOutputRow *row = &legacy_register_rows[plan & 127];
	const uint8_t rex = has_rex ? code[1] : 0;
	const unsigned reg = ((modrm >> 3) & 7) | ((rex & 4) << 1);
	const unsigned rm = (modrm & 7) | ((rex & 1) << 3);
	const unsigned first = plan & 128 ? rm : reg;
	const unsigned second = plan & 128 ? reg : rm;
	*insn_size = insn->size = (uint16_t)length;
	insn->id = row->id;
	memcpy(insn->bytes, code, length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, 0, first);
	memcpy(out, ", ", 2);
	writeVectorRegister(out + 2, 0, second);
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		memcpy(d->groups, row->groups, sizeof(row->groups));
		d->groups_count = row->group_count;
		cs_x86 *x = &d->x86;
		x->prefix[2] = 0x66;
		x->opcode[0] = 0x0f;
		x->opcode[1] = opcode;
		x->rex = rex;
		x->addr_size = wide ? 8 : 4;
		x->modrm = modrm;
		x->encoding.modrm_offset = (uint8_t)(length - 1);
		x->op_count = 2;
		for (unsigned i = 0; i < 2; ++i) {
			cs_x86_op *op = &x->operands[i];
			op->type = X86_OP_REG;
			op->reg =
				(x86_reg)(X86_REG_XMM0 + (i ? second : first));
			op->size = 16;
			op->access = (cs_ac_type)row->access[i];
		}
	}
	return true;
}

bool X86_writeVectorOutput(const uint8_t *code, size_t size, cs_insn *insn,
			   uint16_t *insn_size,
			   const struct X86SimpleRegister *regs, bool wide)
{
	if (code[0] == 0x66)
		return writeLegacyRegisterOutput(code, size, insn, insn_size,
						 wide);
	if (code[0] == 0x62)
		return writeEvexRegisterOutput(code, size, insn, insn_size);
	return writeVexIndexedOutput(code, size, insn, insn_size, regs);
}
#endif
#endif

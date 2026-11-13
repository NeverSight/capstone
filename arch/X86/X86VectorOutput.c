/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86SimpleOutput.h"
struct PaddingOutput {
	unsigned id;
	uint8_t length;
	char mnemonic[8], operands[48];
	uint8_t prefix[4], opcode[4], groups[4];
	unsigned group_count, addr_size, modrm, sib, sib_base, sib_index,
		sib_scale;
	unsigned modrm_offset, disp_offset, disp_size, mem_size, access, base,
		index, scale;
};

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

static bool writeVectorRegisters(const uint8_t *code, cs_insn *insn,
				 uint16_t *insn_size,
				 const struct VectorOutputRow *row,
				 unsigned prefix, unsigned ll, unsigned rex,
				 unsigned first_ll, const unsigned *regs,
				 unsigned reg_count)
{
	const unsigned len = prefix + 2 + row->immediate;
	*insn_size = insn->size = (uint16_t)len;
	insn->id = row->id;
	memcpy(insn->bytes, code, len);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, first_ll, regs[0]);
	for (unsigned n = 1; n != reg_count; ++n) {
		memcpy(out, ", ", 2);
		out = writeVectorRegister(out + 2, ll, regs[n]);
	}
	if (row->immediate) {
		const unsigned value = code[prefix + 2];
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
		memcpy(x->opcode, code, prefix);
		x->addr_size = 8;
		x->rex = (uint8_t)rex;
		x->modrm = code[prefix + 1];
		x->encoding.modrm_offset = (uint8_t)(prefix + 1);
		x->op_count = (uint8_t)(reg_count + row->immediate);
		static const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0,
						 X86_REG_ZMM0 };
		for (unsigned n = 0; n != reg_count; ++n) {
			cs_x86_op *op = &x->operands[n];
			op->type = X86_OP_REG;
			const unsigned width = n == 0 ? first_ll : ll;
			op->reg = (x86_reg)(bases[width] + regs[n]);
			op->access = (cs_ac_type)row->access[n];
			op->size = (uint8_t)(16 << width);
		}
		if (row->immediate) {
			x->operands[reg_count].type = X86_OP_IMM;
			x->operands[reg_count].imm = code[prefix + 2];
			x->operands[reg_count].access =
				(cs_ac_type)row->access[reg_count];
			x->operands[reg_count].size = 1;
			x->encoding.imm_offset = (uint8_t)(prefix + 2);
			x->encoding.imm_size = 1;
		}
	}
	return true;
}

static bool writeEvexBroadcast(const uint8_t *code, size_t size, cs_insn *insn,
			       uint16_t *insn_size,
			       const struct X86SimpleRegister *regs);

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static bool writeEvexOutput(const uint8_t *code, size_t size, cs_insn *insn,
			    uint16_t *insn_size,
			    const struct X86SimpleRegister *address_regs)
{
	if (size >= 6 && code[5] < 0xc0)
		return writeEvexBroadcast(code, size, insn, insn_size,
					  address_regs);
	if (size < 6 || (code[2] & 7) != 5 || (code[3] & 0x97) ||
	    (code[3] & 0x60) == 0x60)
		return false;
	const unsigned ll = code[3] >> 5;
	const unsigned w = code[2] >> 7;
	const unsigned key = ((code[1] & 15) << 8) | code[4];
	const struct VectorOutputRow *row = evexOutputRow(key, w, ll);
	if (!row || (row->immediate && size < 7))
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	const unsigned regs[] = { ((code[5] >> 3) & 7) | ((rxb & 4) << 1) |
					  (~(unsigned)code[1] & 16),
				  ((~(unsigned)code[2] >> 3) & 15) |
					  ((~(unsigned)code[3] & 8) << 1),
				  (code[5] & 7) | ((rxb & 3) << 3) };
	/* These EVEX.0F3A extracts use r/m as the narrow destination, reg as
     * the full-width source, and reserve vvvv/V'. */
	if ((key & ~0x22u) == 0x319) {
		if ((code[2] & 0x78) != 0x78 || !(code[3] & 8))
			return false;
		const unsigned pair[] = { regs[2], regs[0] };
		return writeVectorRegisters(code, insn, insn_size, row, 4, ll,
					    0x40 | (w << 3) | rxb,
					    (key & 2) != 0, pair, 2);
	}
	return writeVectorRegisters(code, insn, insn_size, row, 4, ll,
				    0x40 | (w << 3) | rxb, ll, regs, 3);
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

/* The caller has identified a two-byte VEX prefix and RIP-relative ModR/M. */
static bool writeVexRipLoad(const uint8_t *code, size_t size, cs_insn *insn,
			    uint16_t *insn_size)
{
	const uint8_t flags = code[1], opcode = code[2];
	if (size < 8 || (flags & 0x78) != 0x78 ||
	    (opcode != 0x10 && opcode != 0x28 && opcode != 0x6f))
		return false;
	const unsigned map = opcode == 0x10 ? 0 : opcode == 0x28 ? 1 : 2;
	const struct VexRipLoad *row = &vex_rip_loads[map][flags & 7];
	if (!row->id)
		return false;
	const unsigned high = (~(unsigned)flags >> 4) & 8;
	const unsigned dst = high | ((code[3] >> 3) & 7);
	const int32_t displacement = X86_readDisp32(code + 4);
	insn->id = row->id;
	*insn_size = insn->size = 8;
	memcpy(insn->bytes, code, 8);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, row->length_code, dst);
	memcpy(out, row->address, sizeof(row->address));
	out += row->address_length;
	*X86_writeDisplacement(out, displacement) = ']';
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		memcpy(d->groups, row->groups, sizeof(row->groups));
		d->groups_count = row->group_count;
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, 2);
		x->rex = (uint8_t)(0x40 | (high >> 1));
		x->addr_size = 8;
		x->modrm = code[3];
		x->disp = displacement;
		x->encoding.modrm_offset = 3;
		x->encoding.disp_offset = 4;
		x->encoding.disp_size = 4;
		x->op_count = 2;
		cs_x86_op *reg = &x->operands[0];
		reg->type = X86_OP_REG;
		reg->reg = (x86_reg)((row->length_code ? X86_REG_YMM0 :
							 X86_REG_XMM0) +
				     dst);
		reg->size = row->reg_size;
		reg->access = (cs_ac_type)row->reg_access;
		cs_x86_op *mem = &x->operands[1];
		mem->type = X86_OP_MEM;
		mem->size = row->mem_size;
		mem->access = (cs_ac_type)row->mem_access;
		mem->mem.base = X86_REG_RIP;
		mem->mem.scale = 1;
		mem->mem.disp = displacement;
	}
	return true;
}

static bool writePaddingOutput(const uint8_t *code, size_t size, cs_insn *insn,
			       uint16_t *insn_size, bool wide)
{
	const bool operand_prefix = code[0] == 0x66;
	unsigned row = 0;
	if (code[0] == 0xf3) {
		if (size < 4 || code[1] != 0x0f || code[2] != 0x1e ||
		    (code[3] & 0xfe) != 0xfa)
			return false;
		row = 8 + (code[3] & 1);
	} else if (operand_prefix && size >= 2 && code[1] == 0x90) {
		row = 5;
	} else {
		const size_t lead = operand_prefix;
		if (size < lead + 3 || code[lead] != 0x0f ||
		    code[lead + 1] != 0x1f)
			return false;
		const uint8_t modrm = code[lead + 2];
		unsigned trailing;
		switch (modrm) {
		case 0x00:
			row = 0;
			trailing = 0;
			break;
		case 0x40:
			row = 1;
			trailing = 1;
			break;
		case 0x44:
			row = 2;
			trailing = 2;
			break;
		case 0x80:
			row = 3;
			trailing = 4;
			break;
		case 0x84:
			row = 4;
			trailing = 5;
			break;
		default:
			return false;
		}
		if (operand_prefix) {
			if (row != 2 && row != 4)
				return false;
			row = row == 2 ? 6 : 7;
		}
		static const uint8_t zero[5] = { 0 };
		if (size < lead + 3 + trailing ||
		    memcmp(code + lead + 3, zero, trailing))
			return false;
	}
	const struct PaddingOutput *p = &padding_rows[wide][row];
	insn->id = p->id;
	*insn_size = insn->size = p->length;
	memcpy(insn->bytes, code, p->length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, p->mnemonic, sizeof(p->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	memcpy(insn->op_str, p->operands, sizeof(p->operands));
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		d->groups_count = (uint8_t)p->group_count;
		memcpy(d->groups, p->groups, sizeof(p->groups));
		cs_x86 *x = &d->x86;
		memcpy(x->prefix, p->prefix, 4);
		memcpy(x->opcode, p->opcode, 4);
		x->addr_size = (uint8_t)p->addr_size;
		x->modrm = (uint8_t)p->modrm;
		x->sib = (uint8_t)p->sib;
		x->sib_base = (x86_reg)p->sib_base;
		x->sib_index = (x86_reg)p->sib_index;
		x->sib_scale = (int8_t)p->sib_scale;
		x->encoding.modrm_offset = (uint8_t)p->modrm_offset;
		x->encoding.disp_offset = (uint8_t)p->disp_offset;
		x->encoding.disp_size = (uint8_t)p->disp_size;
		if (p->mem_size) {
			x->op_count = 1;
			cs_x86_op *m = &x->operands[0];
			m->type = X86_OP_MEM;
			m->size = (uint8_t)p->mem_size;
			m->access = (cs_ac_type)p->access;
			m->mem.base = (x86_reg)p->base;
			m->mem.index = (x86_reg)p->index;
			m->mem.scale = (int)p->scale;
		}
	}
	return true;
}

/* The VEX register plan supplies the public fields for vvvv register operands.
 * Memory forms and unsupported vector widths fall back before any output. */
static bool writeVexRegisterOutput(const uint8_t *code, size_t size,
				   cs_insn *insn, uint16_t *insn_size,
				   unsigned prefix)
{
	const unsigned flags = code[prefix - 1];
	const unsigned map = prefix == 2 ? 1 : code[1] & 31;
	if ((flags & 3) != 1 || !map || map > 3)
		return false;
	const unsigned ll = (flags >> 2) & 1;
	const unsigned w = prefix == 3 && (flags & 0x80);
	const unsigned rxb = (~(unsigned)code[1] >> 5) & (prefix == 2 ? 4 : 7);
	const unsigned modrm = code[prefix + 1];
	const unsigned opcode = code[prefix];
	if (map == 1 && opcode >= 0x71 && opcode <= 0x73) {
		unsigned index = vex_shift_plans[opcode - 0x71]
						[(modrm >> 3) & 7][w * 2 + ll];
		if (!index || size < prefix + 3)
			return false;
		const unsigned regs[] = { (~flags >> 3) & 15,
					  (modrm & 7) | ((rxb & 1) << 3) };
		return writeVectorRegisters(code, insn, insn_size,
					    &vex_shift_rows[index], prefix, ll,
					    0x40 | (w << 3) | rxb, ll, regs, 2);
	}
	const unsigned plan = vex_register_plans[map - 1][code[prefix]];
	const unsigned index = vex_register_widths[plan][w * 2 + ll];
	if (!index)
		return false;
	const struct VectorOutputRow *row = &vex_register_rows[index];
	if (size < prefix + 2 + row->immediate)
		return false;
	const unsigned regs[] = { ((modrm >> 3) & 7) | ((rxb & 4) << 1),
				  (~flags >> 3) & 15,
				  (modrm & 7) | ((rxb & 1) << 3) };
	return writeVectorRegisters(code, insn, insn_size, row, prefix, ll,
				    0x40 | (w << 3) | rxb, ll, regs, 3);
}

bool X86_writeVectorOutput(const uint8_t *code, size_t size, cs_insn *insn,
			   uint16_t *insn_size,
			   const struct X86SimpleRegister *regs, bool wide)
{
	if (code[0] == 0x0f || code[0] == 0xf3 ||
	    (code[0] == 0x66 && size >= 2 &&
	     (code[1] == 0x90 ||
	      (size >= 3 && code[1] == 0x0f && code[2] == 0x1f))))
		return writePaddingOutput(code, size, insn, insn_size, wide);
	if (code[0] == 0x66)
		return writeLegacyRegisterOutput(code, size, insn, insn_size,
						 wide);
	if (code[0] == 0x62)
		return writeEvexOutput(code, size, insn, insn_size, regs);
	if (code[0] == 0xc5 && size >= 4 && (code[3] & 0xc7) == 5)
		return writeVexRipLoad(code, size, insn, insn_size);
	const unsigned prefix = code[0] == 0xc5 ? 2 : 3;
	if (size >= prefix + 2 && code[prefix + 1] >= 0xc0)
		return writeVexRegisterOutput(code, size, insn, insn_size,
					      prefix);
	return writeVexIndexedOutput(code, size, insn, insn_size, regs);
}
/* A regular base, an unmasked destination and a full 128-bit memory tuple.
 * Indexed, absolute and RIP-relative addresses go through the ordinary reader. */
#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static bool writeEvexBroadcast(const uint8_t *code, size_t size, cs_insn *insn,
			       uint16_t *insn_size,
			       const struct X86SimpleRegister *regs)
{
	if (size < 6 || (code[1] & 15) != 2 || (code[2] & 0x7f) != 0x7d ||
	    (code[3] & 0x9f) != 8 || code[4] != 0x1a)
		return false;
	const unsigned ll = code[3] >> 5, w = code[2] >> 7;
	const uint8_t modrm = code[5];
	const unsigned mod = modrm >> 6, rm = modrm & 7;
	if (ll >= 3 || mod > 1 || (!mod && rm == 5))
		return false;
	const struct VectorOutputRow *row = &broadcast_rows[w][ll];
	const bool sib = rm == 4;
	const unsigned offset = 6 + sib, length = offset + mod;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	if (!row->id || size < length ||
	    (sib && ((rxb & 2) || code[6] != 0x24)))
		return false;
	const unsigned dst = ((modrm >> 3) & 7) | ((rxb & 4) << 1) |
			     (~(unsigned)code[1] & 16);
	const struct X86SimpleRegister *base = &regs[rm | ((rxb & 1) << 3)];
	const int displacement = mod ? (int8_t)code[offset] * 16 : 0;
	insn->id = row->id;
	*insn_size = insn->size = (uint16_t)length;
	memcpy(insn->bytes, code, length);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, ll, dst);
	memcpy(out, ", xmmword ptr [", 15);
	out += 15;
	memcpy(out, base->name, sizeof(base->name));
	out += base->length;
	if (displacement) {
		const unsigned mag = displacement < 0 ?
					     (unsigned)-displacement :
					     (unsigned)displacement;
		memcpy(out, displacement < 0 ? " - 0x" : " + 0x", 5);
		out += 5;
		static const char digits[] = "0123456789abcdef";
		if (mag >= 256)
			*out++ = digits[mag >> 8];
		*out++ = digits[(mag >> 4) & 15];
		*out++ = '0';
	}
	*out = ']';
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		d->groups_count = row->group_count;
		memcpy(d->groups, row->groups, sizeof(row->groups));
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, sizeof(x->opcode));
		x->rex = (uint8_t)(0x40 | w << 3 | rxb);
		x->addr_size = 8;
		x->modrm = modrm;
		x->encoding.modrm_offset = 5;
		if (mod) {
			x->encoding.disp_offset = (uint8_t)offset;
			x->encoding.disp_size = 1;
		}
		if (sib) {
			x->sib = code[6];
			x->sib_scale = 1;
			x->sib_base = (x86_reg)base->reg;
		}
		x->op_count = 2;
		cs_x86_op *op = &x->operands[0];
		op->type = X86_OP_REG;
		op->size = (uint8_t)(16u << ll);
		static const x86_reg vector_bases[] = { X86_REG_XMM0,
							X86_REG_YMM0,
							X86_REG_ZMM0 };
		op->reg = (x86_reg)(vector_bases[ll] + dst);
		op->access = (cs_ac_type)row->access[0];
		op = &x->operands[1];
		op->type = X86_OP_MEM;
		op->size = 16;
		op->mem.base = (x86_reg)base->reg;
		op->mem.scale = 1;
		op->mem.disp = x->disp = displacement;
		op->access = (cs_ac_type)row->access[1];
	}
	return true;
}

#endif
#endif

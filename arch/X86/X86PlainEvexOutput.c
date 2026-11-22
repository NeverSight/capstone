/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_plain_evex_text" rodata = \
	".cs_x86_plain_evex_rodata"
#endif
#include "X86OutputOptions.h"
#include "X86SimpleOutput.h"
#include "X86VectorRegisterOutput.h"

enum EvexRegisterOrder {
	EVEX_REGISTERS_THREE,
	EVEX_REGISTERS_PAIR,
	EVEX_REGISTERS_REVERSED
};
struct EvexRegisterOutput {
	struct VectorOutputRow instruction;
	uint8_t order;
};
#include "X86GenPlainEvexRegisterOutput.inc"

/* The caller identified six bytes with an EVEX prefix and register ModR/M. */
bool X86_writePlainEvexRegisters(cs_struct *handle, const uint8_t *code,
				 cs_insn *insn, uint16_t *insn_size)
{
	const unsigned map = code[1] & 15, flags = code[2], p2 = code[3];
	const unsigned ll = p2 >> 5;
	if (map < 1 || map > 3 || !(flags & 4) || (p2 & 0x97) || ll >= 3)
		return false;
	const unsigned prefix = plain_evex_opcodes[map - 1][code[4]];
	const unsigned w = flags >> 7;
	const unsigned row =
		plain_evex_prefixes[prefix][(w * 4 + (flags & 3)) * 3 + ll];
	if (!row)
		return false;
	const struct EvexRegisterOutput *record = &plain_evex_rows[row - 1];
	const bool pair = record->order != EVEX_REGISTERS_THREE;
	const unsigned src = ((~flags >> 3) & 15) | ((~p2 & 8) << 1);
	if ((pair && src != 0) || X86_OUTPUT_UNSUPPORTED(handle, false))
		return false;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	const unsigned reg = ((code[5] >> 3) & 7) | ((rxb & 4) << 1) |
			     (~(unsigned)code[1] & 16);
	const unsigned rm = (code[5] & 7) | ((rxb & 3) << 3);
	const bool reversed = record->order == EVEX_REGISTERS_REVERSED;
	const unsigned regs[] = { reversed ? rm : reg,
				  reversed ? reg : (pair ? rm : src), rm };
	return writeVectorRegisters(code, insn, insn_size, &record->instruction,
				    4, ll, 0x40 | (w << 3) | rxb, ll, regs,
				    pair ? 2 : 3);
}

#include "X86GenEvexRipMemory.inc"

/* The caller supplies ten readable bytes with an EVEX RIP-relative ModR/M. */
bool X86_writeEvexRipMemory(cs_struct *handle, const uint8_t *code,
			    cs_insn *insn, uint16_t *insn_size)
{
	const unsigned map = code[1] & 15, flags = code[2], p2 = code[3];
	const unsigned ll = p2 >> 5;
	if (map < 1 || map > 3 || !(flags & 4) || (p2 & 0x97) || ll >= 3)
		return false;
	const unsigned w = flags >> 7;
	const unsigned key = (w * 4 + (flags & 3)) * 3 + ll;
	if (!(evex_rip_forms[map - 1][code[4]] & (1u << key)))
		return false;
	const unsigned prefix = plain_evex_opcodes[map - 1][code[4]];
	const unsigned index = plain_evex_prefixes[prefix][key];
	if (!index ||
	    plain_evex_rows[index - 1].order != EVEX_REGISTERS_THREE ||
	    X86_OUTPUT_UNSUPPORTED(handle, false))
		return false;
	const struct VectorOutputRow *row =
		&plain_evex_rows[index - 1].instruction;
	const unsigned rxb = (~(unsigned)code[1] >> 5) & 7;
	const unsigned dst = ((code[5] >> 3) & 7) | ((rxb & 4) << 1) |
			     (~(unsigned)code[1] & 16);
	const unsigned src = ((~flags >> 3) & 15) | ((~p2 & 8) << 1);
	const int32_t displacement = X86_readDisp32(code + 6);
	insn->id = row->id;
	*insn_size = insn->size = 10;
	memcpy(insn->bytes, code, 10);
	memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
	memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
	memset(insn->op_str, 0, sizeof(insn->op_str));
	char *out = writeVectorRegister(insn->op_str, ll, dst);
	memcpy(out, ", ", 2);
	out = writeVectorRegister(out + 2, ll, src);
	memcpy(out, ", xmmword ptr [rip", 18);
	out[2] = "xyz"[ll];
	*X86_writeDisplacement(out + 18, displacement) = ']';
	if (insn->detail) {
		cs_detail *d = insn->detail;
		memset(d, 0, offsetof(cs_detail, x86) + sizeof(cs_x86));
		d->groups_count = row->group_count;
		memcpy(d->groups, row->groups, sizeof(row->groups));
		cs_x86 *x = &d->x86;
		memcpy(x->opcode, code, sizeof(x->opcode));
		x->rex = (uint8_t)(0x40 | (w << 3) | rxb);
		x->addr_size = 8;
		x->modrm = code[5];
		x->encoding.modrm_offset = 5;
		x->encoding.disp_offset = 6;
		x->encoding.disp_size = 4;
		x->disp = displacement;
		x->op_count = 3;
		static const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0,
						 X86_REG_ZMM0 };
		for (unsigned i = 0; i < 2; ++i) {
			cs_x86_op *op = &x->operands[i];
			op->type = X86_OP_REG;
			op->reg = (x86_reg)(bases[ll] + (i ? src : dst));
			op->size = (uint8_t)(16 << ll);
			op->access = (cs_ac_type)row->access[i];
		}
		cs_x86_op *mem = &x->operands[2];
		mem->type = X86_OP_MEM;
		mem->mem.base = X86_REG_RIP;
		mem->mem.scale = 1;
		mem->mem.disp = displacement;
		mem->size = (uint8_t)(16 << ll);
		mem->access = (cs_ac_type)row->access[2];
	}
	return true;
}
#endif
#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include "../../MCInstrDesc.h"
#include "../../utils.h"
#include "../../arch/AArch64/AArch64BaseInfo.h"
#include "../../arch/AArch64/AArch64Mapping.h"

#define GET_INSTRINFO_MC_DESC
#include "../../arch/AArch64/AArch64GenInstrInfo.inc"
#include "../../arch/AArch64/AArch64GenPostprocess.inc"

static bool check_addressing_details(void)
{
	static const struct {
		const char *name;
		uint8_t bytes[4];
		unsigned id, reg, base;
		int displacement;
		bool writeback, post_index;
		unsigned post_reg;
	} cases[] = {
		/* Existing basic-a64-instructions.s.yaml encodings. */
		{ "ldr x0, [x0]",
		  { 0x00, 0x00, 0x40, 0xf9 },
		  AARCH64_INS_LDR,
		  AARCH64_REG_X0,
		  AARCH64_REG_X0,
		  0,
		  false,
		  false,
		  AARCH64_REG_INVALID },
		{ "ldr x2, [x3, #1]!",
		  { 0x62, 0x1c, 0x40, 0xf8 },
		  AARCH64_INS_LDR,
		  AARCH64_REG_X2,
		  AARCH64_REG_X3,
		  1,
		  true,
		  false,
		  AARCH64_REG_INVALID },
		{ "ldr x2, [x3], #1",
		  { 0x62, 0x14, 0x40, 0xf8 },
		  AARCH64_INS_LDR,
		  AARCH64_REG_X2,
		  AARCH64_REG_X3,
		  1,
		  true,
		  true,
		  AARCH64_REG_INVALID },
		/* neon-simd-post-ldst-multi-elem.s.yaml: register post-increment. */
		{ "ld1 { v0.16b }, [x0], x1",
		  { 0x00, 0x70, 0xc1, 0x4c },
		  AARCH64_INS_LD1,
		  AARCH64_REG_Q0,
		  AARCH64_REG_X0,
		  0,
		  true,
		  true,
		  AARCH64_REG_X1 },
	};
	csh handle;
	if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &handle) !=
	    CS_ERR_OK)
		return false;
	bool result = false;
	cs_insn *insn = NULL;
	/* DIET omits text, but the printer still constructs operand details. */
	if (cs_option(handle, CS_OPT_TEXT, CS_OPT_ON) != CS_ERR_OK ||
	    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		goto done;
	insn = cs_malloc(handle);
	if (!insn)
		goto done;
	for (unsigned i = 0; i < ARR_SIZE(cases); ++i) {
		const uint8_t *cursor = cases[i].bytes;
		size_t left = sizeof(cases[i].bytes);
		uint64_t address = 0x1000;
		if (!cs_disasm_iter(handle, &cursor, &left, &address, insn) ||
		    insn->id != cases[i].id || insn->size != 4 || left != 0 ||
		    cursor != cases[i].bytes + 4 || address != 0x1004) {
			fprintf(stderr, "%s: decoding failed\n", cases[i].name);
			goto done;
		}
		const cs_aarch64 *detail = &insn->detail->aarch64;
		const cs_aarch64_op *reg = &detail->operands[0];
		const cs_aarch64_op *mem = &detail->operands[1];
		unsigned count = cases[i].post_reg == AARCH64_REG_INVALID ? 2 :
									    3;
		if (detail->op_count != count ||
		    insn->detail->writeback != cases[i].writeback ||
		    detail->post_index != cases[i].post_index ||
		    reg->type != AARCH64_OP_REG || reg->reg != cases[i].reg ||
		    mem->type != AARCH64_OP_MEM ||
		    mem->mem.base != cases[i].base ||
		    mem->mem.index != AARCH64_REG_INVALID ||
		    mem->mem.disp != cases[i].displacement ||
		    (count == 3 &&
		     (detail->operands[2].type != AARCH64_OP_REG ||
		      detail->operands[2].reg != cases[i].post_reg))) {
			fprintf(stderr,
				"%s: count=%u writeback=%u post_index=%u base=%u displacement=%lld\n",
				cases[i].name, (unsigned)detail->op_count,
				(unsigned)insn->detail->writeback,
				(unsigned)detail->post_index,
				(unsigned)mem->mem.base,
				(long long)mem->mem.disp);
			goto done;
		}
	}
	result = true;
done:
	if (insn)
		cs_free(insn, 1);
	cs_close(&handle);
	return result;
}

static bool check_matrix_details(void)
{
	/* Encodings from tests/MC/AArch64/SME/{ld1b,ld1h,ld1w,ld1d,ld1q,fmopa}.s.yaml. */
	static const struct {
		const char *name;
		uint8_t bytes[4];
		unsigned id, count;
		aarch64_reg tile, slice_reg;
		AArch64Layout_VectorLayout vas;
		uint16_t slice_offset;
		bool vertical;
	} cases[] = {
		{ "ld1b {za0h.b[w12, 0]}, p0/z, [x0, x0]",
		  { 0x00, 0x00, 0x00, 0xe0 },
		  AARCH64_INS_LD1B,
		  3,
		  AARCH64_REG_ZAB0,
		  AARCH64_REG_W12,
		  AARCH64LAYOUT_VL_B,
		  0,
		  false },
		{ "ld1h {za1v.h[w15, 7]}, p7/z, [sp]",
		  { 0xef, 0xff, 0x5f, 0xe0 },
		  AARCH64_INS_LD1H,
		  3,
		  AARCH64_REG_ZAH1,
		  AARCH64_REG_W15,
		  AARCH64LAYOUT_VL_H,
		  7,
		  true },
		{ "ld1w {za3v.s[w15, 3]}, p7/z, [sp]",
		  { 0xef, 0xff, 0x9f, 0xe0 },
		  AARCH64_INS_LD1W,
		  3,
		  AARCH64_REG_ZAS3,
		  AARCH64_REG_W15,
		  AARCH64LAYOUT_VL_S,
		  3,
		  true },
		{ "ld1d {za7h.d[w15, 1]}, p7/z, [sp]",
		  { 0xef, 0x7f, 0xdf, 0xe0 },
		  AARCH64_INS_LD1D,
		  3,
		  AARCH64_REG_ZAD7,
		  AARCH64_REG_W15,
		  AARCH64LAYOUT_VL_D,
		  1,
		  false },
		{ "ld1q {za15v.q[w15, 0]}, p7/z, [sp]",
		  { 0xef, 0xff, 0xdf, 0xe1 },
		  AARCH64_INS_LD1Q,
		  3,
		  AARCH64_REG_ZAQ15,
		  AARCH64_REG_W15,
		  AARCH64LAYOUT_VL_Q,
		  0,
		  true },
		{ "fmopa za0.s, p0/m, p0/m, z0.h, z0.h",
		  { 0x00, 0x00, 0xa0, 0x81 },
		  AARCH64_INS_FMOPA,
		  5,
		  AARCH64_REG_ZAS0,
		  AARCH64_REG_INVALID,
		  AARCH64LAYOUT_VL_S,
		  AARCH64_SLICE_IMM_INVALID,
		  false },
	};
	csh handle;
	if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &handle) !=
	    CS_ERR_OK)
		return false;
	bool result = false;
	cs_insn *insn = NULL;
	if (cs_option(handle, CS_OPT_TEXT, CS_OPT_ON) != CS_ERR_OK ||
	    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		goto done;
	insn = cs_malloc(handle);
	if (!insn)
		goto done;
	for (unsigned i = 0; i < ARR_SIZE(cases); ++i) {
		const uint8_t *cursor = cases[i].bytes;
		size_t left = sizeof(cases[i].bytes);
		uint64_t address = 0x1000;
		if (!cs_disasm_iter(handle, &cursor, &left, &address, insn) ||
		    insn->id != cases[i].id || insn->size != 4 || left != 0 ||
		    cursor != cases[i].bytes + 4 || address != 0x1004) {
			fprintf(stderr, "%s: decoding failed\n", cases[i].name);
			goto done;
		}
		const cs_aarch64 *detail = &insn->detail->aarch64;
		const cs_aarch64_op *op = &detail->operands[0];
		aarch64_sme_op_type type = cases[i].slice_reg ==
							   AARCH64_REG_INVALID ?
						   AARCH64_SME_OP_TILE :
						   AARCH64_SME_OP_TILE_VEC;
		if (detail->op_count != cases[i].count ||
		    detail->is_doing_sme || op->type != AARCH64_OP_SME ||
		    op->vas != cases[i].vas || op->sme.type != type ||
		    op->sme.tile != cases[i].tile ||
		    op->sme.slice_reg != cases[i].slice_reg ||
		    op->sme.slice_offset.imm != cases[i].slice_offset ||
		    op->sme.has_range_offset ||
		    op->sme.is_vertical != cases[i].vertical) {
			fprintf(stderr,
				"%s: count=%u type=%u tile=%u vas=%u slice=%u offset=%u vertical=%u\n",
				cases[i].name, (unsigned)detail->op_count,
				(unsigned)op->type, (unsigned)op->sme.tile,
				(unsigned)op->vas, (unsigned)op->sme.slice_reg,
				(unsigned)op->sme.slice_offset.imm,
				(unsigned)op->sme.is_vertical);
			goto done;
		}
	}
	result = true;
done:
	if (insn)
		cs_free(insn, 1);
	cs_close(&handle);
	return result;
}

/* Evaluate the real descriptor objects with native enum/constraint values,
 * independently of the generator's source parser. */
int main(void)
{
	unsigned implicit = 0, tied = 0;
	for (unsigned opcode = 0; opcode < ARR_SIZE(AArch64Descs.Insts);
	     ++opcode) {
		const MCInstrDesc *desc =
			&AArch64Descs.Insts[ARR_SIZE(AArch64Descs.Insts) - 1 -
					    opcode];
		unsigned flags = 0;
		for (unsigned i = 0; i < desc->NumOperands; ++i) {
			const MCOperandInfo *op = &desc->OpInfo[i];
			if (op->OperandType == AARCH64_OP_IMPLICIT_IMM_0 ||
			    (op->OperandType == MCOI_OPERAND_REGISTER &&
			     (op->RegClass == AArch64_MPRRegClassID ||
			      op->RegClass == AArch64_MPR8RegClassID ||
			      op->RegClass == AArch64_ZTRRegClassID)))
				flags |= 1;
			if (MCOperandInfo_isTiedToOp(op))
				flags |= 2;
		}
		if (flags != AArch64PostprocessFlags[opcode]) {
			fprintf(stderr, "projection mismatch %u\n", opcode);
			return 1;
		}
		implicit += !!(flags & 1);
		tied += !!(flags & 2);
	}
	printf("%zu descriptors equal: %u implicit, %u tied\n",
	       ARR_SIZE(AArch64Descs.Insts), implicit, tied);
	return check_addressing_details() && check_matrix_details() ? 0 : 1;
}

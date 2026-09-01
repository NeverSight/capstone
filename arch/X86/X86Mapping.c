/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_X86

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#endif

#include <string.h>
#ifndef CAPSTONE_HAS_OSXKERNEL
#include <stdlib.h>
#endif

#include "../../Mapping.h"
#include "../../MCInstPrinter.h"
#include "X86FeatureExtension.h"
#include "X86Mapping.h"
#include "X86DisassemblerDecoder.h"

#include "../../utils.h"

const uint64_t arch_masks[9] = {
	0,
	0xff,
	0xffff, // 16bit
	0,
	0xffffffff, // 32bit
	0,
	0,
	0,
	0xffffffffffffffffLL // 64bit
};

typedef struct x86_feature_memory {
	x86_reg base;
	x86_reg index;
	int8_t scale;
	int64_t displacement;
	uint8_t displacement_offset;
	uint8_t displacement_size;
	uint8_t sib;
	bool has_sib;
	size_t length;
} x86_feature_memory;

static x86_reg rex2_register(unsigned int number, uint8_t width);
static bool is_apx_evex_segment_prefix(uint8_t byte);
static x86_reg apx_segment_register(uint8_t prefix);

static int32_t read_i32(const uint8_t *bytes)
{
	uint32_t value = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
			 ((uint32_t)bytes[2] << 16) |
			 ((uint32_t)bytes[3] << 24);
	return (int32_t)value;
}

static int16_t read_i16(const uint8_t *bytes)
{
	uint16_t value = (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
	return (int16_t)value;
}

static uint64_t read_u64(const uint8_t *bytes)
{
	uint64_t value = 0;
	unsigned int i;

	for (i = 0; i < 8; ++i)
		value |= (uint64_t)bytes[i] << (i * 8);
	return value;
}

static bool decode_feature_memory(const uint8_t *code, size_t code_len,
				  size_t modrm_offset, bool require_sib,
				  bool address32, unsigned int base_extension,
				  unsigned int index_extension,
				  x86_feature_memory *memory)
{
	uint8_t modrm, mod, rm;
	size_t cursor = modrm_offset + 1;
	uint8_t displacement_size = 0;
	const uint8_t address_width = address32 ? 4 : 8;

	if (code_len <= modrm_offset)
		return false;

	memset(memory, 0, sizeof(*memory));
	memory->base = X86_REG_INVALID;
	memory->index = X86_REG_INVALID;
	memory->scale = 1;
	modrm = code[modrm_offset];
	mod = modrm >> 6;
	rm = modrm & 7;
	if (mod == 3 || (require_sib && rm != 4))
		return false;

	if (rm == 4) {
		uint8_t base_number, index_number;

		if (cursor >= code_len)
			return false;
		memory->has_sib = true;
		memory->sib = code[cursor++];
		memory->scale = (int8_t)(1U << (memory->sib >> 6));
		index_number = (memory->sib >> 3) & 7;
		base_number = memory->sib & 7;
		if (index_number != 4 || index_extension != 0)
			memory->index = rex2_register(
				index_number + index_extension, address_width);
		if (mod == 0 && base_number == 5) {
			displacement_size = 4;
		} else {
			memory->base = rex2_register(
				base_number + base_extension, address_width);
		}
	} else if (mod == 0 && rm == 5) {
		memory->base = address32 ? X86_REG_EIP : X86_REG_RIP;
		displacement_size = 4;
	} else {
		memory->base =
			rex2_register(rm + base_extension, address_width);
	}

	if (memory->base == X86_REG_INVALID &&
	    !(mod == 0 && (rm == 5 || memory->has_sib))) {
		return false;
	}
	if (memory->index == X86_REG_INVALID && memory->has_sib &&
	    (((memory->sib >> 3) & 7) != 4 || index_extension != 0)) {
		return false;
	}

	if (mod == 1)
		displacement_size = 1;
	else if (mod == 2)
		displacement_size = 4;

	if (displacement_size != 0) {
		if (code_len - cursor < displacement_size)
			return false;
		memory->displacement_offset = (uint8_t)cursor;
		memory->displacement_size = displacement_size;
		if (displacement_size == 1)
			memory->displacement = (int8_t)code[cursor];
		else
			memory->displacement = read_i32(&code[cursor]);
		cursor += displacement_size;
	}

	if (cursor > 15)
		return false;
	memory->length = cursor;
	return true;
}

static bool decode_feature_memory16(const uint8_t *code, size_t code_len,
				    size_t modrm_offset,
				    x86_feature_memory *memory)
{
	static const x86_reg bases[8] = {
		X86_REG_BX, X86_REG_BX, X86_REG_BP, X86_REG_BP,
		X86_REG_SI, X86_REG_DI, X86_REG_BP, X86_REG_BX,
	};
	static const x86_reg indexes[8] = {
		X86_REG_SI, X86_REG_DI, X86_REG_SI, X86_REG_DI,
		X86_REG_INVALID, X86_REG_INVALID, X86_REG_INVALID,
		X86_REG_INVALID,
	};
	uint8_t modrm, mod, rm, displacement_size = 0;
	size_t cursor = modrm_offset + 1;

	if (code_len <= modrm_offset)
		return false;
	memset(memory, 0, sizeof(*memory));
	memory->base = X86_REG_INVALID;
	memory->index = X86_REG_INVALID;
	memory->scale = 1;
	modrm = code[modrm_offset];
	mod = modrm >> 6;
	rm = modrm & 7;
	if (mod == 3)
		return false;

	if (mod == 0 && rm == 6) {
		displacement_size = 2;
	} else {
		memory->base = bases[rm];
		memory->index = indexes[rm];
		if (mod == 1)
			displacement_size = 1;
		else if (mod == 2)
			displacement_size = 2;
	}

	if (displacement_size != 0) {
		if (code_len - cursor < displacement_size)
			return false;
		memory->displacement_offset = (uint8_t)cursor;
		memory->displacement_size = displacement_size;
		if (displacement_size == 1)
			memory->displacement = (int8_t)code[cursor];
		else if (mod == 0)
			memory->displacement =
				(uint16_t)code[cursor] |
				((uint16_t)code[cursor + 1] << 8);
		else
			memory->displacement = read_i16(&code[cursor]);
		cursor += displacement_size;
	}

	if (cursor > 15)
		return false;
	memory->length = cursor;
	return true;
}

static void set_amx_tile_encoding_detail(MCInst *instr, const uint8_t *code,
					 size_t encoding_offset,
					 uint8_t encoding_size,
					 uint8_t segment_prefix, bool address32,
					 size_t modrm_offset,
					 const x86_feature_memory *memory)
{
	cs_x86 *x86;
	uint8_t i;

	if (!instr->flat_insn->detail)
		return;
	x86 = &instr->flat_insn->detail->x86;
	for (i = 0; i < encoding_size; ++i)
		x86->opcode[i] = code[encoding_offset + i];
	x86->prefix[1] = segment_prefix;
	x86->prefix[3] = address32 ? 0x67 : 0;
	instr->x86_prefix[1] = segment_prefix;
	instr->x86_prefix[3] = address32 ? 0x67 : 0;
	x86->addr_size = address32 ? 4 : 8;
	x86->modrm = code[modrm_offset];
	x86->encoding.modrm_offset = (uint8_t)modrm_offset;
	if (!memory)
		return;

	x86->sib = memory->sib;
	x86->sib_base = memory->has_sib ? memory->base : X86_REG_INVALID;
	x86->sib_index = memory->has_sib ? memory->index : X86_REG_INVALID;
	x86->sib_scale = memory->has_sib ? memory->scale : 0;
	x86->disp = memory->displacement;
	x86->encoding.disp_offset = memory->displacement_offset;
	x86->encoding.disp_size = memory->displacement_size;
}

static void set_amx_encoding_detail(MCInst *instr, const uint8_t *code,
				    const x86_feature_memory *memory)
{
	cs_x86 *x86;

	if (!instr->flat_insn->detail)
		return;

	x86 = &instr->flat_insn->detail->x86;
	x86->opcode[0] = code[0];
	x86->opcode[1] = code[1];
	x86->opcode[2] = code[2];
	x86->addr_size = 8;
	x86->modrm = code[4];
	x86->encoding.modrm_offset = 4;
	if (!memory)
		return;

	x86->sib = memory->sib;
	x86->sib_base = memory->has_sib ? memory->base : X86_REG_INVALID;
	x86->sib_index = memory->has_sib ? memory->index : X86_REG_INVALID;
	x86->sib_scale = memory->has_sib ? memory->scale : 0;
	x86->disp = memory->displacement;
	x86->encoding.disp_offset = memory->displacement_offset;
	x86->encoding.disp_size = memory->displacement_size;
}

static void add_feature_memory_operands(MCInst *instr,
					x86_feature_memory *memory)
{
	MCOperand_CreateImm0(instr, memory->base);
	MCOperand_CreateImm0(instr, memory->index);
	MCOperand_CreateImm0(instr, memory->scale);
	MCOperand_CreateImm0(instr, memory->displacement);
}

static bool is_amx_compute_opcode(uint8_t map, uint8_t opcode)
{
	if (map == 5)
		return opcode == 0xfd;
	return map == 2 && (opcode == 0x48 || opcode == 0x5c ||
			    opcode == 0x5e || opcode == 0x6c);
}

static unsigned int amx_compute_feature_opcode(uint8_t map, uint8_t vex3,
					       uint8_t opcode)
{
	uint8_t prefix = vex3 & 3;

	// All implemented forms are VEX.L0.W0 and use only TMM0-TMM7.
	if ((vex3 & 0x84) || !(vex3 & 0x40))
		return 0;
	if (map == 5) {
		if (opcode != 0xfd)
			return 0;
		if (prefix == 0)
			return X86_FEATURE_TDPBF8PS;
		if (prefix == 3)
			return X86_FEATURE_TDPBHF8PS;
		if (prefix == 2)
			return X86_FEATURE_TDPHBF8PS;
		if (prefix == 1)
			return X86_FEATURE_TDPHF8PS;
		return 0;
	}
	if (map != 2)
		return 0;

	switch (opcode) {
	default:
		return 0;
	case 0x48:
		return prefix == 1 ? X86_FEATURE_TMMULTF32PS : 0;
	case 0x5c:
		if (prefix == 2)
			return X86_FEATURE_TDPBF16PS;
		if (prefix == 3)
			return X86_FEATURE_TDPFP16PS;
		return 0;
	case 0x5e:
		switch (prefix) {
		default:
			return 0;
		case 0:
			return X86_FEATURE_TDPBUUD;
		case 1:
			return X86_FEATURE_TDPBUSD;
		case 2:
			return X86_FEATURE_TDPBSUD;
		case 3:
			return X86_FEATURE_TDPBSSD;
		}
	case 0x6c:
		if (prefix == 0)
			return X86_FEATURE_TCMMRLFP16PS;
		if (prefix == 1)
			return X86_FEATURE_TCMMIMFP16PS;
		return 0;
	}
}

static bool decode_amx_compute(uint8_t map, const uint8_t *code, MCInst *instr,
			       uint16_t *size)
{
	uint8_t vex3 = code[2];
	uint8_t modrm = code[4];
	unsigned int feature_opcode =
		amx_compute_feature_opcode(map, vex3, code[3]);
	unsigned int destination, source2, source3;

	// VEX.X is ignored for this register-only form. R and B must not select
	// nonexistent extended tile registers.
	if (feature_opcode == 0 || (code[1] & 0xbf) != (0xa0 | map) ||
	    (modrm & 0xc0) != 0xc0) {
		return false;
	}
	destination = (modrm >> 3) & 7;
	source2 = modrm & 7;
	source3 = (~(vex3 >> 3)) & 0xf;
	if (source3 > 7 || destination == source2 || destination == source3 ||
	    source2 == source3) {
		return false;
	}

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, destination);
	MCOperand_CreateImm0(instr, source2);
	MCOperand_CreateImm0(instr, source3);
	*size = 5;
	set_amx_encoding_detail(instr, code, NULL);
	return true;
}

static unsigned int amx_row_feature_opcode(uint8_t map, uint8_t opcode,
					   uint8_t prefix, bool *immediate)
{
	*immediate = map == 3;
	if (map == 2) {
		if (opcode == 0x4a) {
			if (prefix == 1)
				return X86_FEATURE_TILEMOVROW;
			if (prefix == 2)
				return X86_FEATURE_TCVTROWD2PS;
			return 0;
		}
		if (opcode != 0x6d)
			return 0;
		switch (prefix) {
		default:
			return 0;
		case 0:
			return X86_FEATURE_TCVTROWPS2PHH;
		case 1:
			return X86_FEATURE_TCVTROWPS2PHL;
		case 2:
			return X86_FEATURE_TCVTROWPS2BF16L;
		case 3:
			return X86_FEATURE_TCVTROWPS2BF16H;
		}
	}
	if (map != 3)
		return 0;
	if (opcode == 0x07) {
		switch (prefix) {
		default:
			return 0;
		case 0:
			return X86_FEATURE_TCVTROWPS2PHH;
		case 1:
			return X86_FEATURE_TILEMOVROW;
		case 2:
			return X86_FEATURE_TCVTROWD2PS;
		case 3:
			return X86_FEATURE_TCVTROWPS2BF16H;
		}
	}
	if (opcode == 0x77) {
		if (prefix == 2)
			return X86_FEATURE_TCVTROWPS2BF16L;
		if (prefix == 3)
			return X86_FEATURE_TCVTROWPS2PHL;
	}
	return 0;
}

static x86_feature_decode_result decode_amx_row(csh handle, const uint8_t *code,
						size_t code_len, MCInst *instr,
						uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t encoding_offset = 0, modrm_offset, instruction_size;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false, immediate;
	uint8_t p0, p1, p2, opcode, modrm, map, prefix;
	unsigned int feature_opcode, destination_number, tile_number;
	x86_reg destination, tile, selector = X86_REG_INVALID;
	uint8_t immediate_value = 0;

	while (encoding_offset < code_len && code[encoding_offset] != 0x62) {
		uint8_t legacy_prefix = code[encoding_offset];

		if (is_apx_evex_segment_prefix(legacy_prefix)) {
			segment_prefix = legacy_prefix;
		} else if (legacy_prefix == 0x67) {
			address32 = true;
		} else if (legacy_prefix == 0x66 || legacy_prefix == 0xf0 ||
			   legacy_prefix == 0xf2 || legacy_prefix == 0xf3 ||
			   (legacy_prefix >= 0x40 && legacy_prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++encoding_offset;
	}
	if (encoding_offset == code_len || code_len - encoding_offset < 5)
		return X86_FEATURE_NOT_HANDLED;
	p0 = code[encoding_offset + 1];
	p1 = code[encoding_offset + 2];
	p2 = code[encoding_offset + 3];
	opcode = code[encoding_offset + 4];
	map = p0 & 7;
	prefix = p1 & 3;
	feature_opcode =
		amx_row_feature_opcode(map, opcode, prefix, &immediate);
	if (feature_opcode == 0)
		return X86_FEATURE_NOT_HANDLED;

	modrm_offset = encoding_offset + 5;
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    modrm_offset >= code_len) {
		return X86_FEATURE_INVALID;
	}
	modrm = code[modrm_offset];
	// MAP2/66/4A shares its memory form with TILELOADDRST1.  Defer that
	// encoding before interpreting X'/B' and VL as row-move fields.
	if (feature_opcode == X86_FEATURE_TILEMOVROW && map == 2 &&
	    (modrm & 0xc0) != 0xc0) {
		return X86_FEATURE_NOT_HANDLED;
	}
	// EVEX.X'/B' cannot select nonexistent extended TMM registers.  B4 is
	// ignored because the r/m operand is a tile rather than a GPR.
	// W, U, VL, z, b, and aaa are fixed by AMX-E7/E8.
	if ((p0 & 0x60) != 0x60 || (p1 & 0x84) != 0x04 || (p2 & 0xf7) != 0x40) {
		return X86_FEATURE_INVALID;
	}
	if ((modrm & 0xc0) != 0xc0) {
		return X86_FEATURE_INVALID;
	}
	if (immediate) {
		// The immediate form has no EVEX.vvvv/V' operand.
		if ((p1 & 0x78) != 0x78 || !(p2 & 0x08) ||
		    modrm_offset + 1 >= code_len) {
			return X86_FEATURE_INVALID;
		}
		immediate_value = code[modrm_offset + 1];
		instruction_size = modrm_offset + 2;
	} else {
		unsigned int selector_number = ((~p1 >> 3) & 0xf) |
					       ((~p2 & 0x08) << 1);

		selector = rex2_register(selector_number, 4);
		if (selector == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		instruction_size = modrm_offset + 1;
	}
	if (instruction_size > 15)
		return X86_FEATURE_INVALID;

	destination_number = ((modrm >> 3) & 7) | ((~p0 & 0x80) >> 4) |
			     (~p0 & 0x10);
	tile_number = modrm & 7;
	destination = X86_REG_ZMM0 + destination_number;
	tile = X86_REG_TMM0 + tile_number;

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, destination);
	MCOperand_CreateImm0(instr, tile);
	MCOperand_CreateImm0(instr, immediate ? immediate_value : selector);
	MCOperand_CreateImm0(instr, immediate ? 1 : 0);
	*size = (uint16_t)instruction_size;
	set_amx_tile_encoding_detail(instr, code, encoding_offset, 4,
				     segment_prefix, address32, modrm_offset,
				     NULL);
	if (immediate) {
		instr->imm_size = 1;
		if (instr->flat_insn->detail) {
			cs_x86 *x86 = &instr->flat_insn->detail->x86;

			x86->encoding.imm_offset = (uint8_t)(modrm_offset + 1);
			x86->encoding.imm_size = 1;
		}
	}
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_amx_tile(csh handle,
						 const uint8_t *code,
						 size_t code_len, MCInst *instr,
						 uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t encoding_offset = 0;
	size_t modrm_offset;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false;
	bool evex;
	uint8_t p0, p1, p2 = 0, opcode, modrm, encoding_size;
	unsigned int feature_opcode = 0;
	x86_feature_memory memory;
	bool has_memory = false;
	bool has_tile = false;
	unsigned int tile = 0;
	unsigned int base_extension = 0, index_extension = 0;
	x86_reg segment;

	while (encoding_offset < code_len && code[encoding_offset] != 0xc4 &&
	       code[encoding_offset] != 0x62) {
		uint8_t prefix = code[encoding_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			   prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++encoding_offset;
	}
	if (encoding_offset == code_len)
		return X86_FEATURE_NOT_HANDLED;
	evex = code[encoding_offset] == 0x62;
	encoding_size = evex ? 4 : 3;
	if (code_len - encoding_offset < encoding_size + 1)
		return X86_FEATURE_NOT_HANDLED;
	p0 = code[encoding_offset + 1];
	p1 = code[encoding_offset + 2];
	if (evex)
		p2 = code[encoding_offset + 3];
	opcode = code[encoding_offset + encoding_size];
	if ((evex ? (p0 & 7) != 2 : (p0 & 0x1f) != 2) ||
	    (opcode != 0x49 && opcode != 0x4a && opcode != 0x4b)) {
		return X86_FEATURE_NOT_HANDLED;
	}
	modrm_offset = encoding_offset + encoding_size + 1;
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    modrm_offset >= code_len || modrm_offset + 1 > 15) {
		return X86_FEATURE_INVALID;
	}
	modrm = code[modrm_offset];

	if (evex) {
		uint8_t pp = p1 & 3;

		// APX-promoted VEX instructions preserve VEX.vvvv = 1111,
		// require W0/128-bit vector length, and do not support NF.
		if ((p1 & 0xf8) != 0x78 || p2 != 0x08)
			return X86_FEATURE_INVALID;
		if (opcode == 0x49) {
			if ((modrm & 0xc0) == 0xc0 || (modrm & 0x38) != 0)
				return X86_FEATURE_INVALID;
			if (pp == 0)
				feature_opcode = X86_FEATURE_LDTILECFG;
			else if (pp == 1)
				feature_opcode = X86_FEATURE_STTILECFG;
			else
				return X86_FEATURE_INVALID;
		} else {
			// R3/R4 cannot select a nonexistent extended tile register.
			if ((p0 & 0x90) != 0x90 || (modrm & 0xc0) == 0xc0 ||
			    (modrm & 7) != 4) {
				return X86_FEATURE_INVALID;
			}
			if (opcode == 0x4a) {
				if (pp == 1)
					feature_opcode =
						X86_FEATURE_TILELOADDRST1;
				else if (pp == 3)
					feature_opcode =
						X86_FEATURE_TILELOADDRS;
				else
					return X86_FEATURE_INVALID;
			} else if (pp == 1) {
				feature_opcode = X86_FEATURE_TILELOADDT1;
			} else if (pp == 2) {
				feature_opcode = X86_FEATURE_TILESTORED;
			} else if (pp == 3) {
				feature_opcode = X86_FEATURE_TILELOADD;
			} else {
				return X86_FEATURE_INVALID;
			}
			has_tile = true;
			tile = (modrm >> 3) & 7;
		}
		has_memory = true;
		base_extension = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1);
		index_extension = ((~p0 & 0x40) >> 3) | ((~p1 & 0x04) << 2);
	} else if (opcode == 0x49) {
		if (p1 == 0x78 && modrm == 0xc0) {
			// VEX.R/X/B are ignored by the operand-free form.
			feature_opcode = X86_FEATURE_TILERELEASE;
		} else if (p1 == 0x78 || p1 == 0x79) {
			// VEX.R is ignored for the /0 opcode extension.
			if ((modrm & 0xc0) == 0xc0 || (modrm & 0x38) != 0)
				return X86_FEATURE_INVALID;
			feature_opcode = p1 == 0x78 ? X86_FEATURE_LDTILECFG :
						      X86_FEATURE_STTILECFG;
			has_memory = true;
		} else if (p1 == 0x7b) {
			// VEX.X/B are ignored; VEX.R must name TMM0-TMM7.
			if (!(p0 & 0x80) || (modrm & 0xc7) != 0xc0)
				return X86_FEATURE_INVALID;
			feature_opcode = X86_FEATURE_TILEZERO;
			has_tile = true;
			tile = (modrm >> 3) & 7;
		} else {
			return X86_FEATURE_INVALID;
		}
		base_extension = (p0 & 0x20) ? 0 : 8;
		index_extension = (p0 & 0x40) ? 0 : 8;
	} else {
		if (!(p0 & 0x80) || (modrm & 0xc0) == 0xc0 ||
		    (modrm & 7) != 4) {
			return X86_FEATURE_INVALID;
		}
		if (opcode == 0x4a) {
			if (p1 == 0x79)
				feature_opcode = X86_FEATURE_TILELOADDRST1;
			else if (p1 == 0x7b)
				feature_opcode = X86_FEATURE_TILELOADDRS;
			else
				return X86_FEATURE_INVALID;
		} else if (p1 == 0x79) {
			feature_opcode = X86_FEATURE_TILELOADDT1;
		} else if (p1 == 0x7a) {
			feature_opcode = X86_FEATURE_TILESTORED;
		} else if (p1 == 0x7b) {
			feature_opcode = X86_FEATURE_TILELOADD;
		} else {
			return X86_FEATURE_INVALID;
		}
		has_memory = true;
		has_tile = true;
		tile = (modrm >> 3) & 7;
		base_extension = (p0 & 0x20) ? 0 : 8;
		index_extension = (p0 & 0x40) ? 0 : 8;
	}

	if (has_memory &&
	    !decode_feature_memory(code, code_len, modrm_offset, opcode != 0x49,
				   address32, base_extension, index_extension,
				   &memory)) {
		return X86_FEATURE_INVALID;
	}

	segment = apx_segment_register(segment_prefix);
	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	if (has_tile)
		MCOperand_CreateImm0(instr, tile);
	if (has_memory) {
		add_feature_memory_operands(instr, &memory);
		MCOperand_CreateImm0(instr, segment);
		MCOperand_CreateImm0(instr, address32 ? 4 : 8);
	}
	*size = (uint16_t)(has_memory ? memory.length : modrm_offset + 1);
	set_amx_tile_encoding_detail(instr, code, encoding_offset,
				     encoding_size, segment_prefix, address32,
				     modrm_offset, has_memory ? &memory : NULL);
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_amx(csh handle, const uint8_t *code,
					    size_t code_len, MCInst *instr,
					    uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	x86_feature_decode_result result =
		decode_amx_row(handle, code, code_len, instr, size);
	uint8_t vex2, map, opcode;

	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_amx_tile(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	if (code_len < 4 || code[0] != 0xc4)
		return X86_FEATURE_NOT_HANDLED;
	vex2 = code[1];
	map = vex2 & 0x1f;
	opcode = code[3];
	if (map != 2 && map != 5)
		return X86_FEATURE_NOT_HANDLED;
	if (map == 2 && !is_amx_compute_opcode(map, opcode)) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (map == 5 && !is_amx_compute_opcode(map, opcode))
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || code_len < 5)
		return X86_FEATURE_INVALID;
	if (!(vex2 & 0x80))
		return X86_FEATURE_INVALID;
	return decode_amx_compute(map, code, instr, size) ?
		       X86_FEATURE_DECODED :
		       X86_FEATURE_INVALID;
}

static bool is_rex2_leading_prefix(uint8_t byte);

static x86_feature_decode_result
decode_rex2_push_pop(csh handle, const uint8_t *code, size_t code_len,
		     MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t rex2_offset = 0;
	uint8_t segment_prefix = 0;
	uint8_t repeat_prefix = 0;
	bool operand_size_prefix = false;
	bool address_size_prefix = false;
	bool invalid_prefix = false;
	bool effective_rex = false;
	uint8_t payload, opcode, width;
	unsigned int number, feature_opcode;
	x86_reg reg;
	cs_x86 *x86;

	if (!(arch->mode & CS_MODE_64))
		return X86_FEATURE_NOT_HANDLED;

	while (rex2_offset < code_len && code[rex2_offset] != 0xd5) {
		uint8_t prefix = code[rex2_offset];

		if (!is_rex2_leading_prefix(prefix))
			return X86_FEATURE_NOT_HANDLED;
		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
			effective_rex = false;
		} else if (prefix == 0x66) {
			operand_size_prefix = true;
			effective_rex = false;
		} else if (prefix == 0x67) {
			address_size_prefix = true;
			effective_rex = false;
		} else if (prefix == 0xf2 || prefix == 0xf3) {
			repeat_prefix = prefix;
			effective_rex = false;
		} else if (prefix >= 0x40 && prefix <= 0x4f) {
			effective_rex = true;
		} else {
			// LOCK is not accepted by stack operations.
			invalid_prefix = true;
			effective_rex = false;
		}
		++rex2_offset;
	}
	if (rex2_offset == code_len)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - rex2_offset < 3)
		return X86_FEATURE_INVALID;

	payload = code[rex2_offset + 1];
	opcode = code[rex2_offset + 2];
	if (opcode < 0x50 || opcode > 0x5f)
		return X86_FEATURE_NOT_HANDLED;
	if (payload & 0x80)
		return X86_FEATURE_NOT_HANDLED;
	if (invalid_prefix || effective_rex || rex2_offset + 3 > 15)
		return X86_FEATURE_INVALID;

	number = (payload & 0x10) | ((payload & 0x01) << 3) | (opcode & 7);
	width = (payload & 0x08) ? 8 : operand_size_prefix ? 2 : 8;
	reg = rex2_register(number, width);
	if (reg == X86_REG_INVALID)
		return X86_FEATURE_INVALID;

	if (payload & 0x08)
		feature_opcode = opcode < 0x58 ? X86_FEATURE_PUSHP :
						 X86_FEATURE_POPP;
	else
		feature_opcode = opcode < 0x58 ? X86_FEATURE_REX2_PUSH :
						 X86_FEATURE_REX2_POP;
	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, reg);
	MCOperand_CreateImm0(instr, width);
	*size = (uint16_t)(rex2_offset + 3);

	if (!instr->flat_insn->detail)
		return X86_FEATURE_DECODED;
	x86 = &instr->flat_insn->detail->x86;
	x86->prefix[0] = repeat_prefix;
	x86->prefix[1] = segment_prefix;
	x86->prefix[2] = operand_size_prefix ? 0x66 : 0;
	x86->prefix[3] = address_size_prefix ? 0x67 : 0;
	instr->x86_prefix[0] = repeat_prefix;
	instr->x86_prefix[1] = segment_prefix;
	instr->x86_prefix[2] = operand_size_prefix ? 0x66 : 0;
	instr->x86_prefix[3] = address_size_prefix ? 0x67 : 0;
	x86->opcode[0] = opcode;
	x86->rex2 = payload;
	x86->addr_size = address_size_prefix ? 4 : 8;
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result
decode_apx_push2_pop2(csh handle, const uint8_t *code, size_t code_len,
		      MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	uint8_t p0, p1, p2, opcode, modrm;
	unsigned int v_number, b_number, feature_opcode;
	x86_reg v_register, b_register;
	cs_x86 *x86;

	if (code_len < 2 || code[0] != 0x62 || (code[1] & 7) != 4)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len < 5)
		return X86_FEATURE_INVALID;
	opcode = code[4];
	if (opcode != 0xff && opcode != 0x8f)
		return X86_FEATURE_NOT_HANDLED;
	if (opcode == 0xff && (code_len < 6 || (code[5] & 0x38) != 0x30))
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || code_len < 6)
		return X86_FEATURE_INVALID;

	p0 = code[1];
	p1 = code[2];
	p2 = code[3];
	modrm = code[5];
	// MAP4, the mandatory EVEX fixed bit, pp=0, LLZ=0, ND=1, NF=0,
	// and ModRM.Mod=3 are architectural requirements.  R/R' address an
	// unused field and are architecturally ignored for PUSH2/POP2.
	if (!(p1 & 0x04) || (p1 & 3) != 0 || (p2 & 0xe7) != 0 || !(p2 & 0x10) ||
	    (modrm & 0xc0) != 0xc0) {
		return X86_FEATURE_INVALID;
	}
	if (opcode == 0xff) {
		if ((modrm & 0x38) != 0x30)
			return X86_FEATURE_INVALID;
		feature_opcode = (p1 & 0x80) ? X86_FEATURE_PUSH2P :
					       X86_FEATURE_PUSH2;
	} else {
		if ((modrm & 0x38) != 0)
			return X86_FEATURE_INVALID;
		feature_opcode = (p1 & 0x80) ? X86_FEATURE_POP2P :
					       X86_FEATURE_POP2;
	}

	v_number = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
	b_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) | (modrm & 7);
	v_register = rex2_register(v_number, 8);
	b_register = rex2_register(b_number, 8);
	if (v_register == X86_REG_INVALID || b_register == X86_REG_INVALID ||
	    v_register == X86_REG_RSP || b_register == X86_REG_RSP ||
	    (opcode == 0x8f && v_register == b_register)) {
		return X86_FEATURE_INVALID;
	}

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, v_register);
	MCOperand_CreateImm0(instr, b_register);
	*size = 6;

	if (!instr->flat_insn->detail)
		return X86_FEATURE_DECODED;
	x86 = &instr->flat_insn->detail->x86;
	x86->opcode[0] = 0x62;
	x86->opcode[1] = p0;
	x86->opcode[2] = p1;
	x86->opcode[3] = p2;
	x86->addr_size = 8;
	x86->modrm = modrm;
	x86->encoding.modrm_offset = 5;
	return X86_FEATURE_DECODED;
}

static unsigned int apx_evex_alu_feature_opcode(uint8_t opcode)
{
	switch (opcode & 0xfc) {
	default:
		return 0;
	case 0x00:
		return X86_FEATURE_REX2_ADD;
	case 0x08:
		return X86_FEATURE_REX2_OR;
	case 0x20:
		return X86_FEATURE_REX2_AND;
	case 0x28:
		return X86_FEATURE_REX2_SUB;
	case 0x30:
		return X86_FEATURE_REX2_XOR;
	}
}

static bool is_apx_evex_segment_prefix(uint8_t byte)
{
	switch (byte) {
	default:
		return false;
	case 0x26:
	case 0x2e:
	case 0x36:
	case 0x3e:
	case 0x64:
	case 0x65:
		return true;
	}
}

static x86_reg apx_segment_register(uint8_t prefix)
{
	switch (prefix) {
	default:
		return X86_REG_INVALID;
	case 0x26:
		return X86_REG_ES;
	case 0x2e:
		return X86_REG_CS;
	case 0x36:
		return X86_REG_SS;
	case 0x3e:
		return X86_REG_DS;
	case 0x64:
		return X86_REG_FS;
	case 0x65:
		return X86_REG_GS;
	}
}

static bool decode_apx_evex_memory(const uint8_t *code, size_t code_len,
				   size_t modrm_offset, uint8_t p0, uint8_t p1,
				   bool address32, x86_feature_memory *memory)
{
	uint8_t modrm, mod, rm;
	unsigned int base_extension, index_extension;
	size_t cursor = modrm_offset + 1;
	uint8_t displacement_size = 0;
	const uint8_t address_width = address32 ? 4 : 8;

	if (modrm_offset >= code_len)
		return false;

	memset(memory, 0, sizeof(*memory));
	memory->base = X86_REG_INVALID;
	memory->index = X86_REG_INVALID;
	memory->scale = 1;
	modrm = code[modrm_offset];
	mod = modrm >> 6;
	rm = modrm & 7;
	if (mod == 3)
		return false;

	base_extension = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1);
	index_extension = ((~p0 & 0x40) >> 3) | ((~p1 & 0x04) << 2);
	if (rm == 4) {
		uint8_t base_number, index_number;

		if (cursor >= code_len)
			return false;
		memory->has_sib = true;
		memory->sib = code[cursor++];
		memory->scale = (int8_t)(1U << (memory->sib >> 6));
		index_number = (memory->sib >> 3) & 7;
		base_number = memory->sib & 7;
		if (index_number != 4 || index_extension != 0) {
			memory->index = rex2_register(
				index_number + index_extension, address_width);
		}
		if (mod == 0 && base_number == 5) {
			displacement_size = 4;
		} else {
			memory->base = rex2_register(
				base_number + base_extension, address_width);
		}
	} else if (mod == 0 && rm == 5) {
		memory->base = address32 ? X86_REG_EIP : X86_REG_RIP;
		displacement_size = 4;
	} else {
		memory->base =
			rex2_register(rm + base_extension, address_width);
	}

	if (memory->base == X86_REG_INVALID &&
	    !(mod == 0 && (rm == 5 || memory->has_sib))) {
		return false;
	}
	if (memory->index == X86_REG_INVALID && memory->has_sib &&
	    (((memory->sib >> 3) & 7) != 4 || index_extension != 0)) {
		return false;
	}

	if (mod == 1)
		displacement_size = 1;
	else if (mod == 2)
		displacement_size = 4;
	if (displacement_size != 0) {
		if (code_len - cursor < displacement_size)
			return false;
		memory->displacement_offset = (uint8_t)cursor;
		memory->displacement_size = displacement_size;
		memory->displacement = displacement_size == 1 ?
					       (int8_t)code[cursor] :
					       read_i32(&code[cursor]);
		cursor += displacement_size;
	}
	if (cursor > 15)
		return false;
	memory->length = cursor;
	return true;
}

static void set_apx_evex_encoding_detail(MCInst *instr, const uint8_t *evex,
					 size_t evex_offset,
					 uint8_t segment_prefix, bool address32,
					 const x86_feature_memory *memory)
{
	cs_x86 *x86;

	if (!instr->flat_insn->detail)
		return;
	x86 = &instr->flat_insn->detail->x86;
	x86->opcode[0] = evex[0];
	x86->opcode[1] = evex[1];
	x86->opcode[2] = evex[2];
	x86->opcode[3] = evex[3];
	x86->prefix[1] = segment_prefix;
	x86->prefix[3] = address32 ? 0x67 : 0;
	instr->x86_prefix[1] = segment_prefix;
	instr->x86_prefix[3] = address32 ? 0x67 : 0;
	x86->addr_size = address32 ? 4 : 8;
	x86->modrm = evex[5];
	x86->encoding.modrm_offset = (uint8_t)(evex_offset + 5);
	if (!memory)
		return;
	x86->sib = memory->sib;
	x86->sib_base = memory->has_sib ? memory->base : X86_REG_INVALID;
	x86->sib_index = memory->has_sib ? memory->index : X86_REG_INVALID;
	x86->sib_scale = memory->has_sib ? memory->scale : 0;
	x86->disp = memory->displacement;
	x86->encoding.disp_offset = memory->displacement_offset;
	x86->encoding.disp_size = memory->displacement_size;
}

static x86_feature_decode_result
decode_apx_evex_vector_gpr(csh handle, const uint8_t *code, size_t code_len,
			   MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t evex_offset = 0;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false;
	const uint8_t *evex;
	uint8_t p0, p1, p2, opcode, modrm, element_size, vector_size;
	unsigned int destination_number, source_number, feature_opcode;
	x86_reg destination, source, mask;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		const uint8_t prefix = code[evex_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			   prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++evex_offset;
	}
	if (code_len - evex_offset < 5 || code[evex_offset] != 0x62)
		return X86_FEATURE_NOT_HANDLED;
	evex = &code[evex_offset];
	p0 = evex[1];
	opcode = evex[4];
	if ((p0 & 7) != 2 || (p0 & 0x08) == 0 || opcode < 0x7a ||
	    opcode > 0x7c)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - evex_offset < 6 || evex_offset + 6 > 15)
		return X86_FEATURE_INVALID;
	p1 = evex[2];
	p2 = evex[3];
	modrm = evex[5];
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    (modrm & 0xc0) != 0xc0 || (p1 & 0x7f) != 0x7d ||
	    (p2 & 0x18) != 0x08 || (p2 & 0x60) == 0x60 ||
	    ((p2 & 0x80) != 0 && (p2 & 7) == 0))
		return X86_FEATURE_INVALID;

	if (opcode == 0x7a) {
		if (p1 & 0x80)
			return X86_FEATURE_INVALID;
		element_size = 1;
		feature_opcode = X86_FEATURE_APX_VPBROADCAST_BASE;
	} else if (opcode == 0x7b) {
		if (p1 & 0x80)
			return X86_FEATURE_INVALID;
		element_size = 2;
		feature_opcode = X86_FEATURE_APX_VPBROADCAST_BASE + 1;
	} else if (p1 & 0x80) {
		element_size = 8;
		feature_opcode = X86_FEATURE_APX_VPBROADCAST_BASE + 3;
	} else {
		element_size = 4;
		feature_opcode = X86_FEATURE_APX_VPBROADCAST_BASE + 2;
	}

	vector_size = (p2 & 0x60) == 0 ? 16 :
		      (p2 & 0x60) == 0x20 ? 32 : 64;
	destination_number = ((modrm >> 3) & 7) | ((~p0 & 0x80) >> 4) |
			     (~p0 & 0x10);
	source_number = (modrm & 7) | ((~p0 & 0x20) >> 2) |
			((p0 & 0x08) << 1);
	destination = (vector_size == 16 ? X86_REG_XMM0 :
		       vector_size == 32 ? X86_REG_YMM0 : X86_REG_ZMM0) +
		      destination_number;
	source = rex2_register(source_number, element_size == 8 ? 8 : 4);
	mask = (p2 & 7) == 0 ? X86_REG_INVALID : X86_REG_K0 + (p2 & 7);
	if (destination_number >= 32 || source_number < 16 ||
	    source == X86_REG_INVALID)
		return X86_FEATURE_INVALID;

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, destination);
	MCOperand_CreateImm0(instr, source);
	MCOperand_CreateImm0(instr, mask);
	MCOperand_CreateImm0(instr, vector_size);
	MCOperand_CreateImm0(instr, element_size);
	MCOperand_CreateImm0(instr, (p2 & 0x80) != 0);
	*size = (uint16_t)(evex_offset + 6);
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32, NULL);
	return X86_FEATURE_DECODED;
}

enum x86_feature_shift_count {
	X86_FEATURE_SHIFT_IMMEDIATE,
	X86_FEATURE_SHIFT_ONE,
	X86_FEATURE_SHIFT_CL,
};

static unsigned int apx_shift_rotate_feature_opcode(uint8_t group)
{
	switch (group) {
	default:
		return 0;
	case 0:
		return X86_FEATURE_APX_ROL;
	case 1:
		return X86_FEATURE_APX_ROR;
	case 2:
		return X86_FEATURE_APX_RCL;
	case 3:
		return X86_FEATURE_APX_RCR;
	case 4:
	case 6:
		return X86_FEATURE_APX_SHL;
	case 5:
		return X86_FEATURE_APX_SHR;
	case 7:
		return X86_FEATURE_APX_SAR;
	}
}

static x86_feature_decode_result
decode_apx_shift_rotate(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0, modrm_offset, instruction_size;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false, memory_form;
	uint8_t p0, p1, p2, opcode, modrm, width, count_kind, count_value = 0;
	unsigned int feature_opcode, rm_number, ndd_number;
	x86_reg destination = X86_REG_INVALID, source = X86_REG_INVALID;
	x86_reg segment;
	x86_feature_memory memory;
	bool nd, nf;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			   prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++evex_offset;
	}
	if (evex_offset == code_len || code_len - evex_offset < 2 ||
	    (code[evex_offset + 1] & 7) != 4) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (code_len - evex_offset < 5)
		return X86_FEATURE_INVALID;
	evex = &code[evex_offset];
	opcode = evex[4];
	if (opcode != 0xc0 && opcode != 0xc1 && opcode != 0xd0 &&
	    opcode != 0xd1 && opcode != 0xd2 && opcode != 0xd3) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    code_len - evex_offset < 6) {
		return X86_FEATURE_INVALID;
	}

	p0 = evex[1];
	p1 = evex[2];
	p2 = evex[3];
	modrm = evex[5];
	modrm_offset = evex_offset + 5;
	memory_form = (modrm & 0xc0) != 0xc0;
	feature_opcode = apx_shift_rotate_feature_opcode((modrm >> 3) & 7);
	if (feature_opcode == 0 || (p2 & 0xe3) != 0 ||
	    (!memory_form && !(p1 & 0x04))) {
		return X86_FEATURE_INVALID;
	}

	if ((opcode & 1) == 0) {
		if ((p1 & 3) != 0)
			return X86_FEATURE_INVALID;
		width = 1;
	} else if (p1 & 0x80) {
		if ((p1 & 3) > 1)
			return X86_FEATURE_INVALID;
		width = 8;
	} else if ((p1 & 3) == 1) {
		width = 2;
	} else if ((p1 & 3) == 0) {
		width = 4;
	} else {
		return X86_FEATURE_INVALID;
	}

	nd = (p2 & 0x10) != 0;
	nf = (p2 & 0x04) != 0;
	ndd_number = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
	if ((!nd && ndd_number != 0) ||
	    (nf && (feature_opcode == X86_FEATURE_APX_RCL ||
		    feature_opcode == X86_FEATURE_APX_RCR))) {
		return X86_FEATURE_INVALID;
	}
	if (nd) {
		destination = rex2_register(ndd_number, width);
		if (destination == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
	}

	if (opcode == 0xc0 || opcode == 0xc1) {
		count_kind = X86_FEATURE_SHIFT_IMMEDIATE;
	} else if (opcode == 0xd0 || opcode == 0xd1) {
		count_kind = X86_FEATURE_SHIFT_ONE;
		count_value = 1;
	} else {
		count_kind = X86_FEATURE_SHIFT_CL;
	}

	memset(&memory, 0, sizeof(memory));
	if (memory_form) {
		if (!decode_apx_evex_memory(code, code_len, modrm_offset, p0,
					    p1, address32, &memory)) {
			return X86_FEATURE_INVALID;
		}
		instruction_size = memory.length;
	} else {
		rm_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) |
			    (modrm & 7);
		source = rex2_register(rm_number, width);
		if (source == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		if (!nd)
			destination = source;
		instruction_size = modrm_offset + 1;
	}
	if (count_kind == X86_FEATURE_SHIFT_IMMEDIATE) {
		if (instruction_size >= code_len)
			return X86_FEATURE_INVALID;
		count_value = code[instruction_size++];
	}
	if (instruction_size > 15)
		return X86_FEATURE_INVALID;

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, destination);
	MCOperand_CreateImm0(instr, memory_form);
	if (memory_form) {
		segment = apx_segment_register(segment_prefix);
		add_feature_memory_operands(instr, &memory);
		MCOperand_CreateImm0(instr, segment);
		MCOperand_CreateImm0(instr, address32 ? 4 : 8);
	} else {
		MCOperand_CreateImm0(instr, source);
	}
	MCOperand_CreateImm0(instr, width);
	MCOperand_CreateImm0(instr, count_kind);
	MCOperand_CreateImm0(instr, count_value);
	MCOperand_CreateImm0(instr, nd);
	MCOperand_CreateImm0(instr, nf);
	*size = (uint16_t)instruction_size;
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32, memory_form ? &memory : NULL);
	if (count_kind == X86_FEATURE_SHIFT_IMMEDIATE) {
		instr->imm_size = 1;
		if (instr->flat_insn->detail) {
			cs_x86 *x86 = &instr->flat_insn->detail->x86;

			x86->encoding.imm_offset =
				(uint8_t)(instruction_size - 1);
			x86->encoding.imm_size = 1;
		}
	}
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_imul(csh handle,
						 const uint8_t *code,
						 size_t code_len, MCInst *instr,
						 uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false, memory_form;
	uint8_t p0, p1, p2, modrm, width, pp;
	unsigned int reg_number, rm_number, ndd_number;
	x86_reg reg_field, rm_field = X86_REG_INVALID;
	x86_reg ndd_field = X86_REG_INVALID;
	x86_reg segment;
	bool nd, nf;
	x86_feature_memory memory;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			   prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++evex_offset;
	}
	if (evex_offset == code_len || code_len - evex_offset < 2 ||
	    (code[evex_offset + 1] & 7) != 4) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (code_len - evex_offset < 5)
		return X86_FEATURE_INVALID;
	evex = &code[evex_offset];
	if (evex[4] != 0xaf)
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    code_len - evex_offset < 6 || evex_offset + 6 > 15) {
		return X86_FEATURE_INVALID;
	}

	p0 = evex[1];
	p1 = evex[2];
	p2 = evex[3];
	modrm = evex[5];
	pp = p1 & 3;
	memory_form = (modrm & 0xc0) != 0xc0;
	if (pp > 1 || (p2 & 0xe3) != 0 || (!memory_form && !(p1 & 0x04))) {
		return X86_FEATURE_INVALID;
	}

	nd = (p2 & 0x10) != 0;
	nf = (p2 & 0x04) != 0;
	ndd_number = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
	if (!nd && ndd_number != 0)
		return X86_FEATURE_INVALID;
	width = (p1 & 0x80) ? 8 : pp == 1 ? 2 : 4;
	reg_number = ((~p0 & 0x80) >> 4) | (~p0 & 0x10) | ((modrm >> 3) & 7);
	reg_field = rex2_register(reg_number, width);
	if (reg_field == X86_REG_INVALID)
		return X86_FEATURE_INVALID;
	if (nd) {
		ndd_field = rex2_register(ndd_number, width);
		if (ndd_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
	}

	MCInst_clear(instr);
	MCInst_setOpcode(instr, X86_FEATURE_APX_IMUL);
	MCOperand_CreateImm0(instr, reg_field);
	MCOperand_CreateImm0(instr, ndd_field);
	MCOperand_CreateImm0(instr, memory_form);
	if (!memory_form) {
		rm_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) |
			    (modrm & 7);
		rm_field = rex2_register(rm_number, width);
		if (rm_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		MCOperand_CreateImm0(instr, rm_field);
		MCOperand_CreateImm0(instr, width);
		MCOperand_CreateImm0(instr, nd);
		MCOperand_CreateImm0(instr, nf);
		*size = (uint16_t)(evex_offset + 6);
		set_apx_evex_encoding_detail(instr, evex, evex_offset,
					     segment_prefix, address32, NULL);
		return X86_FEATURE_DECODED;
	}

	if (!decode_apx_evex_memory(code, code_len, evex_offset + 5, p0, p1,
				    address32, &memory)) {
		return X86_FEATURE_INVALID;
	}
	segment = apx_segment_register(segment_prefix);
	add_feature_memory_operands(instr, &memory);
	MCOperand_CreateImm0(instr, segment);
	MCOperand_CreateImm0(instr, address32 ? 4 : 8);
	MCOperand_CreateImm0(instr, width);
	MCOperand_CreateImm0(instr, nd);
	MCOperand_CreateImm0(instr, nf);
	*size = (uint16_t)memory.length;
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32, &memory);
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result
decode_apx_imul_immediate(csh handle, const uint8_t *code, size_t code_len,
			  MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0, instruction_size, immediate_offset;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false, memory_form;
	uint8_t p0, p1, p2, opcode, modrm, pp, width, immediate_size;
	unsigned int destination_number, source_number, vvvvv_number;
	x86_reg destination, source = X86_REG_INVALID;
	x86_reg segment = X86_REG_INVALID;
	int64_t immediate;
	x86_feature_memory memory;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66 || prefix == 0xf0 ||
			   prefix == 0xf2 || prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++evex_offset;
	}
	if (evex_offset == code_len || code_len - evex_offset < 2 ||
	    (code[evex_offset + 1] & 7) != 4) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (code_len - evex_offset < 5)
		return X86_FEATURE_INVALID;
	evex = &code[evex_offset];
	opcode = evex[4];
	if (opcode != 0x69 && opcode != 0x6b)
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    code_len - evex_offset < 6 || evex_offset + 6 > 15) {
		return X86_FEATURE_INVALID;
	}

	p0 = evex[1];
	p1 = evex[2];
	p2 = evex[3];
	modrm = evex[5];
	pp = p1 & 3;
	memory_form = (modrm & 0xc0) != 0xc0;
	if (pp > 1 || (p2 & 0xe3) != 0 ||
	    (!memory_form && !(p1 & 0x04))) {
		return X86_FEATURE_INVALID;
	}
	width = (p1 & 0x80) ? 8 : pp == 1 ? 2 : 4;
	vvvvv_number = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
	if (vvvvv_number != 0)
		return X86_FEATURE_INVALID;

	destination_number = ((~p0 & 0x80) >> 4) | (~p0 & 0x10) |
			     ((modrm >> 3) & 7);
	destination = rex2_register(destination_number, width);
	if (destination == X86_REG_INVALID)
		return X86_FEATURE_INVALID;

	memset(&memory, 0, sizeof(memory));
	if (memory_form) {
		if (!decode_apx_evex_memory(code, code_len, evex_offset + 5, p0,
					    p1, address32, &memory)) {
			return X86_FEATURE_INVALID;
		}
		instruction_size = memory.length;
		segment = apx_segment_register(segment_prefix);
	} else {
		source_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) |
				(modrm & 7);
		source = rex2_register(source_number, width);
		if (source == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		instruction_size = evex_offset + 6;
	}

	immediate_size = opcode == 0x6b ? 1 : width == 2 ? 2 : 4;
	immediate_offset = instruction_size;
	if (code_len - instruction_size < immediate_size ||
	    instruction_size + immediate_size > 15) {
		return X86_FEATURE_INVALID;
	}
	if (immediate_size == 1) {
		immediate = (int8_t)code[instruction_size];
	} else if (immediate_size == 2) {
		uint16_t value = (uint16_t)code[instruction_size] |
				 ((uint16_t)code[instruction_size + 1] << 8);

		immediate = (int16_t)value;
	} else {
		immediate = read_i32(&code[instruction_size]);
	}
	instruction_size += immediate_size;

	MCInst_clear(instr);
	MCInst_setOpcode(instr, X86_FEATURE_APX_IMUL_IMMEDIATE);
	MCOperand_CreateImm0(instr, destination);
	MCOperand_CreateImm0(instr, memory_form);
	if (memory_form) {
		add_feature_memory_operands(instr, &memory);
		MCOperand_CreateImm0(instr, segment);
		MCOperand_CreateImm0(instr, address32 ? 4 : 8);
	} else {
		MCOperand_CreateImm0(instr, source);
	}
	MCOperand_CreateImm0(instr, width);
	MCOperand_CreateImm0(instr, immediate);
	MCOperand_CreateImm0(instr, (p2 & 0x10) != 0);
	MCOperand_CreateImm0(instr, (p2 & 0x04) != 0);
	*size = (uint16_t)instruction_size;
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32,
				     memory_form ? &memory : NULL);
	instr->imm_size = immediate_size;
	if (instr->flat_insn->detail) {
		cs_x86 *x86 = &instr->flat_insn->detail->x86;

		x86->encoding.imm_offset = (uint8_t)immediate_offset;
		x86->encoding.imm_size = immediate_size;
	}
	return X86_FEATURE_DECODED;
}

static bool is_apx_adc_sbb_binary_opcode(uint8_t opcode)
{
	return (opcode >= 0x10 && opcode <= 0x13) ||
	       (opcode >= 0x18 && opcode <= 0x1b);
}

static x86_feature_decode_result decode_apx_adx(csh handle,
						 const uint8_t *code,
						 size_t code_len, MCInst *instr,
						 uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false, memory_form;
	uint8_t p0, p1, p2, modrm, width, pp;
	unsigned int reg_number, rm_number, ndd_number, feature_opcode;
	x86_reg reg_field, rm_field = X86_REG_INVALID;
	x86_reg ndd_field = X86_REG_INVALID, segment;
	bool nd;
	x86_feature_memory memory;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];
		if (is_apx_evex_segment_prefix(prefix))
			segment_prefix = prefix;
		else if (prefix == 0x67)
			address32 = true;
		else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			 prefix == 0xf3 || (prefix >= 0x40 && prefix <= 0x4f))
			invalid_prefix = true;
		else
			return X86_FEATURE_NOT_HANDLED;
		++evex_offset;
	}
	if (evex_offset == code_len || code_len - evex_offset < 2 ||
	    (code[evex_offset + 1] & 7) != 4)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - evex_offset < 5)
		return X86_FEATURE_INVALID;
	evex = &code[evex_offset];
	if (evex[4] != 0x66)
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    code_len - evex_offset < 6 || evex_offset + 6 > 15)
		return X86_FEATURE_INVALID;

	p0 = evex[1]; p1 = evex[2]; p2 = evex[3]; modrm = evex[5];
	pp = p1 & 3;
	if ((pp != 1 && pp != 2) || (p2 & 0xe7) != 0)
		return X86_FEATURE_INVALID;
	feature_opcode = pp == 1 ? X86_FEATURE_APX_ADCX : X86_FEATURE_APX_ADOX;
	memory_form = (modrm & 0xc0) != 0xc0;
	if (!memory_form && !(p1 & 0x04))
		return X86_FEATURE_INVALID;
	nd = (p2 & 0x10) != 0;
	ndd_number = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
	if (!nd && ndd_number != 0)
		return X86_FEATURE_INVALID;
	width = (p1 & 0x80) ? 8 : 4;
	reg_number = ((~p0 & 0x80) >> 4) | (~p0 & 0x10) |
		     ((modrm >> 3) & 7);
	reg_field = rex2_register(reg_number, width);
	if (reg_field == X86_REG_INVALID)
		return X86_FEATURE_INVALID;
	if (nd) {
		ndd_field = rex2_register(ndd_number, width);
		if (ndd_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
	}

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, reg_field);
	MCOperand_CreateImm0(instr, ndd_field);
	MCOperand_CreateImm0(instr, memory_form);
	if (!memory_form) {
		rm_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) |
			    (modrm & 7);
		rm_field = rex2_register(rm_number, width);
		if (rm_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		MCOperand_CreateImm0(instr, rm_field);
		MCOperand_CreateImm0(instr, width);
		MCOperand_CreateImm0(instr, nd);
		MCOperand_CreateImm0(instr, 0);
		*size = (uint16_t)(evex_offset + 6);
		set_apx_evex_encoding_detail(instr, evex, evex_offset,
					     segment_prefix, address32, NULL);
		return X86_FEATURE_DECODED;
	}
	if (!decode_apx_evex_memory(code, code_len, evex_offset + 5, p0, p1,
				    address32, &memory))
		return X86_FEATURE_INVALID;
	segment = apx_segment_register(segment_prefix);
	add_feature_memory_operands(instr, &memory);
	MCOperand_CreateImm0(instr, segment);
	MCOperand_CreateImm0(instr, address32 ? 4 : 8);
	MCOperand_CreateImm0(instr, width);
	MCOperand_CreateImm0(instr, nd);
	MCOperand_CreateImm0(instr, 0);
	*size = (uint16_t)memory.length;
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32, &memory);
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_unary(csh handle,
		const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle; const uint8_t *e;
	size_t off=0; uint8_t segp=0,p0,p1,p2,op,m,w,pp,group; bool a32=false,bad=false,mem,nd,nf;
	unsigned n,ndn,feature; x86_reg r=X86_REG_INVALID,d=X86_REG_INVALID,seg; x86_feature_memory memory;
	while(off<code_len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==code_len||code_len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;
	if(code_len-off<5)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0xfe&&op!=0xff&&op!=0xf6&&op!=0xf7)return X86_FEATURE_NOT_HANDLED;
	if(!(arch->mode&CS_MODE_64)||bad||code_len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;group=(m>>3)&7;mem=(m&0xc0)!=0xc0;nd=(p2&0x10)!=0;nf=(p2&4)!=0;
	if((p2&0xe3)!=0||pp>1||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;
	if(op==0xfe||op==0xff){if(group>1)return X86_FEATURE_NOT_HANDLED;feature=group?X86_FEATURE_APX_DEC:X86_FEATURE_APX_INC;}
	else {if(group!=2&&group!=3&&group!=4&&group!=5&&group!=6&&group!=7)return X86_FEATURE_NOT_HANDLED;feature=group==2?X86_FEATURE_APX_NOT:group==3?X86_FEATURE_APX_NEG:group==4?X86_FEATURE_APX_MUL:group==5?X86_FEATURE_APX_IMUL_ONE:group==6?X86_FEATURE_APX_DIV:X86_FEATURE_APX_IDIV;if(feature==X86_FEATURE_APX_NOT&&nf)return X86_FEATURE_INVALID;if(group>=4&&nd)return X86_FEATURE_INVALID;}
	if((op==0xfe||op==0xf6)){if(pp)return X86_FEATURE_INVALID;w=1;}else w=(p1&0x80)?8:pp?2:4;
	ndn=((~p2&8)<<1)|((~p1&0x78)>>3);if(!nd&&ndn)return X86_FEATURE_INVALID;
	if(nd){d=rex2_register(ndn,w);if(d==X86_REG_INVALID)return X86_FEATURE_INVALID;}
	MCInst_clear(instr);MCInst_setOpcode(instr,feature);MCOperand_CreateImm0(instr,d);MCOperand_CreateImm0(instr,mem);
	if(!mem){n=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);r=rex2_register(n,w);if(r==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(instr,r);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,nd);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(instr,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,code_len,off+5,p0,p1,a32,&memory))return X86_FEATURE_INVALID;
	seg=apx_segment_register(segp);add_feature_memory_operands(instr,&memory);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,nd);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)memory.length;set_apx_evex_encoding_detail(instr,e,off,segp,a32,&memory);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_bmi_ternary(csh handle,const uint8_t *code,size_t len,MCInst *instr,uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle;const uint8_t *e;size_t off=0;uint8_t segp=0,p0,p1,p2,op,m,w;bool a32=false,bad=false,mem,nf;x86_reg dst,s1,s2=X86_REG_INVALID,seg;unsigned dn,sn,rn,feature;x86_feature_memory memory;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=2)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0xf2&&op!=0xf5)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];mem=(m&0xc0)!=0xc0;nf=(p2&4)!=0;if((p1&3)!=0||(p2&0xf3)!=0||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;/* ND=0, LL=0, zeroing=0; memory U is inverted X4. */
	w=(p1&0x80)?8:4;feature=op==0xf2?X86_FEATURE_APX_ANDN:X86_FEATURE_APX_BZHI;dn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);sn=((~p2&8)<<1)|((~p1&0x78)>>3);dst=rex2_register(dn,w);s1=rex2_register(sn,w);if(dst==X86_REG_INVALID||s1==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(instr);MCInst_setOpcode(instr,feature);MCOperand_CreateImm0(instr,s1);MCOperand_CreateImm0(instr,dst);MCOperand_CreateImm0(instr,mem);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);s2=rex2_register(rn,w);if(s2==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(instr,s2);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,1);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(instr,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&memory))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(instr,&memory);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,1);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)memory.length;set_apx_evex_encoding_detail(instr,e,off,segp,a32,&memory);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_pdep_pext(csh handle,const uint8_t *code,size_t len,MCInst *instr,uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle;const uint8_t*e;size_t off=0;uint8_t segp=0,p0,p1,p2,m,w,pp;bool a32=false,bad=false,mem;x86_reg dst,s1,s2=X86_REG_INVALID,seg;unsigned dn,sn,rn;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=2)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];if(e[4]!=0xf5)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;if(pp!=2&&pp!=3)return X86_FEATURE_NOT_HANDLED;mem=(m&0xc0)!=0xc0;if((p2&0xf7)!=0||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;w=(p1&0x80)?8:4;dn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);sn=((~p2&8)<<1)|((~p1&0x78)>>3);dst=rex2_register(dn,w);s1=rex2_register(sn,w);if(dst==X86_REG_INVALID||s1==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(instr);MCInst_setOpcode(instr,pp==3?X86_FEATURE_APX_PDEP:X86_FEATURE_APX_PEXT);MCOperand_CreateImm0(instr,dst);MCOperand_CreateImm0(instr,s1);MCOperand_CreateImm0(instr,mem);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);s2=rex2_register(rn,w);if(s2==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(instr,s2);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,0);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(instr,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(instr,&mm);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,0);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(instr,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_double_shift(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0,io;uint8_t segp=0,p0,p1,p2,op,m,pp,w,imm=0;bool a32=false,bad=false,mem,nd,nf,cl;x86_reg dst=X86_REG_INVALID,src,rm=X86_REG_INVALID,seg;unsigned dn,sn,rn;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0x24&&op!=0x2c&&op!=0xa5&&op!=0xad)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;mem=(m&0xc0)!=0xc0;nd=(p2&0x10)!=0;nf=(p2&4)!=0;cl=op>=0xa5;if(pp>1||(p2&0xe3)!=0||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;w=pp?2:((p1&0x80)?8:4);dn=((~p2&8)<<1)|((~p1&0x78)>>3);if(!nd&&dn)return X86_FEATURE_INVALID;if(nd){dst=rex2_register(dn,w);if(dst==X86_REG_INVALID)return X86_FEATURE_INVALID;}sn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);src=rex2_register(sn,w);if(src==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(in);MCInst_setOpcode(in,(op==0x24||op==0xa5)?X86_FEATURE_APX_SHLD:X86_FEATURE_APX_SHRD);MCOperand_CreateImm0(in,dst);MCOperand_CreateImm0(in,src);MCOperand_CreateImm0(in,mem);MCOperand_CreateImm0(in,nd);MCOperand_CreateImm0(in,nf);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);rm=rex2_register(rn,w);if(rm==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(in,rm);io=off+6;}else{if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);io=mm.length;}
	if(!cl){if(io>=len||io>=15)return X86_FEATURE_INVALID;imm=code[io++];in->imm_size=1;}MCOperand_CreateImm0(in,w);MCOperand_CreateImm0(in,cl);MCOperand_CreateImm0(in,imm);*size=(uint16_t)io;set_apx_evex_encoding_detail(in,e,off,segp,a32,mem?&mm:NULL);if(!cl&&in->flat_insn->detail){in->flat_insn->detail->x86.encoding.imm_offset=(uint8_t)(io-1);in->flat_insn->detail->x86.encoding.imm_size=1;}return X86_FEATURE_DECODED;
}

static x86_feature_decode_result
decode_legacy_cet_store(csh handle, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t opcode_offset = 0;
	unsigned int segment_count = 0, address_size_count = 0;
	unsigned int operand_size_count = 0, repeat_count = 0, rex_count = 0;
	uint8_t segment_prefix = 0, rex = 0;
	bool lock_prefix = false, rex_precedes_legacy_prefix = false;
	bool saw_rex = false, mode64, mode32, mode16, user_store;
	uint8_t opcode, modrm, address_width, operand_width;
	unsigned int source_number, feature_opcode;
	x86_feature_memory memory;
	x86_reg source, segment;
	cs_x86 *x86;

	while (opcode_offset < code_len) {
		uint8_t prefix = code[opcode_offset];

		if ((arch->mode & CS_MODE_64) && prefix >= 0x40 &&
		    prefix <= 0x4f) {
			rex = prefix;
			++rex_count;
			saw_rex = true;
			++opcode_offset;
			continue;
		}
		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
			++segment_count;
		} else if (prefix == 0x67) {
			++address_size_count;
		} else if (prefix == 0x66) {
			++operand_size_count;
		} else if (prefix == 0xf2 || prefix == 0xf3) {
			++repeat_count;
		} else if (prefix == 0xf0) {
			lock_prefix = true;
		} else {
			break;
		}
		if (saw_rex)
			rex_precedes_legacy_prefix = true;
		++opcode_offset;
	}

	if (code_len - opcode_offset < 3 || code[opcode_offset] != 0x0f ||
	    code[opcode_offset + 1] != 0x38)
		return X86_FEATURE_NOT_HANDLED;
	opcode = code[opcode_offset + 2];
	if (opcode != 0xf5 && opcode != 0xf6)
		return X86_FEATURE_NOT_HANDLED;
	user_store = opcode == 0xf5;
	// 66/F6 and F3/F6 belong to ADCX and ADOX, respectively.
	if (!user_store && (operand_size_count != 0 || repeat_count != 0))
		return X86_FEATURE_NOT_HANDLED;
	// WRUSS has one mandatory 66 prefix; leave unrelated F5 encodings alone.
	if (user_store && operand_size_count == 0)
		return X86_FEATURE_NOT_HANDLED;

	mode64 = (arch->mode & CS_MODE_64) != 0;
	mode32 = (arch->mode & CS_MODE_32) != 0;
	mode16 = (arch->mode & CS_MODE_16) != 0;
	if ((!mode64 && !mode32 && !mode16) || lock_prefix ||
	    segment_count > 1 || address_size_count > 1 || repeat_count != 0 ||
	    operand_size_count != (user_store ? 1U : 0U) || rex_count > 1 ||
	    rex_precedes_legacy_prefix || code_len - opcode_offset < 4 ||
	    opcode_offset + 4 > 15) {
		return X86_FEATURE_INVALID;
	}

	modrm = code[opcode_offset + 3];
	if ((modrm & 0xc0) == 0xc0)
		return X86_FEATURE_INVALID;
	operand_width = (rex & 0x08) ? 8 : 4;
	if (operand_width == 8 && !mode64)
		return X86_FEATURE_INVALID;
	address_width = mode64 ? (address_size_count ? 4 : 8) :
			mode32 ? (address_size_count ? 2 : 4) :
				 (address_size_count ? 4 : 2);
	source_number = ((modrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0);
	source = rex2_register(source_number, operand_width);
	if (source == X86_REG_INVALID)
		return X86_FEATURE_INVALID;
	if (address_width == 2) {
		if (!decode_feature_memory16(code, code_len, opcode_offset + 3,
					     &memory))
			return X86_FEATURE_INVALID;
	} else if (!decode_feature_memory(
			   code, code_len, opcode_offset + 3, false,
			   address_width == 4, mode64 && (rex & 0x01) ? 8 : 0,
			   mode64 && (rex & 0x02) ? 8 : 0, &memory)) {
		return X86_FEATURE_INVALID;
	}
	// Legacy 32-bit addressing uses an absolute disp32 for mod=00,r/m=101;
	// only long mode's addr32 form is EIP-relative.
	if (!mode64 && address_width == 4 && (modrm & 0xc7) == 0x05 &&
	    !memory.has_sib)
		memory.base = X86_REG_INVALID;

	if (user_store)
		feature_opcode = operand_width == 8 ? X86_FEATURE_APX_WRUSSQ :
						      X86_FEATURE_APX_WRUSSD;
	else
		feature_opcode = operand_width == 8 ? X86_FEATURE_APX_WRSSQ :
						      X86_FEATURE_APX_WRSSD;
	segment = apx_segment_register(segment_prefix);
	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, source);
	add_feature_memory_operands(instr, &memory);
	MCOperand_CreateImm0(instr, segment);
	MCOperand_CreateImm0(instr, address_width);
	MCOperand_CreateImm0(instr, operand_width);
	*size = (uint16_t)memory.length;

	if (!instr->flat_insn->detail)
		return X86_FEATURE_DECODED;
	x86 = &instr->flat_insn->detail->x86;
	x86->prefix[1] = segment_prefix;
	x86->prefix[2] = user_store ? 0x66 : 0;
	x86->prefix[3] = address_size_count ? 0x67 : 0;
	instr->x86_prefix[1] = segment_prefix;
	instr->x86_prefix[2] = user_store ? 0x66 : 0;
	instr->x86_prefix[3] = address_size_count ? 0x67 : 0;
	x86->opcode[0] = 0x0f;
	x86->opcode[1] = 0x38;
	x86->opcode[2] = opcode;
	x86->rex = rex;
	x86->addr_size = address_width;
	x86->modrm = modrm;
	x86->encoding.modrm_offset = (uint8_t)(opcode_offset + 3);
	x86->sib = memory.sib;
	x86->sib_base = memory.has_sib ? memory.base : X86_REG_INVALID;
	x86->sib_index = memory.has_sib ? memory.index : X86_REG_INVALID;
	x86->sib_scale = memory.has_sib ? memory.scale : 0;
	x86->disp = memory.displacement;
	x86->encoding.disp_offset = memory.displacement_offset;
	x86->encoding.disp_size = memory.displacement_size;
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_direct_store(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0;uint8_t segp=0,p0,p1,p2,op,m,pp,w;bool a32=false,bad=false;x86_reg src,seg;unsigned sn,feature;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0xf9&&op!=0x66&&op!=0x65)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;if(op==0x66&&pp!=0)return X86_FEATURE_NOT_HANDLED;if((m&0xc0)==0xc0||(p1&0x78)!=0x78||p2!=8)return X86_FEATURE_INVALID;
	if(op==0xf9){if(pp)return X86_FEATURE_INVALID;feature=X86_FEATURE_APX_MOVDIRI;}else if(op==0x66){if(pp)return X86_FEATURE_INVALID;feature=(p1&0x80)?X86_FEATURE_APX_WRSSQ:X86_FEATURE_APX_WRSSD;}else{if(pp!=1)return X86_FEATURE_INVALID;feature=(p1&0x80)?X86_FEATURE_APX_WRUSSQ:X86_FEATURE_APX_WRUSSD;}w=(p1&0x80)?8:4;sn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);src=rex2_register(sn,w);if(src==X86_REG_INVALID)return X86_FEATURE_INVALID;if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);MCInst_clear(in);MCInst_setOpcode(in,feature);MCOperand_CreateImm0(in,src);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);MCOperand_CreateImm0(in,w);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(in,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result
decode_legacy_enqueue(csh handle, const uint8_t *code, size_t code_len,
		      MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t opcode_offset = 0;
	unsigned int segment_count = 0, address_size_count = 0;
	unsigned int mandatory_count = 0;
	uint8_t segment_prefix = 0, mandatory_prefix = 0, rex = 0;
	bool operand_size_prefix = false, lock_prefix = false;
	bool mode64, mode32, mode16;
	x86_feature_memory memory;
	x86_reg destination, segment;
	uint8_t modrm, address_width;
	unsigned int destination_number;
	cs_x86 *x86;

	while (opcode_offset < code_len) {
		uint8_t prefix = code[opcode_offset];

		if ((arch->mode & CS_MODE_64) && prefix >= 0x40 &&
		    prefix <= 0x4f) {
			// Only the final REX immediately before the opcode is
			// effective; an earlier REX is ignored.
			rex = prefix;
			++opcode_offset;
			continue;
		}
		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
			++segment_count;
		} else if (prefix == 0x67) {
			++address_size_count;
		} else if (prefix == 0xf2 || prefix == 0xf3) {
			mandatory_prefix = prefix;
			++mandatory_count;
		} else if (prefix == 0x66) {
			operand_size_prefix = true;
		} else if (prefix == 0xf0) {
			lock_prefix = true;
		} else {
			break;
		}
		// A legacy prefix after REX makes that REX ineffective.
		rex = 0;
		++opcode_offset;
	}

	if (mandatory_count == 0)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - opcode_offset < 2 || code[opcode_offset] != 0x0f ||
	    code[opcode_offset + 1] != 0x38) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (code_len - opcode_offset < 3)
		return X86_FEATURE_INVALID;
	if (code[opcode_offset + 2] != 0xf8)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - opcode_offset >= 4 &&
	    (code[opcode_offset + 3] & 0xc0) == 0xc0) {
		/* The register form belongs to USER_MSR, including its distinct
		 * legacy-prefix rules. */
		return X86_FEATURE_NOT_HANDLED;
	}
	mode64 = (arch->mode & CS_MODE_64) != 0;
	mode32 = (arch->mode & CS_MODE_32) != 0;
	mode16 = (arch->mode & CS_MODE_16) != 0;
	if ((!mode64 && !mode32 && !mode16) || lock_prefix ||
	    segment_count > 1 || address_size_count > 1 ||
	    mandatory_count != 1 || code_len - opcode_offset < 4 ||
	    opcode_offset + 4 > 15) {
		return X86_FEATURE_INVALID;
	}

	modrm = code[opcode_offset + 3];
	address_width = mode64 ? (address_size_count ? 4 : 8) :
			mode32 ? (address_size_count ? 2 : 4) :
				 (address_size_count ? 4 : 2);
	destination_number = ((modrm >> 3) & 7) | ((rex & 0x04) ? 8 : 0);
	destination = rex2_register(destination_number, address_width);
	if (destination == X86_REG_INVALID)
		return X86_FEATURE_INVALID;
	if (address_width == 2) {
		if (!decode_feature_memory16(code, code_len, opcode_offset + 3,
					     &memory))
			return X86_FEATURE_INVALID;
	} else if (!decode_feature_memory(
			   code, code_len, opcode_offset + 3, false,
			   address_width == 4, mode64 && (rex & 0x01) ? 8 : 0,
			   mode64 && (rex & 0x02) ? 8 : 0, &memory)) {
		return X86_FEATURE_INVALID;
	}
	// Legacy 32-bit addressing uses an absolute disp32 for mod=00,r/m=101;
	// only long mode's addr32 form is EIP-relative.
	if (!mode64 && address_width == 4 && (modrm & 0xc7) == 0x05 &&
	    !memory.has_sib)
		memory.base = X86_REG_INVALID;

	segment = apx_segment_register(segment_prefix);
	MCInst_clear(instr);
	MCInst_setOpcode(instr, mandatory_prefix == 0xf2 ?
					X86_FEATURE_APX_ENQCMD :
					X86_FEATURE_APX_ENQCMDS);
	MCOperand_CreateImm0(instr, destination);
	add_feature_memory_operands(instr, &memory);
	MCOperand_CreateImm0(instr, segment);
	MCOperand_CreateImm0(instr, address_width);
	*size = (uint16_t)memory.length;

	if (!instr->flat_insn->detail)
		return X86_FEATURE_DECODED;
	x86 = &instr->flat_insn->detail->x86;
	x86->prefix[0] = mandatory_prefix;
	x86->prefix[1] = segment_prefix;
	x86->prefix[2] = operand_size_prefix ? 0x66 : 0;
	x86->prefix[3] = address_size_count ? 0x67 : 0;
	instr->x86_prefix[0] = mandatory_prefix;
	instr->x86_prefix[1] = segment_prefix;
	instr->x86_prefix[2] = operand_size_prefix ? 0x66 : 0;
	instr->x86_prefix[3] = address_size_count ? 0x67 : 0;
	x86->rex = rex;
	x86->opcode[0] = 0x0f;
	x86->opcode[1] = 0x38;
	x86->opcode[2] = 0xf8;
	x86->addr_size = address_width;
	x86->modrm = modrm;
	x86->encoding.modrm_offset = (uint8_t)(opcode_offset + 3);
	x86->sib = memory.sib;
	x86->sib_base = memory.has_sib ? memory.base : X86_REG_INVALID;
	x86->sib_index = memory.has_sib ? memory.index : X86_REG_INVALID;
	x86->sib_scale = memory.has_sib ? memory.scale : 0;
	x86->disp = memory.displacement;
	x86->encoding.disp_offset = memory.displacement_offset;
	x86->encoding.disp_size = memory.displacement_size;
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_enqueue(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0;uint8_t segp=0,p0,p1,p2,m,pp,w;bool a32=false,bad=false;x86_reg reg,seg;unsigned rn,feature;x86_feature_memory mm;while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];if(e[4]!=0xf8)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;if(pp<1||(m&0xc0)==0xc0||(p1&0x78)!=0x78||p2!=8)return X86_FEATURE_INVALID;feature=pp==3?X86_FEATURE_APX_ENQCMD:pp==2?X86_FEATURE_APX_ENQCMDS:X86_FEATURE_APX_MOVDIR64B;w=a32?4:8;rn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);reg=rex2_register(rn,w);if(reg==X86_REG_INVALID||!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);MCInst_clear(in);MCInst_setOpcode(in,feature);MCOperand_CreateImm0(in,reg);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,w);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(in,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_rao(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0;uint8_t segp=0,p0,p1,p2,m,pp,w;bool a32=false,bad=false;x86_reg reg,seg;unsigned rn,feature,seg_count=0,a32_count=0;x86_feature_memory mm;while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p)){segp=p;++seg_count;}else if(p==0x67){a32=true;++a32_count;}else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];if(e[4]!=0xfc)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||seg_count>1||a32_count>1||len-off<6||off+6>15)return X86_FEATURE_INVALID;p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;if((m&0xc0)==0xc0||(p1&0x78)!=0x78||p2!=8)return X86_FEATURE_INVALID;feature=pp==0?X86_FEATURE_APX_AADD:pp==1?X86_FEATURE_APX_AAND:pp==3?X86_FEATURE_APX_AOR:X86_FEATURE_APX_AXOR;w=(p1&0x80)?8:4;rn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);reg=rex2_register(rn,w);if(reg==X86_REG_INVALID||!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);MCInst_clear(in);MCInst_setOpcode(in,feature);MCOperand_CreateImm0(in,reg);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);MCOperand_CreateImm0(in,w);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(in,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_cmpccxadd(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0;uint8_t segp=0,p0,p1,p2,op,m,w;x86_reg cmp,add,seg;bool a32=false,bad=false;unsigned cn,an;x86_feature_memory mm;while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}if(off==len||len-off<2||(code[off+1]&7)!=2)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op<0xe0||op>0xef)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;p0=e[1];p1=e[2];p2=e[3];m=e[5];if((p1&3)!=1||(m&0xc0)==0xc0||(p2&0xf7)!=0)return X86_FEATURE_INVALID;w=(p1&0x80)?8:4;cn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);an=((~p2&8)<<1)|((~p1&0x78)>>3);cmp=rex2_register(cn,w);add=rex2_register(an,w);if(cmp==X86_REG_INVALID||add==X86_REG_INVALID||!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);MCInst_clear(in);MCInst_setOpcode(in,X86_FEATURE_APX_CMPCCXADD_BASE+(op-0xe0));MCOperand_CreateImm0(in,cmp);MCOperand_CreateImm0(in,add);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);MCOperand_CreateImm0(in,w);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(in,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_ccmp(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0,io;uint8_t segp=0,p0,p1,p2,op,m,w,dfv,imm_size=0;bool a32=false,bad=false,mem,imm=false,rm_first=true;x86_reg rr=X86_REG_INVALID,rm=X86_REG_INVALID,seg=X86_REG_INVALID;unsigned rn;int64_t iv=0;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<6)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0x38&&op!=0x39&&op!=0x3a&&op!=0x3b&&op!=0x80&&op!=0x81&&op!=0x83)return X86_FEATURE_NOT_HANDLED;
	if(!(arch->mode&CS_MODE_64)||bad||off+6>15)return X86_FEATURE_INVALID;p0=e[1];p1=e[2];p2=e[3];m=e[5];mem=(m&0xc0)!=0xc0;dfv=(p1>>3)&15;
	/* SCC occupies all of P2; ND, NF, zeroing, VL and EVEX.b are reserved here. */
	if(p2&0xf0)return X86_FEATURE_INVALID;
	if(!mem&&!(p1&4))return X86_FEATURE_INVALID;if(op==0x38||op==0x3a||op==0x80){if((p1&0x83)!=0)return X86_FEATURE_INVALID;w=1;}else{if((p1&3)>1||((p1&3)==1&&(p1&0x80)))return X86_FEATURE_INVALID;w=(p1&1)?2:(p1&0x80)?8:4;}
	imm=op>=0x80;if(imm&&((m>>3)&7)!=7)return X86_FEATURE_INVALID;if(!imm){rn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);rr=rex2_register(rn,w);if(rr==X86_REG_INVALID)return X86_FEATURE_INVALID;rm_first=op==0x38||op==0x39;}
	MCInst_clear(in);MCInst_setOpcode(in,X86_FEATURE_APX_CCMP_BASE+(p2&15));MCOperand_CreateImm0(in,mem);MCOperand_CreateImm0(in,rm_first);MCOperand_CreateImm0(in,rr);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);rm=rex2_register(rn,w);if(rm==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(in,rm);io=off+6;}else{if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);io=mm.length;}
	if(imm){imm_size=op==0x81?(w==2?2:4):1;if(io+imm_size>len||io+imm_size>15)return X86_FEATURE_INVALID;if(imm_size==1)iv=(int8_t)code[io];else if(imm_size==2)iv=(int16_t)(code[io]|code[io+1]<<8);else iv=(int32_t)((uint32_t)code[io]|(uint32_t)code[io+1]<<8|(uint32_t)code[io+2]<<16|(uint32_t)code[io+3]<<24);io+=imm_size;in->imm_size=imm_size;}
	MCOperand_CreateImm0(in,imm);MCOperand_CreateImm0(in,iv);MCOperand_CreateImm0(in,w);MCOperand_CreateImm0(in,dfv);*size=(uint16_t)io;set_apx_evex_encoding_detail(in,e,off,segp,a32,mem?&mm:NULL);if(in->flat_insn->detail&&imm){in->flat_insn->detail->x86.encoding.imm_offset=(uint8_t)(io-imm_size);in->flat_insn->detail->x86.encoding.imm_size=imm_size;}return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_ctest(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0,io;uint8_t segp=0,p0,p1,p2,op,m,w,dfv,imm_size=0;bool a32=false,bad=false,mem,imm;x86_reg rr=X86_REG_INVALID,rm=X86_REG_INVALID,seg=X86_REG_INVALID;unsigned rn,group;int64_t iv=0;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<6)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0x84&&op!=0x85&&op!=0xf6&&op!=0xf7)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];mem=(m&0xc0)!=0xc0;imm=op==0xf6||op==0xf7;group=(m>>3)&7;if(imm&&group>1)return X86_FEATURE_NOT_HANDLED;dfv=(p1>>3)&15;if((p2&0xf0)||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;
	if(op==0x84||op==0xf6){if(p1&0x83)return X86_FEATURE_INVALID;w=1;}else{if((p1&3)>1||((p1&3)==1&&(p1&0x80)))return X86_FEATURE_INVALID;w=(p1&1)?2:(p1&0x80)?8:4;}
	if(!imm){rn=((~p0&0x80)>>4)|(~p0&0x10)|group;rr=rex2_register(rn,w);if(rr==X86_REG_INVALID)return X86_FEATURE_INVALID;}
	MCInst_clear(in);MCInst_setOpcode(in,X86_FEATURE_APX_CTEST_BASE+(p2&15));MCOperand_CreateImm0(in,mem);MCOperand_CreateImm0(in,1);MCOperand_CreateImm0(in,rr);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);rm=rex2_register(rn,w);if(rm==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(in,rm);io=off+6;}else{if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);io=mm.length;}
	if(imm){imm_size=op==0xf7?(w==2?2:4):1;if(io+imm_size>len||io+imm_size>15)return X86_FEATURE_INVALID;if(imm_size==1)iv=(int8_t)code[io];else if(imm_size==2)iv=(int16_t)(code[io]|code[io+1]<<8);else iv=(int32_t)((uint32_t)code[io]|(uint32_t)code[io+1]<<8|(uint32_t)code[io+2]<<16|(uint32_t)code[io+3]<<24);io+=imm_size;in->imm_size=imm_size;}
	MCOperand_CreateImm0(in,imm);MCOperand_CreateImm0(in,iv);MCOperand_CreateImm0(in,w);MCOperand_CreateImm0(in,dfv);*size=(uint16_t)io;set_apx_evex_encoding_detail(in,e,off,segp,a32,mem?&mm:NULL);if(in->flat_insn->detail&&imm){in->flat_insn->detail->x86.encoding.imm_offset=(uint8_t)(io-imm_size);in->flat_insn->detail->x86.encoding.imm_size=imm_size;}return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_kmov(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0;uint8_t segp=0,p0,p1,p2,op,m,pp,w,fi;bool a32=false,bad=false,mem;x86_reg reg,rm=X86_REG_INVALID,seg=X86_REG_INVALID;unsigned rn,mn;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=1)return X86_FEATURE_NOT_HANDLED;if(len-off<6)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op<0x90||op>0x93)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;mem=(m&0xc0)!=0xc0;if((p1&0x78)!=0x78||(!mem&&!(p1&4))||p2!=8)return X86_FEATURE_INVALID;
	if(op<=0x91){if(pp==1&&!(p1&0x80)){w=1;fi=0;}else if(pp==0&&!(p1&0x80)){w=2;fi=3;}else if(pp==1&&(p1&0x80)){w=4;fi=1;}else if(pp==0&&(p1&0x80)){w=8;fi=2;}else return X86_FEATURE_INVALID;}else{if(pp==1&&!(p1&0x80)){w=1;fi=0;}else if(pp==0&&!(p1&0x80)){w=2;fi=3;}else if(pp==3&&!(p1&0x80)){w=4;fi=1;}else if(pp==3&&(p1&0x80)){w=8;fi=2;}else return X86_FEATURE_INVALID;}
	if((op==0x91&&!mem)||((op==0x92||op==0x93)&&mem))return X86_FEATURE_INVALID;rn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);mn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);
	if(op==0x93)reg=rex2_register(rn,w==8?8:4);else{if(rn>7)return X86_FEATURE_INVALID;reg=(x86_reg)(X86_REG_K0+rn);}if(reg==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(in);MCInst_setOpcode(in,X86_FEATURE_APX_KMOV_BASE+fi);MCOperand_CreateImm0(in,op);MCOperand_CreateImm0(in,reg);MCOperand_CreateImm0(in,mem);
	if(!mem){if(op==0x92)rm=rex2_register(mn,w==8?8:4);else{if(mn>7)return X86_FEATURE_INVALID;rm=(x86_reg)(X86_REG_K0+mn);}if(rm==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(in,rm);MCOperand_CreateImm0(in,w);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(in,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);MCOperand_CreateImm0(in,w);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(in,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_movrs(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0;uint8_t segp=0,p0,p1,p2,op,m,w;bool a32=false,bad=false;x86_reg dst,seg;unsigned rn;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<6)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0x8a&&op!=0x8b)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];if((m&0xc0)==0xc0||(p1&0x78)!=0x78||p2!=8)return X86_FEATURE_INVALID;if(op==0x8a){if(p1&0x83)return X86_FEATURE_INVALID;w=1;}else{if((p1&3)>1||((p1&3)==1&&(p1&0x80)))return X86_FEATURE_INVALID;w=(p1&1)?2:(p1&0x80)?8:4;}
	rn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);dst=rex2_register(rn,w);if(dst==X86_REG_INVALID||!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);MCInst_clear(in);MCInst_setOpcode(in,X86_FEATURE_APX_MOVRS);MCOperand_CreateImm0(in,dst);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);MCOperand_CreateImm0(in,w);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(in,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_invalidate(csh handle,const uint8_t*code,size_t len,MCInst*in,uint16_t*size)
{
	const cs_struct*arch=(const cs_struct*)(uintptr_t)handle;const uint8_t*e;size_t off=0;uint8_t segp=0,p0,p1,p2,op,m;bool a32=false,bad=false;x86_reg type,seg;unsigned rn;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<6)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op<0xf0||op>0xf2)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];if((m&0xc0)==0xc0||(p1&0x7b)!=0x7a||p2!=8)return X86_FEATURE_INVALID;rn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);type=rex2_register(rn,8);if(type==X86_REG_INVALID||!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);MCInst_clear(in);MCInst_setOpcode(in,X86_FEATURE_APX_INV_BASE+(op-0xf0));MCOperand_CreateImm0(in,type);add_feature_memory_operands(in,&mm);MCOperand_CreateImm0(in,seg);MCOperand_CreateImm0(in,a32?4:8);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(in,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result
decode_user_msr_legacy_vex(csh handle, const uint8_t *code, size_t code_len,
			   MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t encoding_offset = 0, instruction_size;
	uint8_t segment_prefix = 0, mandatory_prefix = 0, rex = 0;
	bool address32 = false, operand_size = false, lock_prefix = false;
	bool vex_forbidden_prefix = false;
	uint8_t modrm;
	unsigned int b_number;
	x86_reg b_register;

	while (encoding_offset < code_len && code[encoding_offset] != 0x0f &&
	       code[encoding_offset] != 0xc4) {
		uint8_t prefix = code[encoding_offset];

		if ((arch->mode & CS_MODE_64) && prefix >= 0x40 &&
		    prefix <= 0x4f) {
			rex = prefix;
			vex_forbidden_prefix = true;
			++encoding_offset;
			continue;
		}
		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66) {
			operand_size = true;
			vex_forbidden_prefix = true;
		} else if (prefix == 0xf2 || prefix == 0xf3) {
			mandatory_prefix = prefix;
			vex_forbidden_prefix = true;
		} else if (prefix == 0xf0) {
			lock_prefix = true;
			vex_forbidden_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		/* A legacy prefix following REX makes that REX ineffective. */
		rex = 0;
		++encoding_offset;
	}
	if (encoding_offset == code_len)
		return X86_FEATURE_NOT_HANDLED;

	if (code[encoding_offset] == 0xc4) {
		uint8_t p0, p1, pp;
		uint32_t immediate;

		if (code_len - encoding_offset < 4)
			return X86_FEATURE_NOT_HANDLED;
		p0 = code[encoding_offset + 1];
		p1 = code[encoding_offset + 2];
		pp = p1 & 3;
		if ((p0 & 0x1f) != 7 || code[encoding_offset + 3] != 0xf8 ||
		    (pp != 2 && pp != 3))
			return X86_FEATURE_NOT_HANDLED;
		instruction_size = encoding_offset + 9;
		if (!(arch->mode & CS_MODE_64) || vex_forbidden_prefix ||
		    lock_prefix || instruction_size > code_len ||
		    instruction_size > 15 || (p1 & 0xfc) != 0x78)
			return X86_FEATURE_INVALID;
		modrm = code[encoding_offset + 4];
		if ((modrm & 0xf8) != 0xc0)
			return X86_FEATURE_INVALID;
		b_number = ((~p0 & 0x20) >> 2) | (modrm & 7);
		b_register = rex2_register(b_number, 8);
		if (b_register == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		immediate = (uint32_t)code[encoding_offset + 5] |
			    ((uint32_t)code[encoding_offset + 6] << 8) |
			    ((uint32_t)code[encoding_offset + 7] << 16) |
			    ((uint32_t)code[encoding_offset + 8] << 24);

		MCInst_clear(instr);
		MCInst_setOpcode(instr, pp == 2 ? X86_FEATURE_APX_UWRMSR :
					       X86_FEATURE_APX_URDMSR);
		MCOperand_CreateImm0(instr, 1);
		MCOperand_CreateImm0(instr, b_register);
		MCOperand_CreateImm0(instr, (int64_t)immediate);
		*size = (uint16_t)instruction_size;
		set_amx_tile_encoding_detail(instr, code, encoding_offset, 3,
					     segment_prefix, address32,
					     encoding_offset + 4, NULL);
		instr->imm_size = 4;
		if (instr->flat_insn->detail) {
			cs_x86 *x86 = &instr->flat_insn->detail->x86;
			x86->rex = (uint8_t)(0x40 |
					     ((p1 & 0x80) ? 0x08 : 0) |
					     ((p0 & 0x80) ? 0 : 0x04) |
					     ((p0 & 0x40) ? 0 : 0x02) |
					     ((p0 & 0x20) ? 0 : 0x01));
			x86->encoding.imm_offset =
				(uint8_t)(encoding_offset + 5);
			x86->encoding.imm_size = 4;
		}
		return X86_FEATURE_DECODED;
	}

	if (mandatory_prefix != 0xf2 && mandatory_prefix != 0xf3)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - encoding_offset < 3 || code[encoding_offset] != 0x0f ||
	    code[encoding_offset + 1] != 0x38)
		return X86_FEATURE_NOT_HANDLED;
	if (code[encoding_offset + 2] != 0xf8)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - encoding_offset < 4)
		return X86_FEATURE_INVALID;
	modrm = code[encoding_offset + 3];
	/* The memory form is ENQCMD/ENQCMDS and belongs to its decoder. */
	if ((modrm & 0xc0) != 0xc0)
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || lock_prefix ||
	    encoding_offset + 4 > 15)
		return X86_FEATURE_INVALID;

	b_number = (modrm & 7) | ((rex & 1) ? 8 : 0);
	b_register = rex2_register(b_number, 8);
	{
		const unsigned int r_number = ((modrm >> 3) & 7) |
					      ((rex & 4) ? 8 : 0);
		const x86_reg r_register = rex2_register(r_number, 8);
		cs_x86 *x86;

		if (b_register == X86_REG_INVALID ||
		    r_register == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		MCInst_clear(instr);
		MCInst_setOpcode(instr,
				 mandatory_prefix == 0xf3 ? X86_FEATURE_APX_UWRMSR :
							X86_FEATURE_APX_URDMSR);
		MCOperand_CreateImm0(instr, 0);
		MCOperand_CreateImm0(instr, b_register);
		MCOperand_CreateImm0(instr, r_register);
		*size = (uint16_t)(encoding_offset + 4);
		if (!instr->flat_insn->detail)
			return X86_FEATURE_DECODED;
		x86 = &instr->flat_insn->detail->x86;
		x86->prefix[0] = mandatory_prefix;
		x86->prefix[1] = segment_prefix;
		x86->prefix[2] = operand_size ? 0x66 : 0;
		x86->prefix[3] = address32 ? 0x67 : 0;
		instr->x86_prefix[0] = mandatory_prefix;
		instr->x86_prefix[1] = segment_prefix;
		instr->x86_prefix[2] = operand_size ? 0x66 : 0;
		instr->x86_prefix[3] = address32 ? 0x67 : 0;
		x86->rex = rex;
		x86->opcode[0] = 0x0f;
		x86->opcode[1] = 0x38;
		x86->opcode[2] = 0xf8;
		x86->addr_size = address32 ? 4 : 8;
		x86->modrm = modrm;
		x86->encoding.modrm_offset = (uint8_t)(encoding_offset + 3);
	}
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result
decode_apx_msr(csh handle, const uint8_t *code, size_t code_len,
	       MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0, instruction_size;
	uint8_t segment_prefix = 0;
	bool address32 = false, forbidden_prefix = false;
	uint8_t p0, p1, p2, map, opcode, modrm, pp;
	bool immediate_form, write;
	unsigned int b_number, r_number, feature_opcode;
	x86_reg b_register, r_register = X86_REG_INVALID;
	uint32_t immediate = 0;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];
		if (is_apx_evex_segment_prefix(prefix))
			segment_prefix = prefix;
		else if (prefix == 0x67)
			address32 = true;
		else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			 prefix == 0xf3 || (prefix >= 0x40 && prefix <= 0x4f))
			forbidden_prefix = true;
		else
			return X86_FEATURE_NOT_HANDLED;
		++evex_offset;
	}
	if (evex_offset == code_len || code_len - evex_offset < 2)
		return X86_FEATURE_NOT_HANDLED;
	evex = &code[evex_offset];
	map = evex[1] & 7;
	if (map != 4 && map != 7)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - evex_offset < 5)
		return X86_FEATURE_INVALID;
	opcode = evex[4];
	if ((map == 4 && opcode != 0xf8) ||
	    (map == 7 && opcode != 0xf6 && opcode != 0xf8))
		return X86_FEATURE_NOT_HANDLED;
	p1 = evex[2];
	pp = p1 & 3;
	if (pp != 2 && pp != 3)
		return X86_FEATURE_NOT_HANDLED;
	if (code_len - evex_offset < 6)
		return X86_FEATURE_INVALID;
	modrm = evex[5];
	if (map == 4 && (modrm & 0xc0) != 0xc0)
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || forbidden_prefix ||
	    evex_offset + 6 > 15 || (modrm & 0xc0) != 0xc0)
		return X86_FEATURE_INVALID;

	p0 = evex[1];
	p2 = evex[3];
	immediate_form = map == 7;
	write = pp == 2;
	if ((p1 & 0x7c) != 0x7c || p2 != 0x08 ||
	    (immediate_form && ((modrm >> 3) & 7) != 0) ||
	    (opcode == 0xf8 && (p1 & 0x80) != 0))
		return X86_FEATURE_INVALID;

	b_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) |
		   (modrm & 7);
	b_register = rex2_register(b_number, 8);
	if (b_register == X86_REG_INVALID)
		return X86_FEATURE_INVALID;
	if (!immediate_form) {
		r_number = ((~p0 & 0x80) >> 4) | (~p0 & 0x10) |
			   ((modrm >> 3) & 7);
		r_register = rex2_register(r_number, 8);
		if (r_register == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		instruction_size = evex_offset + 6;
	} else {
		instruction_size = evex_offset + 10;
		if (instruction_size > code_len || instruction_size > 15)
			return X86_FEATURE_INVALID;
		immediate = (uint32_t)code[evex_offset + 6] |
			    ((uint32_t)code[evex_offset + 7] << 8) |
			    ((uint32_t)code[evex_offset + 8] << 16) |
			    ((uint32_t)code[evex_offset + 9] << 24);
	}

	if (opcode == 0xf6)
		feature_opcode = write ? X86_FEATURE_APX_WRMSRNS_IMM :
					 X86_FEATURE_APX_RDMSR_IMM;
	else
		feature_opcode = write ? X86_FEATURE_APX_UWRMSR :
					 X86_FEATURE_APX_URDMSR;
	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, immediate_form);
	MCOperand_CreateImm0(instr, b_register);
	MCOperand_CreateImm0(instr,
			     immediate_form ? (int64_t)immediate : r_register);
	*size = (uint16_t)instruction_size;
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32, NULL);
	if (immediate_form) {
		instr->imm_size = 4;
		if (instr->flat_insn->detail) {
			cs_x86 *x86 = &instr->flat_insn->detail->x86;
			x86->encoding.imm_offset = (uint8_t)(evex_offset + 6);
			x86->encoding.imm_size = 4;
		}
	}
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_bls(csh handle,const uint8_t *code,size_t len,MCInst *instr,uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle;const uint8_t *e;size_t off=0;uint8_t segp=0,p0,p1,p2,m,w,g;bool a32=false,bad=false,mem,nf;x86_reg dst,src=X86_REG_INVALID,seg;unsigned dn,rn,feature;x86_feature_memory memory;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=2)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];if(e[4]!=0xf3)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];g=(m>>3)&7;if(g<1||g>3)return X86_FEATURE_NOT_HANDLED;mem=(m&0xc0)!=0xc0;nf=(p2&4)!=0;if((p1&3)!=0||(p2&0xf3)!=0||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;
	w=(p1&0x80)?8:4;dn=((~p2&8)<<1)|((~p1&0x78)>>3);dst=rex2_register(dn,w);if(dst==X86_REG_INVALID)return X86_FEATURE_INVALID;feature=g==1?X86_FEATURE_APX_BLSR:g==2?X86_FEATURE_APX_BLSMSK:X86_FEATURE_APX_BLSI;
	MCInst_clear(instr);MCInst_setOpcode(instr,feature);MCOperand_CreateImm0(instr,dst);MCOperand_CreateImm0(instr,mem);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);src=rex2_register(rn,w);if(src==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(instr,src);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,1);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(instr,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&memory))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(instr,&memory);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,1);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)memory.length;set_apx_evex_encoding_detail(instr,e,off,segp,a32,&memory);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_bextr(csh handle,const uint8_t *code,size_t len,MCInst *instr,uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle;const uint8_t *e;size_t off=0;uint8_t segp=0,p0,p1,p2,m,w;bool a32=false,bad=false,mem,nf;x86_reg dst,ctl,data=X86_REG_INVALID,seg;unsigned dn,cn,rn;x86_feature_memory memory;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=2)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];if(e[4]!=0xf7)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];mem=(m&0xc0)!=0xc0;nf=(p2&4)!=0;if((p2&0xf3)!=0||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;unsigned feature=(p1&3)==0?X86_FEATURE_APX_BEXTR:(p1&3)==2?X86_FEATURE_APX_SARX:(p1&3)==1?X86_FEATURE_APX_SHLX:X86_FEATURE_APX_SHRX;if(feature!=X86_FEATURE_APX_BEXTR&&nf)return X86_FEATURE_INVALID;w=(p1&0x80)?8:4;dn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);cn=((~p2&8)<<1)|((~p1&0x78)>>3);dst=rex2_register(dn,w);ctl=rex2_register(cn,w);if(dst==X86_REG_INVALID||ctl==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(instr);MCInst_setOpcode(instr,feature);MCOperand_CreateImm0(instr,dst);MCOperand_CreateImm0(instr,ctl);MCOperand_CreateImm0(instr,mem);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);data=rex2_register(rn,w);if(data==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(instr,data);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(instr,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&memory))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(instr,&memory);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)memory.length;set_apx_evex_encoding_detail(instr,e,off,segp,a32,&memory);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_count(csh handle,const uint8_t *code,size_t len,MCInst *instr,uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle;const uint8_t *e;size_t off=0;uint8_t segp=0,p0,p1,p2,op,m,w,pp;bool a32=false,bad=false,mem,nf;x86_reg dst,src=X86_REG_INVALID,seg;unsigned dn,rn,feature;x86_feature_memory memory;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0xf5&&op!=0xf4&&op!=0x88)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;mem=(m&0xc0)!=0xc0;nf=(p2&4)!=0;if(pp>1||(p1&0x78)!=0x78||!(p2&8)||(p2&0xf3)!=0||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;w=(p1&0x80)?8:pp?2:4;feature=op==0xf5?X86_FEATURE_APX_LZCNT:op==0xf4?X86_FEATURE_APX_TZCNT:X86_FEATURE_APX_POPCNT;dn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);dst=rex2_register(dn,w);if(dst==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(instr);MCInst_setOpcode(instr,feature);MCOperand_CreateImm0(instr,dst);MCOperand_CreateImm0(instr,mem);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);src=rex2_register(rn,w);if(src==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(instr,src);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,1);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(instr,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&memory))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(instr,&memory);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,1);MCOperand_CreateImm0(instr,nf);*size=(uint16_t)memory.length;set_apx_evex_encoding_detail(instr,e,off,segp,a32,&memory);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_rorx(csh handle,const uint8_t *code,size_t len,MCInst *instr,uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle;const uint8_t *e;size_t off=0,io;uint8_t segp=0,p0,p1,p2,m,w,imm;bool a32=false,bad=false,mem;x86_reg dst,src=X86_REG_INVALID,seg;unsigned dn,rn;x86_feature_memory memory;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=3)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];if(e[4]!=0xf0)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<7||off+7>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];mem=(m&0xc0)!=0xc0;if((p1&0x7b)!=0x7b||(!mem&&!(p1&4))||p2!=8)return X86_FEATURE_INVALID;w=(p1&0x80)?8:4;dn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);dst=rex2_register(dn,w);if(dst==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(instr);MCInst_setOpcode(instr,X86_FEATURE_APX_RORX);MCOperand_CreateImm0(instr,dst);MCOperand_CreateImm0(instr,mem);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);src=rex2_register(rn,w);if(src==X86_REG_INVALID)return X86_FEATURE_INVALID;io=off+6;}else{if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&memory))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(instr,&memory);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);io=memory.length;}
	if(io>=len||io>=15)return X86_FEATURE_INVALID;imm=code[io];if(!mem)MCOperand_CreateImm0(instr,src);MCOperand_CreateImm0(instr,w);MCOperand_CreateImm0(instr,imm);*size=(uint16_t)(io+1);set_apx_evex_encoding_detail(instr,e,off,segp,a32,mem?&memory:NULL);instr->imm_size=1;if(instr->flat_insn->detail){instr->flat_insn->detail->x86.encoding.imm_offset=(uint8_t)io;instr->flat_insn->detail->x86.encoding.imm_size=1;}return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_mulx(csh handle,const uint8_t *code,size_t len,MCInst *instr,uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle;const uint8_t *e;size_t off=0;uint8_t segp=0,p0,p1,p2,m,w;bool a32=false,bad=false,mem;x86_reg d1,d2,src=X86_REG_INVALID,seg;unsigned n1,n2,rn;x86_feature_memory memory;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=2)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];if(e[4]!=0xf6)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];mem=(m&0xc0)!=0xc0;if((p1&3)!=3||(!mem&&!(p1&4))||(p2&0xf7)!=0)return X86_FEATURE_INVALID;w=(p1&0x80)?8:4;n1=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);n2=((~p2&8)<<1)|((~p1&0x78)>>3);d1=rex2_register(n1,w);d2=rex2_register(n2,w);if(d1==X86_REG_INVALID||d2==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(instr);MCInst_setOpcode(instr,X86_FEATURE_APX_MULX);MCOperand_CreateImm0(instr,d1);MCOperand_CreateImm0(instr,d2);MCOperand_CreateImm0(instr,mem);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);src=rex2_register(rn,w);if(src==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(instr,src);MCOperand_CreateImm0(instr,w);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(instr,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&memory))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(instr,&memory);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);MCOperand_CreateImm0(instr,w);*size=(uint16_t)memory.length;set_apx_evex_encoding_detail(instr,e,off,segp,a32,&memory);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_convert(csh handle,const uint8_t *code,size_t len,MCInst *instr,uint16_t *size)
{
	const cs_struct *arch=(const cs_struct *)(uintptr_t)handle;const uint8_t *e;size_t off=0;uint8_t segp=0,p0,p1,p2,op,m,pp,dw,sw;bool a32=false,bad=false,mem,crc,store;x86_reg d,s=X86_REG_INVALID,seg;unsigned dn,rn;x86_feature_memory mm;
	while(off<len&&code[off]!=0x62){uint8_t p=code[off];if(is_apx_evex_segment_prefix(p))segp=p;else if(p==0x67)a32=true;else if(p==0x66||p==0xf0||p==0xf2||p==0xf3||(p>=0x40&&p<=0x4f))bad=true;else return X86_FEATURE_NOT_HANDLED;++off;}
	if(off==len||len-off<2||(code[off+1]&7)!=4)return X86_FEATURE_NOT_HANDLED;if(len-off<5)return X86_FEATURE_INVALID;e=&code[off];op=e[4];if(op!=0x60&&op!=0x61&&op!=0xf0&&op!=0xf1)return X86_FEATURE_NOT_HANDLED;if(!(arch->mode&CS_MODE_64)||bad||len-off<6||off+6>15)return X86_FEATURE_INVALID;
	p0=e[1];p1=e[2];p2=e[3];m=e[5];pp=p1&3;mem=(m&0xc0)!=0xc0;crc=op>=0xf0;store=op==0x61;if(pp>1||(p1&0x78)!=0x78||p2!=8||(!mem&&!(p1&4)))return X86_FEATURE_INVALID;
	if(crc){if(op==0xf0&&pp)return X86_FEATURE_INVALID;dw=(p1&0x80)?8:4;sw=op==0xf0?1:(pp?2:dw);store=false;}else{dw=sw=pp?2:((p1&0x80)?8:4);}
	dn=((~p0&0x80)>>4)|(~p0&0x10)|((m>>3)&7);d=rex2_register(dn,store?sw:dw);if(d==X86_REG_INVALID)return X86_FEATURE_INVALID;
	MCInst_clear(instr);MCInst_setOpcode(instr,crc?X86_FEATURE_APX_CRC32:X86_FEATURE_APX_MOVBE);MCOperand_CreateImm0(instr,d);MCOperand_CreateImm0(instr,mem);MCOperand_CreateImm0(instr,store);
	if(!mem){rn=((~p0&0x20)>>2)|((p0&8)<<1)|(m&7);s=rex2_register(rn,store?dw:sw);if(s==X86_REG_INVALID)return X86_FEATURE_INVALID;MCOperand_CreateImm0(instr,s);MCOperand_CreateImm0(instr,dw);MCOperand_CreateImm0(instr,sw);*size=(uint16_t)(off+6);set_apx_evex_encoding_detail(instr,e,off,segp,a32,NULL);return X86_FEATURE_DECODED;}
	if(!decode_apx_evex_memory(code,len,off+5,p0,p1,a32,&mm))return X86_FEATURE_INVALID;seg=apx_segment_register(segp);add_feature_memory_operands(instr,&mm);MCOperand_CreateImm0(instr,seg);MCOperand_CreateImm0(instr,a32?4:8);MCOperand_CreateImm0(instr,dw);MCOperand_CreateImm0(instr,sw);*size=(uint16_t)mm.length;set_apx_evex_encoding_detail(instr,e,off,segp,a32,&mm);return X86_FEATURE_DECODED;
}

static x86_feature_decode_result
decode_apx_adc_sbb(csh handle, const uint8_t *code, size_t code_len,
		   MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0, instruction_size, immediate_offset = 0;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false, memory_form;
	bool binary_form, immediate_form, nd;
	uint8_t p0, p1, p2, opcode, modrm, pp, width, memory_position = 0;
	uint8_t immediate_size = 0;
	unsigned int feature_opcode, reg_number, rm_number, ndd_number;
	x86_reg destination = X86_REG_INVALID;
	x86_reg source1 = X86_REG_INVALID, source2 = X86_REG_INVALID;
	x86_reg reg_field = X86_REG_INVALID, rm_field = X86_REG_INVALID;
	x86_reg ndd_field = X86_REG_INVALID, segment;
	int64_t immediate = 0;
	x86_feature_memory memory;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			   prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++evex_offset;
	}
	if (evex_offset == code_len || code_len - evex_offset < 2 ||
	    (code[evex_offset + 1] & 7) != 4) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (code_len - evex_offset < 5)
		return X86_FEATURE_INVALID;
	evex = &code[evex_offset];
	opcode = evex[4];
	binary_form = is_apx_adc_sbb_binary_opcode(opcode);
	immediate_form = opcode == 0x80 || opcode == 0x81 || opcode == 0x83;
	if (!binary_form && !immediate_form)
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    code_len - evex_offset < 6 || evex_offset + 6 > 15) {
		return X86_FEATURE_INVALID;
	}

	p0 = evex[1];
	p1 = evex[2];
	p2 = evex[3];
	modrm = evex[5];
	pp = p1 & 3;
	memory_form = (modrm & 0xc0) != 0xc0;
	if (binary_form) {
		feature_opcode = opcode < 0x18 ? X86_FEATURE_APX_ADC :
						 X86_FEATURE_APX_SBB;
	} else {
		uint8_t group = (modrm >> 3) & 7;

		if (group != 2 && group != 3)
			return X86_FEATURE_NOT_HANDLED;
		feature_opcode = group == 2 ? X86_FEATURE_APX_ADC :
					      X86_FEATURE_APX_SBB;
	}
	if ((p2 & 0xe7) != 0 || (!memory_form && !(p1 & 0x04)))
		return X86_FEATURE_INVALID;
	if ((binary_form && (opcode & 1) == 0) || opcode == 0x80) {
		if (pp != 0)
			return X86_FEATURE_INVALID;
		width = 1;
	} else if (p1 & 0x80) {
		if (pp > 1)
			return X86_FEATURE_INVALID;
		width = 8;
	} else if (pp == 1) {
		width = 2;
	} else if (pp == 0) {
		width = 4;
	} else {
		return X86_FEATURE_INVALID;
	}

	nd = (p2 & 0x10) != 0;
	ndd_number = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
	if (!nd && ndd_number != 0)
		return X86_FEATURE_INVALID;
	if (nd) {
		ndd_field = rex2_register(ndd_number, width);
		if (ndd_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
	}

	if (binary_form || !memory_form) {
		reg_number = ((~p0 & 0x80) >> 4) | (~p0 & 0x10) |
			     ((modrm >> 3) & 7);
		reg_field = rex2_register(reg_number, width);
		if (binary_form && reg_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
	}

	memset(&memory, 0, sizeof(memory));
	if (memory_form) {
		if (!decode_apx_evex_memory(code, code_len, evex_offset + 5, p0,
					    p1, address32, &memory)) {
			return X86_FEATURE_INVALID;
		}
		instruction_size = memory.length;
	} else {
		rm_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) |
			    (modrm & 7);
		rm_field = rex2_register(rm_number, width);
		if (rm_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		instruction_size = evex_offset + 6;
	}

	if (binary_form) {
		if (opcode & 2) {
			source1 = reg_field;
			source2 = rm_field;
			memory_position = memory_form ? 2 : 0;
		} else {
			source1 = rm_field;
			source2 = reg_field;
			memory_position = memory_form ? 1 : 0;
		}
	} else {
		source1 = rm_field;
		memory_position = memory_form ? 1 : 0;
		immediate_size = opcode == 0x81 ? (width == 2 ? 2 : 4) : 1;
		immediate_offset = instruction_size;
		if (code_len - instruction_size < immediate_size)
			return X86_FEATURE_INVALID;
		if (immediate_size == 1) {
			immediate = width == 1 ? code[instruction_size] :
						 (int8_t)code[instruction_size];
		} else if (immediate_size == 2) {
			immediate = (uint16_t)code[instruction_size] |
				    ((uint16_t)code[instruction_size + 1] << 8);
		} else if (width == 8) {
			immediate = read_i32(&code[instruction_size]);
		} else {
			immediate = (uint32_t)read_i32(&code[instruction_size]);
		}
		instruction_size += immediate_size;
	}
	if (instruction_size > 15)
		return X86_FEATURE_INVALID;
	destination = nd ? ndd_field : source1;
	if ((source1 == X86_REG_INVALID && memory_position != 1) ||
	    (binary_form && source2 == X86_REG_INVALID &&
	     memory_position != 2) ||
	    (destination == X86_REG_INVALID &&
	     !(memory_position == 1 && !nd))) {
		return X86_FEATURE_INVALID;
	}

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, destination);
	MCOperand_CreateImm0(instr, source1);
	MCOperand_CreateImm0(instr, source2);
	MCOperand_CreateImm0(instr, memory_position);
	if (memory_form) {
		segment = apx_segment_register(segment_prefix);
		add_feature_memory_operands(instr, &memory);
		MCOperand_CreateImm0(instr, segment);
		MCOperand_CreateImm0(instr, address32 ? 4 : 8);
	}
	MCOperand_CreateImm0(instr, immediate_form);
	MCOperand_CreateImm0(instr, immediate);
	MCOperand_CreateImm0(instr, width);
	MCOperand_CreateImm0(instr, nd);
	*size = (uint16_t)instruction_size;
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32, memory_form ? &memory : NULL);
	if (immediate_form) {
		instr->imm_size = immediate_size;
		if (instr->flat_insn->detail) {
			cs_x86 *x86 = &instr->flat_insn->detail->x86;

			x86->encoding.imm_offset = (uint8_t)immediate_offset;
			x86->encoding.imm_size = immediate_size;
		}
	}
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_setcc(csh handle,
						  const uint8_t *code,
						  size_t code_len,
						  MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false;
	uint8_t p0, p1, p2, opcode, modrm;
	bool zu, memory_form;
	unsigned int feature_opcode;
	x86_reg destination = X86_REG_INVALID;
	x86_reg segment;
	x86_feature_memory memory;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			   prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++evex_offset;
	}
	if (code_len - evex_offset < 2 || (code[evex_offset + 1] & 7) != 4) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (code_len - evex_offset < 5)
		return X86_FEATURE_INVALID;
	evex = &code[evex_offset];
	opcode = evex[4];
	if (opcode < 0x40 || opcode > 0x4f)
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    code_len - evex_offset < 6 || evex_offset + 6 > 15) {
		return X86_FEATURE_INVALID;
	}

	p0 = evex[1];
	p1 = evex[2];
	p2 = evex[3];
	modrm = evex[5];
	memory_form = (modrm & 0xc0) != 0xc0;
	// SETcc is fixed to F2/map4, uses logical VVVVV=0, never accepts NF,
	// and leaves W ignored. U is fixed to one for a register destination
	// and becomes the inverted X4 address bit for a memory destination.
	if ((p1 & 0x7b) != 0x7b || (p2 & 0xe7) != 0 || !(p2 & 0x08) ||
	    (!memory_form && !(p1 & 0x04))) {
		return X86_FEATURE_INVALID;
	}
	zu = (p2 & 0x10) != 0;
	feature_opcode = (zu ? X86_FEATURE_APX_SETZUCC_BASE :
			       X86_FEATURE_APX_SETCC_BASE) +
			 (opcode & 15);

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	if (!memory_form) {
		unsigned int number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) |
				      (modrm & 7);

		destination = rex2_register(number, 1);
		if (destination == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		MCOperand_CreateImm0(instr, destination);
		*size = (uint16_t)(evex_offset + 6);
		set_apx_evex_encoding_detail(instr, evex, evex_offset,
					     segment_prefix, address32, NULL);
		return X86_FEATURE_DECODED;
	}

	if (!decode_apx_evex_memory(code, code_len, evex_offset + 5, p0, p1,
				    address32, &memory)) {
		return X86_FEATURE_INVALID;
	}
	segment = apx_segment_register(segment_prefix);
	MCOperand_CreateImm0(instr, memory.base);
	MCOperand_CreateImm0(instr, memory.index);
	MCOperand_CreateImm0(instr, memory.scale);
	MCOperand_CreateImm0(instr, memory.displacement);
	MCOperand_CreateImm0(instr, segment);
	MCOperand_CreateImm0(instr, address32 ? 4 : 8);
	*size = (uint16_t)memory.length;
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32, &memory);
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result decode_apx_cmov(csh handle,
						 const uint8_t *code,
						 size_t code_len, MCInst *instr,
						 uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0;
	uint8_t segment_prefix = 0;
	bool address32 = false, invalid_prefix = false;
	uint8_t p0, p1, p2, opcode, modrm, width, pp;
	bool nd, nf, memory_form;
	unsigned int reg_number, rm_number, ndd_number, feature_opcode;
	x86_reg reg_field, rm_field = X86_REG_INVALID;
	x86_reg ndd_field = X86_REG_INVALID;
	x86_reg segment;
	x86_feature_memory memory;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address32 = true;
		} else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			   prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++evex_offset;
	}
	if (code_len - evex_offset < 2 || (code[evex_offset + 1] & 7) != 4) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (code_len - evex_offset < 5)
		return X86_FEATURE_INVALID;
	evex = &code[evex_offset];
	opcode = evex[4];
	if (opcode < 0x40 || opcode > 0x4f)
		return X86_FEATURE_NOT_HANDLED;
	p1 = evex[2];
	pp = p1 & 3;
	// F2 selects the promoted SETcc family sharing these opcodes.
	if (pp == 3)
		return X86_FEATURE_NOT_HANDLED;
	if (!(arch->mode & CS_MODE_64) || invalid_prefix || pp > 1 ||
	    code_len - evex_offset < 6 || evex_offset + 6 > 15) {
		return X86_FEATURE_INVALID;
	}

	p0 = evex[1];
	p2 = evex[3];
	modrm = evex[5];
	memory_form = (modrm & 0xc0) != 0xc0;
	// LL and the two low payload bits are reserved.  VVVVV names an NDD
	// only when ND is set; otherwise its logical value must be zero.
	if ((p2 & 0xe3) != 0 || (!memory_form && !(p1 & 0x04)))
		return X86_FEATURE_INVALID;
	nd = (p2 & 0x10) != 0;
	nf = (p2 & 0x04) != 0;
	ndd_number = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
	if (!nd && ndd_number != 0)
		return X86_FEATURE_INVALID;
	width = (p1 & 0x80) ? 8 : pp == 1 ? 2 : 4;
	reg_number = ((~p0 & 0x80) >> 4) | (~p0 & 0x10) | ((modrm >> 3) & 7);
	reg_field = rex2_register(reg_number, width);
	if (reg_field == X86_REG_INVALID)
		return X86_FEATURE_INVALID;
	if (nd) {
		ndd_field = rex2_register(ndd_number, width);
		if (ndd_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
	}
	feature_opcode = (nd && !nf ? X86_FEATURE_APX_CMOVCC_BASE :
				      X86_FEATURE_APX_CFCMOVCC_BASE) +
			 (opcode & 15);

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, reg_field);
	MCOperand_CreateImm0(instr, ndd_field);
	MCOperand_CreateImm0(instr, memory_form);
	if (!memory_form) {
		rm_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) |
			    (modrm & 7);
		rm_field = rex2_register(rm_number, width);
		if (rm_field == X86_REG_INVALID)
			return X86_FEATURE_INVALID;
		MCOperand_CreateImm0(instr, rm_field);
		MCOperand_CreateImm0(instr, width);
		MCOperand_CreateImm0(instr, nd);
		MCOperand_CreateImm0(instr, nf);
		*size = (uint16_t)(evex_offset + 6);
		set_apx_evex_encoding_detail(instr, evex, evex_offset,
					     segment_prefix, address32, NULL);
		return X86_FEATURE_DECODED;
	}

	if (!decode_apx_evex_memory(code, code_len, evex_offset + 5, p0, p1,
				    address32, &memory)) {
		return X86_FEATURE_INVALID;
	}
	segment = apx_segment_register(segment_prefix);
	MCOperand_CreateImm0(instr, memory.base);
	MCOperand_CreateImm0(instr, memory.index);
	MCOperand_CreateImm0(instr, memory.scale);
	MCOperand_CreateImm0(instr, memory.displacement);
	MCOperand_CreateImm0(instr, segment);
	MCOperand_CreateImm0(instr, address32 ? 4 : 8);
	MCOperand_CreateImm0(instr, width);
	MCOperand_CreateImm0(instr, nd);
	MCOperand_CreateImm0(instr, nf);
	*size = (uint16_t)memory.length;
	set_apx_evex_encoding_detail(instr, evex, evex_offset, segment_prefix,
				     address32, &memory);
	return X86_FEATURE_DECODED;
}

static x86_feature_decode_result
decode_apx_evex_alu(csh handle, const uint8_t *code, size_t code_len,
		    MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	const uint8_t *evex;
	size_t evex_offset = 0;
	uint8_t p0, p1, p2, opcode, modrm;
	uint8_t segment_prefix = 0;
	unsigned int reg_number, rm_number, ndd_number;
	unsigned int feature_opcode;
	x86_reg destination, source1, source2;
	uint8_t width;
	bool nd, nf, address_size_prefix = false, invalid_prefix = false;
	cs_x86 *x86;

	while (evex_offset < code_len && code[evex_offset] != 0x62) {
		uint8_t prefix = code[evex_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
		} else if (prefix == 0x67) {
			address_size_prefix = true;
		} else if (prefix == 0x66 || prefix == 0xf0 || prefix == 0xf2 ||
			   prefix == 0xf3 ||
			   (prefix >= 0x40 && prefix <= 0x4f)) {
			invalid_prefix = true;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++evex_offset;
	}
	if (code_len - evex_offset < 2 || (code[evex_offset + 1] & 7) != 4) {
		return X86_FEATURE_NOT_HANDLED;
	}
	if (!(arch->mode & CS_MODE_64) || invalid_prefix ||
	    code_len - evex_offset < 6 || evex_offset + 6 > 15) {
		return X86_FEATURE_INVALID;
	}

	evex = &code[evex_offset];
	p0 = evex[1];
	p1 = evex[2];
	p2 = evex[3];
	opcode = evex[4];
	modrm = evex[5];
	feature_opcode = apx_evex_alu_feature_opcode(opcode);
	if (feature_opcode == 0 || (modrm & 0xc0) != 0xc0 || !(p1 & 0x04) ||
	    (p2 & 0xe3) != 0) {
		return X86_FEATURE_INVALID;
	}
	if ((opcode & 1) == 0) {
		if ((p1 & 3) != 0)
			return X86_FEATURE_INVALID;
		width = 1;
	} else if (p1 & 0x80) {
		if ((p1 & 3) > 1)
			return X86_FEATURE_INVALID;
		width = 8;
	} else if ((p1 & 3) == 1) {
		width = 2;
	} else if ((p1 & 3) == 0) {
		width = 4;
	} else {
		return X86_FEATURE_INVALID;
	}
	nd = (p2 & 0x10) != 0;
	nf = (p2 & 0x04) != 0;
	ndd_number = ((~p2 & 0x08) << 1) | ((~p1 & 0x78) >> 3);
	if (!nd && ndd_number != 0)
		return X86_FEATURE_INVALID;

	reg_number = ((~p0 & 0x80) >> 4) | (~p0 & 0x10) | ((modrm >> 3) & 7);
	rm_number = ((~p0 & 0x20) >> 2) | ((p0 & 0x08) << 1) | (modrm & 7);
	if (opcode & 2) {
		source1 = rex2_register(reg_number, width);
		source2 = rex2_register(rm_number, width);
	} else {
		source1 = rex2_register(rm_number, width);
		source2 = rex2_register(reg_number, width);
	}
	destination = nd ? rex2_register(ndd_number, width) : source1;
	if (destination == X86_REG_INVALID || source1 == X86_REG_INVALID ||
	    source2 == X86_REG_INVALID) {
		return X86_FEATURE_INVALID;
	}

	MCInst_clear(instr);
	MCInst_setOpcode(instr, feature_opcode);
	MCOperand_CreateImm0(instr, destination);
	MCOperand_CreateImm0(instr, source1);
	MCOperand_CreateImm0(instr, source2);
	MCOperand_CreateImm0(instr, width);
	MCOperand_CreateImm0(instr, nd);
	MCOperand_CreateImm0(instr, nf);
	*size = (uint16_t)(evex_offset + 6);

	if (!instr->flat_insn->detail)
		return X86_FEATURE_DECODED;
	x86 = &instr->flat_insn->detail->x86;
	x86->opcode[0] = evex[0];
	x86->opcode[1] = p0;
	x86->opcode[2] = p1;
	x86->opcode[3] = p2;
	x86->prefix[1] = segment_prefix;
	x86->prefix[3] = address_size_prefix ? 0x67 : 0;
	instr->x86_prefix[1] = segment_prefix;
	instr->x86_prefix[3] = address_size_prefix ? 0x67 : 0;
	x86->addr_size = address_size_prefix ? 4 : 8;
	x86->modrm = modrm;
	x86->encoding.modrm_offset = (uint8_t)(evex_offset + 5);
	return X86_FEATURE_DECODED;
}

static bool is_rex2_leading_prefix(uint8_t byte)
{
	switch (byte) {
	default:
		return byte >= 0x40 && byte <= 0x4f;
	case 0x26:
	case 0x2e:
	case 0x36:
	case 0x3e:
	case 0x64:
	case 0x65:
	case 0x66:
	case 0x67:
	case 0xf0:
	case 0xf2:
	case 0xf3:
		return true;
	}
}

static bool starts_with_legacy_inc_dec(csh handle, const uint8_t *code,
				       size_t code_len)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t offset = 0;

	if (arch->mode & CS_MODE_64)
		return false;
	while (offset < code_len) {
		const uint8_t byte = code[offset];

		if (byte >= 0x40 && byte <= 0x4f)
			return true;
		if (!is_apx_evex_segment_prefix(byte) && byte != 0x66 &&
		    byte != 0x67 && byte != 0xf0 && byte != 0xf2 &&
		    byte != 0xf3)
			return false;
		++offset;
	}
	return false;
}

static x86_reg rex2_register(unsigned int number, uint8_t width)
{
	static const x86_reg registers_8[] = {
		X86_REG_AL,   X86_REG_CL,   X86_REG_DL,	  X86_REG_BL,
		X86_REG_SPL,  X86_REG_BPL,  X86_REG_SIL,  X86_REG_DIL,
		X86_REG_R8B,  X86_REG_R9B,  X86_REG_R10B, X86_REG_R11B,
		X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B,
		X86_REG_R16B, X86_REG_R17B, X86_REG_R18B, X86_REG_R19B,
		X86_REG_R20B, X86_REG_R21B, X86_REG_R22B, X86_REG_R23B,
		X86_REG_R24B, X86_REG_R25B, X86_REG_R26B, X86_REG_R27B,
		X86_REG_R28B, X86_REG_R29B, X86_REG_R30B, X86_REG_R31B,
	};
	static const x86_reg registers_16[] = {
		X86_REG_AX,   X86_REG_CX,   X86_REG_DX,	  X86_REG_BX,
		X86_REG_SP,   X86_REG_BP,   X86_REG_SI,	  X86_REG_DI,
		X86_REG_R8W,  X86_REG_R9W,  X86_REG_R10W, X86_REG_R11W,
		X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, X86_REG_R15W,
		X86_REG_R16W, X86_REG_R17W, X86_REG_R18W, X86_REG_R19W,
		X86_REG_R20W, X86_REG_R21W, X86_REG_R22W, X86_REG_R23W,
		X86_REG_R24W, X86_REG_R25W, X86_REG_R26W, X86_REG_R27W,
		X86_REG_R28W, X86_REG_R29W, X86_REG_R30W, X86_REG_R31W,
	};
	static const x86_reg registers_32[] = {
		X86_REG_EAX,  X86_REG_ECX,  X86_REG_EDX,  X86_REG_EBX,
		X86_REG_ESP,  X86_REG_EBP,  X86_REG_ESI,  X86_REG_EDI,
		X86_REG_R8D,  X86_REG_R9D,  X86_REG_R10D, X86_REG_R11D,
		X86_REG_R12D, X86_REG_R13D, X86_REG_R14D, X86_REG_R15D,
		X86_REG_R16D, X86_REG_R17D, X86_REG_R18D, X86_REG_R19D,
		X86_REG_R20D, X86_REG_R21D, X86_REG_R22D, X86_REG_R23D,
		X86_REG_R24D, X86_REG_R25D, X86_REG_R26D, X86_REG_R27D,
		X86_REG_R28D, X86_REG_R29D, X86_REG_R30D, X86_REG_R31D,
	};
	static const x86_reg registers_64[] = {
		X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX, X86_REG_RSP,
		X86_REG_RBP, X86_REG_RSI, X86_REG_RDI, X86_REG_R8,  X86_REG_R9,
		X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14,
		X86_REG_R15, X86_REG_R16, X86_REG_R17, X86_REG_R18, X86_REG_R19,
		X86_REG_R20, X86_REG_R21, X86_REG_R22, X86_REG_R23, X86_REG_R24,
		X86_REG_R25, X86_REG_R26, X86_REG_R27, X86_REG_R28, X86_REG_R29,
		X86_REG_R30, X86_REG_R31,
	};

	if (number >= ARR_SIZE(registers_8))
		return X86_REG_INVALID;

	switch (width) {
	default:
		return X86_REG_INVALID;
	case 1:
		return registers_8[number];
	case 2:
		return registers_16[number];
	case 4:
		return registers_32[number];
	case 8:
		return registers_64[number];
	}
}

static x86_feature_decode_result
decode_apx_jmpabs(csh handle, const uint8_t *code, size_t code_len,
		  MCInst *instr, uint16_t *size)
{
	const cs_struct *arch = (const cs_struct *)(uintptr_t)handle;
	size_t rex2_offset = 0;
	uint8_t segment_prefix = 0;
	uint8_t payload;
	bool invalid_prefix = false;
	bool effective_rex = false;
	uint64_t target;
	cs_x86 *x86;

	if (!(arch->mode & CS_MODE_64))
		return X86_FEATURE_NOT_HANDLED;

	while (rex2_offset < code_len && code[rex2_offset] != 0xd5) {
		uint8_t prefix = code[rex2_offset];

		if (is_apx_evex_segment_prefix(prefix)) {
			segment_prefix = prefix;
			effective_rex = false;
		} else if (prefix >= 0x40 && prefix <= 0x4f) {
			effective_rex = true;
		} else if (is_rex2_leading_prefix(prefix)) {
			// JMPABS accepts segment overrides only.  Other effective
			// legacy prefixes are invalid for this opcode.
			invalid_prefix = true;
			effective_rex = false;
		} else {
			return X86_FEATURE_NOT_HANDLED;
		}
		++rex2_offset;
	}
	if (rex2_offset == code_len || code_len - rex2_offset < 3 ||
	    code[rex2_offset + 2] != 0xa1) {
		return X86_FEATURE_NOT_HANDLED;
	}
	payload = code[rex2_offset + 1];
	if ((payload & 0x80) != 0)
		return X86_FEATURE_NOT_HANDLED;
	if (invalid_prefix || effective_rex || (payload & 0x08) != 0 ||
	    code_len - rex2_offset < 11 ||
	    rex2_offset + 11 > 15) {
		return X86_FEATURE_INVALID;
	}

	target = read_u64(&code[rex2_offset + 3]);
	MCInst_clear(instr);
	MCInst_setOpcode(instr, X86_FEATURE_JMPABS);
	MCOperand_CreateImm0(instr, (int64_t)target);
	instr->imm_size = 8;
	*size = (uint16_t)(rex2_offset + 11);

	if (!instr->flat_insn->detail)
		return X86_FEATURE_DECODED;
	x86 = &instr->flat_insn->detail->x86;
	x86->prefix[1] = segment_prefix;
	instr->x86_prefix[1] = segment_prefix;
	x86->opcode[0] = 0xa1;
	x86->rex2 = payload;
	x86->addr_size = 8;
	x86->encoding.imm_offset = (uint8_t)(rex2_offset + 3);
	x86->encoding.imm_size = 8;
	return X86_FEATURE_DECODED;
}

static bool has_duplicate_feature_evex_prefixes(const uint8_t *code,
						 size_t code_len)
{
	// Repeated legacy segment/address-size prefixes are architecturally
	// undefined.  Keep this fork's canonical fail-closed policy stateless and
	// ahead of every feature-extension decoder so a newly added APX topology
	// cannot accidentally reintroduce last-prefix-wins normalization.
	size_t prefix_offset = 0;
	unsigned int segment_count = 0, address_size_count = 0;
	while (prefix_offset < code_len && code[prefix_offset] != 0x62 &&
	       code[prefix_offset] != 0xd5) {
		uint8_t prefix = code[prefix_offset++];
		if (is_apx_evex_segment_prefix(prefix))
			++segment_count;
		else if (prefix == 0x67)
			++address_size_count;
		else if (is_rex2_leading_prefix(prefix))
			continue;
		else
			break;
	}
	if ((segment_count <= 1 && address_size_count <= 1) ||
	    prefix_offset >= code_len)
		return false;
	if (code[prefix_offset] == 0xd5)
		return true;
	return code[prefix_offset] == 0x62 && code_len - prefix_offset >= 2 &&
	       (code[prefix_offset + 1] & 7) >= 2 &&
	       (code[prefix_offset + 1] & 7) <= 4;
}

x86_feature_decode_result
X86_decodeFeatureExtension(csh handle, const uint8_t *code, size_t code_len,
			   MCInst *instr, uint16_t *size)
{
	/* In 16/32-bit modes 0x40..0x4f are INC/DEC opcodes, not REX
	 * prefixes.  Do not let a later EVEX-looking byte sequence make a
	 * feature decoder reinterpret the current legacy instruction. */
	if (starts_with_legacy_inc_dec(handle, code, code_len))
		return X86_FEATURE_NOT_HANDLED;
	if (has_duplicate_feature_evex_prefixes(code, code_len))
		return X86_FEATURE_INVALID;

	x86_feature_decode_result result =
		decode_legacy_cet_store(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_legacy_enqueue(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_user_msr_legacy_vex(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_evex_vector_gpr(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_direct_store(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_msr(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_enqueue(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_rao(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_cmpccxadd(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_ccmp(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_ctest(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_kmov(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_movrs(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_invalidate(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_amx(handle, code, code_len, instr, size);

	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_rex2_push_pop(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_push2_pop2(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_cmov(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_setcc(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_shift_rotate(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_imul_immediate(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_imul(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_adx(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_unary(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_pdep_pext(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_double_shift(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_bmi_ternary(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_bls(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_bextr(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_count(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_rorx(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_mulx(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_convert(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_adc_sbb(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_evex_alu(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	result = decode_apx_jmpabs(handle, code, code_len, instr, size);
	if (result != X86_FEATURE_NOT_HANDLED)
		return result;
	return X86_FEATURE_NOT_HANDLED;
}

static bool print_tilezero(MCInst *instr, SStream *stream, bool att_syntax)
{
	const MCOperand *operand;
	unsigned int tile;
	cs_x86_op *public_operand;

	if (MCInst_getOpcode(instr) != X86_FEATURE_TILEZERO ||
	    MCInst_getNumOperands(instr) != 1)
		return false;

	operand = MCInst_getOperand(instr, 0);
	if (!MCOperand_isImm(operand))
		return false;
	tile = (unsigned int)MCOperand_getImm(operand);
	if (tile > 7)
		return false;

	if (att_syntax)
		SStream_concat(stream, "tilezero\t%%tmm%u", tile);
	else
		SStream_concat(stream, "tilezero\ttmm%u", tile);

	if (!instr->flat_insn->detail)
		return true;

	public_operand = &instr->flat_insn->detail->x86.operands[0];
	public_operand->type = X86_OP_REG;
	public_operand->reg = X86_REG_TMM0 + tile;
	// Tile dimensions are configured at runtime and may exceed uint8_t.
	public_operand->size = 0;
	public_operand->access = CS_AC_WRITE;
	instr->flat_insn->detail->x86.op_count = 1;
	return true;
}

static const char *feature_register_name(x86_reg reg)
{
	const char *extension_name = X86_featureExtensionRegisterName(reg);

	if (extension_name)
		return extension_name;
	switch (reg) {
	default:
		return NULL;
	case X86_REG_RAX:
		return "rax";
	case X86_REG_RCX:
		return "rcx";
	case X86_REG_RDX:
		return "rdx";
	case X86_REG_RBX:
		return "rbx";
	case X86_REG_RSP:
		return "rsp";
	case X86_REG_RBP:
		return "rbp";
	case X86_REG_RSI:
		return "rsi";
	case X86_REG_RDI:
		return "rdi";
	case X86_REG_R8:
		return "r8";
	case X86_REG_R9:
		return "r9";
	case X86_REG_R10:
		return "r10";
	case X86_REG_R11:
		return "r11";
	case X86_REG_R12:
		return "r12";
	case X86_REG_R13:
		return "r13";
	case X86_REG_R14:
		return "r14";
	case X86_REG_R15:
		return "r15";
	case X86_REG_RIP:
		return "rip";
	case X86_REG_EIP:
		return "eip";
	case X86_REG_EAX:
		return "eax";
	case X86_REG_ECX:
		return "ecx";
	case X86_REG_EDX:
		return "edx";
	case X86_REG_EBX:
		return "ebx";
	case X86_REG_ESP:
		return "esp";
	case X86_REG_EBP:
		return "ebp";
	case X86_REG_ESI:
		return "esi";
	case X86_REG_EDI:
		return "edi";
	case X86_REG_R8D:
		return "r8d";
	case X86_REG_R9D:
		return "r9d";
	case X86_REG_R10D:
		return "r10d";
	case X86_REG_R11D:
		return "r11d";
	case X86_REG_R12D:
		return "r12d";
	case X86_REG_R13D:
		return "r13d";
	case X86_REG_R14D:
		return "r14d";
	case X86_REG_R15D:
		return "r15d";
	case X86_REG_AX:
		return "ax";
	case X86_REG_CX:
		return "cx";
	case X86_REG_DX:
		return "dx";
	case X86_REG_BX:
		return "bx";
	case X86_REG_SP:
		return "sp";
	case X86_REG_BP:
		return "bp";
	case X86_REG_SI:
		return "si";
	case X86_REG_DI:
		return "di";
	case X86_REG_ES:
		return "es";
	case X86_REG_CS:
		return "cs";
	case X86_REG_SS:
		return "ss";
	case X86_REG_DS:
		return "ds";
	case X86_REG_FS:
		return "fs";
	case X86_REG_GS:
		return "gs";
	}
}

static bool get_feature_memory(MCInst *instr, unsigned int first_operand,
			       x86_feature_memory *memory)
{
	const MCOperand *base, *index, *scale, *displacement;

	if (MCInst_getNumOperands(instr) < first_operand + 4)
		return false;
	base = MCInst_getOperand(instr, first_operand);
	index = MCInst_getOperand(instr, first_operand + 1);
	scale = MCInst_getOperand(instr, first_operand + 2);
	displacement = MCInst_getOperand(instr, first_operand + 3);
	if (!MCOperand_isImm(base) || !MCOperand_isImm(index) ||
	    !MCOperand_isImm(scale) || !MCOperand_isImm(displacement)) {
		return false;
	}

	memset(memory, 0, sizeof(*memory));
	memory->base = (x86_reg)MCOperand_getImm(base);
	memory->index = (x86_reg)MCOperand_getImm(index);
	memory->scale = (int8_t)MCOperand_getImm(scale);
	memory->displacement = MCOperand_getImm(displacement);
	if (memory->scale != 1 && memory->scale != 2 && memory->scale != 4 &&
	    memory->scale != 8) {
		return false;
	}
	if (memory->base != X86_REG_INVALID &&
	    !feature_register_name(memory->base)) {
		return false;
	}
	if (memory->index != X86_REG_INVALID &&
	    !feature_register_name(memory->index)) {
		return false;
	}
	return true;
}

static uint64_t displacement_magnitude(int64_t displacement)
{
	return displacement < 0 ? (uint64_t)(-(displacement + 1)) + 1 :
				  (uint64_t)displacement;
}

static bool print_feature_memory(SStream *stream,
				 const x86_feature_memory *memory,
				 bool att_syntax)
{
	const char *base_name = feature_register_name(memory->base);
	const char *index_name = feature_register_name(memory->index);
	bool has_register = base_name || index_name;
	uint64_t magnitude = displacement_magnitude(memory->displacement);

	if (att_syntax) {
		if (memory->displacement != 0 || !has_register) {
			if (memory->displacement < 0)
				SStream_concat(stream, "-0x%llx",
					       (unsigned long long)magnitude);
			else
				SStream_concat(stream, "0x%llx",
					       (unsigned long long)magnitude);
		}
		if (has_register) {
			SStream_concat0(stream, "(");
			if (base_name)
				SStream_concat(stream, "%%%s", base_name);
			if (index_name) {
				SStream_concat(stream, ",%%%s", index_name);
				if (memory->scale != 1)
					SStream_concat(stream, ",%d",
						       memory->scale);
			}
			SStream_concat0(stream, ")");
		}
		return true;
	}

	SStream_concat0(stream, "[");
	if (base_name)
		SStream_concat0(stream, base_name);
	if (index_name) {
		if (base_name)
			SStream_concat0(stream, " + ");
		SStream_concat0(stream, index_name);
		if (memory->scale != 1)
			SStream_concat(stream, "*%d", memory->scale);
	}
	if (memory->displacement != 0 || !has_register) {
		if (has_register) {
			SStream_concat0(stream, memory->displacement < 0 ?
							" - " :
							" + ");
		} else if (memory->displacement < 0) {
			SStream_concat0(stream, "-");
		}
		SStream_concat(stream, "0x%llx", (unsigned long long)magnitude);
	}
	SStream_concat0(stream, "]");
	return true;
}

static void set_feature_memory_operand(cs_x86_op *operand,
				       const x86_feature_memory *memory,
				       uint8_t size, cs_ac_type access)
{
	operand->type = X86_OP_MEM;
	operand->mem.segment = X86_REG_INVALID;
	operand->mem.base = memory->base;
	operand->mem.index = memory->index;
	operand->mem.scale = memory->scale;
	operand->mem.disp = memory->displacement;
	operand->size = size;
	operand->access = access;
}

static void set_feature_tile_operand(cs_x86_op *operand, x86_reg tile,
				     cs_ac_type access)
{
	operand->type = X86_OP_REG;
	operand->reg = tile;
	// Tile dimensions are configured at runtime and may exceed uint8_t.
	operand->size = 0;
	operand->access = access;
}

static void set_all_tile_writes(cs_detail *detail)
{
	uint8_t tile;

	// TILECFG and TILES_CONFIGURED are architectural state, not addressable
	// registers.  Publish the observable TMM invalidation without inventing a
	// synthetic register ID.
	for (tile = 0; tile < 8; ++tile)
		detail->regs_write[tile] = X86_REG_TMM0 + tile;
	detail->regs_write_count = 8;
}

static bool print_tile_control(MCInst *instr, SStream *stream, bool att_syntax)
{
	unsigned int opcode = MCInst_getOpcode(instr);
	const char *mnemonic;
	x86_feature_memory memory;
	cs_ac_type access;
	const MCOperand *segment_operand, *address_size_operand;
	x86_reg segment;
	uint8_t address_size;
	const char *segment_name;

	if (opcode == X86_FEATURE_TILERELEASE) {
		if (MCInst_getNumOperands(instr) != 0)
			return false;
		SStream_concat0(stream, "tilerelease");
		if (instr->flat_insn->detail)
			set_all_tile_writes(instr->flat_insn->detail);
		return true;
	}
	if (opcode != X86_FEATURE_LDTILECFG &&
	    opcode != X86_FEATURE_STTILECFG) {
		return false;
	}
	if (MCInst_getNumOperands(instr) != 6 ||
	    !get_feature_memory(instr, 0, &memory)) {
		return false;
	}
	segment_operand = MCInst_getOperand(instr, 4);
	address_size_operand = MCInst_getOperand(instr, 5);
	if (!MCOperand_isImm(segment_operand) ||
	    !MCOperand_isImm(address_size_operand)) {
		return false;
	}
	segment = (x86_reg)MCOperand_getImm(segment_operand);
	address_size = (uint8_t)MCOperand_getImm(address_size_operand);
	segment_name = segment == X86_REG_INVALID ?
			       NULL :
			       feature_register_name(segment);
	if ((address_size != 4 && address_size != 8) ||
	    (segment != X86_REG_INVALID && !segment_name)) {
		return false;
	}

	mnemonic = opcode == X86_FEATURE_LDTILECFG ? "ldtilecfg" : "sttilecfg";
	access = opcode == X86_FEATURE_LDTILECFG ? CS_AC_READ : CS_AC_WRITE;
	SStream_concat(stream, "%s\t", mnemonic);
	if (segment_name) {
		SStream_concat(stream,
			       att_syntax ? "%%%s:" : "%s:", segment_name);
	}
	if (!print_feature_memory(stream, &memory, att_syntax))
		return false;
	if (instr->flat_insn->detail) {
		set_feature_memory_operand(
			&instr->flat_insn->detail->x86.operands[0], &memory, 64,
			access);
		instr->flat_insn->detail->x86.operands[0].mem.segment = segment;
		instr->flat_insn->detail->x86.op_count = 1;
		if (opcode == X86_FEATURE_LDTILECFG)
			set_all_tile_writes(instr->flat_insn->detail);
	}
	return true;
}

static bool print_tile_memory(MCInst *instr, SStream *stream, bool att_syntax)
{
	unsigned int opcode = MCInst_getOpcode(instr);
	const MCOperand *tile_operand;
	unsigned int tile_number;
	x86_reg tile;
	const char *tile_name, *mnemonic;
	x86_feature_memory memory;
	bool is_store;
	uint8_t tile_index, memory_index;
	const MCOperand *segment_operand, *address_size_operand;
	x86_reg segment;
	uint8_t address_size;
	const char *segment_name;

	if (opcode != X86_FEATURE_TILELOADD &&
	    opcode != X86_FEATURE_TILELOADDT1 &&
	    opcode != X86_FEATURE_TILELOADDRS &&
	    opcode != X86_FEATURE_TILELOADDRST1 &&
	    opcode != X86_FEATURE_TILESTORED) {
		return false;
	}
	if (MCInst_getNumOperands(instr) != 7)
		return false;
	tile_operand = MCInst_getOperand(instr, 0);
	if (!MCOperand_isImm(tile_operand) ||
	    !get_feature_memory(instr, 1, &memory)) {
		return false;
	}
	segment_operand = MCInst_getOperand(instr, 5);
	address_size_operand = MCInst_getOperand(instr, 6);
	if (!MCOperand_isImm(segment_operand) ||
	    !MCOperand_isImm(address_size_operand)) {
		return false;
	}
	segment = (x86_reg)MCOperand_getImm(segment_operand);
	address_size = (uint8_t)MCOperand_getImm(address_size_operand);
	segment_name = segment == X86_REG_INVALID ?
			       NULL :
			       feature_register_name(segment);
	if ((address_size != 4 && address_size != 8) ||
	    (segment != X86_REG_INVALID && !segment_name)) {
		return false;
	}
	tile_number = (unsigned int)MCOperand_getImm(tile_operand);
	if (tile_number > 7)
		return false;
	tile = X86_REG_TMM0 + tile_number;
	tile_name = feature_register_name(tile);
	if (!tile_name)
		return false;

	is_store = opcode == X86_FEATURE_TILESTORED;
	mnemonic = is_store			       ? "tilestored" :
		   opcode == X86_FEATURE_TILELOADDT1   ? "tileloaddt1" :
		   opcode == X86_FEATURE_TILELOADDRS   ? "tileloaddrs" :
		   opcode == X86_FEATURE_TILELOADDRST1 ? "tileloaddrst1" :
							 "tileloadd";
	SStream_concat(stream, "%s\t", mnemonic);
	if (att_syntax == is_store) {
		if (att_syntax)
			SStream_concat(stream, "%%%s, ", tile_name);
		else
			SStream_concat(stream, "%s, ", tile_name);
	}
	if (segment_name) {
		SStream_concat(stream,
			       att_syntax ? "%%%s:" : "%s:", segment_name);
	}
	if (!print_feature_memory(stream, &memory, att_syntax))
		return false;
	if (att_syntax != is_store) {
		if (att_syntax)
			SStream_concat(stream, ", %%%s", tile_name);
		else
			SStream_concat(stream, ", %s", tile_name);
	}

	if (!instr->flat_insn->detail)
		return true;
	tile_index = att_syntax == is_store ? 0 : 1;
	memory_index = tile_index ^ 1;
	set_feature_tile_operand(
		&instr->flat_insn->detail->x86.operands[tile_index], tile,
		is_store ? CS_AC_READ : CS_AC_WRITE);
	set_feature_memory_operand(
		&instr->flat_insn->detail->x86.operands[memory_index], &memory,
		0, is_store ? CS_AC_WRITE : CS_AC_READ);
	instr->flat_insn->detail->x86.operands[memory_index].mem.segment =
		segment;
	instr->flat_insn->detail->x86.op_count = 2;
	return true;
}

static const char *amx_row_mnemonic(unsigned int opcode)
{
	switch (opcode) {
	default:
		return NULL;
	case X86_FEATURE_TILEMOVROW:
		return "tilemovrow";
	case X86_FEATURE_TCVTROWD2PS:
		return "tcvtrowd2ps";
	case X86_FEATURE_TCVTROWPS2BF16H:
		return "tcvtrowps2bf16h";
	case X86_FEATURE_TCVTROWPS2BF16L:
		return "tcvtrowps2bf16l";
	case X86_FEATURE_TCVTROWPS2PHH:
		return "tcvtrowps2phh";
	case X86_FEATURE_TCVTROWPS2PHL:
		return "tcvtrowps2phl";
	}
}

static void set_feature_register_operand(cs_x86_op *operand, x86_reg reg,
					 uint8_t size, cs_ac_type access)
{
	operand->type = X86_OP_REG;
	operand->reg = reg;
	operand->size = size;
	operand->access = access;
}

static bool print_amx_row(MCInst *instr, SStream *stream, bool att_syntax)
{
	const char *mnemonic = amx_row_mnemonic(MCInst_getOpcode(instr));
	const MCOperand *destination_operand, *tile_operand, *selector_operand,
		*immediate_form_operand;
	x86_reg destination, tile, selector;
	unsigned int destination_number, tile_number;
	uint8_t selector_value;
	bool immediate_form;
	const char *selector_name = NULL;
	cs_x86 *x86;

	if (!mnemonic || MCInst_getNumOperands(instr) != 4)
		return false;
	destination_operand = MCInst_getOperand(instr, 0);
	tile_operand = MCInst_getOperand(instr, 1);
	selector_operand = MCInst_getOperand(instr, 2);
	immediate_form_operand = MCInst_getOperand(instr, 3);
	if (!MCOperand_isImm(destination_operand) ||
	    !MCOperand_isImm(tile_operand) ||
	    !MCOperand_isImm(selector_operand) ||
	    !MCOperand_isImm(immediate_form_operand)) {
		return false;
	}
	destination = (x86_reg)MCOperand_getImm(destination_operand);
	tile = (x86_reg)MCOperand_getImm(tile_operand);
	immediate_form = MCOperand_getImm(immediate_form_operand) != 0;
	if (destination < X86_REG_ZMM0 || destination > X86_REG_ZMM31 ||
	    tile < X86_REG_TMM0 || tile > X86_REG_TMM7)
		return false;
	destination_number = destination - X86_REG_ZMM0;
	tile_number = tile - X86_REG_TMM0;
	if (immediate_form) {
		int64_t value = MCOperand_getImm(selector_operand);

		if (value < 0 || value > UINT8_MAX)
			return false;
		selector_value = (uint8_t)value;
	} else {
		selector = (x86_reg)MCOperand_getImm(selector_operand);
		selector_name = feature_register_name(selector);
		if (!selector_name)
			return false;
	}

	if (att_syntax) {
		if (immediate_form)
			SStream_concat(stream, "%s\t$0x%x, %%tmm%u, %%zmm%u",
				       mnemonic, selector_value, tile_number,
				       destination_number);
		else
			SStream_concat(stream, "%s\t%%%s, %%tmm%u, %%zmm%u",
				       mnemonic, selector_name, tile_number,
				       destination_number);
	} else if (immediate_form) {
		SStream_concat(stream, "%s\tzmm%u, tmm%u, 0x%x", mnemonic,
			       destination_number, tile_number, selector_value);
	} else {
		SStream_concat(stream, "%s\tzmm%u, tmm%u, %s", mnemonic,
			       destination_number, tile_number, selector_name);
	}

	if (!instr->flat_insn->detail)
		return true;
	x86 = &instr->flat_insn->detail->x86;
	if (att_syntax) {
		if (immediate_form) {
			x86->operands[0].type = X86_OP_IMM;
			x86->operands[0].imm = selector_value;
			x86->operands[0].size = 1;
			x86->operands[0].access = CS_AC_READ;
		} else {
			set_feature_register_operand(&x86->operands[0],
						     selector, 4, CS_AC_READ);
		}
		set_feature_tile_operand(&x86->operands[1], tile, CS_AC_READ);
		set_feature_register_operand(&x86->operands[2], destination, 64,
					     CS_AC_WRITE);
	} else {
		set_feature_register_operand(&x86->operands[0], destination, 64,
					     CS_AC_WRITE);
		set_feature_tile_operand(&x86->operands[1], tile, CS_AC_READ);
		if (immediate_form) {
			x86->operands[2].type = X86_OP_IMM;
			x86->operands[2].imm = selector_value;
			x86->operands[2].size = 1;
			x86->operands[2].access = CS_AC_READ;
		} else {
			set_feature_register_operand(&x86->operands[2],
						     selector, 4, CS_AC_READ);
		}
	}
	x86->op_count = 3;
	return true;
}

static const char *tile_compute_mnemonic(unsigned int opcode)
{
	switch (opcode) {
	default:
		return NULL;
	case X86_FEATURE_TDPBSSD:
		return "tdpbssd";
	case X86_FEATURE_TDPBSUD:
		return "tdpbsud";
	case X86_FEATURE_TDPBUSD:
		return "tdpbusd";
	case X86_FEATURE_TDPBUUD:
		return "tdpbuud";
	case X86_FEATURE_TDPBF16PS:
		return "tdpbf16ps";
	case X86_FEATURE_TDPFP16PS:
		return "tdpfp16ps";
	case X86_FEATURE_TCMMIMFP16PS:
		return "tcmmimfp16ps";
	case X86_FEATURE_TCMMRLFP16PS:
		return "tcmmrlfp16ps";
	case X86_FEATURE_TDPBF8PS:
		return "tdpbf8ps";
	case X86_FEATURE_TDPBHF8PS:
		return "tdpbhf8ps";
	case X86_FEATURE_TDPHBF8PS:
		return "tdphbf8ps";
	case X86_FEATURE_TDPHF8PS:
		return "tdphf8ps";
	case X86_FEATURE_TMMULTF32PS:
		return "tmmultf32ps";
	}
}

static bool print_tile_compute(MCInst *instr, SStream *stream, bool att_syntax)
{
	const char *mnemonic = tile_compute_mnemonic(MCInst_getOpcode(instr));
	unsigned int tiles[3];
	uint8_t printed_tiles[3];
	uint8_t access[3];
	uint8_t i;

	if (!mnemonic || MCInst_getNumOperands(instr) != 3)
		return false;
	for (i = 0; i < 3; ++i) {
		const MCOperand *operand = MCInst_getOperand(instr, i);

		if (!MCOperand_isImm(operand))
			return false;
		tiles[i] = (unsigned int)MCOperand_getImm(operand);
		if (tiles[i] > 7)
			return false;
	}
	if (tiles[0] == tiles[1] || tiles[0] == tiles[2] ||
	    tiles[1] == tiles[2]) {
		return false;
	}

	if (att_syntax) {
		printed_tiles[0] = (uint8_t)tiles[2];
		printed_tiles[1] = (uint8_t)tiles[1];
		printed_tiles[2] = (uint8_t)tiles[0];
		access[0] = CS_AC_READ;
		access[1] = CS_AC_READ;
		access[2] = CS_AC_READ | CS_AC_WRITE;
		SStream_concat(stream, "%s\t%%tmm%u, %%tmm%u, %%tmm%u",
			       mnemonic, printed_tiles[0], printed_tiles[1],
			       printed_tiles[2]);
	} else {
		printed_tiles[0] = (uint8_t)tiles[0];
		printed_tiles[1] = (uint8_t)tiles[1];
		printed_tiles[2] = (uint8_t)tiles[2];
		access[0] = CS_AC_READ | CS_AC_WRITE;
		access[1] = CS_AC_READ;
		access[2] = CS_AC_READ;
		SStream_concat(stream, "%s\ttmm%u, tmm%u, tmm%u", mnemonic,
			       printed_tiles[0], printed_tiles[1],
			       printed_tiles[2]);
	}

	if (!instr->flat_insn->detail)
		return true;
	for (i = 0; i < 3; ++i) {
		set_feature_tile_operand(
			&instr->flat_insn->detail->x86.operands[i],
			X86_REG_TMM0 + printed_tiles[i], access[i]);
	}
	instr->flat_insn->detail->x86.op_count = 3;
	return true;
}

static bool print_apx_evex_alu(MCInst *instr, SStream *stream, bool att_syntax)
{
	const MCOperand *destination_operand, *source1_operand,
		*source2_operand;
	const MCOperand *width_operand, *nd_operand, *nf_operand;
	x86_reg destination, source1, source2;
	const char *destination_name, *source1_name, *source2_name;
	cs_detail *detail;
	cs_x86 *x86;
	uint8_t width;
	x86_reg printed_registers[3];
	uint8_t printed_count;
	uint8_t destination_index;
	uint8_t i;
	bool nd, nf;
	char suffix;
	const char *mnemonic;
	uint64_t eflags;

	if (MCInst_getNumOperands(instr) != 6)
		return false;
	switch (MCInst_getOpcode(instr)) {
	default:
		return false;
	case X86_FEATURE_REX2_ADD:
		mnemonic = "add";
		eflags = X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
			 X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_OR:
		mnemonic = "or";
		eflags = X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_AND:
		mnemonic = "and";
		eflags = X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_SUB:
		mnemonic = "sub";
		eflags = X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
			 X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_XOR:
		mnemonic = "xor";
		eflags = X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	}
	destination_operand = MCInst_getOperand(instr, 0);
	source1_operand = MCInst_getOperand(instr, 1);
	source2_operand = MCInst_getOperand(instr, 2);
	width_operand = MCInst_getOperand(instr, 3);
	nd_operand = MCInst_getOperand(instr, 4);
	nf_operand = MCInst_getOperand(instr, 5);
	if (!MCOperand_isImm(destination_operand) ||
	    !MCOperand_isImm(source1_operand) ||
	    !MCOperand_isImm(source2_operand) ||
	    !MCOperand_isImm(width_operand) || !MCOperand_isImm(nd_operand) ||
	    !MCOperand_isImm(nf_operand)) {
		return false;
	}

	destination = (x86_reg)MCOperand_getImm(destination_operand);
	source1 = (x86_reg)MCOperand_getImm(source1_operand);
	source2 = (x86_reg)MCOperand_getImm(source2_operand);
	width = (uint8_t)MCOperand_getImm(width_operand);
	nd = MCOperand_getImm(nd_operand) != 0;
	nf = MCOperand_getImm(nf_operand) != 0;
	if ((!nd && source1 != destination) ||
	    (width != 1 && width != 2 && width != 4 && width != 8)) {
		return false;
	}
	destination_name = X86_reg_name((csh)instr->csh, destination);
	source1_name = X86_reg_name((csh)instr->csh, source1);
	source2_name = X86_reg_name((csh)instr->csh, source2);
	if (!destination_name || !source1_name || !source2_name)
		return false;

	if (nf)
		SStream_concat0(stream, "{nf}|");
	if (att_syntax) {
		switch (width) {
		default:
			return false;
		case 1:
			suffix = 'b';
			break;
		case 2:
			suffix = 'w';
			break;
		case 4:
			suffix = 'l';
			break;
		case 8:
			suffix = 'q';
			break;
		}
		if (nd) {
			SStream_concat(stream, "%s%c\t%%%s, %%%s, %%%s",
				       mnemonic, suffix, source2_name,
				       source1_name, destination_name);
			printed_registers[0] = source2;
			printed_registers[1] = source1;
			printed_registers[2] = destination;
			destination_index = 2;
			printed_count = 3;
		} else {
			SStream_concat(stream, "%s%c\t%%%s, %%%s", mnemonic,
				       suffix, source2_name, destination_name);
			printed_registers[0] = source2;
			printed_registers[1] = destination;
			destination_index = 1;
			printed_count = 2;
		}
	} else if (nd) {
		SStream_concat(stream, "%s\t%s, %s, %s", mnemonic,
			       destination_name, source1_name, source2_name);
		printed_registers[0] = destination;
		printed_registers[1] = source1;
		printed_registers[2] = source2;
		destination_index = 0;
		printed_count = 3;
	} else {
		SStream_concat(stream, "%s\t%s, %s", mnemonic, destination_name,
			       source2_name);
		printed_registers[0] = destination;
		printed_registers[1] = source2;
		destination_index = 0;
		printed_count = 2;
	}
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	for (i = 0; i < printed_count; ++i) {
		x86->operands[i].type = X86_OP_REG;
		x86->operands[i].reg = printed_registers[i];
		x86->operands[i].size = width;
		x86->operands[i].access =
			i == destination_index ?
				(nd ? CS_AC_WRITE : CS_AC_READ | CS_AC_WRITE) :
				CS_AC_READ;
	}
	x86->op_count = printed_count;
	if (!nf) {
		detail->regs_write[0] = X86_REG_EFLAGS;
		detail->regs_write_count = 1;
		x86->eflags = eflags;
	}
	return true;
}

static bool print_rex2(MCInst *instr, SStream *stream, bool att_syntax)
{
	unsigned int opcode = MCInst_getOpcode(instr);
	const MCOperand *destination_operand, *source_operand, *width_operand;
	x86_reg destination, source;
	uint8_t width;
	uint8_t destination_index, source_index;
	uint8_t destination_access;
	const char *destination_name, *source_name, *mnemonic;
	char suffix;
	uint64_t eflags = 0;
	cs_detail *detail;
	cs_x86 *x86;

	if (MCInst_getNumOperands(instr) != 3)
		return false;
	switch (opcode) {
	default:
		return false;
	case X86_FEATURE_REX2_MOV:
		mnemonic = "mov";
		destination_access = CS_AC_WRITE;
		break;
	case X86_FEATURE_REX2_ADD:
		mnemonic = "add";
		destination_access = CS_AC_READ | CS_AC_WRITE;
		eflags = X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
			 X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_SUB:
		mnemonic = "sub";
		destination_access = CS_AC_READ | CS_AC_WRITE;
		eflags = X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
			 X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_CMP:
		mnemonic = "cmp";
		destination_access = CS_AC_READ;
		eflags = X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF |
			 X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_AND:
		mnemonic = "and";
		destination_access = CS_AC_READ | CS_AC_WRITE;
		eflags = X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_OR:
		mnemonic = "or";
		destination_access = CS_AC_READ | CS_AC_WRITE;
		eflags = X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_XOR:
		mnemonic = "xor";
		destination_access = CS_AC_READ | CS_AC_WRITE;
		eflags = X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	case X86_FEATURE_REX2_TEST:
		mnemonic = "test";
		destination_access = CS_AC_READ;
		eflags = X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_RESET_CF |
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_PF |
			 X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF;
		break;
	}

	destination_operand = MCInst_getOperand(instr, 0);
	source_operand = MCInst_getOperand(instr, 1);
	width_operand = MCInst_getOperand(instr, 2);
	if (!MCOperand_isImm(destination_operand) ||
	    !MCOperand_isImm(source_operand) || !MCOperand_isImm(width_operand))
		return false;

	destination = (x86_reg)MCOperand_getImm(destination_operand);
	source = (x86_reg)MCOperand_getImm(source_operand);
	width = (uint8_t)MCOperand_getImm(width_operand);
	destination_name = X86_reg_name((csh)instr->csh, destination);
	source_name = X86_reg_name((csh)instr->csh, source);
	if (!destination_name || !source_name)
		return false;

	if (att_syntax) {
		switch (width) {
		default:
			return false;
		case 1:
			suffix = 'b';
			break;
		case 2:
			suffix = 'w';
			break;
		case 4:
			suffix = 'l';
			break;
		case 8:
			suffix = 'q';
			break;
		}
		SStream_concat(stream, "%s%c\t%%%s, %%%s", mnemonic, suffix,
			       source_name, destination_name);
	} else {
		SStream_concat(stream, "%s\t%s, %s", mnemonic, destination_name,
			       source_name);
	}

	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	destination_index = att_syntax ? 1 : 0;
	source_index = att_syntax ? 0 : 1;
	x86->operands[destination_index].type = X86_OP_REG;
	x86->operands[destination_index].reg = destination;
	x86->operands[destination_index].size = width;
	x86->operands[destination_index].access = destination_access;
	x86->operands[source_index].type = X86_OP_REG;
	x86->operands[source_index].reg = source;
	x86->operands[source_index].size = width;
	x86->operands[source_index].access = CS_AC_READ;
	x86->op_count = 2;

	if (eflags != 0) {
		detail->regs_write[0] = X86_REG_EFLAGS;
		detail->regs_write_count = 1;
		x86->eflags = eflags;
	}
	return true;
}

static bool print_apx_jmpabs(MCInst *instr, SStream *stream)
{
	const MCOperand *target_operand;
	uint64_t target;
	cs_x86_op *public_operand;

	if (MCInst_getOpcode(instr) != X86_FEATURE_JMPABS ||
	    MCInst_getNumOperands(instr) != 1)
		return false;
	target_operand = MCInst_getOperand(instr, 0);
	if (!MCOperand_isImm(target_operand))
		return false;
	target = (uint64_t)MCOperand_getImm(target_operand);
	SStream_concat(stream, "jmpabs\t0x%llx", (unsigned long long)target);

	if (!instr->flat_insn->detail)
		return true;
	public_operand = &instr->flat_insn->detail->x86.operands[0];
	public_operand->type = X86_OP_IMM;
	public_operand->imm = (int64_t)target;
	public_operand->size = 8;
	public_operand->access = CS_AC_READ;
	instr->flat_insn->detail->x86.op_count = 1;
	return true;
}

static bool print_apx_push2_pop2(MCInst *instr, SStream *stream,
				 bool att_syntax)
{
	const MCOperand *v_operand, *b_operand;
	x86_reg v_register, b_register;
	const char *v_name, *b_name, *mnemonic;
	bool push;
	cs_detail *detail;
	cs_x86 *x86;
	x86_reg printed[2];
	uint8_t access;
	unsigned int opcode = MCInst_getOpcode(instr);

	if (MCInst_getNumOperands(instr) != 2)
		return false;
	switch (opcode) {
	default:
		return false;
	case X86_FEATURE_PUSH2:
		mnemonic = att_syntax ? "push2q" : "push2";
		push = true;
		break;
	case X86_FEATURE_PUSH2P:
		mnemonic = att_syntax ? "push2pq" : "push2p";
		push = true;
		break;
	case X86_FEATURE_POP2:
		mnemonic = att_syntax ? "pop2q" : "pop2";
		push = false;
		break;
	case X86_FEATURE_POP2P:
		mnemonic = att_syntax ? "pop2pq" : "pop2p";
		push = false;
		break;
	}
	v_operand = MCInst_getOperand(instr, 0);
	b_operand = MCInst_getOperand(instr, 1);
	if (!MCOperand_isImm(v_operand) || !MCOperand_isImm(b_operand))
		return false;
	v_register = (x86_reg)MCOperand_getImm(v_operand);
	b_register = (x86_reg)MCOperand_getImm(b_operand);
	v_name = X86_reg_name((csh)instr->csh, v_register);
	b_name = X86_reg_name((csh)instr->csh, b_register);
	if (!v_name || !b_name)
		return false;

	if (att_syntax) {
		SStream_concat(stream, "%s\t%%%s, %%%s", mnemonic, b_name,
			       v_name);
		printed[0] = b_register;
		printed[1] = v_register;
	} else {
		SStream_concat(stream, "%s\t%s, %s", mnemonic, v_name, b_name);
		printed[0] = v_register;
		printed[1] = b_register;
	}
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	access = push ? CS_AC_READ : CS_AC_WRITE;
	x86->operands[0].type = X86_OP_REG;
	x86->operands[0].reg = printed[0];
	x86->operands[0].size = 8;
	x86->operands[0].access = access;
	x86->operands[1].type = X86_OP_REG;
	x86->operands[1].reg = printed[1];
	x86->operands[1].size = 8;
	x86->operands[1].access = access;
	x86->op_count = 2;
	detail->regs_read[0] = X86_REG_RSP;
	detail->regs_read_count = 1;
	detail->regs_write[0] = X86_REG_RSP;
	detail->regs_write_count = 1;
	return true;
}

static bool print_rex2_push_pop(MCInst *instr, SStream *stream, bool att_syntax)
{
	const MCOperand *reg_operand, *width_operand;
	unsigned int opcode = MCInst_getOpcode(instr);
	x86_reg reg;
	const char *name;
	const char *mnemonic;
	uint8_t width, access;
	bool push;
	cs_detail *detail;
	cs_x86 *x86;

	if (MCInst_getNumOperands(instr) != 2)
		return false;
	switch (opcode) {
	default:
		return false;
	case X86_FEATURE_REX2_PUSH:
		mnemonic = "push";
		push = true;
		break;
	case X86_FEATURE_REX2_POP:
		mnemonic = "pop";
		push = false;
		break;
	case X86_FEATURE_PUSHP:
		mnemonic = "pushp";
		push = true;
		break;
	case X86_FEATURE_POPP:
		mnemonic = "popp";
		push = false;
		break;
	}
	reg_operand = MCInst_getOperand(instr, 0);
	width_operand = MCInst_getOperand(instr, 1);
	if (!MCOperand_isImm(reg_operand) || !MCOperand_isImm(width_operand))
		return false;
	reg = (x86_reg)MCOperand_getImm(reg_operand);
	width = (uint8_t)MCOperand_getImm(width_operand);
	name = X86_reg_name((csh)instr->csh, reg);
	if (!name || (width != 2 && width != 8))
		return false;

	if (att_syntax)
		SStream_concat(stream, "%s%c\t%%%s", mnemonic,
			       width == 2 ? 'w' : 'q', name);
	else
		SStream_concat(stream, "%s\t%s", mnemonic, name);
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	access = push ? CS_AC_READ : CS_AC_WRITE;
	x86->operands[0].type = X86_OP_REG;
	x86->operands[0].reg = reg;
	x86->operands[0].size = width;
	x86->operands[0].access = access;
	x86->op_count = 1;
	detail->regs_read[0] = X86_REG_RSP;
	detail->regs_read_count = 1;
	detail->regs_write[0] = X86_REG_RSP;
	detail->regs_write_count = 1;
	return true;
}

static const char *apx_condition_name(unsigned int condition)
{
	static const char *const names[] = {
		"o", "no", "b", "ae", "e", "ne", "be", "a",
		"s", "ns", "p", "np", "l", "ge", "le", "g",
	};

	return condition < ARR_SIZE(names) ? names[condition] : NULL;
}

typedef struct x86_feature_print_operand {
	bool is_memory;
	x86_reg reg;
	cs_ac_type access;
} x86_feature_print_operand;

static bool print_apx_cmov(MCInst *instr, SStream *stream, bool att_syntax)
{
	unsigned int opcode = MCInst_getOpcode(instr);
	unsigned int condition;
	bool cfcmov;
	const char *condition_name;
	const MCOperand *reg_operand, *ndd_operand, *memory_form_operand;
	const MCOperand *width_operand, *nd_operand, *nf_operand;
	x86_reg reg_field, ndd_field, rm_field = X86_REG_INVALID;
	x86_reg segment = X86_REG_INVALID;
	uint8_t width, address_size = 8;
	bool memory_form, nd, nf;
	x86_feature_memory memory;
	x86_feature_print_operand logical[3];
	uint8_t logical_count, i;
	const char *mnemonic;
	char suffix;
	cs_detail *detail;
	cs_x86 *x86;

	if (opcode >= X86_FEATURE_APX_CMOVCC_BASE &&
	    opcode < X86_FEATURE_APX_CMOVCC_BASE +
			     X86_FEATURE_APX_CMOVCC_COUNT) {
		condition = opcode - X86_FEATURE_APX_CMOVCC_BASE;
		cfcmov = false;
	} else if (opcode >= X86_FEATURE_APX_CFCMOVCC_BASE &&
		   opcode < X86_FEATURE_APX_CFCMOVCC_BASE +
				    X86_FEATURE_APX_CMOVCC_COUNT) {
		condition = opcode - X86_FEATURE_APX_CFCMOVCC_BASE;
		cfcmov = true;
	} else {
		return false;
	}
	condition_name = apx_condition_name(condition);
	if (!condition_name || MCInst_getNumOperands(instr) < 7)
		return false;

	reg_operand = MCInst_getOperand(instr, 0);
	ndd_operand = MCInst_getOperand(instr, 1);
	memory_form_operand = MCInst_getOperand(instr, 2);
	if (!MCOperand_isImm(reg_operand) || !MCOperand_isImm(ndd_operand) ||
	    !MCOperand_isImm(memory_form_operand)) {
		return false;
	}
	reg_field = (x86_reg)MCOperand_getImm(reg_operand);
	ndd_field = (x86_reg)MCOperand_getImm(ndd_operand);
	memory_form = MCOperand_getImm(memory_form_operand) != 0;
	memset(&memory, 0, sizeof(memory));
	if (memory_form) {
		const MCOperand *segment_operand, *address_size_operand;

		if (MCInst_getNumOperands(instr) != 12 ||
		    !get_feature_memory(instr, 3, &memory)) {
			return false;
		}
		segment_operand = MCInst_getOperand(instr, 7);
		address_size_operand = MCInst_getOperand(instr, 8);
		width_operand = MCInst_getOperand(instr, 9);
		nd_operand = MCInst_getOperand(instr, 10);
		nf_operand = MCInst_getOperand(instr, 11);
		if (!MCOperand_isImm(segment_operand) ||
		    !MCOperand_isImm(address_size_operand)) {
			return false;
		}
		segment = (x86_reg)MCOperand_getImm(segment_operand);
		address_size = (uint8_t)MCOperand_getImm(address_size_operand);
		if ((segment != X86_REG_INVALID &&
		     !feature_register_name(segment)) ||
		    (address_size != 4 && address_size != 8)) {
			return false;
		}
	} else {
		const MCOperand *rm_operand;

		if (MCInst_getNumOperands(instr) != 7)
			return false;
		rm_operand = MCInst_getOperand(instr, 3);
		width_operand = MCInst_getOperand(instr, 4);
		nd_operand = MCInst_getOperand(instr, 5);
		nf_operand = MCInst_getOperand(instr, 6);
		if (!MCOperand_isImm(rm_operand))
			return false;
		rm_field = (x86_reg)MCOperand_getImm(rm_operand);
	}
	if (!MCOperand_isImm(width_operand) || !MCOperand_isImm(nd_operand) ||
	    !MCOperand_isImm(nf_operand)) {
		return false;
	}
	width = (uint8_t)MCOperand_getImm(width_operand);
	nd = MCOperand_getImm(nd_operand) != 0;
	nf = MCOperand_getImm(nf_operand) != 0;
	if ((width != 2 && width != 4 && width != 8) || cfcmov == (nd && !nf) ||
	    (nd ? ndd_field == X86_REG_INVALID :
		  ndd_field != X86_REG_INVALID) ||
	    !X86_reg_name((csh)instr->csh, reg_field) ||
	    (!memory_form && !X86_reg_name((csh)instr->csh, rm_field))) {
		return false;
	}

	if (nd) {
		logical[0] = (x86_feature_print_operand){ false, ndd_field,
							  CS_AC_WRITE };
		logical[1] = (x86_feature_print_operand){ false, reg_field,
							  CS_AC_READ };
		logical[2] = (x86_feature_print_operand){ memory_form, rm_field,
							  CS_AC_READ };
		logical_count = 3;
	} else if (nf) {
		logical[0] = (x86_feature_print_operand){ memory_form, rm_field,
							  CS_AC_WRITE };
		logical[1] = (x86_feature_print_operand){ false, reg_field,
							  CS_AC_READ };
		logical_count = 2;
	} else {
		logical[0] = (x86_feature_print_operand){ false, reg_field,
							  CS_AC_WRITE };
		logical[1] = (x86_feature_print_operand){ memory_form, rm_field,
							  CS_AC_READ };
		logical_count = 2;
	}

	mnemonic = cfcmov ? "cfcmov" : "cmov";
	if (att_syntax) {
		suffix = width == 2 ? 'w' : width == 4 ? 'l' : 'q';
		SStream_concat(stream, "%s%s%c\t", mnemonic, condition_name,
			       suffix);
	} else {
		SStream_concat(stream, "%s%s\t", mnemonic, condition_name);
	}
	for (i = 0; i < logical_count; ++i) {
		const uint8_t logical_index =
			att_syntax ? logical_count - 1 - i : i;
		const x86_feature_print_operand *operand =
			&logical[logical_index];

		if (i != 0)
			SStream_concat0(stream, ", ");
		if (operand->is_memory) {
			const char *segment_name =
				segment == X86_REG_INVALID ?
					NULL :
					feature_register_name(segment);

			if (!att_syntax) {
				SStream_concat0(stream,
						width == 2 ? "word ptr " :
						width == 4 ? "dword ptr " :
							     "qword ptr ");
			}
			if (segment_name) {
				SStream_concat(stream,
					       att_syntax ? "%%%s:" : "%s:",
					       segment_name);
			}
			if (!print_feature_memory(stream, &memory, att_syntax))
				return false;
		} else {
			const char *name =
				X86_reg_name((csh)instr->csh, operand->reg);

			if (!name)
				return false;
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       name);
		}
	}
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	for (i = 0; i < logical_count; ++i) {
		const uint8_t logical_index =
			att_syntax ? logical_count - 1 - i : i;
		const x86_feature_print_operand *operand =
			&logical[logical_index];

		if (operand->is_memory) {
			set_feature_memory_operand(&x86->operands[i], &memory,
						   width, operand->access);
			x86->operands[i].mem.segment = segment;
		} else {
			x86->operands[i].type = X86_OP_REG;
			x86->operands[i].reg = operand->reg;
			x86->operands[i].size = width;
			x86->operands[i].access = operand->access;
		}
	}
	x86->op_count = logical_count;
	detail->regs_read[0] = X86_REG_EFLAGS;
	detail->regs_read_count = 1;
	return true;
}

static bool print_apx_shift_rotate(MCInst *instr, SStream *stream,
				   bool att_syntax)
{
	const MCOperand *destination_operand, *memory_form_operand;
	const MCOperand *width_operand, *count_kind_operand;
	const MCOperand *count_value_operand, *nd_operand, *nf_operand;
	x86_reg destination, source = X86_REG_INVALID;
	x86_reg segment = X86_REG_INVALID;
	x86_feature_memory memory;
	x86_feature_print_operand data_operands[2];
	uint8_t data_count, width, count_kind, count_value, address_size = 8;
	bool memory_form, nd, nf;
	const char *mnemonic;
	char suffix;
	uint64_t eflags;
	bool reads_carry;
	uint8_t output_index = 0, i;
	cs_detail *detail;
	cs_x86 *x86;

	switch (MCInst_getOpcode(instr)) {
	default:
		return false;
	case X86_FEATURE_APX_ROL:
		mnemonic = "rol";
		reads_carry = false;
		eflags = X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF;
		break;
	case X86_FEATURE_APX_ROR:
		mnemonic = "ror";
		reads_carry = false;
		eflags = X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF;
		break;
	case X86_FEATURE_APX_RCL:
		mnemonic = "rcl";
		reads_carry = true;
		eflags = X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF;
		break;
	case X86_FEATURE_APX_RCR:
		mnemonic = "rcr";
		reads_carry = true;
		eflags = X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF;
		break;
	case X86_FEATURE_APX_SHL:
		mnemonic = "shl";
		reads_carry = false;
		eflags = X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			 X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF;
		break;
	case X86_FEATURE_APX_SHR:
		mnemonic = "shr";
		reads_carry = false;
		eflags = X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			 X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF;
		break;
	case X86_FEATURE_APX_SAR:
		mnemonic = "sar";
		reads_carry = false;
		eflags = X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			 X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF;
		break;
	}
	if (MCInst_getNumOperands(instr) < 8)
		return false;
	destination_operand = MCInst_getOperand(instr, 0);
	memory_form_operand = MCInst_getOperand(instr, 1);
	if (!MCOperand_isImm(destination_operand) ||
	    !MCOperand_isImm(memory_form_operand)) {
		return false;
	}
	destination = (x86_reg)MCOperand_getImm(destination_operand);
	memory_form = MCOperand_getImm(memory_form_operand) != 0;
	memset(&memory, 0, sizeof(memory));
	if (memory_form) {
		const MCOperand *segment_operand, *address_size_operand;

		if (MCInst_getNumOperands(instr) != 13 ||
		    !get_feature_memory(instr, 2, &memory)) {
			return false;
		}
		segment_operand = MCInst_getOperand(instr, 6);
		address_size_operand = MCInst_getOperand(instr, 7);
		width_operand = MCInst_getOperand(instr, 8);
		count_kind_operand = MCInst_getOperand(instr, 9);
		count_value_operand = MCInst_getOperand(instr, 10);
		nd_operand = MCInst_getOperand(instr, 11);
		nf_operand = MCInst_getOperand(instr, 12);
		if (!MCOperand_isImm(segment_operand) ||
		    !MCOperand_isImm(address_size_operand)) {
			return false;
		}
		segment = (x86_reg)MCOperand_getImm(segment_operand);
		address_size = (uint8_t)MCOperand_getImm(address_size_operand);
		if ((segment != X86_REG_INVALID &&
		     !feature_register_name(segment)) ||
		    (address_size != 4 && address_size != 8)) {
			return false;
		}
	} else {
		const MCOperand *source_operand;

		if (MCInst_getNumOperands(instr) != 8)
			return false;
		source_operand = MCInst_getOperand(instr, 2);
		width_operand = MCInst_getOperand(instr, 3);
		count_kind_operand = MCInst_getOperand(instr, 4);
		count_value_operand = MCInst_getOperand(instr, 5);
		nd_operand = MCInst_getOperand(instr, 6);
		nf_operand = MCInst_getOperand(instr, 7);
		if (!MCOperand_isImm(source_operand))
			return false;
		source = (x86_reg)MCOperand_getImm(source_operand);
	}
	if (!MCOperand_isImm(width_operand) ||
	    !MCOperand_isImm(count_kind_operand) ||
	    !MCOperand_isImm(count_value_operand) ||
	    !MCOperand_isImm(nd_operand) || !MCOperand_isImm(nf_operand)) {
		return false;
	}
	width = (uint8_t)MCOperand_getImm(width_operand);
	count_kind = (uint8_t)MCOperand_getImm(count_kind_operand);
	count_value = (uint8_t)MCOperand_getImm(count_value_operand);
	nd = MCOperand_getImm(nd_operand) != 0;
	nf = MCOperand_getImm(nf_operand) != 0;
	if ((width != 1 && width != 2 && width != 4 && width != 8) ||
	    count_kind > X86_FEATURE_SHIFT_CL ||
	    (count_kind == X86_FEATURE_SHIFT_ONE && count_value != 1) ||
	    (nd		 ? destination == X86_REG_INVALID :
	     memory_form ? destination != X86_REG_INVALID :
			   destination != source) ||
	    (!memory_form && !X86_reg_name((csh)instr->csh, source)) ||
	    (nd && !X86_reg_name((csh)instr->csh, destination)) ||
	    (nf && reads_carry)) {
		return false;
	}

	if (nd) {
		data_operands[0] = (x86_feature_print_operand){ false,
								destination,
								CS_AC_WRITE };
		data_operands[1] = (x86_feature_print_operand){ memory_form,
								source,
								CS_AC_READ };
		data_count = 2;
	} else {
		data_operands[0] =
			(x86_feature_print_operand){ memory_form, source,
						     CS_AC_READ | CS_AC_WRITE };
		data_count = 1;
	}

	if (nf)
		SStream_concat0(stream, "{nf}|");
	suffix = width == 1 ? 'b' : width == 2 ? 'w' : width == 4 ? 'l' : 'q';
	if (att_syntax)
		SStream_concat(stream, "%s%c\t", mnemonic, suffix);
	else
		SStream_concat(stream, "%s\t", mnemonic);

	if (att_syntax) {
		if (count_kind == X86_FEATURE_SHIFT_CL)
			SStream_concat0(stream, "%cl");
		else
			SStream_concat(stream, "$%u", count_value);
		++output_index;
	}
	for (i = 0; i < data_count; ++i) {
		const uint8_t data_index = att_syntax ? data_count - 1 - i : i;
		const x86_feature_print_operand *operand =
			&data_operands[data_index];

		if (output_index != 0)
			SStream_concat0(stream, ", ");
		if (operand->is_memory) {
			const char *segment_name =
				segment == X86_REG_INVALID ?
					NULL :
					feature_register_name(segment);

			if (!att_syntax) {
				SStream_concat0(stream,
						width == 1 ? "byte ptr " :
						width == 2 ? "word ptr " :
						width == 4 ? "dword ptr " :
							     "qword ptr ");
			}
			if (segment_name) {
				SStream_concat(stream,
					       att_syntax ? "%%%s:" : "%s:",
					       segment_name);
			}
			if (!print_feature_memory(stream, &memory, att_syntax))
				return false;
		} else {
			const char *name =
				X86_reg_name((csh)instr->csh, operand->reg);

			if (!name)
				return false;
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       name);
		}
		++output_index;
	}
	if (!att_syntax) {
		SStream_concat0(stream, ", ");
		if (count_kind == X86_FEATURE_SHIFT_CL)
			SStream_concat0(stream, "cl");
		else
			SStream_concat(stream, "%u", count_value);
	}
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	output_index = 0;
	if (att_syntax) {
		if (count_kind == X86_FEATURE_SHIFT_CL) {
			x86->operands[0].type = X86_OP_REG;
			x86->operands[0].reg = X86_REG_CL;
		} else {
			x86->operands[0].type = X86_OP_IMM;
			x86->operands[0].imm = count_value;
		}
		x86->operands[0].size = 1;
		x86->operands[0].access = CS_AC_READ;
		output_index = 1;
	}
	for (i = 0; i < data_count; ++i) {
		const uint8_t data_index = att_syntax ? data_count - 1 - i : i;
		const x86_feature_print_operand *operand =
			&data_operands[data_index];
		cs_x86_op *public_operand = &x86->operands[output_index++];

		if (operand->is_memory) {
			set_feature_memory_operand(public_operand, &memory,
						   width, operand->access);
			public_operand->mem.segment = segment;
		} else {
			public_operand->type = X86_OP_REG;
			public_operand->reg = operand->reg;
			public_operand->size = width;
			public_operand->access = operand->access;
		}
	}
	if (!att_syntax) {
		cs_x86_op *count_operand = &x86->operands[output_index++];

		if (count_kind == X86_FEATURE_SHIFT_CL) {
			count_operand->type = X86_OP_REG;
			count_operand->reg = X86_REG_CL;
		} else {
			count_operand->type = X86_OP_IMM;
			count_operand->imm = count_value;
		}
		count_operand->size = 1;
		count_operand->access = CS_AC_READ;
	}
	x86->op_count = output_index;
	if (reads_carry) {
		detail->regs_read[detail->regs_read_count++] = X86_REG_EFLAGS;
	}
	if (!nf) {
		detail->regs_write[detail->regs_write_count++] = X86_REG_EFLAGS;
		x86->eflags = eflags;
	}
	return true;
}

static bool print_apx_mulx(MCInst*in,SStream*s,bool att){const MCOperand*a,*b,*mf,*wo;x86_reg d1,d2,src=X86_REG_INVALID,seg=X86_REG_INVALID;bool mem;uint8_t w,i;x86_feature_memory m;cs_detail*detail;cs_x86*x;if(MCInst_getOpcode(in)!=X86_FEATURE_APX_MULX)return false;a=MCInst_getOperand(in,0);b=MCInst_getOperand(in,1);mf=MCInst_getOperand(in,2);d1=(x86_reg)MCOperand_getImm(a);d2=(x86_reg)MCOperand_getImm(b);mem=MCOperand_getImm(mf)!=0;memset(&m,0,sizeof(m));if(mem){if(MCInst_getNumOperands(in)!=10||!get_feature_memory(in,3,&m))return false;seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,7));wo=MCInst_getOperand(in,9);}else{if(MCInst_getNumOperands(in)!=5)return false;src=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,3));wo=MCInst_getOperand(in,4);}w=(uint8_t)MCOperand_getImm(wo);SStream_concat(s,att?"mulx%c\t":"mulx\t",w==4?'l':'q');for(i=0;i<3;i++){unsigned k=att?2-i:i;if(i)SStream_concat0(s,", ");if(k<2)SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,k?d2:d1));else if(mem){if(!att)SStream_concat0(s,w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,src));}if(!in->flat_insn->detail)return true;detail=in->flat_insn->detail;x=&detail->x86;for(i=0;i<3;i++){unsigned k=att?2-i:i;cs_x86_op*o=&x->operands[i];if(k<2){o->type=X86_OP_REG;o->reg=k?d2:d1;o->size=w;o->access=CS_AC_WRITE;}else if(mem){set_feature_memory_operand(o,&m,w,CS_AC_READ);o->mem.segment=seg;}else{o->type=X86_OP_REG;o->reg=src;o->size=w;o->access=CS_AC_READ;}}x->op_count=3;detail->regs_read[detail->regs_read_count++]=w==4?X86_REG_EDX:X86_REG_RDX;return true;}

static bool print_apx_convert(MCInst*in,SStream*out,bool att){unsigned opc=MCInst_getOpcode(in);bool crc=opc==X86_FEATURE_APX_CRC32,mem,store;const MCOperand*mf;x86_reg reg,rm=X86_REG_INVALID,seg=X86_REG_INVALID;uint8_t dw,sw,i;x86_feature_memory m;cs_x86*x;if(!crc&&opc!=X86_FEATURE_APX_MOVBE)return false;reg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,0));mf=MCInst_getOperand(in,1);mem=MCOperand_getImm(mf)!=0;store=MCOperand_getImm(MCInst_getOperand(in,2))!=0;memset(&m,0,sizeof(m));if(mem){if(MCInst_getNumOperands(in)!=11||!get_feature_memory(in,3,&m))return false;seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,7));dw=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,9));sw=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,10));}else{if(MCInst_getNumOperands(in)!=6)return false;rm=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,3));dw=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,4));sw=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,5));}SStream_concat(out,att?"%s%c\t":"%s\t",crc?"crc32":"movbe",(crc?dw:(store?sw:dw))==2?'w':(crc?dw:(store?sw:dw))==4?'l':'q');for(i=0;i<2;i++){unsigned logical=att?1-i:i;bool rmop=store?(logical==0):(logical==1);uint8_t w=rmop?sw:dw;if(i)SStream_concat0(out,", ");if(rmop&&mem){if(!att)SStream_concat0(out,w==1?"byte ptr ":w==2?"word ptr ":w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(out,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(out,&m,att))return false;}else{SStream_concat(out,att?"%%%s":"%s",X86_reg_name((csh)in->csh,rmop?rm:reg));}}if(!in->flat_insn->detail)return true;x=&in->flat_insn->detail->x86;for(i=0;i<2;i++){unsigned logical=att?1-i:i;bool rmop=store?(logical==0):(logical==1);uint8_t w=rmop?sw:dw;uint8_t ac=crc&&!rmop?CS_AC_READ_WRITE:(store?(!rmop?CS_AC_READ:CS_AC_WRITE):(!rmop?CS_AC_WRITE:CS_AC_READ));cs_x86_op*o=&x->operands[i];if(rmop&&mem){set_feature_memory_operand(o,&m,w,ac);o->mem.segment=seg;}else{o->type=X86_OP_REG;o->reg=rmop?rm:reg;o->size=w;o->access=ac;}}x->op_count=2;return true;}

static bool print_apx_double_shift(MCInst*in,SStream*s,bool att)
{
	unsigned op=MCInst_getOpcode(in),n,i;bool right=op==X86_FEATURE_APX_SHRD,mem,nd,nf,cl;x86_reg dst,src,rm=X86_REG_INVALID,seg=X86_REG_INVALID;uint8_t w,imm;x86_feature_memory m;cs_detail*d;cs_x86*x;if(!right&&op!=X86_FEATURE_APX_SHLD)return false;dst=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,0));src=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,1));mem=MCOperand_getImm(MCInst_getOperand(in,2))!=0;nd=MCOperand_getImm(MCInst_getOperand(in,3))!=0;nf=MCOperand_getImm(MCInst_getOperand(in,4))!=0;memset(&m,0,sizeof(m));if(mem){if(MCInst_getNumOperands(in)!=14||!get_feature_memory(in,5,&m))return false;seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,9));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,11));cl=MCOperand_getImm(MCInst_getOperand(in,12))!=0;imm=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,13));}else{if(MCInst_getNumOperands(in)!=9)return false;rm=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,5));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,6));cl=MCOperand_getImm(MCInst_getOperand(in,7))!=0;imm=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,8));}if(nf)SStream_concat0(s,"{nf}|");SStream_concat(s,att?"%s%c\t":"%s\t",right?"shrd":"shld",w==2?'w':w==4?'l':'q');n=nd?4:3;for(i=0;i<n;i++){unsigned k=att?n-1-i:i;if(i)SStream_concat0(s,", ");if(k==n-1){if(cl)SStream_concat0(s,att?"%cl":"cl");else SStream_concat(s,att?"$%u":"%u",imm);}else if(nd&&k==0)SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,dst));else if((nd&&k==1)||(!nd&&k==0)){if(mem){if(!att)SStream_concat0(s,w==2?"word ptr ":w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,rm));}else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,src));}if(!in->flat_insn->detail)return true;d=in->flat_insn->detail;x=&d->x86;for(i=0;i<n;i++){unsigned k=att?n-1-i:i;cs_x86_op*o=&x->operands[i];if(k==n-1){o->type=cl?X86_OP_REG:X86_OP_IMM;if(cl)o->reg=X86_REG_CL;else o->imm=imm;o->size=1;o->access=CS_AC_READ;}else if(nd&&k==0){o->type=X86_OP_REG;o->reg=dst;o->size=w;o->access=CS_AC_WRITE;}else if((nd&&k==1)||(!nd&&k==0)){uint8_t ac=nd?CS_AC_READ:CS_AC_READ_WRITE;if(mem){set_feature_memory_operand(o,&m,w,ac);o->mem.segment=seg;}else{o->type=X86_OP_REG;o->reg=rm;o->size=w;o->access=ac;}}else{o->type=X86_OP_REG;o->reg=src;o->size=w;o->access=CS_AC_READ;}}x->op_count=n;if(cl)d->regs_read[d->regs_read_count++]=X86_REG_CL;if(!nf){d->regs_write[d->regs_write_count++]=X86_REG_EFLAGS;x->eflags=X86_EFLAGS_MODIFY_OF|X86_EFLAGS_MODIFY_SF|X86_EFLAGS_MODIFY_ZF|X86_EFLAGS_UNDEFINED_AF|X86_EFLAGS_MODIFY_PF|X86_EFLAGS_MODIFY_CF;}return true;
}

static bool print_apx_cmpccxadd(MCInst*in,SStream*s,bool att)
{
	static const char*const names[]={"cmpoxadd","cmpnoxadd","cmpbxadd","cmpnbxadd","cmpzxadd","cmpnzxadd","cmpbexadd","cmpnbexadd","cmpsxadd","cmpnsxadd","cmppxadd","cmpnpxadd","cmplxadd","cmpnlxadd","cmplexadd","cmpnlexadd"};unsigned op=MCInst_getOpcode(in),idx,i;x86_reg cmp,add,seg;x86_feature_memory m;uint8_t w;cs_detail*d;cs_x86*x;if(op<X86_FEATURE_APX_CMPCCXADD_BASE||op>=X86_FEATURE_APX_CMPCCXADD_BASE+16)return false;idx=op-X86_FEATURE_APX_CMPCCXADD_BASE;if(MCInst_getNumOperands(in)!=9||!get_feature_memory(in,2,&m))return false;cmp=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,0));add=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,1));seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,6));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,8));SStream_concat(s,att?"%s%c\t":"%s\t",names[idx],w==4?'l':'q');for(i=0;i<3;i++){unsigned k=att?2-i:i;if(i)SStream_concat0(s,", ");if(k==0){if(!att)SStream_concat0(s,w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,k==1?cmp:add));}if(!in->flat_insn->detail)return true;d=in->flat_insn->detail;x=&d->x86;for(i=0;i<3;i++){unsigned k=att?2-i:i;cs_x86_op*o=&x->operands[i];if(k==0){set_feature_memory_operand(o,&m,w,CS_AC_READ_WRITE);o->mem.segment=seg;}else{o->type=X86_OP_REG;o->reg=k==1?cmp:add;o->size=w;o->access=k==1?CS_AC_READ_WRITE:CS_AC_READ;}}x->op_count=3;d->regs_write[d->regs_write_count++]=X86_REG_EFLAGS;x->eflags=X86_EFLAGS_MODIFY_OF|X86_EFLAGS_MODIFY_SF|X86_EFLAGS_MODIFY_ZF|X86_EFLAGS_MODIFY_AF|X86_EFLAGS_MODIFY_PF|X86_EFLAGS_MODIFY_CF;return true;
}

static bool print_apx_ccmp(MCInst*in,SStream*s,bool att)
{
static const char*const ccmp_names[]={"ccmpo","ccmpno","ccmpb","ccmpnb","ccmpz","ccmpnz","ccmpbe","ccmpnbe","ccmps","ccmpns","ccmpt","ccmpf","ccmpl","ccmpnl","ccmple","ccmpnle"};static const char*const ctest_names[]={"ctesto","ctestno","ctestb","ctestnb","ctestz","ctestnz","ctestbe","ctestnbe","ctests","ctestns","ctestt","ctestf","ctestl","ctestnl","ctestle","ctestnle"};static const char*const dfvs[]={"0","cf","zf","zf,cf","sf","sf,cf","sf,zf","sf,zf,cf","of","of,cf","of,zf","of,zf,cf","of,sf","of,sf,cf","of,sf,zf","of,sf,zf,cf"};unsigned op=MCInst_getOpcode(in),i,n,idx;bool mem,rmfirst,imm,ctest;x86_reg rr,rm=X86_REG_INVALID,seg=X86_REG_INVALID;x86_feature_memory m;uint8_t w,dfv;int64_t iv;cs_detail*d;cs_x86*x;ctest=op>=X86_FEATURE_APX_CTEST_BASE&&op<X86_FEATURE_APX_CTEST_BASE+16;if(!ctest&&(op<X86_FEATURE_APX_CCMP_BASE||op>=X86_FEATURE_APX_CCMP_BASE+16))return false;idx=op-(ctest?X86_FEATURE_APX_CTEST_BASE:X86_FEATURE_APX_CCMP_BASE);mem=MCOperand_getImm(MCInst_getOperand(in,0))!=0;rmfirst=MCOperand_getImm(MCInst_getOperand(in,1))!=0;rr=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,2));memset(&m,0,sizeof(m));if(mem){if(MCInst_getNumOperands(in)!=13||!get_feature_memory(in,3,&m))return false;seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,7));imm=MCOperand_getImm(MCInst_getOperand(in,9))!=0;iv=MCOperand_getImm(MCInst_getOperand(in,10));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,11));dfv=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,12));}else{if(MCInst_getNumOperands(in)!=8)return false;rm=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,3));imm=MCOperand_getImm(MCInst_getOperand(in,4))!=0;iv=MCOperand_getImm(MCInst_getOperand(in,5));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,6));dfv=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,7));}if(w!=1&&w!=2&&w!=4&&w!=8)return false;if(att)SStream_concat(s,"%s%c\t{dfv=%s} ",(ctest?ctest_names:ccmp_names)[idx],w==1?'b':w==2?'w':w==4?'l':'q',dfvs[dfv]);else SStream_concat(s,"%s\t{dfv=%s} ",(ctest?ctest_names:ccmp_names)[idx],dfvs[dfv]);n=2;for(i=0;i<n;i++){unsigned k=att?1-i:i;bool isrm=imm?k==0:(rmfirst?k==0:k==1);if(i)SStream_concat0(s,", ");if(!isrm){if(imm)SStream_concat(s,att?"$%" PRId64:"%" PRId64,iv);else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,rr));}else if(mem){if(!att)SStream_concat0(s,w==1?"byte ptr ":w==2?"word ptr ":w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,rm));}
	if(!in->flat_insn->detail)return true;d=in->flat_insn->detail;x=&d->x86;for(i=0;i<n;i++){unsigned k=att?1-i:i;bool isrm=imm?k==0:(rmfirst?k==0:k==1);cs_x86_op*o=&x->operands[i];if(!isrm){if(imm){o->type=X86_OP_IMM;o->imm=iv;o->size=in->imm_size;o->access=CS_AC_READ;}else{o->type=X86_OP_REG;o->reg=rr;o->size=w;o->access=CS_AC_READ;}}else if(mem){set_feature_memory_operand(o,&m,w,CS_AC_READ);o->mem.segment=seg;}else{o->type=X86_OP_REG;o->reg=rm;o->size=w;o->access=CS_AC_READ;}}x->op_count=2;d->regs_read[d->regs_read_count++]=X86_REG_EFLAGS;d->regs_write[d->regs_write_count++]=X86_REG_EFLAGS;x->eflags=ctest?(X86_EFLAGS_RESET_OF|X86_EFLAGS_MODIFY_SF|X86_EFLAGS_MODIFY_ZF|X86_EFLAGS_UNDEFINED_AF|X86_EFLAGS_MODIFY_PF|X86_EFLAGS_RESET_CF):(X86_EFLAGS_MODIFY_OF|X86_EFLAGS_MODIFY_SF|X86_EFLAGS_MODIFY_ZF|X86_EFLAGS_MODIFY_AF|X86_EFLAGS_MODIFY_PF|X86_EFLAGS_MODIFY_CF);return true;
}

static bool print_apx_kmov(MCInst*in,SStream*s,bool att)
{
	unsigned f=MCInst_getOpcode(in),op,i;x86_reg reg,rm=X86_REG_INVALID,seg=X86_REG_INVALID;x86_feature_memory m;bool mem;uint8_t w;cs_x86*x;if(f<X86_FEATURE_APX_KMOV_BASE||f>=X86_FEATURE_APX_KMOV_BASE+4)return false;op=(unsigned)MCOperand_getImm(MCInst_getOperand(in,0));reg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,1));mem=MCOperand_getImm(MCInst_getOperand(in,2))!=0;memset(&m,0,sizeof(m));if(mem){if(MCInst_getNumOperands(in)!=10||!get_feature_memory(in,3,&m))return false;seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,7));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,9));}else{if(MCInst_getNumOperands(in)!=5)return false;rm=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,3));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,4));}SStream_concat(s,"kmov%c\t",w==1?'b':w==2?'w':w==4?'d':'q');for(i=0;i<2;i++){unsigned k=att?1-i:i;bool ismem=mem&&((op==0x91&&k==0)||(op==0x90&&k==1));x86_reg r=k==0?reg:rm;if(op==0x91){if(k==0)r=X86_REG_INVALID;else r=reg;}if(i)SStream_concat0(s,", ");if(ismem){if(!att)SStream_concat0(s,w==1?"byte ptr ":w==2?"word ptr ":w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,r));}if(!in->flat_insn->detail)return true;x=&in->flat_insn->detail->x86;for(i=0;i<2;i++){unsigned k=att?1-i:i;bool ismem=mem&&((op==0x91&&k==0)||(op==0x90&&k==1));bool gpr=(op==0x92&&k==1)||(op==0x93&&k==0);x86_reg r=k==0?reg:rm;uint8_t sz=gpr?(w==8?8:4):w;if(op==0x91){if(k==0)r=X86_REG_INVALID;else r=reg;}if(ismem){set_feature_memory_operand(&x->operands[i],&m,w,k==0?CS_AC_WRITE:CS_AC_READ);x->operands[i].mem.segment=seg;}else{x->operands[i].type=X86_OP_REG;x->operands[i].reg=r;x->operands[i].size=sz;x->operands[i].access=k==0?CS_AC_WRITE:CS_AC_READ;}}x->op_count=2;return true;
}

static bool print_apx_movrs(MCInst*in,SStream*s,bool att)
{
	x86_reg dst,seg;x86_feature_memory m;uint8_t w,i;cs_x86*x;if(MCInst_getOpcode(in)!=X86_FEATURE_APX_MOVRS)return false;if(MCInst_getNumOperands(in)!=8||!get_feature_memory(in,1,&m))return false;dst=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,0));seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,5));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,7));if(att)SStream_concat(s,"movrs%c\t",w==1?'b':w==2?'w':w==4?'l':'q');else SStream_concat0(s,"movrs\t");for(i=0;i<2;i++){unsigned k=att?1-i:i;if(i)SStream_concat0(s,", ");if(k==0)SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,dst));else{if(!att)SStream_concat0(s,w==1?"byte ptr ":w==2?"word ptr ":w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}}if(!in->flat_insn->detail)return true;x=&in->flat_insn->detail->x86;for(i=0;i<2;i++){unsigned k=att?1-i:i;if(k==0){x->operands[i].type=X86_OP_REG;x->operands[i].reg=dst;x->operands[i].size=w;x->operands[i].access=CS_AC_WRITE;}else{set_feature_memory_operand(&x->operands[i],&m,w,CS_AC_READ);x->operands[i].mem.segment=seg;}}x->op_count=2;return true;
}

static bool print_apx_invalidate(MCInst*in,SStream*s,bool att)
{
	unsigned f=MCInst_getOpcode(in),i;x86_reg type,seg;x86_feature_memory m;cs_x86*x;const char*mn;if(f<X86_FEATURE_APX_INV_BASE||f>=X86_FEATURE_APX_INV_BASE+3)return false;mn=f==X86_FEATURE_APX_INV_BASE?"invept":f==X86_FEATURE_APX_INV_BASE+1?"invvpid":"invpcid";if(MCInst_getNumOperands(in)!=7||!get_feature_memory(in,1,&m))return false;type=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,0));seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,5));SStream_concat(s,"%s\t",mn);for(i=0;i<2;i++){unsigned k=att?1-i:i;if(i)SStream_concat0(s,", ");if(k==0)SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,type));else{if(!att)SStream_concat0(s,"xmmword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}}if(!in->flat_insn->detail)return true;x=&in->flat_insn->detail->x86;for(i=0;i<2;i++){unsigned k=att?1-i:i;if(k==0){x->operands[i].type=X86_OP_REG;x->operands[i].reg=type;x->operands[i].size=8;x->operands[i].access=CS_AC_READ;}else{set_feature_memory_operand(&x->operands[i],&m,16,CS_AC_READ);x->operands[i].mem.segment=seg;}}x->op_count=2;return true;
}

static bool print_apx_rao(MCInst*in,SStream*s,bool att)
{
	unsigned op=MCInst_getOpcode(in);const char*mn=op==X86_FEATURE_APX_AADD?"aadd":op==X86_FEATURE_APX_AAND?"aand":op==X86_FEATURE_APX_AOR?"aor":op==X86_FEATURE_APX_AXOR?"axor":NULL;x86_reg reg,seg;x86_feature_memory m;uint8_t w,i;cs_x86*x;if(!mn)return false;if(MCInst_getNumOperands(in)!=8||!get_feature_memory(in,1,&m))return false;reg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,0));seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,5));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,7));SStream_concat(s,att?"%s%c\t":"%s\t",mn,w==4?'l':'q');for(i=0;i<2;i++){bool mem=att?i==1:i==0;if(i)SStream_concat0(s,", ");if(mem){if(!att)SStream_concat0(s,w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,reg));}if(!in->flat_insn->detail)return true;x=&in->flat_insn->detail->x86;for(i=0;i<2;i++){bool mem=att?i==1:i==0;cs_x86_op*o=&x->operands[i];if(mem){set_feature_memory_operand(o,&m,w,CS_AC_READ_WRITE);o->mem.segment=seg;}else{o->type=X86_OP_REG;o->reg=reg;o->size=w;o->access=CS_AC_READ;}}x->op_count=2;return true;
}

static bool print_apx_enqueue(MCInst *instr, SStream *stream, bool att_syntax)
{
	const cs_struct *arch =
		(const cs_struct *)(uintptr_t)(csh)instr->csh;
	unsigned int opcode = MCInst_getOpcode(instr);
	const char *mnemonic = opcode == X86_FEATURE_APX_ENQCMD	 ? "enqcmd" :
			       opcode == X86_FEATURE_APX_ENQCMDS ? "enqcmds" :
			       opcode == X86_FEATURE_APX_MOVDIR64B ?
								   "movdir64b" :
								   NULL;
	x86_reg reg, segment;
	x86_feature_memory memory;
	uint8_t register_width, i;
	cs_detail *detail;
	cs_x86 *x86;

	if (!mnemonic || MCInst_getNumOperands(instr) != 7 ||
	    !get_feature_memory(instr, 1, &memory)) {
		return false;
	}
	reg = (x86_reg)MCOperand_getImm(MCInst_getOperand(instr, 0));
	segment = (x86_reg)MCOperand_getImm(MCInst_getOperand(instr, 5));
	register_width = (uint8_t)MCOperand_getImm(MCInst_getOperand(instr, 6));
	if (register_width != 2 && register_width != 4 && register_width != 8)
		return false;

	SStream_concat(stream, "%s\t", mnemonic);
	for (i = 0; i < 2; ++i) {
		bool is_memory = att_syntax ? i == 0 : i == 1;

		if (i)
			SStream_concat0(stream, ", ");
		if (is_memory) {
			if (!att_syntax)
				SStream_concat0(stream, "zmmword ptr ");
			if (segment != X86_REG_INVALID)
				SStream_concat(stream,
					       att_syntax ? "%%%s:" : "%s:",
					       feature_register_name(segment));
			if (!print_feature_memory(stream, &memory, att_syntax))
				return false;
		} else {
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       X86_reg_name((csh)instr->csh, reg));
		}
	}
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	for (i = 0; i < 2; ++i) {
		bool is_memory = att_syntax ? i == 0 : i == 1;
		cs_x86_op *operand = &x86->operands[i];

		if (is_memory) {
			set_feature_memory_operand(operand, &memory, 64,
						   CS_AC_READ);
			operand->mem.segment = segment;
		} else {
			operand->type = X86_OP_REG;
			operand->reg = reg;
			operand->size = register_width;
			operand->access = CS_AC_READ;
		}
	}
	x86->op_count = 2;
	if (opcode != X86_FEATURE_APX_MOVDIR64B) {
		// Outside long mode the portal offset is relative to the implicit
		// ES segment even though the source memory may use an override.
		if (!(arch->mode & CS_MODE_64))
			detail->regs_read[detail->regs_read_count++] = X86_REG_ES;
		detail->regs_write[detail->regs_write_count++] = X86_REG_EFLAGS;
		x86->eflags = X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_RESET_CF |
			      X86_EFLAGS_RESET_PF | X86_EFLAGS_RESET_OF |
			      X86_EFLAGS_RESET_SF | X86_EFLAGS_RESET_AF;
	}
	return true;
}

static bool print_apx_direct_store(MCInst*in,SStream*s,bool att)
{
	unsigned op=MCInst_getOpcode(in);const char*mn=op==X86_FEATURE_APX_MOVDIRI?"movdiri":op==X86_FEATURE_APX_WRSSD?"wrssd":op==X86_FEATURE_APX_WRSSQ?"wrssq":op==X86_FEATURE_APX_WRUSSD?"wrussd":op==X86_FEATURE_APX_WRUSSQ?"wrussq":NULL;x86_reg src,seg;x86_feature_memory m;uint8_t w,i;cs_x86*x;if(!mn)return false;if(MCInst_getNumOperands(in)!=8||!get_feature_memory(in,1,&m))return false;src=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,0));seg=(x86_reg)MCOperand_getImm(MCInst_getOperand(in,5));w=(uint8_t)MCOperand_getImm(MCInst_getOperand(in,7));if(att&&op==X86_FEATURE_APX_MOVDIRI)SStream_concat(s,"%s%c\t",mn,w==4?'l':'q');else SStream_concat(s,"%s\t",mn);for(i=0;i<2;i++){bool mem=att?i==1:i==0;if(i)SStream_concat0(s,", ");if(mem){if(!att)SStream_concat0(s,w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}else SStream_concat(s,att?"%%%s":"%s",X86_reg_name((csh)in->csh,src));}if(!in->flat_insn->detail)return true;x=&in->flat_insn->detail->x86;for(i=0;i<2;i++){bool mem=att?i==1:i==0;cs_x86_op*o=&x->operands[i];if(mem){set_feature_memory_operand(o,&m,w,CS_AC_WRITE);o->mem.segment=seg;}else{o->type=X86_OP_REG;o->reg=src;o->size=w;o->access=CS_AC_READ;}}x->op_count=2;return true;
}

static bool print_apx_rorx(MCInst *in, SStream *s, bool att)
{
	const MCOperand *d, *mf, *wo, *io;
	x86_reg dr, src = X86_REG_INVALID, seg = X86_REG_INVALID;
	bool mem;
	uint8_t w, imm, i;
	x86_feature_memory m;
	cs_x86 *x;
	if (MCInst_getOpcode(in) != X86_FEATURE_APX_RORX)
		return false;
	d = MCInst_getOperand(in, 0);
	mf = MCInst_getOperand(in, 1);
	dr = (x86_reg)MCOperand_getImm(d);
	mem = MCOperand_getImm(mf) != 0;
	memset(&m, 0, sizeof(m));
	if (mem) {
		if (MCInst_getNumOperands(in) != 10 ||
		    !get_feature_memory(in, 2, &m))
			return false;
		seg = (x86_reg)MCOperand_getImm(MCInst_getOperand(in, 6));
		wo = MCInst_getOperand(in, 8);
		io = MCInst_getOperand(in, 9);
	} else {
		if (MCInst_getNumOperands(in) != 5)
			return false;
		src = (x86_reg)MCOperand_getImm(MCInst_getOperand(in, 2));
		wo = MCInst_getOperand(in, 3);
		io = MCInst_getOperand(in, 4);
	}
	w = (uint8_t)MCOperand_getImm(wo);
	imm = (uint8_t)MCOperand_getImm(io);
	SStream_concat(s, att ? "rorx%c\t" : "rorx\t", w == 4 ? 'l' : 'q');
	for (i = 0; i < 3; i++) {
		unsigned k = att ? 2 - i : i;
		if (i)
			SStream_concat0(s, ", ");
		if (k == 0)
			SStream_concat(s, att ? "%%%s" : "%s",
				       X86_reg_name((csh)in->csh, dr));
		else if (k == 2)
			SStream_concat(s, att ? "$%u" : "%u", imm);
		else if (mem) {
			if (!att)
				SStream_concat0(s, w == 4 ? "dword ptr " :
							    "qword ptr ");
			if (seg != X86_REG_INVALID)
				SStream_concat(s, att ? "%%%s:" : "%s:",
					       feature_register_name(seg));
			if (!print_feature_memory(s, &m, att))
				return false;
		} else
			SStream_concat(s, att ? "%%%s" : "%s",
				       X86_reg_name((csh)in->csh, src));
	}
	if (!in->flat_insn->detail)
		return true;
	x = &in->flat_insn->detail->x86;
	for (i = 0; i < 3; i++) {
		unsigned k = att ? 2 - i : i;
		cs_x86_op *o = &x->operands[i];
		if (k == 0) {
			o->type = X86_OP_REG;
			o->reg = dr;
			o->size = w;
			o->access = CS_AC_WRITE;
		} else if (k == 2) {
			o->type = X86_OP_IMM;
			o->imm = imm;
			o->size = 1;
			o->access = CS_AC_READ;
		} else if (mem) {
			set_feature_memory_operand(o, &m, w, CS_AC_READ);
			o->mem.segment = seg;
		} else {
			o->type = X86_OP_REG;
			o->reg = src;
			o->size = w;
			o->access = CS_AC_READ;
		}
	}
	x->op_count = 3;
	return true;
}

static bool print_apx_bextr(MCInst *in, SStream *s, bool att)
{
	const MCOperand *d, *c, *mf, *wo, *nfo;
	x86_reg dr, cr, data = X86_REG_INVALID, seg = X86_REG_INVALID;
	bool mem, nf;
	uint8_t w, i;
	x86_feature_memory m;
	cs_detail *detail;
	cs_x86 *x;
	const unsigned op = MCInst_getOpcode(in);
	const bool deposit_extract = op == X86_FEATURE_APX_PDEP ||
				     op == X86_FEATURE_APX_PEXT;
	const char *mn = op == X86_FEATURE_APX_BEXTR ? "bextr" :
			 op == X86_FEATURE_APX_SARX ? "sarx" :
			 op == X86_FEATURE_APX_SHLX ? "shlx" :
			 op == X86_FEATURE_APX_SHRX ? "shrx" :
			 op == X86_FEATURE_APX_PDEP ? "pdep" :
			 op == X86_FEATURE_APX_PEXT ? "pext" : NULL;
	if (!mn)
		return false;
	d = MCInst_getOperand(in, 0);
	c = MCInst_getOperand(in, 1);
	mf = MCInst_getOperand(in, 2);
	if (!MCOperand_isImm(d) || !MCOperand_isImm(c) || !MCOperand_isImm(mf))
		return false;
	dr = (x86_reg)MCOperand_getImm(d);
	cr = (x86_reg)MCOperand_getImm(c);
	mem = MCOperand_getImm(mf) != 0;
	memset(&m, 0, sizeof(m));
	if (mem) {
		if (MCInst_getNumOperands(in) != 11 ||
		    !get_feature_memory(in, 3, &m))
			return false;
		seg = (x86_reg)MCOperand_getImm(MCInst_getOperand(in, 7));
		wo = MCInst_getOperand(in, 9);
		nfo = MCInst_getOperand(in, 10);
	} else {
		if (MCInst_getNumOperands(in) != 6)
			return false;
		data = (x86_reg)MCOperand_getImm(MCInst_getOperand(in, 3));
		wo = MCInst_getOperand(in, 4);
		nfo = MCInst_getOperand(in, 5);
	}
	w = (uint8_t)MCOperand_getImm(wo);
	nf = MCOperand_getImm(nfo) != 0;
	if (nf)
		SStream_concat0(s, "{nf}|");
	if (att)
		SStream_concat(s, "%s%c\t", mn,
			       w == 2 ? 'w' : w == 4 ? 'l' : 'q');
	else
		SStream_concat(s, "%s\t", mn);
	for (i = 0; i < 3; i++) {
		unsigned k = att ? 2 - i : i;
		if (i)
			SStream_concat0(s, ", ");
		if (k == (deposit_extract ? 2U : 1U) && mem) {
			if (!att)
				SStream_concat0(s, w == 4 ? "dword ptr " :
							    "qword ptr ");
			if (seg != X86_REG_INVALID)
				SStream_concat(s, att ? "%%%s:" : "%s:",
					       feature_register_name(seg));
			if (!print_feature_memory(s, &m, att))
				return false;
		} else {
			const char *n = X86_reg_name((csh)in->csh,
				k == 0 ? dr : deposit_extract ?
				(k == 1 ? cr : data) : (k == 1 ? data : cr));
			SStream_concat(s, att ? "%%%s" : "%s", n);
		}
	}
	if (!in->flat_insn->detail)
		return true;
	detail = in->flat_insn->detail;
	x = &detail->x86;
	for (i = 0; i < 3; i++) {
		unsigned k = att ? 2 - i : i;
		cs_x86_op *o = &x->operands[i];
		if (k == (deposit_extract ? 2U : 1U) && mem) {
			set_feature_memory_operand(o, &m, w, CS_AC_READ);
			o->mem.segment = seg;
		} else {
			o->type = X86_OP_REG;
			o->reg = k == 0 ? dr : deposit_extract ?
				 (k == 1 ? cr : data) : (k == 1 ? data : cr);
			o->size = w;
			o->access = k == 0 ? CS_AC_WRITE : CS_AC_READ;
		}
	}
	x->op_count = 3;
	if (!nf && op == X86_FEATURE_APX_BEXTR) {
		detail->regs_write[detail->regs_write_count++] = X86_REG_EFLAGS;
		x->eflags = X86_EFLAGS_RESET_OF | X86_EFLAGS_UNDEFINED_SF |
			    X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			    X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_RESET_CF;
	}
	return true;
}

static bool print_apx_bls(MCInst *instr, SStream *s, bool att)
{
	unsigned op = MCInst_getOpcode(instr);
	const char *mn = op == X86_FEATURE_APX_BLSR   ? "blsr" :
			 op == X86_FEATURE_APX_BLSMSK ? "blsmsk" :
			 op == X86_FEATURE_APX_BLSI   ? "blsi" :
			 op == X86_FEATURE_APX_LZCNT ? "lzcnt" :
			 op == X86_FEATURE_APX_TZCNT ? "tzcnt" :
			 op == X86_FEATURE_APX_POPCNT ? "popcnt" :
							NULL;
	const MCOperand *d, *mf, *src, *wo, *nfo;
	bool mem, nf;
	uint8_t w;
	x86_reg dr, sr = X86_REG_INVALID, seg = X86_REG_INVALID;
	x86_feature_memory m;
	cs_x86 *x;
	cs_detail *detail;
	if (!mn)
		return false;
	d = MCInst_getOperand(instr, 0);
	mf = MCInst_getOperand(instr, 1);
	if (!MCOperand_isImm(d) || !MCOperand_isImm(mf))
		return false;
	dr = (x86_reg)MCOperand_getImm(d);
	mem = MCOperand_getImm(mf) != 0;
	memset(&m, 0, sizeof(m));
	if (mem) {
		if (!get_feature_memory(instr, 2, &m))
			return false;
		seg = (x86_reg)MCOperand_getImm(MCInst_getOperand(instr, 6));
		wo = MCInst_getOperand(instr, 8);
		nfo = MCInst_getOperand(instr, 10);
	} else {
		src = MCInst_getOperand(instr, 2);
		wo = MCInst_getOperand(instr, 3);
		nfo = MCInst_getOperand(instr, 5);
		sr = (x86_reg)MCOperand_getImm(src);
	}
	w = (uint8_t)MCOperand_getImm(wo);
	nf = MCOperand_getImm(nfo) != 0;
	if (nf)
		SStream_concat0(s, "{nf}|");
	if (att)
		SStream_concat(s, "%s%c\t", mn,
			       w == 2 ? 'w' : w == 4 ? 'l' : 'q');
	else
		SStream_concat(s, "%s\t", mn);
	if (att) {
		if (mem) {
			if (seg != X86_REG_INVALID)
				SStream_concat(s, "%%%s:", feature_register_name(seg));
			if (!print_feature_memory(s, &m, true))
				return false;
		} else
			SStream_concat(s, "%%%s",
				       X86_reg_name((csh)instr->csh, sr));
		SStream_concat(s, ", %%%s", X86_reg_name((csh)instr->csh, dr));
	} else {
		SStream_concat(s, "%s, ", X86_reg_name((csh)instr->csh, dr));
		if (mem) {
			SStream_concat0(s,
					w == 2 ? "word ptr " :
					w == 4 ? "dword ptr " : "qword ptr ");
			if (seg != X86_REG_INVALID)
				SStream_concat(s, "%s:", feature_register_name(seg));
			if (!print_feature_memory(s, &m, false))
				return false;
		} else
			SStream_concat(s, "%s",
				       X86_reg_name((csh)instr->csh, sr));
	}
	if (!instr->flat_insn->detail)
		return true;
	detail = instr->flat_insn->detail;
	x = &detail->x86;
	if (!mem || !att) {
		x->operands[att ? 1 : 0].type = X86_OP_REG;
		x->operands[att ? 1 : 0].reg = dr;
		x->operands[att ? 1 : 0].size = w;
		x->operands[att ? 1 : 0].access = CS_AC_WRITE;
	}
	if (mem) {
		set_feature_memory_operand(&x->operands[att ? 0 : 1], &m, w,
					   CS_AC_READ);
		x->operands[att ? 0 : 1].mem.segment = seg;
		if (att) {
			x->operands[1].type = X86_OP_REG;
			x->operands[1].reg = dr;
			x->operands[1].size = w;
			x->operands[1].access = CS_AC_WRITE;
		}
	} else {
		x->operands[att ? 0 : 1].type = X86_OP_REG;
		x->operands[att ? 0 : 1].reg = sr;
		x->operands[att ? 0 : 1].size = w;
		x->operands[att ? 0 : 1].access = CS_AC_READ;
	}
	x->op_count = 2;
	if (!nf) {
		detail->regs_write[detail->regs_write_count++] = X86_REG_EFLAGS;
		x->eflags = op == X86_FEATURE_APX_POPCNT ?
			X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_SF |
			X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_RESET_AF |
			X86_EFLAGS_RESET_PF | X86_EFLAGS_RESET_CF :
			(op == X86_FEATURE_APX_LZCNT || op == X86_FEATURE_APX_TZCNT) ?
			X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF |
			X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF :
			X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF |
			X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF;
	}
	return true;
}

static bool print_apx_unary(MCInst *instr, SStream *s, bool att)
{
	unsigned op=MCInst_getOpcode(instr); const char *mn; uint64_t flags; const MCOperand *d,*mf,*wo,*ndo,*nfo; bool mem,nd,nf; uint8_t w,i,count; x86_reg dst,src=X86_REG_INVALID,seg=X86_REG_INVALID; x86_feature_memory m; cs_x86 *x; cs_detail *detail;
	switch(op){case X86_FEATURE_APX_INC:mn="inc";flags=X86_EFLAGS_MODIFY_OF|X86_EFLAGS_MODIFY_SF|X86_EFLAGS_MODIFY_ZF|X86_EFLAGS_MODIFY_AF|X86_EFLAGS_MODIFY_PF;break;case X86_FEATURE_APX_DEC:mn="dec";flags=X86_EFLAGS_MODIFY_OF|X86_EFLAGS_MODIFY_SF|X86_EFLAGS_MODIFY_ZF|X86_EFLAGS_MODIFY_AF|X86_EFLAGS_MODIFY_PF;break;case X86_FEATURE_APX_NEG:mn="neg";flags=X86_EFLAGS_MODIFY_OF|X86_EFLAGS_MODIFY_SF|X86_EFLAGS_MODIFY_ZF|X86_EFLAGS_MODIFY_AF|X86_EFLAGS_MODIFY_PF|X86_EFLAGS_MODIFY_CF;break;case X86_FEATURE_APX_NOT:mn="not";flags=0;break;case X86_FEATURE_APX_MUL:mn="mul";flags=X86_EFLAGS_MODIFY_OF|X86_EFLAGS_UNDEFINED_SF|X86_EFLAGS_UNDEFINED_ZF|X86_EFLAGS_UNDEFINED_AF|X86_EFLAGS_UNDEFINED_PF|X86_EFLAGS_MODIFY_CF;break;case X86_FEATURE_APX_IMUL_ONE:mn="imul";flags=X86_EFLAGS_MODIFY_OF|X86_EFLAGS_UNDEFINED_SF|X86_EFLAGS_UNDEFINED_ZF|X86_EFLAGS_UNDEFINED_AF|X86_EFLAGS_UNDEFINED_PF|X86_EFLAGS_MODIFY_CF;break;case X86_FEATURE_APX_DIV:mn="div";flags=X86_EFLAGS_UNDEFINED_OF|X86_EFLAGS_UNDEFINED_SF|X86_EFLAGS_UNDEFINED_ZF|X86_EFLAGS_UNDEFINED_AF|X86_EFLAGS_UNDEFINED_PF|X86_EFLAGS_UNDEFINED_CF;break;case X86_FEATURE_APX_IDIV:mn="idiv";flags=X86_EFLAGS_UNDEFINED_OF|X86_EFLAGS_UNDEFINED_SF|X86_EFLAGS_UNDEFINED_ZF|X86_EFLAGS_UNDEFINED_AF|X86_EFLAGS_UNDEFINED_PF|X86_EFLAGS_UNDEFINED_CF;break;default:return false;}
	if(MCInst_getNumOperands(instr)<6)return false; d=MCInst_getOperand(instr,0);mf=MCInst_getOperand(instr,1);if(!MCOperand_isImm(d)||!MCOperand_isImm(mf))return false;dst=(x86_reg)MCOperand_getImm(d);mem=MCOperand_getImm(mf)!=0;memset(&m,0,sizeof(m));
	if(mem){const MCOperand *so;if(MCInst_getNumOperands(instr)!=11||!get_feature_memory(instr,2,&m))return false;so=MCInst_getOperand(instr,6);wo=MCInst_getOperand(instr,8);ndo=MCInst_getOperand(instr,9);nfo=MCInst_getOperand(instr,10);if(!MCOperand_isImm(so))return false;seg=(x86_reg)MCOperand_getImm(so);}else{const MCOperand *ro;if(MCInst_getNumOperands(instr)!=6)return false;ro=MCInst_getOperand(instr,2);wo=MCInst_getOperand(instr,3);ndo=MCInst_getOperand(instr,4);nfo=MCInst_getOperand(instr,5);if(!MCOperand_isImm(ro))return false;src=(x86_reg)MCOperand_getImm(ro);}
	if(!MCOperand_isImm(wo)||!MCOperand_isImm(ndo)||!MCOperand_isImm(nfo))return false;w=(uint8_t)MCOperand_getImm(wo);nd=MCOperand_getImm(ndo)!=0;nf=MCOperand_getImm(nfo)!=0;if((w!=1&&w!=2&&w!=4&&w!=8)||(nd?dst==X86_REG_INVALID:dst!=X86_REG_INVALID))return false;
	if(nf)SStream_concat0(s,"{nf}|");if(att)SStream_concat(s,"%s%c\t",mn,w==1?'b':w==2?'w':w==4?'l':'q');else SStream_concat(s,"%s\t",mn);count=nd?2:1;
	for(i=0;i<count;++i){bool isdst=nd&&(att?i==1:i==0);if(i)SStream_concat0(s,", ");if(isdst){const char*n=X86_reg_name((csh)instr->csh,dst);if(!n)return false;SStream_concat(s,att?"%%%s":"%s",n);}else if(mem){if(!att)SStream_concat0(s,w==1?"byte ptr ":w==2?"word ptr ":w==4?"dword ptr ":"qword ptr ");if(seg!=X86_REG_INVALID)SStream_concat(s,att?"%%%s:":"%s:",feature_register_name(seg));if(!print_feature_memory(s,&m,att))return false;}else{const char*n=X86_reg_name((csh)instr->csh,src);if(!n)return false;SStream_concat(s,att?"%%%s":"%s",n);}}
	if(!instr->flat_insn->detail)return true;detail=instr->flat_insn->detail;x=&detail->x86;for(i=0;i<count;++i){bool isdst=nd&&(att?i==1:i==0);bool implicit=op==X86_FEATURE_APX_MUL||op==X86_FEATURE_APX_IMUL_ONE||op==X86_FEATURE_APX_DIV||op==X86_FEATURE_APX_IDIV;cs_ac_type a=(nd||implicit)?CS_AC_READ:CS_AC_READ|CS_AC_WRITE;cs_x86_op*o=&x->operands[i];if(isdst){o->type=X86_OP_REG;o->reg=dst;o->size=w;o->access=CS_AC_WRITE;}else if(mem){set_feature_memory_operand(o,&m,w,a);o->mem.segment=seg;}else{o->type=X86_OP_REG;o->reg=src;o->size=w;o->access=a;}}x->op_count=count;if(op==X86_FEATURE_APX_MUL||op==X86_FEATURE_APX_IMUL_ONE||op==X86_FEATURE_APX_DIV||op==X86_FEATURE_APX_IDIV){x86_reg lo=w==1?X86_REG_AL:w==2?X86_REG_AX:w==4?X86_REG_EAX:X86_REG_RAX;x86_reg hi=w==1?X86_REG_AH:w==2?X86_REG_DX:w==4?X86_REG_EDX:X86_REG_RDX;detail->regs_read[detail->regs_read_count++]=lo;if(op==X86_FEATURE_APX_DIV||op==X86_FEATURE_APX_IDIV)detail->regs_read[detail->regs_read_count++]=hi;detail->regs_write[detail->regs_write_count++]=lo;detail->regs_write[detail->regs_write_count++]=hi;}if(!nf&&flags){detail->regs_write[detail->regs_write_count++]=X86_REG_EFLAGS;x->eflags=flags;}return true;
}

static bool print_apx_imul(MCInst *instr, SStream *stream, bool att_syntax)
{
	const MCOperand *reg_operand, *ndd_operand, *memory_form_operand;
	const MCOperand *width_operand, *nd_operand, *nf_operand;
	x86_reg reg_field, ndd_field, rm_field = X86_REG_INVALID;
	x86_reg segment = X86_REG_INVALID;
	uint8_t width, address_size = 8;
	bool memory_form, nd, nf;
	x86_feature_memory memory;
	x86_feature_print_operand logical[3];
	uint8_t logical_count, i;
	char suffix;
	cs_detail *detail;
	cs_x86 *x86;

	const unsigned int feature_opcode = MCInst_getOpcode(instr);
	const char *mnemonic = feature_opcode == X86_FEATURE_APX_ADCX ? "adcx" :
		feature_opcode == X86_FEATURE_APX_ADOX ? "adox" :
		feature_opcode == X86_FEATURE_APX_ANDN ? "andn" :
		feature_opcode == X86_FEATURE_APX_BZHI ? "bzhi" : "imul";
	const bool adx = feature_opcode == X86_FEATURE_APX_ADCX ||
			 feature_opcode == X86_FEATURE_APX_ADOX;
	const bool bmi = feature_opcode == X86_FEATURE_APX_ANDN ||
			 feature_opcode == X86_FEATURE_APX_BZHI;
	if ((feature_opcode != X86_FEATURE_APX_IMUL && !adx && !bmi) ||
	    MCInst_getNumOperands(instr) < 7) {
		return false;
	}
	reg_operand = MCInst_getOperand(instr, 0);
	ndd_operand = MCInst_getOperand(instr, 1);
	memory_form_operand = MCInst_getOperand(instr, 2);
	if (!MCOperand_isImm(reg_operand) || !MCOperand_isImm(ndd_operand) ||
	    !MCOperand_isImm(memory_form_operand)) {
		return false;
	}
	reg_field = (x86_reg)MCOperand_getImm(reg_operand);
	ndd_field = (x86_reg)MCOperand_getImm(ndd_operand);
	memory_form = MCOperand_getImm(memory_form_operand) != 0;
	memset(&memory, 0, sizeof(memory));
	if (memory_form) {
		const MCOperand *segment_operand, *address_size_operand;

		if (MCInst_getNumOperands(instr) != 12 ||
		    !get_feature_memory(instr, 3, &memory)) {
			return false;
		}
		segment_operand = MCInst_getOperand(instr, 7);
		address_size_operand = MCInst_getOperand(instr, 8);
		width_operand = MCInst_getOperand(instr, 9);
		nd_operand = MCInst_getOperand(instr, 10);
		nf_operand = MCInst_getOperand(instr, 11);
		if (!MCOperand_isImm(segment_operand) ||
		    !MCOperand_isImm(address_size_operand)) {
			return false;
		}
		segment = (x86_reg)MCOperand_getImm(segment_operand);
		address_size = (uint8_t)MCOperand_getImm(address_size_operand);
		if ((segment != X86_REG_INVALID &&
		     !feature_register_name(segment)) ||
		    (address_size != 4 && address_size != 8)) {
			return false;
		}
	} else {
		const MCOperand *rm_operand;

		if (MCInst_getNumOperands(instr) != 7)
			return false;
		rm_operand = MCInst_getOperand(instr, 3);
		width_operand = MCInst_getOperand(instr, 4);
		nd_operand = MCInst_getOperand(instr, 5);
		nf_operand = MCInst_getOperand(instr, 6);
		if (!MCOperand_isImm(rm_operand))
			return false;
		rm_field = (x86_reg)MCOperand_getImm(rm_operand);
	}
	if (!MCOperand_isImm(width_operand) || !MCOperand_isImm(nd_operand) ||
	    !MCOperand_isImm(nf_operand)) {
		return false;
	}
	width = (uint8_t)MCOperand_getImm(width_operand);
	nd = MCOperand_getImm(nd_operand) != 0;
	nf = MCOperand_getImm(nf_operand) != 0;
	if ((adx ? (width != 4 && width != 8) :
		   (width != 2 && width != 4 && width != 8)) ||
	    (nd ? ndd_field == X86_REG_INVALID :
		  ndd_field != X86_REG_INVALID) ||
	    !X86_reg_name((csh)instr->csh, reg_field) ||
	    (!memory_form && !X86_reg_name((csh)instr->csh, rm_field))) {
		return false;
	}

	if (nd) {
		logical[0] = (x86_feature_print_operand){ false, ndd_field,
							  CS_AC_WRITE };
		logical[1] = (x86_feature_print_operand){ false, reg_field,
							  CS_AC_READ };
		logical[2] = (x86_feature_print_operand){ memory_form, rm_field,
							  CS_AC_READ };
		logical_count = 3;
	} else {
		logical[0] =
			(x86_feature_print_operand){ false, reg_field,
						     CS_AC_READ | CS_AC_WRITE };
		logical[1] = (x86_feature_print_operand){ memory_form, rm_field,
							  CS_AC_READ };
		logical_count = 2;
	}

	if (nf)
		SStream_concat0(stream, "{nf}|");
	suffix = width == 2 ? 'w' : width == 4 ? 'l' : 'q';
	if (att_syntax)
		SStream_concat(stream, "%s%c\t", mnemonic, suffix);
	else
		SStream_concat(stream, "%s\t", mnemonic);
	for (i = 0; i < logical_count; ++i) {
		const uint8_t logical_index =
			att_syntax ? logical_count - 1 - i : i;
		const x86_feature_print_operand *operand =
			&logical[logical_index];

		if (i != 0)
			SStream_concat0(stream, ", ");
		if (operand->is_memory) {
			const char *segment_name =
				segment == X86_REG_INVALID ?
					NULL :
					feature_register_name(segment);

			if (!att_syntax) {
				SStream_concat0(stream,
						width == 2 ? "word ptr " :
						width == 4 ? "dword ptr " :
							     "qword ptr ");
			}
			if (segment_name) {
				SStream_concat(stream,
					       att_syntax ? "%%%s:" : "%s:",
					       segment_name);
			}
			if (!print_feature_memory(stream, &memory, att_syntax))
				return false;
		} else {
			const char *name =
				X86_reg_name((csh)instr->csh, operand->reg);

			if (!name)
				return false;
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       name);
		}
	}
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	for (i = 0; i < logical_count; ++i) {
		const uint8_t logical_index =
			att_syntax ? logical_count - 1 - i : i;
		const x86_feature_print_operand *operand =
			&logical[logical_index];

		if (operand->is_memory) {
			set_feature_memory_operand(&x86->operands[i], &memory,
						   width, operand->access);
			x86->operands[i].mem.segment = segment;
		} else {
			x86->operands[i].type = X86_OP_REG;
			x86->operands[i].reg = operand->reg;
			x86->operands[i].size = width;
			x86->operands[i].access = operand->access;
		}
	}
	x86->op_count = logical_count;
	if (!nf) {
		detail->regs_write[detail->regs_write_count++] = X86_REG_EFLAGS;
		x86->eflags = bmi ?
			(feature_opcode == X86_FEATURE_APX_BZHI ?
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF |
			 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			 X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF :
			 X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF |
			 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			 X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_RESET_CF) : adx ?
			(feature_opcode == X86_FEATURE_APX_ADCX ?
			 X86_EFLAGS_TEST_CF | X86_EFLAGS_MODIFY_CF :
			 X86_EFLAGS_TEST_OF | X86_EFLAGS_MODIFY_OF) :
			X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_SF |
			      X86_EFLAGS_UNDEFINED_ZF |
			      X86_EFLAGS_UNDEFINED_AF |
			      X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF;
	}
	if (adx)
		detail->regs_read[detail->regs_read_count++] = X86_REG_EFLAGS;
	return true;
}

static void print_apx_scalar_immediate(MCInst *instr, SStream *stream,
				       int64_t immediate, uint8_t width,
				       bool att_syntax)
{
	if (att_syntax)
		SStream_concat0(stream, "$");
	if (instr->csh->imm_unsigned && immediate < 0) {
		uint64_t value = (uint64_t)immediate;

		if (width == 1)
			value &= 0xff;
		else if (width == 2)
			value &= 0xffff;
		else if (width == 4)
			value &= 0xffffffff;
		SStream_concat(stream, "0x%llx", (unsigned long long)value);
	} else if (immediate < -HEX_THRESHOLD) {
		uint64_t magnitude = (uint64_t)(-(immediate + 1)) + 1;

		SStream_concat(stream, "-0x%llx",
			       (unsigned long long)magnitude);
	} else if (immediate < 0) {
		uint64_t magnitude = (uint64_t)(-(immediate + 1)) + 1;

		SStream_concat(stream, "-%llu", (unsigned long long)magnitude);
	} else if (immediate > HEX_THRESHOLD) {
		SStream_concat(stream, "0x%llx", (unsigned long long)immediate);
	} else {
		SStream_concat(stream, "%llu", (unsigned long long)immediate);
	}
}

static bool print_apx_imul_immediate(MCInst *instr, SStream *stream,
				     bool att_syntax)
{
	const MCOperand *destination_operand, *memory_form_operand;
	const MCOperand *source_operand = NULL, *width_operand;
	const MCOperand *immediate_operand, *zu_operand, *nf_operand;
	x86_reg destination, source = X86_REG_INVALID;
	x86_reg segment = X86_REG_INVALID;
	uint8_t width, address_size = 8, i;
	bool memory_form, nf;
	int64_t immediate;
	x86_feature_memory memory;
	cs_detail *detail;
	cs_x86 *x86;

	if (MCInst_getOpcode(instr) != X86_FEATURE_APX_IMUL_IMMEDIATE ||
	    MCInst_getNumOperands(instr) < 7) {
		return false;
	}
	destination_operand = MCInst_getOperand(instr, 0);
	memory_form_operand = MCInst_getOperand(instr, 1);
	if (!MCOperand_isImm(destination_operand) ||
	    !MCOperand_isImm(memory_form_operand)) {
		return false;
	}
	destination = (x86_reg)MCOperand_getImm(destination_operand);
	memory_form = MCOperand_getImm(memory_form_operand) != 0;
	memset(&memory, 0, sizeof(memory));
	if (memory_form) {
		const MCOperand *segment_operand, *address_size_operand;

		if (MCInst_getNumOperands(instr) != 12 ||
		    !get_feature_memory(instr, 2, &memory)) {
			return false;
		}
		segment_operand = MCInst_getOperand(instr, 6);
		address_size_operand = MCInst_getOperand(instr, 7);
		width_operand = MCInst_getOperand(instr, 8);
		immediate_operand = MCInst_getOperand(instr, 9);
		zu_operand = MCInst_getOperand(instr, 10);
		nf_operand = MCInst_getOperand(instr, 11);
		if (!MCOperand_isImm(segment_operand) ||
		    !MCOperand_isImm(address_size_operand)) {
			return false;
		}
		segment = (x86_reg)MCOperand_getImm(segment_operand);
		address_size = (uint8_t)MCOperand_getImm(address_size_operand);
		if ((segment != X86_REG_INVALID &&
		     !feature_register_name(segment)) ||
		    (address_size != 4 && address_size != 8)) {
			return false;
		}
	} else {
		if (MCInst_getNumOperands(instr) != 7)
			return false;
		source_operand = MCInst_getOperand(instr, 2);
		width_operand = MCInst_getOperand(instr, 3);
		immediate_operand = MCInst_getOperand(instr, 4);
		zu_operand = MCInst_getOperand(instr, 5);
		nf_operand = MCInst_getOperand(instr, 6);
		if (!MCOperand_isImm(source_operand))
			return false;
		source = (x86_reg)MCOperand_getImm(source_operand);
	}
	if (!MCOperand_isImm(width_operand) ||
	    !MCOperand_isImm(immediate_operand) || !MCOperand_isImm(zu_operand) ||
	    !MCOperand_isImm(nf_operand)) {
		return false;
	}
	width = (uint8_t)MCOperand_getImm(width_operand);
	immediate = MCOperand_getImm(immediate_operand);
	if (MCOperand_getImm(zu_operand) > 1 ||
	    MCOperand_getImm(nf_operand) > 1 ||
	    (width != 2 && width != 4 && width != 8) ||
	    (instr->imm_size != 1 &&
	     !(instr->imm_size == 2 && width == 2) &&
	     !(instr->imm_size == 4 && (width == 4 || width == 8))) ||
	    !X86_reg_name((csh)instr->csh, destination) ||
	    (!memory_form && !X86_reg_name((csh)instr->csh, source))) {
		return false;
	}
	nf = MCOperand_getImm(nf_operand) != 0;

	if (nf)
		SStream_concat0(stream, "{nf}|");
	if (att_syntax)
		SStream_concat(stream, "imul%c\t",
			       width == 2 ? 'w' : width == 4 ? 'l' : 'q');
	else
		SStream_concat0(stream, "imul\t");
	for (i = 0; i < 3; ++i) {
		uint8_t logical = att_syntax ? 2 - i : i;

		if (i != 0)
			SStream_concat0(stream, ", ");
		if (logical == 0) {
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       X86_reg_name((csh)instr->csh,
						    destination));
		} else if (logical == 2) {
			print_apx_scalar_immediate(instr, stream, immediate, width,
						   att_syntax);
		} else if (memory_form) {
			if (!att_syntax)
				SStream_concat0(stream, width == 2 ? "word ptr " :
							width == 4 ? "dword ptr " :
								     "qword ptr ");
			if (segment != X86_REG_INVALID)
				SStream_concat(stream, att_syntax ? "%%%s:" : "%s:",
					       feature_register_name(segment));
			if (!print_feature_memory(stream, &memory, att_syntax))
				return false;
		} else {
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       X86_reg_name((csh)instr->csh, source));
		}
	}
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	for (i = 0; i < 3; ++i) {
		uint8_t logical = att_syntax ? 2 - i : i;
		cs_x86_op *operand = &x86->operands[i];

		if (logical == 0) {
			operand->type = X86_OP_REG;
			operand->reg = destination;
			operand->size = width;
			operand->access = CS_AC_WRITE;
		} else if (logical == 2) {
			operand->type = X86_OP_IMM;
			operand->imm = immediate;
			operand->size = width;
			operand->access = CS_AC_READ;
		} else if (memory_form) {
			set_feature_memory_operand(operand, &memory, width,
						   CS_AC_READ);
			operand->mem.segment = segment;
		} else {
			operand->type = X86_OP_REG;
			operand->reg = source;
			operand->size = width;
			operand->access = CS_AC_READ;
		}
	}
	x86->op_count = 3;
	if (!nf) {
		detail->regs_write[detail->regs_write_count++] = X86_REG_EFLAGS;
		x86->eflags = X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_SF |
			      X86_EFLAGS_UNDEFINED_ZF |
			      X86_EFLAGS_UNDEFINED_AF |
			      X86_EFLAGS_UNDEFINED_PF |
			      X86_EFLAGS_MODIFY_CF;
	}
	return true;
}

static bool print_apx_adc_sbb(MCInst *instr, SStream *stream, bool att_syntax)
{
	enum {
		APX_ARITHMETIC_REGISTER,
		APX_ARITHMETIC_MEMORY,
		APX_ARITHMETIC_IMMEDIATE,
	};
	const MCOperand *destination_operand, *source1_operand,
		*source2_operand;
	const MCOperand *memory_position_operand, *immediate_form_operand;
	const MCOperand *immediate_operand, *width_operand, *nd_operand;
	x86_reg destination, source1, source2;
	x86_reg segment = X86_REG_INVALID;
	uint8_t memory_position, width, address_size = 8;
	bool immediate_form, nd;
	int64_t immediate;
	x86_feature_memory memory;
	uint8_t kind[3], logical_count, i;
	x86_reg logical_register[3] = { X86_REG_INVALID, X86_REG_INVALID,
					X86_REG_INVALID };
	cs_ac_type access[3];
	const char *mnemonic;
	uint64_t eflags;
	cs_detail *detail;
	cs_x86 *x86;

	switch (MCInst_getOpcode(instr)) {
	default:
		return false;
	case X86_FEATURE_APX_ADC:
		mnemonic = "adc";
		eflags = X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF |
			 X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF |
			 X86_EFLAGS_TEST_CF;
		break;
	case X86_FEATURE_APX_SBB:
		mnemonic = "sbb";
		eflags = X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF |
			 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF |
			 X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF |
			 X86_EFLAGS_TEST_CF;
		break;
	}
	if (MCInst_getNumOperands(instr) < 8)
		return false;
	destination_operand = MCInst_getOperand(instr, 0);
	source1_operand = MCInst_getOperand(instr, 1);
	source2_operand = MCInst_getOperand(instr, 2);
	memory_position_operand = MCInst_getOperand(instr, 3);
	if (!MCOperand_isImm(destination_operand) ||
	    !MCOperand_isImm(source1_operand) ||
	    !MCOperand_isImm(source2_operand) ||
	    !MCOperand_isImm(memory_position_operand)) {
		return false;
	}
	destination = (x86_reg)MCOperand_getImm(destination_operand);
	source1 = (x86_reg)MCOperand_getImm(source1_operand);
	source2 = (x86_reg)MCOperand_getImm(source2_operand);
	memory_position = (uint8_t)MCOperand_getImm(memory_position_operand);
	memset(&memory, 0, sizeof(memory));
	if (memory_position != 0) {
		const MCOperand *segment_operand, *address_size_operand;

		if ((memory_position != 1 && memory_position != 2) ||
		    MCInst_getNumOperands(instr) != 14 ||
		    !get_feature_memory(instr, 4, &memory)) {
			return false;
		}
		segment_operand = MCInst_getOperand(instr, 8);
		address_size_operand = MCInst_getOperand(instr, 9);
		immediate_form_operand = MCInst_getOperand(instr, 10);
		immediate_operand = MCInst_getOperand(instr, 11);
		width_operand = MCInst_getOperand(instr, 12);
		nd_operand = MCInst_getOperand(instr, 13);
		if (!MCOperand_isImm(segment_operand) ||
		    !MCOperand_isImm(address_size_operand)) {
			return false;
		}
		segment = (x86_reg)MCOperand_getImm(segment_operand);
		address_size = (uint8_t)MCOperand_getImm(address_size_operand);
		if ((segment != X86_REG_INVALID &&
		     !feature_register_name(segment)) ||
		    (address_size != 4 && address_size != 8)) {
			return false;
		}
	} else {
		if (MCInst_getNumOperands(instr) != 8)
			return false;
		immediate_form_operand = MCInst_getOperand(instr, 4);
		immediate_operand = MCInst_getOperand(instr, 5);
		width_operand = MCInst_getOperand(instr, 6);
		nd_operand = MCInst_getOperand(instr, 7);
	}
	if (!MCOperand_isImm(immediate_form_operand) ||
	    !MCOperand_isImm(immediate_operand) ||
	    !MCOperand_isImm(width_operand) || !MCOperand_isImm(nd_operand)) {
		return false;
	}
	immediate_form = MCOperand_getImm(immediate_form_operand) != 0;
	immediate = MCOperand_getImm(immediate_operand);
	width = (uint8_t)MCOperand_getImm(width_operand);
	nd = MCOperand_getImm(nd_operand) != 0;
	if ((width != 1 && width != 2 && width != 4 && width != 8) ||
	    (memory_position == 1 ? source1 != X86_REG_INVALID :
				    !X86_reg_name((csh)instr->csh, source1)) ||
	    (!immediate_form &&
	     (memory_position == 2 ?
		      source2 != X86_REG_INVALID :
		      !X86_reg_name((csh)instr->csh, source2))) ||
	    (immediate_form &&
	     (source2 != X86_REG_INVALID || memory_position == 2)) ||
	    (nd ? !X86_reg_name((csh)instr->csh, destination) :
	     memory_position == 1 ? destination != X86_REG_INVALID :
				    destination != source1)) {
		return false;
	}

	if (nd) {
		kind[0] = APX_ARITHMETIC_REGISTER;
		logical_register[0] = destination;
		access[0] = CS_AC_WRITE;
		kind[1] = memory_position == 1 ? APX_ARITHMETIC_MEMORY :
						 APX_ARITHMETIC_REGISTER;
		logical_register[1] = source1;
		access[1] = CS_AC_READ;
		logical_count = 3;
	} else {
		kind[0] = memory_position == 1 ? APX_ARITHMETIC_MEMORY :
						 APX_ARITHMETIC_REGISTER;
		logical_register[0] = source1;
		access[0] = CS_AC_READ | CS_AC_WRITE;
		logical_count = 2;
	}
	if (immediate_form) {
		kind[logical_count - 1] = APX_ARITHMETIC_IMMEDIATE;
		access[logical_count - 1] = CS_AC_READ;
	} else {
		kind[logical_count - 1] = memory_position == 2 ?
						  APX_ARITHMETIC_MEMORY :
						  APX_ARITHMETIC_REGISTER;
		logical_register[logical_count - 1] = source2;
		access[logical_count - 1] = CS_AC_READ;
	}

	if (att_syntax)
		SStream_concat(stream, "%s%c\t", mnemonic,
			       width == 1 ? 'b' :
			       width == 2 ? 'w' :
			       width == 4 ? 'l' :
					    'q');
	else
		SStream_concat(stream, "%s\t", mnemonic);
	for (i = 0; i < logical_count; ++i) {
		uint8_t logical_index = att_syntax ? logical_count - 1 - i : i;

		if (i != 0)
			SStream_concat0(stream, ", ");
		if (kind[logical_index] == APX_ARITHMETIC_MEMORY) {
			const char *segment_name =
				segment == X86_REG_INVALID ?
					NULL :
					feature_register_name(segment);

			if (!att_syntax) {
				SStream_concat0(stream,
						width == 1 ? "byte ptr " :
						width == 2 ? "word ptr " :
						width == 4 ? "dword ptr " :
							     "qword ptr ");
			}
			if (segment_name) {
				SStream_concat(stream,
					       att_syntax ? "%%%s:" : "%s:",
					       segment_name);
			}
			if (!print_feature_memory(stream, &memory, att_syntax))
				return false;
		} else if (kind[logical_index] == APX_ARITHMETIC_IMMEDIATE) {
			print_apx_scalar_immediate(instr, stream, immediate,
						   width, att_syntax);
		} else {
			const char *name =
				X86_reg_name((csh)instr->csh,
					     logical_register[logical_index]);

			if (!name)
				return false;
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       name);
		}
	}
	if (!instr->flat_insn->detail)
		return true;

	detail = instr->flat_insn->detail;
	x86 = &detail->x86;
	for (i = 0; i < logical_count; ++i) {
		uint8_t logical_index = att_syntax ? logical_count - 1 - i : i;
		cs_x86_op *operand = &x86->operands[i];

		if (kind[logical_index] == APX_ARITHMETIC_MEMORY) {
			set_feature_memory_operand(operand, &memory, width,
						   access[logical_index]);
			operand->mem.segment = segment;
		} else if (kind[logical_index] == APX_ARITHMETIC_IMMEDIATE) {
			operand->type = X86_OP_IMM;
			operand->imm = immediate;
			operand->size = width;
			operand->access = access[logical_index];
		} else {
			operand->type = X86_OP_REG;
			operand->reg = logical_register[logical_index];
			operand->size = width;
			operand->access = access[logical_index];
		}
	}
	x86->op_count = logical_count;
	detail->regs_read[detail->regs_read_count++] = X86_REG_EFLAGS;
	detail->regs_write[detail->regs_write_count++] = X86_REG_EFLAGS;
	x86->eflags = eflags;
	return true;
}

static bool print_apx_setcc(MCInst *instr, SStream *stream, bool att_syntax)
{
	unsigned int opcode = MCInst_getOpcode(instr);
	unsigned int condition;
	bool zu;
	const char *condition_name;
	cs_detail *detail;
	cs_x86 *x86;

	if (opcode >= X86_FEATURE_APX_SETCC_BASE &&
	    opcode < X86_FEATURE_APX_SETCC_BASE + X86_FEATURE_APX_SETCC_COUNT) {
		condition = opcode - X86_FEATURE_APX_SETCC_BASE;
		zu = false;
	} else if (opcode >= X86_FEATURE_APX_SETZUCC_BASE &&
		   opcode < X86_FEATURE_APX_SETZUCC_BASE +
				    X86_FEATURE_APX_SETCC_COUNT) {
		condition = opcode - X86_FEATURE_APX_SETZUCC_BASE;
		zu = true;
	} else {
		return false;
	}
	condition_name = apx_condition_name(condition);
	if (!condition_name)
		return false;

	if (MCInst_getNumOperands(instr) == 1) {
		const MCOperand *register_operand = MCInst_getOperand(instr, 0);
		x86_reg reg;
		const char *name;

		if (!MCOperand_isImm(register_operand))
			return false;
		reg = (x86_reg)MCOperand_getImm(register_operand);
		name = X86_reg_name((csh)instr->csh, reg);
		if (!name)
			return false;
		if (att_syntax)
			SStream_concat(stream,
				       zu ? "setzu%sb\t%%%s" : "set%s\t%%%s",
				       condition_name, name);
		else
			SStream_concat(stream, zu ? "setzu%s\t%s" : "set%s\t%s",
				       condition_name, name);
		if (!instr->flat_insn->detail)
			return true;
		detail = instr->flat_insn->detail;
		x86 = &detail->x86;
		x86->operands[0].type = X86_OP_REG;
		x86->operands[0].reg = reg;
		x86->operands[0].size = 1;
		x86->operands[0].access = CS_AC_WRITE;
		x86->op_count = 1;
		detail->regs_read[0] = X86_REG_EFLAGS;
		detail->regs_read_count = 1;
		return true;
	}

	if (MCInst_getNumOperands(instr) == 6) {
		x86_feature_memory memory;
		const MCOperand *segment_operand = MCInst_getOperand(instr, 4);
		const MCOperand *address_size_operand =
			MCInst_getOperand(instr, 5);
		x86_reg segment;
		uint8_t address_size;
		const char *segment_name;

		if (!get_feature_memory(instr, 0, &memory) ||
		    !MCOperand_isImm(segment_operand) ||
		    !MCOperand_isImm(address_size_operand)) {
			return false;
		}
		segment = (x86_reg)MCOperand_getImm(segment_operand);
		address_size = (uint8_t)MCOperand_getImm(address_size_operand);
		if (address_size != 4 && address_size != 8)
			return false;
		segment_name = segment == X86_REG_INVALID ?
				       NULL :
				       feature_register_name(segment);
		if (segment != X86_REG_INVALID && !segment_name)
			return false;

		if (att_syntax && zu)
			SStream_concat(stream, "setzu%sb\t", condition_name);
		else
			SStream_concat(stream, zu ? "setzu%s\t" : "set%s\t",
				       condition_name);
		if (!att_syntax)
			SStream_concat0(stream, "byte ptr ");
		if (segment_name) {
			SStream_concat(stream, att_syntax ? "%%%s:" : "%s:",
				       segment_name);
		}
		if (!print_feature_memory(stream, &memory, att_syntax))
			return false;
		if (!instr->flat_insn->detail)
			return true;
		detail = instr->flat_insn->detail;
		x86 = &detail->x86;
		set_feature_memory_operand(&x86->operands[0], &memory, 1,
					   CS_AC_WRITE);
		x86->operands[0].mem.segment = segment;
		x86->op_count = 1;
		detail->regs_read[0] = X86_REG_EFLAGS;
		detail->regs_read_count = 1;
		return true;
	}
	return false;
}

static bool print_apx_evex_vector_gpr(MCInst *instr, SStream *stream,
				      bool att_syntax)
{
	static const char *const mnemonics[] = {
		"vpbroadcastb", "vpbroadcastw", "vpbroadcastd", "vpbroadcastq"
	};
	const unsigned int opcode = MCInst_getOpcode(instr);
	const MCOperand *destination_operand, *source_operand, *mask_operand;
	const MCOperand *vector_size_operand, *element_size_operand;
	const MCOperand *zeroing_operand;
	unsigned int kind;
	x86_reg destination, source, mask;
	uint8_t vector_size, element_size, mask_size, destination_access;
	bool zeroing;
	const char *destination_name, *source_name, *mask_name = NULL;
	cs_x86 *x86;

	if (opcode < X86_FEATURE_APX_VPBROADCAST_BASE ||
	    opcode >= X86_FEATURE_APX_VPBROADCAST_BASE +
			      X86_FEATURE_APX_VPBROADCAST_COUNT ||
	    MCInst_getNumOperands(instr) != 6)
		return false;
	destination_operand = MCInst_getOperand(instr, 0);
	source_operand = MCInst_getOperand(instr, 1);
	mask_operand = MCInst_getOperand(instr, 2);
	vector_size_operand = MCInst_getOperand(instr, 3);
	element_size_operand = MCInst_getOperand(instr, 4);
	zeroing_operand = MCInst_getOperand(instr, 5);
	if (!MCOperand_isImm(destination_operand) ||
	    !MCOperand_isImm(source_operand) || !MCOperand_isImm(mask_operand) ||
	    !MCOperand_isImm(vector_size_operand) ||
	    !MCOperand_isImm(element_size_operand) ||
	    !MCOperand_isImm(zeroing_operand))
		return false;

	kind = opcode - X86_FEATURE_APX_VPBROADCAST_BASE;
	destination = (x86_reg)MCOperand_getImm(destination_operand);
	source = (x86_reg)MCOperand_getImm(source_operand);
	mask = (x86_reg)MCOperand_getImm(mask_operand);
	vector_size = (uint8_t)MCOperand_getImm(vector_size_operand);
	element_size = (uint8_t)MCOperand_getImm(element_size_operand);
	zeroing = MCOperand_getImm(zeroing_operand) != 0;
	if ((vector_size != 16 && vector_size != 32 && vector_size != 64) ||
	    element_size != (1U << kind) ||
	    (mask != X86_REG_INVALID &&
	     (mask < X86_REG_K1 || mask > X86_REG_K7)) ||
	    (zeroing && mask == X86_REG_INVALID))
		return false;
	destination_name = X86_reg_name((csh)instr->csh, destination);
	source_name = X86_reg_name((csh)instr->csh, source);
	if (mask != X86_REG_INVALID)
		mask_name = X86_reg_name((csh)instr->csh, mask);
	if (!destination_name || !source_name ||
	    (mask != X86_REG_INVALID && !mask_name))
		return false;

	if (att_syntax) {
		SStream_concat(stream, "%s\t%%%s, %%%s", mnemonics[kind],
			       source_name, destination_name);
		if (mask != X86_REG_INVALID)
			SStream_concat(stream, " {%%%s}", mask_name);
		if (zeroing)
			SStream_concat0(stream, " {z}");
	} else {
		SStream_concat(stream, "%s\t%s", mnemonics[kind],
			       destination_name);
		if (mask != X86_REG_INVALID)
			SStream_concat(stream, " {%s}", mask_name);
		if (zeroing)
			SStream_concat0(stream, " {z}");
		SStream_concat(stream, ", %s", source_name);
	}
	if (!instr->flat_insn->detail)
		return true;

	x86 = &instr->flat_insn->detail->x86;
	destination_access = mask != X86_REG_INVALID && !zeroing ?
				     CS_AC_READ | CS_AC_WRITE :
				     CS_AC_WRITE;
	mask_size = (uint8_t)(((vector_size / element_size) + 7) / 8);
	if (att_syntax) {
		set_feature_register_operand(&x86->operands[0], source,
					     element_size == 8 ? 8 : 4,
					     CS_AC_READ);
		if (mask != X86_REG_INVALID) {
			set_feature_register_operand(&x86->operands[1], mask,
						     mask_size, CS_AC_READ);
			x86->operands[1].avx_zero_opmask = zeroing;
			set_feature_register_operand(&x86->operands[2], destination,
						     vector_size,
						     destination_access);
			x86->op_count = 3;
		} else {
			set_feature_register_operand(&x86->operands[1], destination,
						     vector_size,
						     destination_access);
			x86->op_count = 2;
		}
	} else {
		set_feature_register_operand(&x86->operands[0], destination,
					     vector_size, destination_access);
		if (mask != X86_REG_INVALID) {
			set_feature_register_operand(&x86->operands[1], mask,
						     mask_size, CS_AC_READ);
			x86->operands[1].avx_zero_opmask = zeroing;
			set_feature_register_operand(&x86->operands[2], source,
						     element_size == 8 ? 8 : 4,
						     CS_AC_READ);
			x86->op_count = 3;
		} else {
			set_feature_register_operand(&x86->operands[1], source,
						     element_size == 8 ? 8 : 4,
						     CS_AC_READ);
			x86->op_count = 2;
		}
	}
	return true;
}

static bool print_apx_msr(MCInst *instr, SStream *stream, bool att_syntax)
{
	const unsigned int opcode = MCInst_getOpcode(instr);
	const char *mnemonic;
	const MCOperand *form_operand, *b_operand, *other_operand;
	bool immediate_form, write;
	x86_reg b_register, other_register = X86_REG_INVALID;
	uint32_t immediate = 0;
	bool first_is_b, operand_is_b[2];
	cs_x86 *x86;
	unsigned int i;

	switch (opcode) {
	default:
		return false;
	case X86_FEATURE_APX_RDMSR_IMM:
		mnemonic = "rdmsr";
		write = false;
		break;
	case X86_FEATURE_APX_WRMSRNS_IMM:
		mnemonic = "wrmsrns";
		write = true;
		break;
	case X86_FEATURE_APX_URDMSR:
		mnemonic = "urdmsr";
		write = false;
		break;
	case X86_FEATURE_APX_UWRMSR:
		mnemonic = "uwrmsr";
		write = true;
		break;
	}
	if (MCInst_getNumOperands(instr) != 3)
		return false;
	form_operand = MCInst_getOperand(instr, 0);
	b_operand = MCInst_getOperand(instr, 1);
	other_operand = MCInst_getOperand(instr, 2);
	if (!MCOperand_isImm(form_operand) || !MCOperand_isImm(b_operand) ||
	    !MCOperand_isImm(other_operand))
		return false;
	immediate_form = MCOperand_getImm(form_operand) != 0;
	b_register = (x86_reg)MCOperand_getImm(b_operand);
	if (immediate_form)
		immediate = (uint32_t)MCOperand_getImm(other_operand);
	else
		other_register = (x86_reg)MCOperand_getImm(other_operand);
	if (!X86_reg_name((csh)instr->csh, b_register) ||
	    (!immediate_form &&
	     !X86_reg_name((csh)instr->csh, other_register)))
		return false;

	/* Intel writes the destination/data operand first for reads and the MSR
	 * selector first for writes.  AT&T reverses that display order. */
	first_is_b = write == att_syntax;
	operand_is_b[0] = first_is_b;
	operand_is_b[1] = !first_is_b;
	SStream_concat(stream, "%s\t", mnemonic);
	for (i = 0; i < 2; ++i) {
		bool is_b = operand_is_b[i];
		if (i)
			SStream_concat0(stream, ", ");
		if (is_b) {
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       X86_reg_name((csh)instr->csh, b_register));
		} else if (immediate_form) {
			SStream_concat(stream, att_syntax ? "$0x%x" : "0x%x",
				       immediate);
		} else {
			SStream_concat(stream, att_syntax ? "%%%s" : "%s",
				       X86_reg_name((csh)instr->csh,
						    other_register));
		}
	}
	if (!instr->flat_insn->detail)
		return true;

	x86 = &instr->flat_insn->detail->x86;
	for (i = 0; i < 2; ++i) {
		cs_x86_op *operand = &x86->operands[i];
		bool is_b = operand_is_b[i];
		if (is_b) {
			set_feature_register_operand(operand, b_register, 8,
					     write ? CS_AC_READ : CS_AC_WRITE);
		} else if (immediate_form) {
			operand->type = X86_OP_IMM;
			operand->imm = immediate;
			operand->size = 4;
			operand->access = CS_AC_READ;
		} else {
			set_feature_register_operand(operand, other_register, 8,
					     CS_AC_READ);
		}
	}
	x86->op_count = 2;
	return true;
}

bool X86_printFeatureExtension(MCInst *instr, SStream *stream, bool att_syntax)
{
	return print_apx_msr(instr, stream, att_syntax) ||
	       print_apx_evex_vector_gpr(instr, stream, att_syntax) ||
	       print_tile_control(instr, stream, att_syntax) ||
	       print_tilezero(instr, stream, att_syntax) ||
	       print_tile_memory(instr, stream, att_syntax) ||
	       print_amx_row(instr, stream, att_syntax) ||
	       print_tile_compute(instr, stream, att_syntax) ||
	       print_apx_cmov(instr, stream, att_syntax) ||
	       print_apx_setcc(instr, stream, att_syntax) ||
	       print_apx_shift_rotate(instr, stream, att_syntax) ||
	       print_apx_double_shift(instr, stream, att_syntax) ||
	       print_apx_direct_store(instr, stream, att_syntax) ||
	       print_apx_enqueue(instr, stream, att_syntax) ||
	       print_apx_rao(instr, stream, att_syntax) ||
	       print_apx_cmpccxadd(instr, stream, att_syntax) ||
	       print_apx_ccmp(instr, stream, att_syntax) ||
	       print_apx_kmov(instr, stream, att_syntax) ||
	       print_apx_movrs(instr, stream, att_syntax) ||
	       print_apx_invalidate(instr, stream, att_syntax) ||
	       print_apx_convert(instr, stream, att_syntax) ||
	       print_apx_mulx(instr, stream, att_syntax) ||
	       print_apx_rorx(instr, stream, att_syntax) ||
	       print_apx_bextr(instr, stream, att_syntax) ||
	       print_apx_bls(instr, stream, att_syntax) ||
	       print_apx_unary(instr, stream, att_syntax) ||
	       print_apx_imul_immediate(instr, stream, att_syntax) ||
	       print_apx_imul(instr, stream, att_syntax) ||
	       print_apx_adc_sbb(instr, stream, att_syntax) ||
	       print_apx_evex_alu(instr, stream, att_syntax) ||
	       print_apx_jmpabs(instr, stream) ||
	       print_apx_push2_pop2(instr, stream, att_syntax) ||
	       print_rex2_push_pop(instr, stream, att_syntax) ||
	       print_rex2(instr, stream, att_syntax);
}

bool X86_mapFeatureExtension(cs_insn *insn, unsigned int opcode)
{
	static const x86_insn cmov_ids[] = {
		X86_INS_CMOVO, X86_INS_CMOVNO, X86_INS_CMOVB,  X86_INS_CMOVAE,
		X86_INS_CMOVE, X86_INS_CMOVNE, X86_INS_CMOVBE, X86_INS_CMOVA,
		X86_INS_CMOVS, X86_INS_CMOVNS, X86_INS_CMOVP,  X86_INS_CMOVNP,
		X86_INS_CMOVL, X86_INS_CMOVGE, X86_INS_CMOVLE, X86_INS_CMOVG,
	};
	static const x86_insn cfcmov_ids[] = {
		X86_INS_CFCMOVO,  X86_INS_CFCMOVNO, X86_INS_CFCMOVB,
		X86_INS_CFCMOVAE, X86_INS_CFCMOVE,  X86_INS_CFCMOVNE,
		X86_INS_CFCMOVBE, X86_INS_CFCMOVA,  X86_INS_CFCMOVS,
		X86_INS_CFCMOVNS, X86_INS_CFCMOVP,  X86_INS_CFCMOVNP,
		X86_INS_CFCMOVL,  X86_INS_CFCMOVGE, X86_INS_CFCMOVLE,
		X86_INS_CFCMOVG,
	};
	static const x86_insn setcc_ids[] = {
		X86_INS_SETO, X86_INS_SETNO, X86_INS_SETB,  X86_INS_SETAE,
		X86_INS_SETE, X86_INS_SETNE, X86_INS_SETBE, X86_INS_SETA,
		X86_INS_SETS, X86_INS_SETNS, X86_INS_SETP,  X86_INS_SETNP,
		X86_INS_SETL, X86_INS_SETGE, X86_INS_SETLE, X86_INS_SETG,
	};
	static const x86_insn setzu_ids[] = {
		X86_INS_SETZUO,	 X86_INS_SETZUNO, X86_INS_SETZUB,
		X86_INS_SETZUAE, X86_INS_SETZUE,  X86_INS_SETZUNE,
		X86_INS_SETZUBE, X86_INS_SETZUA,  X86_INS_SETZUS,
		X86_INS_SETZUNS, X86_INS_SETZUP,  X86_INS_SETZUNP,
		X86_INS_SETZUL,	 X86_INS_SETZUGE, X86_INS_SETZULE,
		X86_INS_SETZUG,
	};
	if (opcode >= X86_FEATURE_APX_CMOVCC_BASE &&
	    opcode < X86_FEATURE_APX_CMOVCC_BASE + ARR_SIZE(cmov_ids)) {
		insn->id = cmov_ids[opcode - X86_FEATURE_APX_CMOVCC_BASE];
		if (insn->detail) {
			insn->detail->groups[0] = X86_GRP_CMOV;
			insn->detail->groups_count = 1;
		}
		return true;
	}
	if (opcode >= X86_FEATURE_APX_CFCMOVCC_BASE &&
	    opcode < X86_FEATURE_APX_CFCMOVCC_BASE + ARR_SIZE(cfcmov_ids)) {
		insn->id = cfcmov_ids[opcode - X86_FEATURE_APX_CFCMOVCC_BASE];
		if (insn->detail) {
			insn->detail->groups[0] = X86_GRP_CMOV;
			insn->detail->groups_count = 1;
		}
		return true;
	}
	if (opcode >= X86_FEATURE_APX_CMPCCXADD_BASE &&
	    opcode < X86_FEATURE_APX_CMPCCXADD_BASE + 16) {
		insn->id = X86_INS_CMPOXADD +
			   (opcode - X86_FEATURE_APX_CMPCCXADD_BASE);
		return true;
	}
	if (opcode >= X86_FEATURE_APX_CCMP_BASE &&
	    opcode < X86_FEATURE_APX_CCMP_BASE + 16) {
		insn->id = X86_INS_CCMPO + (opcode - X86_FEATURE_APX_CCMP_BASE);
		return true;
	}
	if (opcode >= X86_FEATURE_APX_CTEST_BASE &&
	    opcode < X86_FEATURE_APX_CTEST_BASE + 16) {
		insn->id = X86_INS_CTESTO + (opcode - X86_FEATURE_APX_CTEST_BASE);
		return true;
	}
	if (opcode >= X86_FEATURE_APX_KMOV_BASE &&
	    opcode < X86_FEATURE_APX_KMOV_BASE + 4) {
		static const x86_insn ids[] = { X86_INS_KMOVB, X86_INS_KMOVD,
			X86_INS_KMOVQ, X86_INS_KMOVW };
		insn->id = ids[opcode - X86_FEATURE_APX_KMOV_BASE];
		return true;
	}
	if (opcode >= X86_FEATURE_APX_INV_BASE &&
	    opcode < X86_FEATURE_APX_INV_BASE + 3) {
		static const x86_insn ids[] = { X86_INS_INVEPT, X86_INS_INVVPID,
			X86_INS_INVPCID };
		insn->id = ids[opcode - X86_FEATURE_APX_INV_BASE];
		if (insn->detail) {
			insn->detail->groups[0] = X86_GRP_PRIVILEGE;
			insn->detail->groups_count = 1;
		}
		return true;
	}
	if (opcode >= X86_FEATURE_APX_VPBROADCAST_BASE &&
	    opcode < X86_FEATURE_APX_VPBROADCAST_BASE +
			     X86_FEATURE_APX_VPBROADCAST_COUNT) {
		static const x86_insn ids[] = {
			X86_INS_VPBROADCASTB, X86_INS_VPBROADCASTW,
			X86_INS_VPBROADCASTD, X86_INS_VPBROADCASTQ
		};

		insn->id = ids[opcode - X86_FEATURE_APX_VPBROADCAST_BASE];
		return true;
	}

	if (opcode >= X86_FEATURE_APX_SETCC_BASE &&
	    opcode < X86_FEATURE_APX_SETCC_BASE + ARR_SIZE(setcc_ids)) {
		insn->id = setcc_ids[opcode - X86_FEATURE_APX_SETCC_BASE];
		return true;
	}
	if (opcode >= X86_FEATURE_APX_SETZUCC_BASE &&
	    opcode < X86_FEATURE_APX_SETZUCC_BASE + ARR_SIZE(setzu_ids)) {
		insn->id = setzu_ids[opcode - X86_FEATURE_APX_SETZUCC_BASE];
		return true;
	}
	switch (opcode) {
	default:
		return false;
	case X86_FEATURE_LDTILECFG:
		insn->id = X86_INS_LDTILECFG;
		return true;
	case X86_FEATURE_STTILECFG:
		insn->id = X86_INS_STTILECFG;
		return true;
	case X86_FEATURE_TILELOADD:
		insn->id = X86_INS_TILELOADD;
		return true;
	case X86_FEATURE_TILELOADDT1:
		insn->id = X86_INS_TILELOADDT1;
		return true;
	case X86_FEATURE_TILELOADDRS:
		insn->id = X86_INS_TILELOADDRS;
		return true;
	case X86_FEATURE_TILELOADDRST1:
		insn->id = X86_INS_TILELOADDRST1;
		return true;
	case X86_FEATURE_TILEMOVROW:
		insn->id = X86_INS_TILEMOVROW;
		return true;
	case X86_FEATURE_TCVTROWD2PS:
		insn->id = X86_INS_TCVTROWD2PS;
		return true;
	case X86_FEATURE_TCVTROWPS2BF16H:
		insn->id = X86_INS_TCVTROWPS2BF16H;
		return true;
	case X86_FEATURE_TCVTROWPS2BF16L:
		insn->id = X86_INS_TCVTROWPS2BF16L;
		return true;
	case X86_FEATURE_TCVTROWPS2PHH:
		insn->id = X86_INS_TCVTROWPS2PHH;
		return true;
	case X86_FEATURE_TCVTROWPS2PHL:
		insn->id = X86_INS_TCVTROWPS2PHL;
		return true;
	case X86_FEATURE_TILERELEASE:
		insn->id = X86_INS_TILERELEASE;
		return true;
	case X86_FEATURE_TILESTORED:
		insn->id = X86_INS_TILESTORED;
		return true;
	case X86_FEATURE_TILEZERO:
		insn->id = X86_INS_TILEZERO;
		return true;
	case X86_FEATURE_TDPBSSD:
		insn->id = X86_INS_TDPBSSD;
		return true;
	case X86_FEATURE_TDPBSUD:
		insn->id = X86_INS_TDPBSUD;
		return true;
	case X86_FEATURE_TDPBUSD:
		insn->id = X86_INS_TDPBUSD;
		return true;
	case X86_FEATURE_TDPBUUD:
		insn->id = X86_INS_TDPBUUD;
		return true;
	case X86_FEATURE_TDPBF16PS:
		insn->id = X86_INS_TDPBF16PS;
		return true;
	case X86_FEATURE_TDPFP16PS:
		insn->id = X86_INS_TDPFP16PS;
		return true;
	case X86_FEATURE_TCMMIMFP16PS:
		insn->id = X86_INS_TCMMIMFP16PS;
		return true;
	case X86_FEATURE_TCMMRLFP16PS:
		insn->id = X86_INS_TCMMRLFP16PS;
		return true;
	case X86_FEATURE_TDPBF8PS:
		insn->id = X86_INS_TDPBF8PS;
		return true;
	case X86_FEATURE_TDPBHF8PS:
		insn->id = X86_INS_TDPBHF8PS;
		return true;
	case X86_FEATURE_TDPHBF8PS:
		insn->id = X86_INS_TDPHBF8PS;
		return true;
	case X86_FEATURE_TDPHF8PS:
		insn->id = X86_INS_TDPHF8PS;
		return true;
	case X86_FEATURE_TMMULTF32PS:
		insn->id = X86_INS_TMMULTF32PS;
		return true;
	case X86_FEATURE_APX_ROL:
		insn->id = X86_INS_ROL;
		return true;
	case X86_FEATURE_APX_ROR:
		insn->id = X86_INS_ROR;
		return true;
	case X86_FEATURE_APX_RCL:
		insn->id = X86_INS_RCL;
		return true;
	case X86_FEATURE_APX_RCR:
		insn->id = X86_INS_RCR;
		return true;
	case X86_FEATURE_APX_SHL:
		insn->id = X86_INS_SHL;
		return true;
	case X86_FEATURE_APX_SHR:
		insn->id = X86_INS_SHR;
		return true;
	case X86_FEATURE_APX_SAR:
		insn->id = X86_INS_SAR;
		return true;
	case X86_FEATURE_APX_IMUL:
	case X86_FEATURE_APX_IMUL_IMMEDIATE:
	case X86_FEATURE_APX_IMUL_ONE:
		insn->id = X86_INS_IMUL;
		return true;
	case X86_FEATURE_APX_ADC:
		insn->id = X86_INS_ADC;
		return true;
	case X86_FEATURE_APX_SBB:
		insn->id = X86_INS_SBB;
		return true;
	case X86_FEATURE_APX_ADCX:
		insn->id = X86_INS_ADCX;
		return true;
	case X86_FEATURE_APX_ADOX:
		insn->id = X86_INS_ADOX;
		return true;
	case X86_FEATURE_APX_INC:
		insn->id = X86_INS_INC;
		return true;
	case X86_FEATURE_APX_DEC:
		insn->id = X86_INS_DEC;
		return true;
	case X86_FEATURE_APX_NEG:
		insn->id = X86_INS_NEG;
		return true;
	case X86_FEATURE_APX_NOT:
		insn->id = X86_INS_NOT;
		return true;
	case X86_FEATURE_APX_MUL:
		insn->id = X86_INS_MUL;
		return true;
	case X86_FEATURE_APX_DIV:
		insn->id = X86_INS_DIV;
		return true;
	case X86_FEATURE_APX_IDIV:
		insn->id = X86_INS_IDIV;
		return true;
	case X86_FEATURE_APX_ANDN:
		insn->id = X86_INS_ANDN;
		return true;
	case X86_FEATURE_APX_BZHI:
		insn->id = X86_INS_BZHI;
		return true;
	case X86_FEATURE_APX_BLSR:
		insn->id = X86_INS_BLSR;
		return true;
	case X86_FEATURE_APX_BLSMSK:
		insn->id = X86_INS_BLSMSK;
		return true;
	case X86_FEATURE_APX_BLSI:
		insn->id = X86_INS_BLSI;
		return true;
	case X86_FEATURE_APX_BEXTR:
		insn->id = X86_INS_BEXTR;
		return true;
	case X86_FEATURE_APX_LZCNT:
		insn->id = X86_INS_LZCNT;
		return true;
	case X86_FEATURE_APX_TZCNT:
		insn->id = X86_INS_TZCNT;
		return true;
	case X86_FEATURE_APX_POPCNT:
		insn->id = X86_INS_POPCNT;
		return true;
	case X86_FEATURE_APX_SARX:
		insn->id = X86_INS_SARX;
		return true;
	case X86_FEATURE_APX_SHLX:
		insn->id = X86_INS_SHLX;
		return true;
	case X86_FEATURE_APX_SHRX:
		insn->id = X86_INS_SHRX;
		return true;
	case X86_FEATURE_APX_RORX:
		insn->id = X86_INS_RORX;
		return true;
	case X86_FEATURE_APX_MULX:
		insn->id = X86_INS_MULX;
		return true;
	case X86_FEATURE_APX_MOVBE:
		insn->id = X86_INS_MOVBE;
		return true;
	case X86_FEATURE_APX_CRC32:
		insn->id = X86_INS_CRC32;
		return true;
	case X86_FEATURE_APX_PDEP:
		insn->id = X86_INS_PDEP;
		return true;
	case X86_FEATURE_APX_PEXT:
		insn->id = X86_INS_PEXT;
		return true;
	case X86_FEATURE_APX_SHLD:
		insn->id = X86_INS_SHLD;
		return true;
	case X86_FEATURE_APX_SHRD:
		insn->id = X86_INS_SHRD;
		return true;
	case X86_FEATURE_APX_MOVDIRI:
		insn->id = X86_INS_MOVDIRI;
		return true;
	case X86_FEATURE_APX_WRSSD:
		insn->id = X86_INS_WRSSD;
		return true;
	case X86_FEATURE_APX_WRSSQ:
		insn->id = X86_INS_WRSSQ;
		return true;
	case X86_FEATURE_APX_WRUSSD:
		insn->id = X86_INS_WRUSSD;
		return true;
	case X86_FEATURE_APX_WRUSSQ:
		insn->id = X86_INS_WRUSSQ;
		return true;
	case X86_FEATURE_APX_ENQCMD:
		insn->id = X86_INS_ENQCMD;
		return true;
	case X86_FEATURE_APX_ENQCMDS:
		insn->id = X86_INS_ENQCMDS;
		return true;
	case X86_FEATURE_APX_MOVDIR64B:
		insn->id = X86_INS_MOVDIR64B;
		return true;
	case X86_FEATURE_APX_AADD:
		insn->id = X86_INS_AADD;
		return true;
	case X86_FEATURE_APX_AAND:
		insn->id = X86_INS_AAND;
		return true;
	case X86_FEATURE_APX_AOR:
		insn->id = X86_INS_AOR;
		return true;
	case X86_FEATURE_APX_AXOR:
		insn->id = X86_INS_AXOR;
		return true;
	case X86_FEATURE_APX_MOVRS:
		insn->id = X86_INS_MOVRS;
		return true;
	case X86_FEATURE_APX_RDMSR_IMM:
		insn->id = X86_INS_RDMSR;
		if (insn->detail) {
			insn->detail->groups[0] = X86_GRP_PRIVILEGE;
			insn->detail->groups_count = 1;
		}
		return true;
	case X86_FEATURE_APX_WRMSRNS_IMM:
		insn->id = X86_INS_WRMSRNS;
		if (insn->detail) {
			insn->detail->groups[0] = X86_GRP_PRIVILEGE;
			insn->detail->groups_count = 1;
		}
		return true;
	case X86_FEATURE_APX_URDMSR:
		insn->id = X86_INS_URDMSR;
		return true;
	case X86_FEATURE_APX_UWRMSR:
		insn->id = X86_INS_UWRMSR;
		return true;
	case X86_FEATURE_REX2_MOV:
		insn->id = X86_INS_MOV;
		return true;
	case X86_FEATURE_REX2_ADD:
		insn->id = X86_INS_ADD;
		return true;
	case X86_FEATURE_REX2_SUB:
		insn->id = X86_INS_SUB;
		return true;
	case X86_FEATURE_REX2_AND:
		insn->id = X86_INS_AND;
		return true;
	case X86_FEATURE_REX2_OR:
		insn->id = X86_INS_OR;
		return true;
	case X86_FEATURE_REX2_XOR:
		insn->id = X86_INS_XOR;
		return true;
	case X86_FEATURE_REX2_CMP:
		insn->id = X86_INS_CMP;
		return true;
	case X86_FEATURE_REX2_TEST:
		insn->id = X86_INS_TEST;
		return true;
	case X86_FEATURE_JMPABS:
		insn->id = X86_INS_JMPABS;
		if (insn->detail) {
			insn->detail->groups[0] = CS_GRP_JUMP;
			insn->detail->groups_count = 1;
		}
		return true;
	case X86_FEATURE_PUSH2:
		insn->id = X86_INS_PUSH2;
		return true;
	case X86_FEATURE_PUSH2P:
		insn->id = X86_INS_PUSH2P;
		return true;
	case X86_FEATURE_POP2:
		insn->id = X86_INS_POP2;
		return true;
	case X86_FEATURE_POP2P:
		insn->id = X86_INS_POP2P;
		return true;
	case X86_FEATURE_REX2_PUSH:
		insn->id = X86_INS_PUSH;
		return true;
	case X86_FEATURE_REX2_POP:
		insn->id = X86_INS_POP;
		return true;
	case X86_FEATURE_PUSHP:
		insn->id = X86_INS_PUSHP;
		return true;
	case X86_FEATURE_POPP:
		insn->id = X86_INS_POPP;
		return true;
	}
}

const char *X86_featureExtensionRegisterName(unsigned int reg)
{
	static const char *const rex2_names_64[] = {
		"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
		"r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
	};
	static const char *const rex2_names_8[] = {
		"r16b", "r17b", "r18b", "r19b", "r20b", "r21b", "r22b", "r23b",
		"r24b", "r25b", "r26b", "r27b", "r28b", "r29b", "r30b", "r31b",
	};
	static const char *const rex2_names_32[] = {
		"r16d", "r17d", "r18d", "r19d", "r20d", "r21d", "r22d", "r23d",
		"r24d", "r25d", "r26d", "r27d", "r28d", "r29d", "r30d", "r31d",
	};
	static const char *const rex2_names_16[] = {
		"r16w", "r17w", "r18w", "r19w", "r20w", "r21w", "r22w", "r23w",
		"r24w", "r25w", "r26w", "r27w", "r28w", "r29w", "r30w", "r31w",
	};
	static const char *const tmm_names[] = {
		"tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7",
	};

	if (reg >= X86_REG_R16 && reg <= X86_REG_R31)
		return rex2_names_64[reg - X86_REG_R16];
	if (reg >= X86_REG_R16B && reg <= X86_REG_R31B)
		return rex2_names_8[reg - X86_REG_R16B];
	if (reg >= X86_REG_R16D && reg <= X86_REG_R31D)
		return rex2_names_32[reg - X86_REG_R16D];
	if (reg >= X86_REG_R16W && reg <= X86_REG_R31W)
		return rex2_names_16[reg - X86_REG_R16W];
	if (reg >= X86_REG_TMM0 && reg <= X86_REG_TMM7)
		return tmm_names[reg - X86_REG_TMM0];
	return NULL;
}

unsigned int X86_featureExtensionMCGPR(unsigned int number, uint8_t width)
{
	unsigned int bank;

	if (number < 16 || number > 31)
		return 0;
	switch (width) {
	default:
		return 0;
	case 1:
		bank = 0;
		break;
	case 2:
		bank = 1;
		break;
	case 4:
		bank = 2;
		break;
	case 8:
		bank = 3;
		break;
	}
	return X86_FEATURE_MC_GPR_BASE +
	       bank * X86_FEATURE_MC_GPR_BANK_SIZE + number - 16;
}

unsigned int X86_featureExtensionMCRegisterMap(unsigned int reg)
{
	unsigned int offset, bank, index;

	if (reg < X86_FEATURE_MC_GPR_BASE ||
	    reg >= X86_FEATURE_MC_GPR_BASE +
			   X86_FEATURE_MC_GPR_BANK_SIZE *
				   X86_FEATURE_MC_GPR_BANK_COUNT)
		return X86_REG_INVALID;
	offset = reg - X86_FEATURE_MC_GPR_BASE;
	bank = offset / X86_FEATURE_MC_GPR_BANK_SIZE;
	index = offset % X86_FEATURE_MC_GPR_BANK_SIZE;
	switch (bank) {
	default:
		return X86_REG_INVALID;
	case 0:
		return X86_REG_R16B + index;
	case 1:
		return X86_REG_R16W + index;
	case 2:
		return X86_REG_R16D + index;
	case 3:
		return X86_REG_R16 + index;
	}
}

const char *X86_featureExtensionMCRegisterName(unsigned int reg)
{
	return X86_featureExtensionRegisterName(
		X86_featureExtensionMCRegisterMap(reg));
}

const char *X86_featureExtensionInstructionName(unsigned int id)
{
	static const char *const cfcmov_names[] = {
		"cfcmovo", "cfcmovno", "cfcmovb",  "cfcmovae",
		"cfcmove", "cfcmovne", "cfcmovbe", "cfcmova",
		"cfcmovs", "cfcmovns", "cfcmovp",  "cfcmovnp",
		"cfcmovl", "cfcmovge", "cfcmovle", "cfcmovg",
	};
	static const char *const setzu_names[] = {
		"setzuo",  "setzuno", "setzub",	 "setzuae", "setzue", "setzune",
		"setzube", "setzua",  "setzus",	 "setzuns", "setzup", "setzunp",
		"setzul",  "setzuge", "setzule", "setzug",
	};
	static const char *const cmpccxadd_names[] = {
		"cmpoxadd", "cmpnoxadd", "cmpbxadd", "cmpnbxadd",
		"cmpzxadd", "cmpnzxadd", "cmpbexadd", "cmpnbexadd",
		"cmpsxadd", "cmpnsxadd", "cmppxadd", "cmpnpxadd",
		"cmplxadd", "cmpnlxadd", "cmplexadd", "cmpnlexadd",
	};
	static const char *const ccmp_names[] = {
		"ccmpo", "ccmpno", "ccmpb", "ccmpnb", "ccmpz", "ccmpnz",
		"ccmpbe", "ccmpnbe", "ccmps", "ccmpns", "ccmpt", "ccmpf",
		"ccmpl", "ccmpnl", "ccmple", "ccmpnle",
	};
	static const char *const ctest_names[] = {
		"ctesto", "ctestno", "ctestb", "ctestnb", "ctestz", "ctestnz",
		"ctestbe", "ctestnbe", "ctests", "ctestns", "ctestt", "ctestf",
		"ctestl", "ctestnl", "ctestle", "ctestnle",
	};

	if (id >= X86_INS_CFCMOVO && id <= X86_INS_CFCMOVG)
		return cfcmov_names[id - X86_INS_CFCMOVO];
	if (id >= X86_INS_SETZUO && id <= X86_INS_SETZUG)
		return setzu_names[id - X86_INS_SETZUO];
	if (id >= X86_INS_CMPOXADD && id <= X86_INS_CMPNLEXADD)
		return cmpccxadd_names[id - X86_INS_CMPOXADD];
	if (id >= X86_INS_CCMPO && id <= X86_INS_CCMPNLE)
		return ccmp_names[id - X86_INS_CCMPO];
	if (id >= X86_INS_CTESTO && id <= X86_INS_CTESTNLE)
		return ctest_names[id - X86_INS_CTESTO];
	switch (id) {
	default:
		return NULL;
	case X86_INS_ENQCMD:
		return "enqcmd";
	case X86_INS_ENQCMDS:
		return "enqcmds";
	case X86_INS_AADD:
		return "aadd";
	case X86_INS_AAND:
		return "aand";
	case X86_INS_AOR:
		return "aor";
	case X86_INS_AXOR:
		return "axor";
	case X86_INS_MOVRS:
		return "movrs";
	case X86_INS_URDMSR:
		return "urdmsr";
	case X86_INS_UWRMSR:
		return "uwrmsr";
	case X86_INS_WRMSRNS:
		return "wrmsrns";
	case X86_INS_LDTILECFG:
		return "ldtilecfg";
	case X86_INS_STTILECFG:
		return "sttilecfg";
	case X86_INS_TILELOADD:
		return "tileloadd";
	case X86_INS_TILELOADDT1:
		return "tileloaddt1";
	case X86_INS_TILELOADDRS:
		return "tileloaddrs";
	case X86_INS_TILELOADDRST1:
		return "tileloaddrst1";
	case X86_INS_TILEMOVROW:
		return "tilemovrow";
	case X86_INS_TCVTROWD2PS:
		return "tcvtrowd2ps";
	case X86_INS_TCVTROWPS2BF16H:
		return "tcvtrowps2bf16h";
	case X86_INS_TCVTROWPS2BF16L:
		return "tcvtrowps2bf16l";
	case X86_INS_TCVTROWPS2PHH:
		return "tcvtrowps2phh";
	case X86_INS_TCVTROWPS2PHL:
		return "tcvtrowps2phl";
	case X86_INS_TILERELEASE:
		return "tilerelease";
	case X86_INS_TILESTORED:
		return "tilestored";
	case X86_INS_TILEZERO:
		return "tilezero";
	case X86_INS_TDPBSSD:
		return "tdpbssd";
	case X86_INS_TDPBSUD:
		return "tdpbsud";
	case X86_INS_TDPBUSD:
		return "tdpbusd";
	case X86_INS_TDPBUUD:
		return "tdpbuud";
	case X86_INS_TDPBF16PS:
		return "tdpbf16ps";
	case X86_INS_TDPFP16PS:
		return "tdpfp16ps";
	case X86_INS_TCMMIMFP16PS:
		return "tcmmimfp16ps";
	case X86_INS_TCMMRLFP16PS:
		return "tcmmrlfp16ps";
	case X86_INS_TDPBF8PS:
		return "tdpbf8ps";
	case X86_INS_TDPBHF8PS:
		return "tdpbhf8ps";
	case X86_INS_TDPHBF8PS:
		return "tdphbf8ps";
	case X86_INS_TDPHF8PS:
		return "tdphf8ps";
	case X86_INS_TMMULTF32PS:
		return "tmmultf32ps";
	case X86_INS_JMPABS:
		return "jmpabs";
	case X86_INS_PUSH2:
		return "push2";
	case X86_INS_PUSH2P:
		return "push2p";
	case X86_INS_POP2:
		return "pop2";
	case X86_INS_POP2P:
		return "pop2p";
	case X86_INS_PUSHP:
		return "pushp";
	case X86_INS_POPP:
		return "popp";
	}
}

static const x86_reg sib_base_map[] = { X86_REG_INVALID,
#define ENTRY(x) X86_REG_##x,
					ALL_SIB_BASES
#undef ENTRY
};

// Fill-ins to make the compiler happy.  These constants are never actually
// assigned; they are just filler to make an automatically-generated switch
// statement work.
enum {
	X86_REG_BX_SI = 500,
	X86_REG_BX_DI = 501,
	X86_REG_BP_SI = 502,
	X86_REG_BP_DI = 503,
	X86_REG_sib = 504,
	X86_REG_sib64 = 505
};

static const x86_reg sib_index_map[] = { X86_REG_INVALID,
#define ENTRY(x) X86_REG_##x,
					 ALL_EA_BASES REGS_XMM REGS_YMM REGS_ZMM
#undef ENTRY
};

static const x86_reg segment_map[] = {
	X86_REG_INVALID, X86_REG_CS, X86_REG_SS, X86_REG_DS,
	X86_REG_ES,	 X86_REG_FS, X86_REG_GS,
};

x86_reg x86_map_sib_base(int r)
{
	return sib_base_map[r];
}

x86_reg x86_map_sib_index(int r)
{
	return sib_index_map[r];
}

x86_reg x86_map_segment(int r)
{
	return segment_map[r];
}

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{ X86_REG_INVALID, NULL },

	{ X86_REG_AH, "ah" },	     { X86_REG_AL, "al" },
	{ X86_REG_AX, "ax" },	     { X86_REG_BH, "bh" },
	{ X86_REG_BL, "bl" },	     { X86_REG_BP, "bp" },
	{ X86_REG_BPL, "bpl" },	     { X86_REG_BX, "bx" },
	{ X86_REG_CH, "ch" },	     { X86_REG_CL, "cl" },
	{ X86_REG_CS, "cs" },	     { X86_REG_CX, "cx" },
	{ X86_REG_DH, "dh" },	     { X86_REG_DI, "di" },
	{ X86_REG_DIL, "dil" },	     { X86_REG_DL, "dl" },
	{ X86_REG_DS, "ds" },	     { X86_REG_DX, "dx" },
	{ X86_REG_EAX, "eax" },	     { X86_REG_EBP, "ebp" },
	{ X86_REG_EBX, "ebx" },	     { X86_REG_ECX, "ecx" },
	{ X86_REG_EDI, "edi" },	     { X86_REG_EDX, "edx" },
	{ X86_REG_EFLAGS, "flags" }, { X86_REG_EIP, "eip" },
	{ X86_REG_EIZ, "eiz" },	     { X86_REG_ES, "es" },
	{ X86_REG_ESI, "esi" },	     { X86_REG_ESP, "esp" },
	{ X86_REG_FPSW, "fpsw" },    { X86_REG_FS, "fs" },
	{ X86_REG_GS, "gs" },	     { X86_REG_IP, "ip" },
	{ X86_REG_RAX, "rax" },	     { X86_REG_RBP, "rbp" },
	{ X86_REG_RBX, "rbx" },	     { X86_REG_RCX, "rcx" },
	{ X86_REG_RDI, "rdi" },	     { X86_REG_RDX, "rdx" },
	{ X86_REG_RIP, "rip" },	     { X86_REG_RIZ, "riz" },
	{ X86_REG_RSI, "rsi" },	     { X86_REG_RSP, "rsp" },
	{ X86_REG_SI, "si" },	     { X86_REG_SIL, "sil" },
	{ X86_REG_SP, "sp" },	     { X86_REG_SPL, "spl" },
	{ X86_REG_SS, "ss" },	     { X86_REG_CR0, "cr0" },
	{ X86_REG_CR1, "cr1" },	     { X86_REG_CR2, "cr2" },
	{ X86_REG_CR3, "cr3" },	     { X86_REG_CR4, "cr4" },
	{ X86_REG_CR5, "cr5" },	     { X86_REG_CR6, "cr6" },
	{ X86_REG_CR7, "cr7" },	     { X86_REG_CR8, "cr8" },
	{ X86_REG_CR9, "cr9" },	     { X86_REG_CR10, "cr10" },
	{ X86_REG_CR11, "cr11" },    { X86_REG_CR12, "cr12" },
	{ X86_REG_CR13, "cr13" },    { X86_REG_CR14, "cr14" },
	{ X86_REG_CR15, "cr15" },    { X86_REG_DR0, "dr0" },
	{ X86_REG_DR1, "dr1" },	     { X86_REG_DR2, "dr2" },
	{ X86_REG_DR3, "dr3" },	     { X86_REG_DR4, "dr4" },
	{ X86_REG_DR5, "dr5" },	     { X86_REG_DR6, "dr6" },
	{ X86_REG_DR7, "dr7" },	     { X86_REG_DR8, "dr8" },
	{ X86_REG_DR9, "dr9" },	     { X86_REG_DR10, "dr10" },
	{ X86_REG_DR11, "dr11" },    { X86_REG_DR12, "dr12" },
	{ X86_REG_DR13, "dr13" },    { X86_REG_DR14, "dr14" },
	{ X86_REG_DR15, "dr15" },    { X86_REG_FP0, "fp0" },
	{ X86_REG_FP1, "fp1" },	     { X86_REG_FP2, "fp2" },
	{ X86_REG_FP3, "fp3" },	     { X86_REG_FP4, "fp4" },
	{ X86_REG_FP5, "fp5" },	     { X86_REG_FP6, "fp6" },
	{ X86_REG_FP7, "fp7" },	     { X86_REG_K0, "k0" },
	{ X86_REG_K1, "k1" },	     { X86_REG_K2, "k2" },
	{ X86_REG_K3, "k3" },	     { X86_REG_K4, "k4" },
	{ X86_REG_K5, "k5" },	     { X86_REG_K6, "k6" },
	{ X86_REG_K7, "k7" },	     { X86_REG_MM0, "mm0" },
	{ X86_REG_MM1, "mm1" },	     { X86_REG_MM2, "mm2" },
	{ X86_REG_MM3, "mm3" },	     { X86_REG_MM4, "mm4" },
	{ X86_REG_MM5, "mm5" },	     { X86_REG_MM6, "mm6" },
	{ X86_REG_MM7, "mm7" },	     { X86_REG_R8, "r8" },
	{ X86_REG_R9, "r9" },	     { X86_REG_R10, "r10" },
	{ X86_REG_R11, "r11" },	     { X86_REG_R12, "r12" },
	{ X86_REG_R13, "r13" },	     { X86_REG_R14, "r14" },
	{ X86_REG_R15, "r15" },	     { X86_REG_ST0, "st(0)" },
	{ X86_REG_ST1, "st(1)" },    { X86_REG_ST2, "st(2)" },
	{ X86_REG_ST3, "st(3)" },    { X86_REG_ST4, "st(4)" },
	{ X86_REG_ST5, "st(5)" },    { X86_REG_ST6, "st(6)" },
	{ X86_REG_ST7, "st(7)" },    { X86_REG_XMM0, "xmm0" },
	{ X86_REG_XMM1, "xmm1" },    { X86_REG_XMM2, "xmm2" },
	{ X86_REG_XMM3, "xmm3" },    { X86_REG_XMM4, "xmm4" },
	{ X86_REG_XMM5, "xmm5" },    { X86_REG_XMM6, "xmm6" },
	{ X86_REG_XMM7, "xmm7" },    { X86_REG_XMM8, "xmm8" },
	{ X86_REG_XMM9, "xmm9" },    { X86_REG_XMM10, "xmm10" },
	{ X86_REG_XMM11, "xmm11" },  { X86_REG_XMM12, "xmm12" },
	{ X86_REG_XMM13, "xmm13" },  { X86_REG_XMM14, "xmm14" },
	{ X86_REG_XMM15, "xmm15" },  { X86_REG_XMM16, "xmm16" },
	{ X86_REG_XMM17, "xmm17" },  { X86_REG_XMM18, "xmm18" },
	{ X86_REG_XMM19, "xmm19" },  { X86_REG_XMM20, "xmm20" },
	{ X86_REG_XMM21, "xmm21" },  { X86_REG_XMM22, "xmm22" },
	{ X86_REG_XMM23, "xmm23" },  { X86_REG_XMM24, "xmm24" },
	{ X86_REG_XMM25, "xmm25" },  { X86_REG_XMM26, "xmm26" },
	{ X86_REG_XMM27, "xmm27" },  { X86_REG_XMM28, "xmm28" },
	{ X86_REG_XMM29, "xmm29" },  { X86_REG_XMM30, "xmm30" },
	{ X86_REG_XMM31, "xmm31" },  { X86_REG_YMM0, "ymm0" },
	{ X86_REG_YMM1, "ymm1" },    { X86_REG_YMM2, "ymm2" },
	{ X86_REG_YMM3, "ymm3" },    { X86_REG_YMM4, "ymm4" },
	{ X86_REG_YMM5, "ymm5" },    { X86_REG_YMM6, "ymm6" },
	{ X86_REG_YMM7, "ymm7" },    { X86_REG_YMM8, "ymm8" },
	{ X86_REG_YMM9, "ymm9" },    { X86_REG_YMM10, "ymm10" },
	{ X86_REG_YMM11, "ymm11" },  { X86_REG_YMM12, "ymm12" },
	{ X86_REG_YMM13, "ymm13" },  { X86_REG_YMM14, "ymm14" },
	{ X86_REG_YMM15, "ymm15" },  { X86_REG_YMM16, "ymm16" },
	{ X86_REG_YMM17, "ymm17" },  { X86_REG_YMM18, "ymm18" },
	{ X86_REG_YMM19, "ymm19" },  { X86_REG_YMM20, "ymm20" },
	{ X86_REG_YMM21, "ymm21" },  { X86_REG_YMM22, "ymm22" },
	{ X86_REG_YMM23, "ymm23" },  { X86_REG_YMM24, "ymm24" },
	{ X86_REG_YMM25, "ymm25" },  { X86_REG_YMM26, "ymm26" },
	{ X86_REG_YMM27, "ymm27" },  { X86_REG_YMM28, "ymm28" },
	{ X86_REG_YMM29, "ymm29" },  { X86_REG_YMM30, "ymm30" },
	{ X86_REG_YMM31, "ymm31" },  { X86_REG_ZMM0, "zmm0" },
	{ X86_REG_ZMM1, "zmm1" },    { X86_REG_ZMM2, "zmm2" },
	{ X86_REG_ZMM3, "zmm3" },    { X86_REG_ZMM4, "zmm4" },
	{ X86_REG_ZMM5, "zmm5" },    { X86_REG_ZMM6, "zmm6" },
	{ X86_REG_ZMM7, "zmm7" },    { X86_REG_ZMM8, "zmm8" },
	{ X86_REG_ZMM9, "zmm9" },    { X86_REG_ZMM10, "zmm10" },
	{ X86_REG_ZMM11, "zmm11" },  { X86_REG_ZMM12, "zmm12" },
	{ X86_REG_ZMM13, "zmm13" },  { X86_REG_ZMM14, "zmm14" },
	{ X86_REG_ZMM15, "zmm15" },  { X86_REG_ZMM16, "zmm16" },
	{ X86_REG_ZMM17, "zmm17" },  { X86_REG_ZMM18, "zmm18" },
	{ X86_REG_ZMM19, "zmm19" },  { X86_REG_ZMM20, "zmm20" },
	{ X86_REG_ZMM21, "zmm21" },  { X86_REG_ZMM22, "zmm22" },
	{ X86_REG_ZMM23, "zmm23" },  { X86_REG_ZMM24, "zmm24" },
	{ X86_REG_ZMM25, "zmm25" },  { X86_REG_ZMM26, "zmm26" },
	{ X86_REG_ZMM27, "zmm27" },  { X86_REG_ZMM28, "zmm28" },
	{ X86_REG_ZMM29, "zmm29" },  { X86_REG_ZMM30, "zmm30" },
	{ X86_REG_ZMM31, "zmm31" },  { X86_REG_R8B, "r8b" },
	{ X86_REG_R9B, "r9b" },	     { X86_REG_R10B, "r10b" },
	{ X86_REG_R11B, "r11b" },    { X86_REG_R12B, "r12b" },
	{ X86_REG_R13B, "r13b" },    { X86_REG_R14B, "r14b" },
	{ X86_REG_R15B, "r15b" },    { X86_REG_R8D, "r8d" },
	{ X86_REG_R9D, "r9d" },	     { X86_REG_R10D, "r10d" },
	{ X86_REG_R11D, "r11d" },    { X86_REG_R12D, "r12d" },
	{ X86_REG_R13D, "r13d" },    { X86_REG_R14D, "r14d" },
	{ X86_REG_R15D, "r15d" },    { X86_REG_R8W, "r8w" },
	{ X86_REG_R9W, "r9w" },	     { X86_REG_R10W, "r10w" },
	{ X86_REG_R11W, "r11w" },    { X86_REG_R12W, "r12w" },
	{ X86_REG_R13W, "r13w" },    { X86_REG_R14W, "r14w" },
	{ X86_REG_R15W, "r15w" },

	{ X86_REG_BND0, "bnd0" },    { X86_REG_BND1, "bnd1" },
	{ X86_REG_BND2, "bnd2" },    { X86_REG_BND3, "bnd3" },
};
#endif

#define X86_REPEAT_16(Value)                                                   \
	Value, Value, Value, Value, Value, Value, Value, Value, Value, Value,    \
		Value, Value, Value, Value, Value, Value
#define X86_REPEAT_8(Value) Value, Value, Value, Value, Value, Value, Value, Value

// register size in non-64bit mode
const uint8_t regsize_map_32[] = {
	0, // 	{ X86_REG_INVALID, NULL },
	1, // { X86_REG_AH, "ah" },
	1, // { X86_REG_AL, "al" },
	2, // { X86_REG_AX, "ax" },
	1, // { X86_REG_BH, "bh" },
	1, // { X86_REG_BL, "bl" },
	2, // { X86_REG_BP, "bp" },
	1, // { X86_REG_BPL, "bpl" },
	2, // { X86_REG_BX, "bx" },
	1, // { X86_REG_CH, "ch" },
	1, // { X86_REG_CL, "cl" },
	2, // { X86_REG_CS, "cs" },
	2, // { X86_REG_CX, "cx" },
	1, // { X86_REG_DH, "dh" },
	2, // { X86_REG_DI, "di" },
	1, // { X86_REG_DIL, "dil" },
	1, // { X86_REG_DL, "dl" },
	2, // { X86_REG_DS, "ds" },
	2, // { X86_REG_DX, "dx" },
	4, // { X86_REG_EAX, "eax" },
	4, // { X86_REG_EBP, "ebp" },
	4, // { X86_REG_EBX, "ebx" },
	4, // { X86_REG_ECX, "ecx" },
	4, // { X86_REG_EDI, "edi" },
	4, // { X86_REG_EDX, "edx" },
	4, // { X86_REG_EFLAGS, "flags" },
	4, // { X86_REG_EIP, "eip" },
	4, // { X86_REG_EIZ, "eiz" },
	2, // { X86_REG_ES, "es" },
	4, // { X86_REG_ESI, "esi" },
	4, // { X86_REG_ESP, "esp" },
	10, // { X86_REG_FPSW, "fpsw" },
	2, // { X86_REG_FS, "fs" },
	2, // { X86_REG_GS, "gs" },
	2, // { X86_REG_IP, "ip" },
	8, // { X86_REG_RAX, "rax" },
	8, // { X86_REG_RBP, "rbp" },
	8, // { X86_REG_RBX, "rbx" },
	8, // { X86_REG_RCX, "rcx" },
	8, // { X86_REG_RDI, "rdi" },
	8, // { X86_REG_RDX, "rdx" },
	8, // { X86_REG_RIP, "rip" },
	8, // { X86_REG_RIZ, "riz" },
	8, // { X86_REG_RSI, "rsi" },
	8, // { X86_REG_RSP, "rsp" },
	2, // { X86_REG_SI, "si" },
	1, // { X86_REG_SIL, "sil" },
	2, // { X86_REG_SP, "sp" },
	1, // { X86_REG_SPL, "spl" },
	2, // { X86_REG_SS, "ss" },
	4, // { X86_REG_CR0, "cr0" },
	4, // { X86_REG_CR1, "cr1" },
	4, // { X86_REG_CR2, "cr2" },
	4, // { X86_REG_CR3, "cr3" },
	4, // { X86_REG_CR4, "cr4" },
	8, // { X86_REG_CR5, "cr5" },
	8, // { X86_REG_CR6, "cr6" },
	8, // { X86_REG_CR7, "cr7" },
	8, // { X86_REG_CR8, "cr8" },
	8, // { X86_REG_CR9, "cr9" },
	8, // { X86_REG_CR10, "cr10" },
	8, // { X86_REG_CR11, "cr11" },
	8, // { X86_REG_CR12, "cr12" },
	8, // { X86_REG_CR13, "cr13" },
	8, // { X86_REG_CR14, "cr14" },
	8, // { X86_REG_CR15, "cr15" },
	4, // { X86_REG_DR0, "dr0" },
	4, // { X86_REG_DR1, "dr1" },
	4, // { X86_REG_DR2, "dr2" },
	4, // { X86_REG_DR3, "dr3" },
	4, // { X86_REG_DR4, "dr4" },
	4, // { X86_REG_DR5, "dr5" },
	4, // { X86_REG_DR6, "dr6" },
	4, // { X86_REG_DR7, "dr7" },
	4, // { X86_REG_DR8, "dr8" },
	4, // { X86_REG_DR9, "dr9" },
	4, // { X86_REG_DR10, "dr10" },
	4, // { X86_REG_DR11, "dr11" },
	4, // { X86_REG_DR12, "dr12" },
	4, // { X86_REG_DR13, "dr13" },
	4, // { X86_REG_DR14, "dr14" },
	4, // { X86_REG_DR15, "dr15" },
	10, // { X86_REG_FP0, "fp0" },
	10, // { X86_REG_FP1, "fp1" },
	10, // { X86_REG_FP2, "fp2" },
	10, // { X86_REG_FP3, "fp3" },
	10, // { X86_REG_FP4, "fp4" },
	10, // { X86_REG_FP5, "fp5" },
	10, // { X86_REG_FP6, "fp6" },
	10, // { X86_REG_FP7, "fp7" },
	2, // { X86_REG_K0, "k0" },
	2, // { X86_REG_K1, "k1" },
	2, // { X86_REG_K2, "k2" },
	2, // { X86_REG_K3, "k3" },
	2, // { X86_REG_K4, "k4" },
	2, // { X86_REG_K5, "k5" },
	2, // { X86_REG_K6, "k6" },
	2, // { X86_REG_K7, "k7" },
	8, // { X86_REG_MM0, "mm0" },
	8, // { X86_REG_MM1, "mm1" },
	8, // { X86_REG_MM2, "mm2" },
	8, // { X86_REG_MM3, "mm3" },
	8, // { X86_REG_MM4, "mm4" },
	8, // { X86_REG_MM5, "mm5" },
	8, // { X86_REG_MM6, "mm6" },
	8, // { X86_REG_MM7, "mm7" },
	8, // { X86_REG_R8, "r8" },
	8, // { X86_REG_R9, "r9" },
	8, // { X86_REG_R10, "r10" },
	8, // { X86_REG_R11, "r11" },
	8, // { X86_REG_R12, "r12" },
	8, // { X86_REG_R13, "r13" },
	8, // { X86_REG_R14, "r14" },
	8, // { X86_REG_R15, "r15" },
	10, // { X86_REG_ST0, "st0" },
	10, // { X86_REG_ST1, "st1" },
	10, // { X86_REG_ST2, "st2" },
	10, // { X86_REG_ST3, "st3" },
	10, // { X86_REG_ST4, "st4" },
	10, // { X86_REG_ST5, "st5" },
	10, // { X86_REG_ST6, "st6" },
	10, // { X86_REG_ST7, "st7" },
	16, // { X86_REG_XMM0, "xmm0" },
	16, // { X86_REG_XMM1, "xmm1" },
	16, // { X86_REG_XMM2, "xmm2" },
	16, // { X86_REG_XMM3, "xmm3" },
	16, // { X86_REG_XMM4, "xmm4" },
	16, // { X86_REG_XMM5, "xmm5" },
	16, // { X86_REG_XMM6, "xmm6" },
	16, // { X86_REG_XMM7, "xmm7" },
	16, // { X86_REG_XMM8, "xmm8" },
	16, // { X86_REG_XMM9, "xmm9" },
	16, // { X86_REG_XMM10, "xmm10" },
	16, // { X86_REG_XMM11, "xmm11" },
	16, // { X86_REG_XMM12, "xmm12" },
	16, // { X86_REG_XMM13, "xmm13" },
	16, // { X86_REG_XMM14, "xmm14" },
	16, // { X86_REG_XMM15, "xmm15" },
	16, // { X86_REG_XMM16, "xmm16" },
	16, // { X86_REG_XMM17, "xmm17" },
	16, // { X86_REG_XMM18, "xmm18" },
	16, // { X86_REG_XMM19, "xmm19" },
	16, // { X86_REG_XMM20, "xmm20" },
	16, // { X86_REG_XMM21, "xmm21" },
	16, // { X86_REG_XMM22, "xmm22" },
	16, // { X86_REG_XMM23, "xmm23" },
	16, // { X86_REG_XMM24, "xmm24" },
	16, // { X86_REG_XMM25, "xmm25" },
	16, // { X86_REG_XMM26, "xmm26" },
	16, // { X86_REG_XMM27, "xmm27" },
	16, // { X86_REG_XMM28, "xmm28" },
	16, // { X86_REG_XMM29, "xmm29" },
	16, // { X86_REG_XMM30, "xmm30" },
	16, // { X86_REG_XMM31, "xmm31" },
	32, // { X86_REG_YMM0, "ymm0" },
	32, // { X86_REG_YMM1, "ymm1" },
	32, // { X86_REG_YMM2, "ymm2" },
	32, // { X86_REG_YMM3, "ymm3" },
	32, // { X86_REG_YMM4, "ymm4" },
	32, // { X86_REG_YMM5, "ymm5" },
	32, // { X86_REG_YMM6, "ymm6" },
	32, // { X86_REG_YMM7, "ymm7" },
	32, // { X86_REG_YMM8, "ymm8" },
	32, // { X86_REG_YMM9, "ymm9" },
	32, // { X86_REG_YMM10, "ymm10" },
	32, // { X86_REG_YMM11, "ymm11" },
	32, // { X86_REG_YMM12, "ymm12" },
	32, // { X86_REG_YMM13, "ymm13" },
	32, // { X86_REG_YMM14, "ymm14" },
	32, // { X86_REG_YMM15, "ymm15" },
	32, // { X86_REG_YMM16, "ymm16" },
	32, // { X86_REG_YMM17, "ymm17" },
	32, // { X86_REG_YMM18, "ymm18" },
	32, // { X86_REG_YMM19, "ymm19" },
	32, // { X86_REG_YMM20, "ymm20" },
	32, // { X86_REG_YMM21, "ymm21" },
	32, // { X86_REG_YMM22, "ymm22" },
	32, // { X86_REG_YMM23, "ymm23" },
	32, // { X86_REG_YMM24, "ymm24" },
	32, // { X86_REG_YMM25, "ymm25" },
	32, // { X86_REG_YMM26, "ymm26" },
	32, // { X86_REG_YMM27, "ymm27" },
	32, // { X86_REG_YMM28, "ymm28" },
	32, // { X86_REG_YMM29, "ymm29" },
	32, // { X86_REG_YMM30, "ymm30" },
	32, // { X86_REG_YMM31, "ymm31" },
	64, // { X86_REG_ZMM0, "zmm0" },
	64, // { X86_REG_ZMM1, "zmm1" },
	64, // { X86_REG_ZMM2, "zmm2" },
	64, // { X86_REG_ZMM3, "zmm3" },
	64, // { X86_REG_ZMM4, "zmm4" },
	64, // { X86_REG_ZMM5, "zmm5" },
	64, // { X86_REG_ZMM6, "zmm6" },
	64, // { X86_REG_ZMM7, "zmm7" },
	64, // { X86_REG_ZMM8, "zmm8" },
	64, // { X86_REG_ZMM9, "zmm9" },
	64, // { X86_REG_ZMM10, "zmm10" },
	64, // { X86_REG_ZMM11, "zmm11" },
	64, // { X86_REG_ZMM12, "zmm12" },
	64, // { X86_REG_ZMM13, "zmm13" },
	64, // { X86_REG_ZMM14, "zmm14" },
	64, // { X86_REG_ZMM15, "zmm15" },
	64, // { X86_REG_ZMM16, "zmm16" },
	64, // { X86_REG_ZMM17, "zmm17" },
	64, // { X86_REG_ZMM18, "zmm18" },
	64, // { X86_REG_ZMM19, "zmm19" },
	64, // { X86_REG_ZMM20, "zmm20" },
	64, // { X86_REG_ZMM21, "zmm21" },
	64, // { X86_REG_ZMM22, "zmm22" },
	64, // { X86_REG_ZMM23, "zmm23" },
	64, // { X86_REG_ZMM24, "zmm24" },
	64, // { X86_REG_ZMM25, "zmm25" },
	64, // { X86_REG_ZMM26, "zmm26" },
	64, // { X86_REG_ZMM27, "zmm27" },
	64, // { X86_REG_ZMM28, "zmm28" },
	64, // { X86_REG_ZMM29, "zmm29" },
	64, // { X86_REG_ZMM30, "zmm30" },
	64, // { X86_REG_ZMM31, "zmm31" },
	1, // { X86_REG_R8B, "r8b" },
	1, // { X86_REG_R9B, "r9b" },
	1, // { X86_REG_R10B, "r10b" },
	1, // { X86_REG_R11B, "r11b" },
	1, // { X86_REG_R12B, "r12b" },
	1, // { X86_REG_R13B, "r13b" },
	1, // { X86_REG_R14B, "r14b" },
	1, // { X86_REG_R15B, "r15b" },
	4, // { X86_REG_R8D, "r8d" },
	4, // { X86_REG_R9D, "r9d" },
	4, // { X86_REG_R10D, "r10d" },
	4, // { X86_REG_R11D, "r11d" },
	4, // { X86_REG_R12D, "r12d" },
	4, // { X86_REG_R13D, "r13d" },
	4, // { X86_REG_R14D, "r14d" },
	4, // { X86_REG_R15D, "r15d" },
	2, // { X86_REG_R8W, "r8w" },
	2, // { X86_REG_R9W, "r9w" },
	2, // { X86_REG_R10W, "r10w" },
	2, // { X86_REG_R11W, "r11w" },
	2, // { X86_REG_R12W, "r12w" },
	2, // { X86_REG_R13W, "r13w" },
	2, // { X86_REG_R14W, "r14w" },
	2, // { X86_REG_R15W, "r15w" },
	16, // { X86_REG_BND0, "bnd0" },
	16, // { X86_REG_BND1, "bnd0" },
	16, // { X86_REG_BND2, "bnd0" },
	16, // { X86_REG_BND3, "bnd0" },
	X86_REPEAT_16(8), // X86_REG_R16...X86_REG_R31
	X86_REPEAT_16(1), // X86_REG_R16B...X86_REG_R31B
	X86_REPEAT_16(4), // X86_REG_R16D...X86_REG_R31D
	X86_REPEAT_16(2), // X86_REG_R16W...X86_REG_R31W
	X86_REPEAT_8(0), // Tile sizes are instruction-configured.
};

// register size in 64bit mode
const uint8_t regsize_map_64[] = {
	0, // 	{ X86_REG_INVALID, NULL },
	1, // { X86_REG_AH, "ah" },
	1, // { X86_REG_AL, "al" },
	2, // { X86_REG_AX, "ax" },
	1, // { X86_REG_BH, "bh" },
	1, // { X86_REG_BL, "bl" },
	2, // { X86_REG_BP, "bp" },
	1, // { X86_REG_BPL, "bpl" },
	2, // { X86_REG_BX, "bx" },
	1, // { X86_REG_CH, "ch" },
	1, // { X86_REG_CL, "cl" },
	2, // { X86_REG_CS, "cs" },
	2, // { X86_REG_CX, "cx" },
	1, // { X86_REG_DH, "dh" },
	2, // { X86_REG_DI, "di" },
	1, // { X86_REG_DIL, "dil" },
	1, // { X86_REG_DL, "dl" },
	2, // { X86_REG_DS, "ds" },
	2, // { X86_REG_DX, "dx" },
	4, // { X86_REG_EAX, "eax" },
	4, // { X86_REG_EBP, "ebp" },
	4, // { X86_REG_EBX, "ebx" },
	4, // { X86_REG_ECX, "ecx" },
	4, // { X86_REG_EDI, "edi" },
	4, // { X86_REG_EDX, "edx" },
	8, // { X86_REG_EFLAGS, "flags" },
	4, // { X86_REG_EIP, "eip" },
	4, // { X86_REG_EIZ, "eiz" },
	2, // { X86_REG_ES, "es" },
	4, // { X86_REG_ESI, "esi" },
	4, // { X86_REG_ESP, "esp" },
	10, // { X86_REG_FPSW, "fpsw" },
	2, // { X86_REG_FS, "fs" },
	2, // { X86_REG_GS, "gs" },
	2, // { X86_REG_IP, "ip" },
	8, // { X86_REG_RAX, "rax" },
	8, // { X86_REG_RBP, "rbp" },
	8, // { X86_REG_RBX, "rbx" },
	8, // { X86_REG_RCX, "rcx" },
	8, // { X86_REG_RDI, "rdi" },
	8, // { X86_REG_RDX, "rdx" },
	8, // { X86_REG_RIP, "rip" },
	8, // { X86_REG_RIZ, "riz" },
	8, // { X86_REG_RSI, "rsi" },
	8, // { X86_REG_RSP, "rsp" },
	2, // { X86_REG_SI, "si" },
	1, // { X86_REG_SIL, "sil" },
	2, // { X86_REG_SP, "sp" },
	1, // { X86_REG_SPL, "spl" },
	2, // { X86_REG_SS, "ss" },
	8, // { X86_REG_CR0, "cr0" },
	8, // { X86_REG_CR1, "cr1" },
	8, // { X86_REG_CR2, "cr2" },
	8, // { X86_REG_CR3, "cr3" },
	8, // { X86_REG_CR4, "cr4" },
	8, // { X86_REG_CR5, "cr5" },
	8, // { X86_REG_CR6, "cr6" },
	8, // { X86_REG_CR7, "cr7" },
	8, // { X86_REG_CR8, "cr8" },
	8, // { X86_REG_CR9, "cr9" },
	8, // { X86_REG_CR10, "cr10" },
	8, // { X86_REG_CR11, "cr11" },
	8, // { X86_REG_CR12, "cr12" },
	8, // { X86_REG_CR13, "cr13" },
	8, // { X86_REG_CR14, "cr14" },
	8, // { X86_REG_CR15, "cr15" },
	8, // { X86_REG_DR0, "dr0" },
	8, // { X86_REG_DR1, "dr1" },
	8, // { X86_REG_DR2, "dr2" },
	8, // { X86_REG_DR3, "dr3" },
	8, // { X86_REG_DR4, "dr4" },
	8, // { X86_REG_DR5, "dr5" },
	8, // { X86_REG_DR6, "dr6" },
	8, // { X86_REG_DR7, "dr7" },
	8, // { X86_REG_DR8, "dr8" },
	8, // { X86_REG_DR9, "dr9" },
	8, // { X86_REG_DR10, "dr10" },
	8, // { X86_REG_DR11, "dr11" },
	8, // { X86_REG_DR12, "dr12" },
	8, // { X86_REG_DR13, "dr13" },
	8, // { X86_REG_DR14, "dr14" },
	8, // { X86_REG_DR15, "dr15" },
	10, // { X86_REG_FP0, "fp0" },
	10, // { X86_REG_FP1, "fp1" },
	10, // { X86_REG_FP2, "fp2" },
	10, // { X86_REG_FP3, "fp3" },
	10, // { X86_REG_FP4, "fp4" },
	10, // { X86_REG_FP5, "fp5" },
	10, // { X86_REG_FP6, "fp6" },
	10, // { X86_REG_FP7, "fp7" },
	2, // { X86_REG_K0, "k0" },
	2, // { X86_REG_K1, "k1" },
	2, // { X86_REG_K2, "k2" },
	2, // { X86_REG_K3, "k3" },
	2, // { X86_REG_K4, "k4" },
	2, // { X86_REG_K5, "k5" },
	2, // { X86_REG_K6, "k6" },
	2, // { X86_REG_K7, "k7" },
	8, // { X86_REG_MM0, "mm0" },
	8, // { X86_REG_MM1, "mm1" },
	8, // { X86_REG_MM2, "mm2" },
	8, // { X86_REG_MM3, "mm3" },
	8, // { X86_REG_MM4, "mm4" },
	8, // { X86_REG_MM5, "mm5" },
	8, // { X86_REG_MM6, "mm6" },
	8, // { X86_REG_MM7, "mm7" },
	8, // { X86_REG_R8, "r8" },
	8, // { X86_REG_R9, "r9" },
	8, // { X86_REG_R10, "r10" },
	8, // { X86_REG_R11, "r11" },
	8, // { X86_REG_R12, "r12" },
	8, // { X86_REG_R13, "r13" },
	8, // { X86_REG_R14, "r14" },
	8, // { X86_REG_R15, "r15" },
	10, // { X86_REG_ST0, "st0" },
	10, // { X86_REG_ST1, "st1" },
	10, // { X86_REG_ST2, "st2" },
	10, // { X86_REG_ST3, "st3" },
	10, // { X86_REG_ST4, "st4" },
	10, // { X86_REG_ST5, "st5" },
	10, // { X86_REG_ST6, "st6" },
	10, // { X86_REG_ST7, "st7" },
	16, // { X86_REG_XMM0, "xmm0" },
	16, // { X86_REG_XMM1, "xmm1" },
	16, // { X86_REG_XMM2, "xmm2" },
	16, // { X86_REG_XMM3, "xmm3" },
	16, // { X86_REG_XMM4, "xmm4" },
	16, // { X86_REG_XMM5, "xmm5" },
	16, // { X86_REG_XMM6, "xmm6" },
	16, // { X86_REG_XMM7, "xmm7" },
	16, // { X86_REG_XMM8, "xmm8" },
	16, // { X86_REG_XMM9, "xmm9" },
	16, // { X86_REG_XMM10, "xmm10" },
	16, // { X86_REG_XMM11, "xmm11" },
	16, // { X86_REG_XMM12, "xmm12" },
	16, // { X86_REG_XMM13, "xmm13" },
	16, // { X86_REG_XMM14, "xmm14" },
	16, // { X86_REG_XMM15, "xmm15" },
	16, // { X86_REG_XMM16, "xmm16" },
	16, // { X86_REG_XMM17, "xmm17" },
	16, // { X86_REG_XMM18, "xmm18" },
	16, // { X86_REG_XMM19, "xmm19" },
	16, // { X86_REG_XMM20, "xmm20" },
	16, // { X86_REG_XMM21, "xmm21" },
	16, // { X86_REG_XMM22, "xmm22" },
	16, // { X86_REG_XMM23, "xmm23" },
	16, // { X86_REG_XMM24, "xmm24" },
	16, // { X86_REG_XMM25, "xmm25" },
	16, // { X86_REG_XMM26, "xmm26" },
	16, // { X86_REG_XMM27, "xmm27" },
	16, // { X86_REG_XMM28, "xmm28" },
	16, // { X86_REG_XMM29, "xmm29" },
	16, // { X86_REG_XMM30, "xmm30" },
	16, // { X86_REG_XMM31, "xmm31" },
	32, // { X86_REG_YMM0, "ymm0" },
	32, // { X86_REG_YMM1, "ymm1" },
	32, // { X86_REG_YMM2, "ymm2" },
	32, // { X86_REG_YMM3, "ymm3" },
	32, // { X86_REG_YMM4, "ymm4" },
	32, // { X86_REG_YMM5, "ymm5" },
	32, // { X86_REG_YMM6, "ymm6" },
	32, // { X86_REG_YMM7, "ymm7" },
	32, // { X86_REG_YMM8, "ymm8" },
	32, // { X86_REG_YMM9, "ymm9" },
	32, // { X86_REG_YMM10, "ymm10" },
	32, // { X86_REG_YMM11, "ymm11" },
	32, // { X86_REG_YMM12, "ymm12" },
	32, // { X86_REG_YMM13, "ymm13" },
	32, // { X86_REG_YMM14, "ymm14" },
	32, // { X86_REG_YMM15, "ymm15" },
	32, // { X86_REG_YMM16, "ymm16" },
	32, // { X86_REG_YMM17, "ymm17" },
	32, // { X86_REG_YMM18, "ymm18" },
	32, // { X86_REG_YMM19, "ymm19" },
	32, // { X86_REG_YMM20, "ymm20" },
	32, // { X86_REG_YMM21, "ymm21" },
	32, // { X86_REG_YMM22, "ymm22" },
	32, // { X86_REG_YMM23, "ymm23" },
	32, // { X86_REG_YMM24, "ymm24" },
	32, // { X86_REG_YMM25, "ymm25" },
	32, // { X86_REG_YMM26, "ymm26" },
	32, // { X86_REG_YMM27, "ymm27" },
	32, // { X86_REG_YMM28, "ymm28" },
	32, // { X86_REG_YMM29, "ymm29" },
	32, // { X86_REG_YMM30, "ymm30" },
	32, // { X86_REG_YMM31, "ymm31" },
	64, // { X86_REG_ZMM0, "zmm0" },
	64, // { X86_REG_ZMM1, "zmm1" },
	64, // { X86_REG_ZMM2, "zmm2" },
	64, // { X86_REG_ZMM3, "zmm3" },
	64, // { X86_REG_ZMM4, "zmm4" },
	64, // { X86_REG_ZMM5, "zmm5" },
	64, // { X86_REG_ZMM6, "zmm6" },
	64, // { X86_REG_ZMM7, "zmm7" },
	64, // { X86_REG_ZMM8, "zmm8" },
	64, // { X86_REG_ZMM9, "zmm9" },
	64, // { X86_REG_ZMM10, "zmm10" },
	64, // { X86_REG_ZMM11, "zmm11" },
	64, // { X86_REG_ZMM12, "zmm12" },
	64, // { X86_REG_ZMM13, "zmm13" },
	64, // { X86_REG_ZMM14, "zmm14" },
	64, // { X86_REG_ZMM15, "zmm15" },
	64, // { X86_REG_ZMM16, "zmm16" },
	64, // { X86_REG_ZMM17, "zmm17" },
	64, // { X86_REG_ZMM18, "zmm18" },
	64, // { X86_REG_ZMM19, "zmm19" },
	64, // { X86_REG_ZMM20, "zmm20" },
	64, // { X86_REG_ZMM21, "zmm21" },
	64, // { X86_REG_ZMM22, "zmm22" },
	64, // { X86_REG_ZMM23, "zmm23" },
	64, // { X86_REG_ZMM24, "zmm24" },
	64, // { X86_REG_ZMM25, "zmm25" },
	64, // { X86_REG_ZMM26, "zmm26" },
	64, // { X86_REG_ZMM27, "zmm27" },
	64, // { X86_REG_ZMM28, "zmm28" },
	64, // { X86_REG_ZMM29, "zmm29" },
	64, // { X86_REG_ZMM30, "zmm30" },
	64, // { X86_REG_ZMM31, "zmm31" },
	1, // { X86_REG_R8B, "r8b" },
	1, // { X86_REG_R9B, "r9b" },
	1, // { X86_REG_R10B, "r10b" },
	1, // { X86_REG_R11B, "r11b" },
	1, // { X86_REG_R12B, "r12b" },
	1, // { X86_REG_R13B, "r13b" },
	1, // { X86_REG_R14B, "r14b" },
	1, // { X86_REG_R15B, "r15b" },
	4, // { X86_REG_R8D, "r8d" },
	4, // { X86_REG_R9D, "r9d" },
	4, // { X86_REG_R10D, "r10d" },
	4, // { X86_REG_R11D, "r11d" },
	4, // { X86_REG_R12D, "r12d" },
	4, // { X86_REG_R13D, "r13d" },
	4, // { X86_REG_R14D, "r14d" },
	4, // { X86_REG_R15D, "r15d" },
	2, // { X86_REG_R8W, "r8w" },
	2, // { X86_REG_R9W, "r9w" },
	2, // { X86_REG_R10W, "r10w" },
	2, // { X86_REG_R11W, "r11w" },
	2, // { X86_REG_R12W, "r12w" },
	2, // { X86_REG_R13W, "r13w" },
	2, // { X86_REG_R14W, "r14w" },
	2, // { X86_REG_R15W, "r15w" },
	16, // { X86_REG_BND0, "bnd0" },
	16, // { X86_REG_BND1, "bnd0" },
	16, // { X86_REG_BND2, "bnd0" },
	16, // { X86_REG_BND3, "bnd0" },
	X86_REPEAT_16(8), // X86_REG_R16...X86_REG_R31
	X86_REPEAT_16(1), // X86_REG_R16B...X86_REG_R31B
	X86_REPEAT_16(4), // X86_REG_R16D...X86_REG_R31D
	X86_REPEAT_16(2), // X86_REG_R16W...X86_REG_R31W
	X86_REPEAT_8(0), // Tile sizes are instruction-configured.
};

#undef X86_REPEAT_8
#undef X86_REPEAT_16

const char *X86_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	cs_struct *ud = (cs_struct *)handle;
	const char *extension_name = X86_featureExtensionRegisterName(reg);

	if (extension_name)
		return extension_name;

	if (reg >= ARR_SIZE(reg_name_maps))
		return NULL;

	if (reg == X86_REG_EFLAGS) {
		if (ud->mode & CS_MODE_32)
			return "eflags";
		if (ud->mode & CS_MODE_64)
			return "rflags";
	}

	return reg_name_maps[reg].name;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const char *const insn_name_maps[] = {
	NULL, // X86_INS_INVALID
#ifndef CAPSTONE_X86_REDUCE
#include "X86MappingInsnName.inc"
#else
#include "X86MappingInsnName_reduce.inc"
#endif
};
#endif

// NOTE: insn_name_maps[] is sorted in order
const char *X86_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	const char *extension_name = X86_featureExtensionInstructionName(id);

	if (extension_name)
		return extension_name;

	if (id >= ARR_SIZE(insn_name_maps))
		return NULL;

	return insn_name_maps[id];
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ X86_GRP_INVALID, NULL },
	{ X86_GRP_JUMP, "jump" },
	{ X86_GRP_CALL, "call" },
	{ X86_GRP_RET, "ret" },
	{ X86_GRP_INT, "int" },
	{ X86_GRP_IRET, "iret" },
	{ X86_GRP_PRIVILEGE, "privilege" },
	{ X86_GRP_BRANCH_RELATIVE, "branch_relative" },

	// architecture-specific groups
	{ X86_GRP_VM, "vm" },
	{ X86_GRP_3DNOW, "3dnow" },
	{ X86_GRP_AES, "aes" },
	{ X86_GRP_ADX, "adx" },
	{ X86_GRP_AVX, "avx" },
	{ X86_GRP_AVX2, "avx2" },
	{ X86_GRP_AVX512, "avx512" },
	{ X86_GRP_BMI, "bmi" },
	{ X86_GRP_BMI2, "bmi2" },
	{ X86_GRP_CMOV, "cmov" },
	{ X86_GRP_F16C, "fc16" },
	{ X86_GRP_FMA, "fma" },
	{ X86_GRP_FMA4, "fma4" },
	{ X86_GRP_FSGSBASE, "fsgsbase" },
	{ X86_GRP_HLE, "hle" },
	{ X86_GRP_MMX, "mmx" },
	{ X86_GRP_MODE32, "mode32" },
	{ X86_GRP_MODE64, "mode64" },
	{ X86_GRP_RTM, "rtm" },
	{ X86_GRP_SHA, "sha" },
	{ X86_GRP_SSE1, "sse1" },
	{ X86_GRP_SSE2, "sse2" },
	{ X86_GRP_SSE3, "sse3" },
	{ X86_GRP_SSE41, "sse41" },
	{ X86_GRP_SSE42, "sse42" },
	{ X86_GRP_SSE4A, "sse4a" },
	{ X86_GRP_SSSE3, "ssse3" },
	{ X86_GRP_PCLMUL, "pclmul" },
	{ X86_GRP_XOP, "xop" },
	{ X86_GRP_CDI, "cdi" },
	{ X86_GRP_ERI, "eri" },
	{ X86_GRP_TBM, "tbm" },
	{ X86_GRP_16BITMODE, "16bitmode" },
	{ X86_GRP_NOT64BITMODE, "not64bitmode" },
	{ X86_GRP_SGX, "sgx" },
	{ X86_GRP_DQI, "dqi" },
	{ X86_GRP_BWI, "bwi" },
	{ X86_GRP_PFI, "pfi" },
	{ X86_GRP_VLX, "vlx" },
	{ X86_GRP_SMAP, "smap" },
	{ X86_GRP_NOVLX, "novlx" },
	{ X86_GRP_FPU, "fpu" },
};
#endif

const char *X86_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenInstrInfo_reduce.inc"

/// reduce x86 instructions
const insn_map_x86 insns[] = {
#include "X86MappingInsn_reduce.inc"
};
#else
#include "X86GenInstrInfo.inc"

/// full x86 instructions
const insn_map_x86 insns[] = {
#include "X86MappingInsn.inc"
};
#endif

#ifndef CAPSTONE_DIET
// in arr, replace r1 = r2
static void arr_replace(uint16_t *arr, uint8_t max, x86_reg r1, x86_reg r2)
{
	uint8_t i;

	for (i = 0; i < max; i++) {
		if (arr[i] == r1) {
			arr[i] = r2;
			break;
		}
	}
}
#endif

// look for @id in @insns
// return -1 if not found
unsigned int find_insn(unsigned int id)
{
	// binary searching since the IDs are sorted in order
	unsigned int left, right, m;
	unsigned int max = ARR_SIZE(insns);

	right = max - 1;

	if (id < insns[0].id || id > insns[right].id)
		// not found
		return -1;

	left = 0;

	while (left <= right) {
		m = (left + right) / 2;
		if (id == insns[m].id) {
			return m;
		}

		if (id < insns[m].id)
			right = m - 1;
		else
			left = m + 1;
	}

	// not found
	// printf("NOT FOUNDDDDDDDDDDDDDDD id = %u\n", id);
	return -1;
}

static inline unsigned int find_insn_h(cs_struct *h, unsigned int id)
{
	if (h && h->x86_insn_lut && id <= h->x86_insn_lut_max)
		return (unsigned int)(int16_t)h->x86_insn_lut[id];

	return find_insn(id);
}

// given internal insn id, return public instruction info
void X86_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned int i;

	if (X86_mapFeatureExtension(insn, id))
		return;

	i = find_insn_h(h, id);
	if (i != -1) {
		insn->id = insns[i].mapid;

		if (h->detail_opt) {
#ifndef CAPSTONE_DIET
			memcpy(insn->detail->regs_read, insns[i].regs_use,
			       sizeof(insns[i].regs_use));
			insn->detail->regs_read_count =
				(uint8_t)count_positive(insns[i].regs_use);

			// special cases when regs_write[] depends on arch
			switch (id) {
			default:
				memcpy(insn->detail->regs_write,
				       insns[i].regs_mod,
				       sizeof(insns[i].regs_mod));
				insn->detail->regs_write_count =
					(uint8_t)count_positive(
						insns[i].regs_mod);
				break;
			case X86_RDTSC:
				if (h->mode == CS_MODE_64) {
					memcpy(insn->detail->regs_write,
					       insns[i].regs_mod,
					       sizeof(insns[i].regs_mod));
					insn->detail->regs_write_count =
						(uint8_t)count_positive(
							insns[i].regs_mod);
				} else {
					insn->detail->regs_write[0] =
						X86_REG_EAX;
					insn->detail->regs_write[1] =
						X86_REG_EDX;
					insn->detail->regs_write_count = 2;
				}
				break;
			case X86_RDTSCP:
				if (h->mode == CS_MODE_64) {
					memcpy(insn->detail->regs_write,
					       insns[i].regs_mod,
					       sizeof(insns[i].regs_mod));
					insn->detail->regs_write_count =
						(uint8_t)count_positive(
							insns[i].regs_mod);
				} else {
					insn->detail->regs_write[0] =
						X86_REG_EAX;
					insn->detail->regs_write[1] =
						X86_REG_ECX;
					insn->detail->regs_write[2] =
						X86_REG_EDX;
					insn->detail->regs_write_count = 3;
				}
				break;
			}
			switch (insn->id) {
			default:
				break;

			case X86_INS_LOOP:
			case X86_INS_LOOPE:
			case X86_INS_LOOPNE:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EIP, X86_REG_IP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_IP);
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ECX, X86_REG_CX);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ECX, X86_REG_CX);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EIP, X86_REG_RIP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_RIP);
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ECX, X86_REG_RCX);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ECX, X86_REG_RCX);
					break;
				}
			}

			switch (insn->id) {
			default:
				break;
			case X86_INS_LODSB:
			case X86_INS_LODSD:
			case X86_INS_LODSQ:
			case X86_INS_LODSW:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ESI, X86_REG_SI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESI, X86_REG_SI);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ESI, X86_REG_RSI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESI, X86_REG_RSI);
					break;
				}
				break;

			case X86_INS_SCASB:
			case X86_INS_SCASD:
			case X86_INS_SCASW:
			case X86_INS_SCASQ:
			case X86_INS_STOSB:
			case X86_INS_STOSD:
			case X86_INS_STOSQ:
			case X86_INS_STOSW:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EDI, X86_REG_DI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EDI, X86_REG_DI);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EDI, X86_REG_RDI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EDI, X86_REG_RDI);
					break;
				}
				break;

			case X86_INS_CMPSB:
			case X86_INS_CMPSD:
			case X86_INS_CMPSQ:
			case X86_INS_CMPSW:
			case X86_INS_MOVSB:
			case X86_INS_MOVSW:
			case X86_INS_MOVSD:
			case X86_INS_MOVSQ:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EDI, X86_REG_DI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EDI, X86_REG_DI);
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ESI, X86_REG_SI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESI, X86_REG_SI);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EDI, X86_REG_RDI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EDI, X86_REG_RDI);
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ESI, X86_REG_RSI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESI, X86_REG_RSI);
					break;
				}
				break;

			case X86_INS_ENTER:
			case X86_INS_LEAVE:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EBP, X86_REG_BP);
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ESP, X86_REG_SP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EBP, X86_REG_BP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESP, X86_REG_SP);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EBP, X86_REG_RBP);
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ESP, X86_REG_RSP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EBP, X86_REG_RBP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESP, X86_REG_RSP);
				}
				break;

			case X86_INS_INSB:
			case X86_INS_INSW:
			case X86_INS_INSD:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EDI, X86_REG_DI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EDI, X86_REG_DI);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EDI, X86_REG_RDI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EDI, X86_REG_RDI);
					break;
				}
				break;

			case X86_INS_OUTSB:
			case X86_INS_OUTSW:
			case X86_INS_OUTSD:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ESI, X86_REG_RSI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESI, X86_REG_RSI);
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ESI, X86_REG_SI);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESI, X86_REG_SI);
					break;
				}
				break;
			}

			switch (insn->id) {
			default:
				break;
			case X86_INS_LODSB:
			case X86_INS_LODSD:
			case X86_INS_LODSW:
			case X86_INS_CMPSB:
			case X86_INS_CMPSD:
			case X86_INS_CMPSW:
			case X86_INS_MOVSB:
			case X86_INS_MOVSW:
			case X86_INS_MOVSD:
			case X86_INS_OUTSB:
			case X86_INS_OUTSW:
			case X86_INS_OUTSD:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
				case CS_MODE_32: {
					int pos = insn->detail->regs_read_count;
					insn->detail->regs_read[pos] =
						X86_REG_DS;
					insn->detail->regs_read_count += 1;
				} break;
				}
				break;

			case X86_INS_JMP:
			case X86_INS_LJMP:
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EIP, X86_REG_IP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_IP);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EIP, X86_REG_RIP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_RIP);
					break;
				}
				break;

			case X86_INS_SYSENTER: {
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_IP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESP, X86_REG_SP);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_RIP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESP, X86_REG_RSP);
					break;
				}
				break;
			} break;
			case X86_INS_SYSEXIT: {
				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ECX, X86_REG_CX);
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EDX, X86_REG_DX);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_IP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESP, X86_REG_SP);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_ECX, X86_REG_RCX);
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EDX, X86_REG_RDX);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_RIP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_ESP, X86_REG_RSP);
					break;
				}
				break;
			} break;
			}

			memcpy(insn->detail->groups, insns[i].groups,
			       sizeof(insns[i].groups));
			insn->detail->groups_count =
				(uint8_t)count_positive8(insns[i].groups);

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail
					->groups[insn->detail->groups_count] =
					X86_GRP_JUMP;
				insn->detail->groups_count++;

				switch (h->mode) {
				default:
					break;
				case CS_MODE_16:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EIP, X86_REG_IP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_IP);
					break;
				case CS_MODE_64:
					arr_replace(
						insn->detail->regs_read,
						insn->detail->regs_read_count,
						X86_REG_EIP, X86_REG_RIP);
					arr_replace(
						insn->detail->regs_write,
						insn->detail->regs_write_count,
						X86_REG_EIP, X86_REG_RIP);
					break;
				}
			}

			switch (insns[i].id) {
			case X86_OUT8ir:
			case X86_OUT16ir:
			case X86_OUT32ir:
				if (insn->detail->x86.operands[0].imm == -78) {
					// Writing to port 0xb2 causes an SMI on most platforms
					// See: http://cs.gmu.edu/~tr-admin/papers/GMU-CS-TR-2011-8.pdf
					insn->detail->groups
						[insn->detail->groups_count] =
						X86_GRP_INT;
					insn->detail->groups_count++;
				}
				break;

			default:
				break;
			}
#endif
		}
	}
}

// map special instructions with accumulate registers.
// this is needed because LLVM embeds these register names into AsmStrs[],
// but not separately in operands
struct insn_reg {
	uint16_t insn;
	x86_reg reg;
	enum cs_ac_type access;
};

struct insn_reg2 {
	uint16_t insn;
	x86_reg reg1, reg2;
	enum cs_ac_type access1, access2;
};

static inline uint16_t pack_insn_reg(x86_reg reg, enum cs_ac_type access)
{
	return (uint16_t)(((unsigned int)access << 12) |
			  ((unsigned int)reg & 0x0fff));
}

static inline x86_reg unpack_insn_reg(uint16_t value, enum cs_ac_type *access)
{
	if (access)
		*access = (enum cs_ac_type)(value >> 12);
	return (x86_reg)(value & 0x0fff);
}

static const struct insn_reg insn_regs_att[] = {
	{ X86_INSB, X86_REG_DX, CS_AC_READ },
	{ X86_INSL, X86_REG_DX, CS_AC_READ },
	{ X86_INSW, X86_REG_DX, CS_AC_READ },
	{ X86_MOV16o16a, X86_REG_AX, CS_AC_READ },
	{ X86_MOV16o32a, X86_REG_AX, CS_AC_READ },
	{ X86_MOV16o64a, X86_REG_AX, CS_AC_READ },
	{ X86_MOV32o16a, X86_REG_EAX, CS_AC_READ },
	{ X86_MOV32o32a, X86_REG_EAX, CS_AC_READ },
	{ X86_MOV32o64a, X86_REG_EAX, CS_AC_READ },
	{ X86_MOV64o32a, X86_REG_RAX, CS_AC_READ },
	{ X86_MOV64o64a, X86_REG_RAX, CS_AC_READ },
	{ X86_MOV8o16a, X86_REG_AL, CS_AC_READ },
	{ X86_MOV8o32a, X86_REG_AL, CS_AC_READ },
	{ X86_MOV8o64a, X86_REG_AL, CS_AC_READ },
	{ X86_OUT16ir, X86_REG_AX, CS_AC_READ },
	{ X86_OUT32ir, X86_REG_EAX, CS_AC_READ },
	{ X86_OUT8ir, X86_REG_AL, CS_AC_READ },
	{ X86_POPDS16, X86_REG_DS, CS_AC_WRITE },
	{ X86_POPDS32, X86_REG_DS, CS_AC_WRITE },
	{ X86_POPES16, X86_REG_ES, CS_AC_WRITE },
	{ X86_POPES32, X86_REG_ES, CS_AC_WRITE },
	{ X86_POPFS16, X86_REG_FS, CS_AC_WRITE },
	{ X86_POPFS32, X86_REG_FS, CS_AC_WRITE },
	{ X86_POPFS64, X86_REG_FS, CS_AC_WRITE },
	{ X86_POPGS16, X86_REG_GS, CS_AC_WRITE },
	{ X86_POPGS32, X86_REG_GS, CS_AC_WRITE },
	{ X86_POPGS64, X86_REG_GS, CS_AC_WRITE },
	{ X86_POPSS16, X86_REG_SS, CS_AC_WRITE },
	{ X86_POPSS32, X86_REG_SS, CS_AC_WRITE },
	{ X86_PUSHCS16, X86_REG_CS, CS_AC_READ },
	{ X86_PUSHCS32, X86_REG_CS, CS_AC_READ },
	{ X86_PUSHDS16, X86_REG_DS, CS_AC_READ },
	{ X86_PUSHDS32, X86_REG_DS, CS_AC_READ },
	{ X86_PUSHES16, X86_REG_ES, CS_AC_READ },
	{ X86_PUSHES32, X86_REG_ES, CS_AC_READ },
	{ X86_PUSHFS16, X86_REG_FS, CS_AC_READ },
	{ X86_PUSHFS32, X86_REG_FS, CS_AC_READ },
	{ X86_PUSHFS64, X86_REG_FS, CS_AC_READ },
	{ X86_PUSHGS16, X86_REG_GS, CS_AC_READ },
	{ X86_PUSHGS32, X86_REG_GS, CS_AC_READ },
	{ X86_PUSHGS64, X86_REG_GS, CS_AC_READ },
	{ X86_PUSHSS16, X86_REG_SS, CS_AC_READ },
	{ X86_PUSHSS32, X86_REG_SS, CS_AC_READ },
	{ X86_RCL16rCL, X86_REG_CL, CS_AC_READ },
	{ X86_RCL32rCL, X86_REG_CL, CS_AC_READ },
	{ X86_RCL64rCL, X86_REG_CL, CS_AC_READ },
	{ X86_RCL8rCL, X86_REG_CL, CS_AC_READ },
	{ X86_RCR16rCL, X86_REG_CL, CS_AC_READ },
	{ X86_RCR32rCL, X86_REG_CL, CS_AC_READ },
	{ X86_RCR64rCL, X86_REG_CL, CS_AC_READ },
	{ X86_RCR8rCL, X86_REG_CL, CS_AC_READ },
	{ X86_ROL16rCL, X86_REG_CL, CS_AC_READ },
	{ X86_ROL32rCL, X86_REG_CL, CS_AC_READ },
	{ X86_ROL64rCL, X86_REG_CL, CS_AC_READ },
	{ X86_ROL8rCL, X86_REG_CL, CS_AC_READ },
	{ X86_ROR16rCL, X86_REG_CL, CS_AC_READ },
	{ X86_ROR32rCL, X86_REG_CL, CS_AC_READ },
	{ X86_ROR64rCL, X86_REG_CL, CS_AC_READ },
	{ X86_ROR8rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SAL16rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SAL32rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SAL64rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SAL8rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SAR16rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SAR32rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SAR64rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SAR8rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHL16rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHL32rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHL64rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHL8rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHLD16mrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHLD16rrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHLD32mrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHLD32rrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHLD64mrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHLD64rrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHR16rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHR32rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHR64rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHR8rCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHRD16mrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHRD16rrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHRD32mrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHRD32rrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHRD64mrCL, X86_REG_CL, CS_AC_READ },
	{ X86_SHRD64rrCL, X86_REG_CL, CS_AC_READ },
	{ X86_XCHG16ar, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_XCHG32ar, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_XCHG64ar, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
};

static const struct insn_reg insn_regs_att_extra[] = {
	// dummy entry, to avoid empty array
	{ 0, 0 },
#ifndef CAPSTONE_X86_REDUCE
	{ X86_ADD_FrST0, X86_REG_ST0, CS_AC_READ },
	{ X86_DIVR_FrST0, X86_REG_ST0, CS_AC_READ },
	{ X86_DIV_FrST0, X86_REG_ST0, CS_AC_READ },
	{ X86_FNSTSW16r, X86_REG_AX, CS_AC_READ },
	{ X86_MUL_FrST0, X86_REG_ST0, CS_AC_READ },
	{ X86_SKINIT, X86_REG_EAX, CS_AC_READ },
	{ X86_SUBR_FrST0, X86_REG_ST0, CS_AC_READ },
	{ X86_SUB_FrST0, X86_REG_ST0, CS_AC_READ },
	{ X86_VMLOAD32, X86_REG_EAX, CS_AC_READ },
	{ X86_VMLOAD64, X86_REG_RAX, CS_AC_READ },
	{ X86_VMRUN32, X86_REG_EAX, CS_AC_READ },
	{ X86_VMRUN64, X86_REG_RAX, CS_AC_READ },
	{ X86_VMSAVE32, X86_REG_EAX, CS_AC_READ },
	{ X86_VMSAVE64, X86_REG_RAX, CS_AC_READ },
#endif
};

static const struct insn_reg insn_regs_intel[] = {
	{ X86_ADC16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_ADC32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_ADC64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_ADC8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_ADD16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_ADD32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_ADD64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_ADD8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_AND16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_AND32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_AND64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_AND8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_CMP16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_CMP32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_CMP64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_CMP8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_IN16ri, X86_REG_AX, CS_AC_WRITE },
	{ X86_IN32ri, X86_REG_EAX, CS_AC_WRITE },
	{ X86_IN8ri, X86_REG_AL, CS_AC_WRITE },
	{ X86_LODSB, X86_REG_AL, CS_AC_WRITE },
	{ X86_LODSL, X86_REG_EAX, CS_AC_WRITE },
	{ X86_LODSQ, X86_REG_RAX, CS_AC_WRITE },
	{ X86_LODSW, X86_REG_AX, CS_AC_WRITE },
	{ X86_MOV16ao16, X86_REG_AX,
	  CS_AC_WRITE }, // 16-bit A1 1020                  // mov     ax, word ptr [0x2010]
	{ X86_MOV16ao32, X86_REG_AX,
	  CS_AC_WRITE }, // 32-bit A1 10203040              // mov     ax, word ptr [0x40302010]
	{ X86_MOV16ao64, X86_REG_AX,
	  CS_AC_WRITE }, // 64-bit 66 A1 1020304050607080   // movabs  ax, word ptr [0x8070605040302010]
	{ X86_MOV32ao16, X86_REG_EAX,
	  CS_AC_WRITE }, // 32-bit 67 A1 1020               // mov     eax, dword ptr [0x2010]
	{ X86_MOV32ao32, X86_REG_EAX,
	  CS_AC_WRITE }, // 32-bit A1 10203040              // mov     eax, dword ptr [0x40302010]
	{ X86_MOV32ao64, X86_REG_EAX,
	  CS_AC_WRITE }, // 64-bit A1 1020304050607080      // movabs  eax, dword ptr [0x8070605040302010]
	{ X86_MOV64ao32, X86_REG_RAX,
	  CS_AC_WRITE }, // 64-bit 48 8B04 10203040         // mov     rax, qword ptr [0x40302010]
	{ X86_MOV64ao64, X86_REG_RAX,
	  CS_AC_WRITE }, // 64-bit 48 A1 1020304050607080   // movabs  rax, qword ptr [0x8070605040302010]
	{ X86_MOV8ao16, X86_REG_AL,
	  CS_AC_WRITE }, // 16-bit A0 1020                  // mov     al, byte ptr [0x2010]
	{ X86_MOV8ao32, X86_REG_AL,
	  CS_AC_WRITE }, // 32-bit A0 10203040              // mov     al, byte ptr [0x40302010]
	{ X86_MOV8ao64, X86_REG_AL,
	  CS_AC_WRITE }, // 64-bit 66 A0 1020304050607080   // movabs  al, byte ptr [0x8070605040302010]
	{ X86_OR16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_OR32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_OR64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_OR8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_OUTSB, X86_REG_DX, CS_AC_WRITE },
	{ X86_OUTSL, X86_REG_DX, CS_AC_WRITE },
	{ X86_OUTSW, X86_REG_DX, CS_AC_WRITE },
	{ X86_POPDS16, X86_REG_DS, CS_AC_WRITE },
	{ X86_POPDS32, X86_REG_DS, CS_AC_WRITE },
	{ X86_POPES16, X86_REG_ES, CS_AC_WRITE },
	{ X86_POPES32, X86_REG_ES, CS_AC_WRITE },
	{ X86_POPFS16, X86_REG_FS, CS_AC_WRITE },
	{ X86_POPFS32, X86_REG_FS, CS_AC_WRITE },
	{ X86_POPFS64, X86_REG_FS, CS_AC_WRITE },
	{ X86_POPGS16, X86_REG_GS, CS_AC_WRITE },
	{ X86_POPGS32, X86_REG_GS, CS_AC_WRITE },
	{ X86_POPGS64, X86_REG_GS, CS_AC_WRITE },
	{ X86_POPSS16, X86_REG_SS, CS_AC_WRITE },
	{ X86_POPSS32, X86_REG_SS, CS_AC_WRITE },
	{ X86_PUSHCS16, X86_REG_CS, CS_AC_READ },
	{ X86_PUSHCS32, X86_REG_CS, CS_AC_READ },
	{ X86_PUSHDS16, X86_REG_DS, CS_AC_READ },
	{ X86_PUSHDS32, X86_REG_DS, CS_AC_READ },
	{ X86_PUSHES16, X86_REG_ES, CS_AC_READ },
	{ X86_PUSHES32, X86_REG_ES, CS_AC_READ },
	{ X86_PUSHFS16, X86_REG_FS, CS_AC_READ },
	{ X86_PUSHFS32, X86_REG_FS, CS_AC_READ },
	{ X86_PUSHFS64, X86_REG_FS, CS_AC_READ },
	{ X86_PUSHGS16, X86_REG_GS, CS_AC_READ },
	{ X86_PUSHGS32, X86_REG_GS, CS_AC_READ },
	{ X86_PUSHGS64, X86_REG_GS, CS_AC_READ },
	{ X86_PUSHSS16, X86_REG_SS, CS_AC_READ },
	{ X86_PUSHSS32, X86_REG_SS, CS_AC_READ },
	{ X86_SBB16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SBB32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SBB64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SBB8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_SCASB, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_SCASL, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SCASQ, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SCASW, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SUB16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SUB32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SUB64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_SUB8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_TEST16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_TEST32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_TEST64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_TEST8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
	{ X86_XOR16i16, X86_REG_AX, CS_AC_WRITE | CS_AC_READ },
	{ X86_XOR32i32, X86_REG_EAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_XOR64i32, X86_REG_RAX, CS_AC_WRITE | CS_AC_READ },
	{ X86_XOR8i8, X86_REG_AL, CS_AC_WRITE | CS_AC_READ },
};

static const struct insn_reg insn_regs_intel_extra[] = {
	// dummy entry, to avoid empty array
	{ 0, 0, 0 },
#ifndef CAPSTONE_X86_REDUCE
	{ X86_CMOVBE_F, X86_REG_ST0, CS_AC_WRITE },
	{ X86_CMOVB_F, X86_REG_ST0, CS_AC_WRITE },
	{ X86_CMOVE_F, X86_REG_ST0, CS_AC_WRITE },
	{ X86_CMOVNBE_F, X86_REG_ST0, CS_AC_WRITE },
	{ X86_CMOVNB_F, X86_REG_ST0, CS_AC_WRITE },
	{ X86_CMOVNE_F, X86_REG_ST0, CS_AC_WRITE },
	{ X86_CMOVNP_F, X86_REG_ST0, CS_AC_WRITE },
	{ X86_CMOVP_F, X86_REG_ST0, CS_AC_WRITE },
	// { X86_COMP_FST0r, X86_REG_ST0, CS_AC_WRITE },
	// { X86_COM_FST0r, X86_REG_ST0, CS_AC_WRITE },
	{ X86_FNSTSW16r, X86_REG_AX, CS_AC_WRITE },
	{ X86_SKINIT, X86_REG_EAX, CS_AC_WRITE },
	{ X86_VMLOAD32, X86_REG_EAX, CS_AC_WRITE },
	{ X86_VMLOAD64, X86_REG_RAX, CS_AC_WRITE },
	{ X86_VMRUN32, X86_REG_EAX, CS_AC_WRITE },
	{ X86_VMRUN64, X86_REG_RAX, CS_AC_WRITE },
	{ X86_VMSAVE32, X86_REG_EAX, CS_AC_READ },
	{ X86_VMSAVE64, X86_REG_RAX, CS_AC_READ },
	{ X86_XCH_F, X86_REG_ST0, CS_AC_WRITE },
#endif
};

static const struct insn_reg2 insn_regs_intel2[] = {
	{ X86_IN16rr, X86_REG_AX, X86_REG_DX, CS_AC_WRITE, CS_AC_READ },
	{ X86_IN32rr, X86_REG_EAX, X86_REG_DX, CS_AC_WRITE, CS_AC_READ },
	{ X86_IN8rr, X86_REG_AL, X86_REG_DX, CS_AC_WRITE, CS_AC_READ },
	{ X86_INVLPGA32, X86_REG_EAX, X86_REG_ECX, CS_AC_READ, CS_AC_READ },
	{ X86_INVLPGA64, X86_REG_RAX, X86_REG_ECX, CS_AC_READ, CS_AC_READ },
	{ X86_OUT16rr, X86_REG_DX, X86_REG_AX, CS_AC_READ, CS_AC_READ },
	{ X86_OUT32rr, X86_REG_DX, X86_REG_EAX, CS_AC_READ, CS_AC_READ },
	{ X86_OUT8rr, X86_REG_DX, X86_REG_AL, CS_AC_READ, CS_AC_READ },
};

static int binary_search1(const struct insn_reg *insns, unsigned int max,
			  unsigned int id)
{
	unsigned int first, last, mid;

	first = 0;
	last = max - 1;

	if (insns[0].insn > id || insns[last].insn < id) {
		// not found
		return -1;
	}

	while (first <= last) {
		mid = (first + last) / 2;
		if (insns[mid].insn < id) {
			first = mid + 1;
		} else if (insns[mid].insn == id) {
			return mid;
		} else {
			if (mid == 0)
				break;
			last = mid - 1;
		}
	}

	// not found
	return -1;
}

static int binary_search2(const struct insn_reg2 *insns, unsigned int max,
			  unsigned int id)
{
	unsigned int first, last, mid;

	first = 0;
	last = max - 1;

	if (insns[0].insn > id || insns[last].insn < id) {
		// not found
		return -1;
	}

	while (first <= last) {
		mid = (first + last) / 2;
		if (insns[mid].insn < id) {
			first = mid + 1;
		} else if (insns[mid].insn == id) {
			return mid;
		} else {
			if (mid == 0)
				break;
			last = mid - 1;
		}
	}

	// not found
	return -1;
}

void X86_build_lookup_tables(cs_struct *h)
{
	unsigned int i;
	unsigned int max = ARR_SIZE(insns);
	unsigned int id_max;

	CS_ASSERT_RET(h && !h->x86_insn_lut);

	id_max = insns[max - 1].id;
	h->x86_insn_lut_max = id_max;
	h->x86_insn_lut =
		(uint16_t *)cs_mem_malloc((id_max + 1) * sizeof(uint16_t));
	CS_ASSERT_RET(h->x86_insn_lut);

	memset(h->x86_insn_lut, 0xff, (id_max + 1) * sizeof(uint16_t));
	for (i = 0; i < max; i++)
		h->x86_insn_lut[insns[i].id] = (uint16_t)i;

	h->x86_insn_reg_lut =
		(uint32_t *)cs_mem_calloc(id_max + 1, sizeof(uint32_t));
	if (!h->x86_insn_reg_lut)
		return;

	for (i = 0; i < ARR_SIZE(insn_regs_intel); i++) {
		unsigned int insn_id = insn_regs_intel[i].insn;
		if (insn_id <= id_max)
			h->x86_insn_reg_lut[insn_id] =
				(h->x86_insn_reg_lut[insn_id] & 0xffff0000) |
				pack_insn_reg(insn_regs_intel[i].reg,
					      insn_regs_intel[i].access);
	}

	for (i = 0; i < ARR_SIZE(insn_regs_intel_extra); i++) {
		unsigned int insn_id = insn_regs_intel_extra[i].insn;
		if (insn_id && insn_id <= id_max &&
		    !(h->x86_insn_reg_lut[insn_id] & 0xffff))
			h->x86_insn_reg_lut[insn_id] =
				(h->x86_insn_reg_lut[insn_id] & 0xffff0000) |
				pack_insn_reg(insn_regs_intel_extra[i].reg,
					      insn_regs_intel_extra[i].access);
	}

	for (i = 0; i < ARR_SIZE(insn_regs_att); i++) {
		unsigned int insn_id = insn_regs_att[i].insn;
		if (insn_id <= id_max)
			h->x86_insn_reg_lut[insn_id] =
				(h->x86_insn_reg_lut[insn_id] & 0x0000ffff) |
				((uint32_t)pack_insn_reg(insn_regs_att[i].reg,
							 insn_regs_att[i].access)
				 << 16);
	}

	for (i = 0; i < ARR_SIZE(insn_regs_att_extra); i++) {
		unsigned int insn_id = insn_regs_att_extra[i].insn;
		if (insn_id && insn_id <= id_max &&
		    !(h->x86_insn_reg_lut[insn_id] >> 16))
			h->x86_insn_reg_lut[insn_id] =
				(h->x86_insn_reg_lut[insn_id] & 0x0000ffff) |
				((uint32_t)pack_insn_reg(
					 insn_regs_att_extra[i].reg,
					 insn_regs_att_extra[i].access)
				 << 16);
	}
}

// return register of given instruction id
// return 0 if not found
// this is to handle instructions embedding accumulate registers into AsmStrs[]
x86_reg X86_insn_reg_intel(unsigned int id, enum cs_ac_type *access)
{
	int i;

	i = binary_search1(insn_regs_intel, ARR_SIZE(insn_regs_intel), id);
	if (i != -1) {
		if (access) {
			*access = insn_regs_intel[i].access;
		}
		return insn_regs_intel[i].reg;
	}

	i = binary_search1(insn_regs_intel_extra,
			   ARR_SIZE(insn_regs_intel_extra), id);
	if (i != -1) {
		if (access) {
			*access = insn_regs_intel_extra[i].access;
		}
		return insn_regs_intel_extra[i].reg;
	}

	// not found
	return 0;
}

x86_reg X86_insn_reg_intel_h(cs_struct *h, unsigned int id,
			     enum cs_ac_type *access)
{
	if (h && h->x86_insn_reg_lut && id <= h->x86_insn_lut_max) {
		uint16_t value = (uint16_t)(h->x86_insn_reg_lut[id] & 0xffff);
		if (value)
			return unpack_insn_reg(value, access);
		return 0;
	}

	return X86_insn_reg_intel(id, access);
}

bool X86_insn_reg_intel2(unsigned int id, x86_reg *reg1,
			 enum cs_ac_type *access1, x86_reg *reg2,
			 enum cs_ac_type *access2)
{
	int i = binary_search2(insn_regs_intel2, ARR_SIZE(insn_regs_intel2),
			       id);
	if (i != -1) {
		*reg1 = insn_regs_intel2[i].reg1;
		*reg2 = insn_regs_intel2[i].reg2;
		if (access1)
			*access1 = insn_regs_intel2[i].access1;
		if (access2)
			*access2 = insn_regs_intel2[i].access2;
		return true;
	}

	// not found
	return false;
}

x86_reg X86_insn_reg_att(unsigned int id, enum cs_ac_type *access)
{
	int i;

	i = binary_search1(insn_regs_att, ARR_SIZE(insn_regs_att), id);
	if (i != -1) {
		if (access)
			*access = insn_regs_att[i].access;
		return insn_regs_att[i].reg;
	}

	i = binary_search1(insn_regs_att_extra, ARR_SIZE(insn_regs_att_extra),
			   id);
	if (i != -1) {
		if (access)
			*access = insn_regs_att_extra[i].access;
		return insn_regs_att_extra[i].reg;
	}

	// not found
	return 0;
}

x86_reg X86_insn_reg_att_h(cs_struct *h, unsigned int id,
			   enum cs_ac_type *access)
{
	if (h && h->x86_insn_reg_lut && id <= h->x86_insn_lut_max) {
		uint16_t value = (uint16_t)(h->x86_insn_reg_lut[id] >> 16);
		if (value)
			return unpack_insn_reg(value, access);
		return 0;
	}

	return X86_insn_reg_att(id, access);
}

// ATT just reuses Intel data, but with the order of registers reversed
bool X86_insn_reg_att2(unsigned int id, x86_reg *reg1, enum cs_ac_type *access1,
		       x86_reg *reg2, enum cs_ac_type *access2)
{
	int i = binary_search2(insn_regs_intel2, ARR_SIZE(insn_regs_intel2),
			       id);
	if (i != -1) {
		*reg1 = insn_regs_intel2[i].reg2;
		*reg2 = insn_regs_intel2[i].reg1;
		if (access1)
			*access1 = insn_regs_intel2[i].access2;
		if (access2)
			*access2 = insn_regs_intel2[i].access1;
		return true;
	}

	// not found
	return false;
}

// given MCInst's id, find out if this insn is valid for REPNE prefix
static bool valid_repne(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	unsigned int i = find_insn_h(h, opcode);
	if (i != -1) {
		id = insns[i].mapid;
		switch (id) {
		default:
			return false;

		case X86_INS_CMPSB:
		case X86_INS_CMPSS:
		case X86_INS_CMPSW:
		case X86_INS_CMPSQ:

		case X86_INS_SCASB:
		case X86_INS_SCASW:
		case X86_INS_SCASQ:

		case X86_INS_MOVSB:
		case X86_INS_MOVSS:
		case X86_INS_MOVSW:
		case X86_INS_MOVSQ:

		case X86_INS_LODSB:
		case X86_INS_LODSW:
		case X86_INS_LODSD:
		case X86_INS_LODSQ:

		case X86_INS_STOSB:
		case X86_INS_STOSW:
		case X86_INS_STOSD:
		case X86_INS_STOSQ:

		case X86_INS_INSB:
		case X86_INS_INSW:
		case X86_INS_INSD:

		case X86_INS_OUTSB:
		case X86_INS_OUTSW:
		case X86_INS_OUTSD:

			return true;

		case X86_INS_MOVSD:
			if (opcode == X86_MOVSW) // REP MOVSB
				return true;
			else if (opcode == X86_MOVSL) // REP MOVSD
				return true;
			return false;

		case X86_INS_CMPSD:
			if (opcode == X86_CMPSL) // REP CMPSD
				return true;
			return false;

		case X86_INS_SCASD:
			if (opcode == X86_SCASL) // REP SCASD
				return true;
			return false;
		}
	}

	// not found
	return false;
}

// given MCInst's id, find out if this insn is valid for BND prefix
// BND prefix is valid for CALL/JMP/RET
#ifndef CAPSTONE_DIET
static bool valid_bnd(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	unsigned int i = find_insn_h(h, opcode);
	if (i != -1) {
		id = insns[i].mapid;
		switch (id) {
		default:
			return false;

		case X86_INS_JAE:
		case X86_INS_JA:
		case X86_INS_JBE:
		case X86_INS_JB:
		case X86_INS_JCXZ:
		case X86_INS_JECXZ:
		case X86_INS_JE:
		case X86_INS_JGE:
		case X86_INS_JG:
		case X86_INS_JLE:
		case X86_INS_JL:
		case X86_INS_JMP:
		case X86_INS_JNE:
		case X86_INS_JNO:
		case X86_INS_JNP:
		case X86_INS_JNS:
		case X86_INS_JO:
		case X86_INS_JP:
		case X86_INS_JRCXZ:
		case X86_INS_JS:

		case X86_INS_CALL:
		case X86_INS_RET:
		case X86_INS_RETF:
		case X86_INS_RETFQ:
			return true;
		}
	}

	// not found
	return false;
}
#endif

// given MCInst's id, find out if this insn is valid for REP prefix
static bool valid_rep(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	unsigned int i = find_insn_h(h, opcode);
	if (i != -1) {
		id = insns[i].mapid;
		switch (id) {
		default:
			return false;

		case X86_INS_MOVSB:
		case X86_INS_MOVSW:
		case X86_INS_MOVSQ:

		case X86_INS_LODSB:
		case X86_INS_LODSW:
		case X86_INS_LODSQ:

		case X86_INS_STOSB:
		case X86_INS_STOSW:
		case X86_INS_STOSQ:

		case X86_INS_INSB:
		case X86_INS_INSW:
		case X86_INS_INSD:

		case X86_INS_OUTSB:
		case X86_INS_OUTSW:
		case X86_INS_OUTSD:
			return true;

		// following are some confused instructions, which have the same
		// mnemonics in 128bit media instructions. Intel is horribly crazy!
		case X86_INS_MOVSD:
			if (opcode == X86_MOVSL) // REP MOVSD
				return true;
			return false;

		case X86_INS_LODSD:
			if (opcode == X86_LODSL) // REP LODSD
				return true;
			return false;

		case X86_INS_STOSD:
			if (opcode == X86_STOSL) // REP STOSD
				return true;
			return false;
		}
	}

	// not found
	return false;
}

#ifndef CAPSTONE_DIET
// given MCInst's id, find if this is a "repz ret" instruction
// gcc generates "repz ret" (f3 c3) instructions in some cases as an
// optimization for AMD platforms, see:
// https://gcc.gnu.org/legacy-ml/gcc-patches/2003-05/msg02117.html
static bool valid_ret_repz(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	unsigned int i = find_insn_h(h, opcode);

	if (i != -1) {
		id = insns[i].mapid;
		return id == X86_INS_RET;
	}

	// not found
	return false;
}
#endif

// given MCInst's id, find out if this insn is valid for REPE prefix
static bool valid_repe(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	unsigned int i = find_insn_h(h, opcode);
	if (i != -1) {
		id = insns[i].mapid;
		switch (id) {
		default:
			return false;

		case X86_INS_CMPSB:
		case X86_INS_CMPSW:
		case X86_INS_CMPSQ:

		case X86_INS_SCASB:
		case X86_INS_SCASW:
		case X86_INS_SCASQ:
			return true;

		// following are some confused instructions, which have the same
		// mnemonics in 128bit media instructions. Intel is horribly crazy!
		case X86_INS_CMPSD:
			if (opcode == X86_CMPSL) // REP CMPSD
				return true;
			return false;

		case X86_INS_SCASD:
			if (opcode == X86_SCASL) // REP SCASD
				return true;
			return false;
		}
	}

	// not found
	return false;
}

// Given MCInst's id, find out if this insn is valid for NOTRACK prefix.
// NOTRACK prefix is valid for CALL/JMP.
static bool valid_notrack(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	unsigned int i = find_insn_h(h, opcode);
	if (i != -1) {
		id = insns[i].mapid;
		switch (id) {
		default:
			return false;
		case X86_INS_CALL:
		case X86_INS_JMP:
			return true;
		}
	}

	// not found
	return false;
}

#ifndef CAPSTONE_DIET
// add *CX register to regs_read[] & regs_write[]
static void add_cx(MCInst *MI)
{
	if (MI->csh->detail_opt) {
		x86_reg cx;

		if (MI->csh->mode & CS_MODE_16)
			cx = X86_REG_CX;
		else if (MI->csh->mode & CS_MODE_32)
			cx = X86_REG_ECX;
		else // 64-bit
			cx = X86_REG_RCX;

		MI->flat_insn->detail
			->regs_read[MI->flat_insn->detail->regs_read_count] =
			cx;
		MI->flat_insn->detail->regs_read_count++;

		MI->flat_insn->detail
			->regs_write[MI->flat_insn->detail->regs_write_count] =
			cx;
		MI->flat_insn->detail->regs_write_count++;
	}
}
#endif

// return true if we patch the mnemonic
bool X86_lockrep(MCInst *MI, SStream *O)
{
	unsigned int opcode;
	bool res = false;

#ifndef CAPSTONE_DIET
	switch (MI->xAcquireRelease) {
	case 0xF2:
		SStream_concat(O, "xacquire|");
		break;
	case 0xF3:
		SStream_concat(O, "xrelease|");
		break;
	default:
		break;
	}
#endif

	if (MI->xAcquireRelease) {
		if (MI->x86Lock) {
			// Force LOCK prefix as group 0 prefix for XACQUIRE and XRELEASE if a LOCK is also present.
			// This is an arbitrary choice, since there are effectively two group 0 prefixes present.
			// The Intel SDM is not clear on how we should interpret group 0 in this case. It states:
			// "it is only useful to include up to one prefix code from each of the four groups"
			// ...and then defines instructions where both an F2/F3 and F0 are useful anyway.
			MI->x86_prefix[0] = 0xF0;
		}
	} else {
		switch (MI->x86_prefix[0]) {
		case 0xF2:
			opcode = MCInst_getOpcode(MI);
#ifndef CAPSTONE_DIET
			if (valid_repne(MI->csh, opcode)) {
				SStream_concat(O, "repne|");
				add_cx(MI);
			} else if (valid_bnd(MI->csh, opcode)) {
				SStream_concat(O, "bnd|");
			} else {
				// invalid prefix
				MI->x86_prefix[0] = 0;
			}
#else
			if (!valid_repne(MI->csh, opcode)) {
				MI->x86_prefix[0] = 0;
			}
#endif
			break;
		case 0xF3:
			opcode = MCInst_getOpcode(MI);
#ifndef CAPSTONE_DIET
			if (valid_rep(MI->csh, opcode)) {
				SStream_concat(O, "rep|");
				add_cx(MI);
			} else if (valid_repe(MI->csh, opcode)) {
				SStream_concat(O, "repe|");
				add_cx(MI);
			} else if (valid_ret_repz(MI->csh, opcode)) {
				SStream_concat(O, "repz|");
			} else {
				// invalid prefix
				MI->x86_prefix[0] = 0;
			}
#else
			if (!valid_rep(MI->csh, opcode) &&
			    !valid_repe(MI->csh, opcode)) {
				MI->x86_prefix[0] = 0;
			}
#endif
			break;
		default:
			break;
		}
	}

	// LOCK and F2/F3 may both be present (for XACQUIRE/XRELEASE).
	// There are also XRELEASEs that can be LOCKless.
	if (MI->x86Lock) {
		SStream_concat(O, "lock|");
	}

	switch (MI->x86_prefix[1]) {
	default:
		break;
	case 0x3e:
		opcode = MCInst_getOpcode(MI);
		if (valid_notrack(MI->csh, opcode)) {
			SStream_concat(O, "notrack|");
		}
		break;
	}

	// copy normalized prefix[] back to x86.prefix[]
	if (MI->csh->detail_opt)
		memcpy(MI->flat_insn->detail->x86.prefix, MI->x86_prefix,
		       ARR_SIZE(MI->x86_prefix));

	return res;
}

void op_addReg(MCInst *MI, int reg)
{
	if (MI->csh->detail_opt) {
		MI->flat_insn->detail->x86
			.operands[MI->flat_insn->detail->x86.op_count]
			.type = X86_OP_REG;
		MI->flat_insn->detail->x86
			.operands[MI->flat_insn->detail->x86.op_count]
			.reg = reg;
		MI->flat_insn->detail->x86
			.operands[MI->flat_insn->detail->x86.op_count]
			.size = MI->csh->regsize_map[reg];
		MI->flat_insn->detail->x86.op_count++;
	}

	if (MI->op1_size == 0)
		MI->op1_size = MI->csh->regsize_map[reg];
}

void op_addImm(MCInst *MI, int v)
{
	if (MI->csh->detail_opt) {
		MI->flat_insn->detail->x86
			.operands[MI->flat_insn->detail->x86.op_count]
			.type = X86_OP_IMM;
		MI->flat_insn->detail->x86
			.operands[MI->flat_insn->detail->x86.op_count]
			.imm = v;
		// if op_count > 0, then this operand's size is taken from the destination op
		if (MI->csh->syntax != CS_OPT_SYNTAX_ATT) {
			if (MI->flat_insn->detail->x86.op_count > 0)
				MI->flat_insn->detail->x86
					.operands[MI->flat_insn->detail->x86
							  .op_count]
					.size =
					MI->flat_insn->detail->x86.operands[0]
						.size;
			else
				MI->flat_insn->detail->x86
					.operands[MI->flat_insn->detail->x86
							  .op_count]
					.size = MI->imm_size;
		} else
			MI->has_imm = true;
		MI->flat_insn->detail->x86.op_count++;
	}

	if (MI->op1_size == 0)
		MI->op1_size = MI->imm_size;
}

void op_addXopCC(MCInst *MI, int v)
{
	if (MI->csh->detail_opt) {
		MI->flat_insn->detail->x86.xop_cc = v;
	}
}

void op_addSseCC(MCInst *MI, int v)
{
	if (MI->csh->detail_opt) {
		MI->flat_insn->detail->x86.sse_cc = v;
	}
}

void op_addAvxCC(MCInst *MI, int v)
{
	if (MI->csh->detail_opt) {
		MI->flat_insn->detail->x86.avx_cc = v;
	}
}

void op_addAvxRoundingMode(MCInst *MI, int v)
{
	if (MI->csh->detail_opt) {
		MI->flat_insn->detail->x86.avx_rm = v;
	}
}

// below functions supply details to X86GenAsmWriter*.inc
void op_addAvxZeroOpmask(MCInst *MI)
{
	if (MI->csh->detail_opt) {
		// link with the previous operand
		MI->flat_insn->detail->x86
			.operands[MI->flat_insn->detail->x86.op_count - 1]
			.avx_zero_opmask = true;
	}
}

void op_addAvxSae(MCInst *MI)
{
	if (MI->csh->detail_opt) {
		MI->flat_insn->detail->x86.avx_sae = true;
	}
}

void op_addAvxBroadcast(MCInst *MI, x86_avx_bcast v)
{
	if (MI->csh->detail_opt) {
		// link with the previous operand
		MI->flat_insn->detail->x86
			.operands[MI->flat_insn->detail->x86.op_count - 1]
			.avx_bcast = v;
	}
}

#ifndef CAPSTONE_DIET
// map instruction to its characteristics
typedef struct insn_op {
	uint64_t flags; // how this instruction update EFLAGS(arithmetic instructions) of FPU FLAGS(for FPU instructions)
	uint8_t access[6];
} insn_op;

static const insn_op insn_ops[] = {
#ifdef CAPSTONE_X86_REDUCE
#include "X86MappingInsnOp_reduce.inc"
#else
#include "X86MappingInsnOp.inc"
#endif
};

// given internal insn id, return operand access info
const uint8_t *X86_get_op_access(cs_struct *h, unsigned int id,
				 uint64_t *eflags)
{
	unsigned int i = find_insn_h(h, id);
	if (i != -1) {
		*eflags = insn_ops[i].flags;
		return insn_ops[i].access;
	}

	return NULL;
}

void X86_reg_access(const cs_insn *insn, cs_regs regs_read,
		    uint8_t *regs_read_count, cs_regs regs_write,
		    uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_x86 *x86 = &(insn->detail->x86);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read,
	       read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write,
	       write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);
		switch ((int)op->type) {
		case X86_OP_REG:
			if ((op->access & CS_AC_READ) &&
			    !arr_exist(regs_read, read_count, op->reg)) {
				regs_read[read_count] = op->reg;
				read_count++;
			}
			if ((op->access & CS_AC_WRITE) &&
			    !arr_exist(regs_write, write_count, op->reg)) {
				regs_write[write_count] = op->reg;
				write_count++;
			}
			break;
		case X86_OP_MEM:
			// registers appeared in memory references always being read
			if ((op->mem.segment != X86_REG_INVALID)) {
				regs_read[read_count] = op->mem.segment;
				read_count++;
			}
			if ((op->mem.base != X86_REG_INVALID) &&
			    !arr_exist(regs_read, read_count, op->mem.base)) {
				regs_read[read_count] = op->mem.base;
				read_count++;
			}
			if ((op->mem.index != X86_REG_INVALID) &&
			    !arr_exist(regs_read, read_count, op->mem.index)) {
				regs_read[read_count] = op->mem.index;
				read_count++;
			}
		default:
			break;
		}
	}

	*regs_read_count = read_count;
	*regs_write_count = write_count;
}
#endif

// map immediate size to instruction id
// this array is sorted for binary searching
static const struct size_id {
	uint8_t enc_size;
	uint8_t size;
	uint16_t id;
} x86_imm_size[] = {
#include "X86ImmSize.inc"
};

// given the instruction name, return the size of its immediate operand (or 0)
uint8_t X86_immediate_size(unsigned int id, uint8_t *enc_size)
{
	// binary searching since the IDs are sorted in order
	unsigned int left, right, m;

	right = ARR_SIZE(x86_imm_size) - 1;

	if (id < x86_imm_size[0].id || id > x86_imm_size[right].id)
		// not found
		return 0;

	left = 0;

	while (left <= right) {
		m = (left + right) / 2;
		if (id == x86_imm_size[m].id) {
			if (enc_size != NULL)
				*enc_size = x86_imm_size[m].enc_size;

			return x86_imm_size[m].size;
		}

		if (id > x86_imm_size[m].id)
			left = m + 1;
		else {
			if (m == 0)
				break;
			right = m - 1;
		}
	}

	// not found
	return 0;
}

#define GET_REGINFO_ENUM
#include "X86GenRegisterInfo.inc"

// map internal register id to public register id
static const struct register_map {
	unsigned short id;
	unsigned short pub_id;
} reg_map[] = {
	// first dummy map
	{ 0, 0 },
#include "X86MappingReg.inc"
};

// return 0 on invalid input, or public register ID otherwise
// NOTE: reg_map is sorted in order of internal register
unsigned short X86_register_map(unsigned short id)
{
	unsigned int extension = X86_featureExtensionMCRegisterMap(id);

	if (extension != X86_REG_INVALID)
		return (unsigned short)extension;
	if (id < ARR_SIZE(reg_map))
		return reg_map[id].pub_id;

	return 0;
}

static bool is_mask_register(x86_reg reg)
{
	return reg >= X86_REG_K0 && reg <= X86_REG_K7;
}

static uint8_t mask_instruction_operand_size(unsigned int id)
{
	switch (id) {
	default:
		return 0;
	case X86_INS_KADDB:
	case X86_INS_KANDB:
	case X86_INS_KANDNB:
	case X86_INS_KMOVB:
	case X86_INS_KNOTB:
	case X86_INS_KORB:
	case X86_INS_KORTESTB:
	case X86_INS_KSHIFTLB:
	case X86_INS_KSHIFTRB:
	case X86_INS_KTESTB:
	case X86_INS_KXNORB:
	case X86_INS_KXORB:
	case X86_INS_VPBROADCASTMB2Q:
		return 1;
	case X86_INS_KADDW:
	case X86_INS_KANDW:
	case X86_INS_KANDNW:
	case X86_INS_KMOVW:
	case X86_INS_KNOTW:
	case X86_INS_KORW:
	case X86_INS_KORTESTW:
	case X86_INS_KSHIFTLW:
	case X86_INS_KSHIFTRW:
	case X86_INS_KTESTW:
	case X86_INS_KXNORW:
	case X86_INS_KXORW:
	case X86_INS_VPBROADCASTMW2D:
		return 2;
	case X86_INS_KADDD:
	case X86_INS_KANDD:
	case X86_INS_KANDND:
	case X86_INS_KMOVD:
	case X86_INS_KNOTD:
	case X86_INS_KORD:
	case X86_INS_KORTESTD:
	case X86_INS_KSHIFTLD:
	case X86_INS_KSHIFTRD:
	case X86_INS_KTESTD:
	case X86_INS_KXNORD:
	case X86_INS_KXORD:
		return 4;
	case X86_INS_KADDQ:
	case X86_INS_KANDQ:
	case X86_INS_KANDNQ:
	case X86_INS_KMOVQ:
	case X86_INS_KNOTQ:
	case X86_INS_KORQ:
	case X86_INS_KORTESTQ:
	case X86_INS_KSHIFTLQ:
	case X86_INS_KSHIFTRQ:
	case X86_INS_KTESTQ:
	case X86_INS_KXNORQ:
	case X86_INS_KXORQ:
		return 8;
	}
}

static void set_mask_register_operand_size(cs_x86 *x86, uint8_t size)
{
	uint8_t i;

	for (i = 0; i < x86->op_count; ++i) {
		cs_x86_op *operand = &x86->operands[i];
		if (operand->type == X86_OP_REG &&
		    is_mask_register(operand->reg)) {
			operand->size = size;
		}
	}
}

static bool is_vector_register(x86_reg reg)
{
	return (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM31) ||
	       (reg >= X86_REG_YMM0 && reg <= X86_REG_YMM31) ||
	       (reg >= X86_REG_ZMM0 && reg <= X86_REG_ZMM31);
}

static bool mnemonic_has_suffix(const char *mnemonic, const char *suffix)
{
	size_t mnemonic_length = strlen(mnemonic);
	size_t suffix_length = strlen(suffix);

	return mnemonic_length >= suffix_length &&
	       strcmp(mnemonic + mnemonic_length - suffix_length, suffix) == 0;
}

static uint8_t vector_element_size(const char *mnemonic, bool *is_scalar)
{
	size_t length = strlen(mnemonic);
	char suffix;

	*is_scalar = false;
	if (mnemonic_has_suffix(mnemonic, "64"))
		return 8;
	if (mnemonic_has_suffix(mnemonic, "32"))
		return 4;
	if (mnemonic_has_suffix(mnemonic, "16"))
		return 2;
	if (mnemonic_has_suffix(mnemonic, "8"))
		return 1;
	if (mnemonic_has_suffix(mnemonic, "ss")) {
		*is_scalar = true;
		return 4;
	}
	if (mnemonic_has_suffix(mnemonic, "sd")) {
		*is_scalar = true;
		return 8;
	}
	if (mnemonic_has_suffix(mnemonic, "sh")) {
		*is_scalar = true;
		return 2;
	}
	if (mnemonic_has_suffix(mnemonic, "ps"))
		return 4;
	if (mnemonic_has_suffix(mnemonic, "pd"))
		return 8;
	if (mnemonic_has_suffix(mnemonic, "ph"))
		return 2;
	if (length >= 3 && mnemonic[length - 2] == '2' &&
	    mnemonic[length - 1] == 'm')
		suffix = mnemonic[length - 3];
	else if (length != 0)
		suffix = mnemonic[length - 1];
	else
		return 0;

	switch (suffix) {
	case 'b':
		return 1;
	case 'w':
		return 2;
	case 'd':
		return 4;
	case 'q':
		return 8;
	default:
		return 0;
	}
}

static uint8_t vector_compare_element_size(unsigned int id)
{
	switch (id) {
	default:
		return 0;
	case X86_INS_VPCMPB:
	case X86_INS_VPCMPUB:
		return 1;
	case X86_INS_VPCMPW:
	case X86_INS_VPCMPUW:
		return 2;
	case X86_INS_VPCMPD:
	case X86_INS_VPCMPUD:
		return 4;
	case X86_INS_VPCMPQ:
	case X86_INS_VPCMPUQ:
		return 8;
	}
}

static uint8_t vector_unpack_element_size(unsigned int id)
{
	switch (id) {
	default:
		return 0;
	case X86_INS_VPUNPCKLBW:
	case X86_INS_VPUNPCKHBW:
		return 1;
	case X86_INS_VPUNPCKLWD:
	case X86_INS_VPUNPCKHWD:
		return 2;
	case X86_INS_VPUNPCKLDQ:
	case X86_INS_VPUNPCKHDQ:
		return 4;
	case X86_INS_VPUNPCKLQDQ:
	case X86_INS_VPUNPCKHQDQ:
		return 8;
	}
}

static uint8_t vector_dot_product_destination_element_size(unsigned int id)
{
	switch (id) {
	default:
		return 0;
	case X86_INS_VP4DPWSSD:
	case X86_INS_VP4DPWSSDS:
	case X86_INS_VPDPBUSDS:
	case X86_INS_VPDPBUSD:
	case X86_INS_VPDPWSSDS:
	case X86_INS_VPDPWSSD:
		return 4;
	}
}

static uint8_t vector_narrow_source_element_size(unsigned int id)
{
	switch (id) {
	default:
		return 0;
	case X86_INS_VCVTPS2PH:
		return 4;
	case X86_INS_VPMOVWB:
	case X86_INS_VPMOVSWB:
	case X86_INS_VPMOVUSWB:
		return 2;
	case X86_INS_VPMOVDB:
	case X86_INS_VPMOVDW:
	case X86_INS_VPMOVSDB:
	case X86_INS_VPMOVSDW:
	case X86_INS_VPMOVUSDB:
	case X86_INS_VPMOVUSDW:
		return 4;
	case X86_INS_VPMOVQB:
	case X86_INS_VPMOVQW:
	case X86_INS_VPMOVQD:
	case X86_INS_VPMOVSQB:
	case X86_INS_VPMOVSQW:
	case X86_INS_VPMOVSQD:
	case X86_INS_VPMOVUSQB:
	case X86_INS_VPMOVUSQW:
	case X86_INS_VPMOVUSQD:
		return 8;
	}
}

static uint8_t vector_conversion_destination_element_size(unsigned int id)
{
	switch (id) {
	default:
		return 0;
	case X86_INS_VCVTPS2DQ:
	case X86_INS_VCVTPD2DQ:
	case X86_INS_VCVTPS2UDQ:
	case X86_INS_VCVTPD2UDQ:
	case X86_INS_VCVTTPS2DQ:
	case X86_INS_VCVTTPD2DQ:
	case X86_INS_VCVTTPS2UDQ:
	case X86_INS_VCVTTPD2UDQ:
		return 4;
	}
}

static uint8_t vector_width_conversion_wide_element_size(unsigned int id)
{
	switch (id) {
	default:
		return 0;
	case X86_INS_VCVTPD2PS:
	case X86_INS_VCVTPS2PD:
		return 8;
	}
}

static uint8_t vector_scalar_broadcast_element_size(unsigned int id)
{
	switch (id) {
	default:
		return 0;
	case X86_INS_VBROADCASTSS:
	case X86_INS_VPBROADCASTD:
		return 4;
	case X86_INS_VBROADCASTSD:
	case X86_INS_VPBROADCASTQ:
		return 8;
	case X86_INS_VPBROADCASTB:
		return 1;
	case X86_INS_VPBROADCASTW:
		return 2;
	}
}

static uint8_t normalized_mask_size(unsigned int lanes)
{
	unsigned int bytes = (lanes + 7) / 8;

	if (bytes <= 1)
		return 1;
	if (bytes <= 2)
		return 2;
	if (bytes <= 4)
		return 4;
	return 8;
}

static bool is_vfpclass(unsigned int id)
{
	return id == X86_INS_VFPCLASSPS || id == X86_INS_VFPCLASSPD ||
	       id == X86_INS_VFPCLASSSS || id == X86_INS_VFPCLASSSD;
}

static void repair_vector_mask_sizes(cs_x86 *x86, const SStream *assembly,
				     unsigned int instruction_id)
{
	char mnemonic[CS_MNEMONIC_SIZE] = { 0 };
	char operands[2] = { 0 };
	uint8_t written_vector_size = 0;
	uint8_t vector_size = 0;
	uint8_t element_size;
	uint8_t mask_size;
	bool scalar = false;
	uint8_t i;

	element_size = vector_narrow_source_element_size(instruction_id);
	if (element_size != 0) {
		for (i = 0; i < x86->op_count; ++i) {
			const cs_x86_op *operand = &x86->operands[i];

			if (operand->type == X86_OP_REG &&
			    is_vector_register(operand->reg) &&
			    operand->size > vector_size)
				vector_size = operand->size;
		}
		if (vector_size != 0) {
			mask_size = normalized_mask_size(vector_size / element_size);
			set_mask_register_operand_size(x86, mask_size);
		}
		return;
	}

	element_size =
		vector_width_conversion_wide_element_size(instruction_id);
	if (element_size != 0) {
		for (i = 0; i < x86->op_count; ++i) {
			const cs_x86_op *operand = &x86->operands[i];

			if (operand->type == X86_OP_REG &&
			    is_vector_register(operand->reg) &&
			    operand->size > vector_size)
				vector_size = operand->size;
		}
		if (vector_size != 0) {
			mask_size = normalized_mask_size(vector_size / element_size);
			set_mask_register_operand_size(x86, mask_size);
		}
		return;
	}

	SStream_extract_mnem_opstr(assembly, mnemonic, sizeof(mnemonic),
				   operands, sizeof(operands));
	element_size = vector_compare_element_size(instruction_id);
	if (element_size == 0)
		element_size = vector_unpack_element_size(instruction_id);
	if (element_size == 0)
		element_size =
			vector_dot_product_destination_element_size(instruction_id);
	if (element_size == 0)
		element_size =
			vector_conversion_destination_element_size(instruction_id);
	if (element_size == 0)
		element_size =
			vector_scalar_broadcast_element_size(instruction_id);
	if (element_size == 0)
		element_size = vector_element_size(mnemonic, &scalar);
	if (element_size == 0)
		return;
	for (i = 0; i < x86->op_count; ++i) {
		const cs_x86_op *operand = &x86->operands[i];

		if (operand->type != X86_OP_REG ||
		    !is_vector_register(operand->reg))
			continue;
		if (operand->size > vector_size)
			vector_size = operand->size;
		if ((operand->access & CS_AC_WRITE) &&
		    operand->size > written_vector_size)
			written_vector_size = operand->size;
	}
	if (written_vector_size != 0)
		vector_size = written_vector_size;
	if (vector_size == 0 && is_vfpclass(instruction_id)) {
		for (i = 0; i < x86->op_count; ++i) {
			const cs_x86_op *operand = &x86->operands[i];
			unsigned int lanes = 0;

			if (operand->type != X86_OP_MEM)
				continue;
			if (scalar) {
				vector_size = element_size;
				break;
			}
			switch (operand->avx_bcast) {
			default:
				vector_size = operand->size;
				break;
			case X86_AVX_BCAST_2:
				lanes = 2;
				break;
			case X86_AVX_BCAST_4:
				lanes = 4;
				break;
			case X86_AVX_BCAST_8:
				lanes = 8;
				break;
			case X86_AVX_BCAST_16:
				lanes = 16;
				break;
			}
			if (lanes != 0)
				vector_size = element_size * lanes;
			break;
		}
	}
	if (vector_size == 0)
		return;
	mask_size = normalized_mask_size(
		scalar ? 1 : (vector_size + element_size - 1) / element_size);
	set_mask_register_operand_size(x86, mask_size);
}

static void repair_vfpclass_mask_access(csh handle, cs_insn *insn)
{
	cs_struct *capstone = (cs_struct *)(uintptr_t)handle;
	cs_detail *detail = insn->detail;
	cs_x86 *x86 = &detail->x86;
	cs_x86_op *destination = NULL;
	cs_x86_op *writemask = NULL;
	x86_reg destination_reg;
	uint8_t i;

	if (!is_vfpclass(insn->id))
		return;
	for (i = 0; i < x86->op_count; ++i) {
		cs_x86_op *operand = &x86->operands[i];
		if (operand->type != X86_OP_REG || !is_mask_register(operand->reg))
			continue;
		if (destination == NULL)
			destination = operand;
		else if (writemask == NULL)
			writemask = operand;
	}
	if (destination == NULL)
		return;
	if (capstone->syntax == CS_OPT_SYNTAX_ATT && writemask != NULL) {
		cs_x86_op *temporary = destination;
		destination = writemask;
		writemask = temporary;
	}
	destination->access = CS_AC_WRITE;
	if (writemask != NULL)
		writemask->access = CS_AC_READ;
	destination_reg = destination->reg;
	if (writemask == NULL || writemask->reg != destination_reg) {
		for (i = 0; i < detail->regs_read_count; ++i) {
			if (detail->regs_read[i] != destination_reg)
				continue;
			memmove(&detail->regs_read[i], &detail->regs_read[i + 1],
				(detail->regs_read_count - i - 1) *
					sizeof(detail->regs_read[0]));
			--detail->regs_read_count;
			break;
		}
	}
	for (i = 0; i < detail->regs_write_count; ++i)
		if (detail->regs_write[i] == destination_reg)
			return;
	detail->regs_write[detail->regs_write_count++] = destination_reg;
}

static void repair_avx_broadcast(cs_x86 *x86, const SStream *assembly)
{
	x86_avx_bcast broadcast = X86_AVX_BCAST_INVALID;
	uint8_t i;

	if (strstr(assembly->buffer, "{1to16}") != NULL)
		broadcast = X86_AVX_BCAST_16;
	else if (strstr(assembly->buffer, "{1to8}") != NULL)
		broadcast = X86_AVX_BCAST_8;
	else if (strstr(assembly->buffer, "{1to4}") != NULL)
		broadcast = X86_AVX_BCAST_4;
	else if (strstr(assembly->buffer, "{1to2}") != NULL)
		broadcast = X86_AVX_BCAST_2;
	if (broadcast == X86_AVX_BCAST_INVALID)
		return;
	for (i = 0; i < x86->op_count; ++i) {
		if (x86->operands[i].type == X86_OP_MEM) {
			x86->operands[i].avx_bcast = broadcast;
			return;
		}
	}
}

static void repair_vpcmp_id(cs_insn *insn, const SStream *assembly, MCInst *mci)
{
	char mnemonic[CS_MNEMONIC_SIZE] = { 0 };
	char operands[2] = { 0 };
	size_t length;

	if (insn->id != X86_INS_VPCMP)
		return;
	SStream_extract_mnem_opstr(assembly, mnemonic, sizeof(mnemonic),
				   operands, sizeof(operands));
	if (strncmp(mnemonic, "vpcmp", 5) != 0)
		return;

	// The condition printer's pseudo-ID adjustment assumes that every
	// predicate spelling has a contiguous public ID. Integer compares expose
	// element-family IDs instead, so applying that adjustment can collide with
	// an unrelated instruction. Normalize aliases to their family ID here.
	mci->popcode_adjust = 0;
	length = strlen(mnemonic);
	if (mnemonic_has_suffix(mnemonic, "ub"))
		insn->id = X86_INS_VPCMPUB;
	else if (mnemonic_has_suffix(mnemonic, "uw"))
		insn->id = X86_INS_VPCMPUW;
	else if (mnemonic_has_suffix(mnemonic, "ud"))
		insn->id = X86_INS_VPCMPUD;
	else if (mnemonic_has_suffix(mnemonic, "uq"))
		insn->id = X86_INS_VPCMPUQ;
	else if (length != 0) {
		switch (mnemonic[length - 1]) {
		case 'b':
			insn->id = X86_INS_VPCMPB;
			break;
		case 'w':
			insn->id = X86_INS_VPCMPW;
			break;
		case 'd':
			insn->id = X86_INS_VPCMPD;
			break;
		case 'q':
			insn->id = X86_INS_VPCMPQ;
			break;
		default:
			break;
		}
	}
}

static void repair_vector_mask_conversion_access(cs_x86 *x86,
						 unsigned int instruction_id)
{
	cs_x86_op *mask = NULL;
	cs_x86_op *vector = NULL;
	bool vector_is_destination;
	uint8_t i;

	switch (instruction_id) {
	default:
		return;
	case X86_INS_VPMOVM2B:
	case X86_INS_VPMOVM2W:
	case X86_INS_VPMOVM2D:
	case X86_INS_VPMOVM2Q:
		vector_is_destination = true;
		break;
	case X86_INS_VPMOVB2M:
	case X86_INS_VPMOVW2M:
	case X86_INS_VPMOVD2M:
	case X86_INS_VPMOVQ2M:
		vector_is_destination = false;
		break;
	}

	for (i = 0; i < x86->op_count; ++i) {
		cs_x86_op *operand = &x86->operands[i];

		if (operand->type != X86_OP_REG)
			continue;
		if (is_mask_register(operand->reg)) {
			if (mask != NULL)
				return;
			mask = operand;
		} else if (is_vector_register(operand->reg)) {
			if (vector != NULL)
				return;
			vector = operand;
		}
	}
	if (mask == NULL || vector == NULL)
		return;

	vector->access = vector_is_destination ? CS_AC_WRITE : CS_AC_READ;
	mask->access = vector_is_destination ? CS_AC_READ : CS_AC_WRITE;
}

static void repair_vector_narrow_access(cs_x86 *x86,
					unsigned int instruction_id)
{
	uint8_t i;

	if (vector_narrow_source_element_size(instruction_id) == 0)
		return;
	for (i = 0; i < x86->op_count; ++i) {
		cs_x86_op *operand = &x86->operands[i];

		if (operand->type == X86_OP_MEM) {
			operand->access |= CS_AC_WRITE;
		} else if (operand->type == X86_OP_REG &&
			   is_mask_register(operand->reg)) {
			operand->access |= CS_AC_READ;
		} else if (operand->type == X86_OP_REG &&
			   is_vector_register(operand->reg) &&
			   (operand->access & CS_AC_WRITE) == 0) {
			operand->access |= CS_AC_READ;
		}
	}
}

static void repair_kmask_access(csh handle, cs_insn *insn)
{
	static const uint64_t mask_test_eflags =
		X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_ZF |
		X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_SF |
		X86_EFLAGS_RESET_AF | X86_EFLAGS_RESET_PF;
	cs_struct *capstone = (cs_struct *)(uintptr_t)handle;
	cs_x86 *x86 = &insn->detail->x86;
	bool is_test = false;
	bool writes_destination = false;
	uint8_t destination_index = 0;
	uint8_t i;

	switch (insn->id) {
	default:
		return;
	case X86_INS_KADDB:
	case X86_INS_KADDW:
	case X86_INS_KADDD:
	case X86_INS_KADDQ:
	case X86_INS_KUNPCKBW:
	case X86_INS_KUNPCKWD:
	case X86_INS_KUNPCKDQ:
		writes_destination = true;
		break;
	case X86_INS_KTESTB:
	case X86_INS_KTESTW:
	case X86_INS_KTESTD:
	case X86_INS_KTESTQ:
	case X86_INS_KORTESTB:
	case X86_INS_KORTESTW:
	case X86_INS_KORTESTD:
	case X86_INS_KORTESTQ:
		is_test = true;
		break;
	}

	if (writes_destination) {
		if (x86->op_count != 3)
			return;
		destination_index = capstone->syntax == CS_OPT_SYNTAX_ATT ? 2 :
									    0;
	} else if (x86->op_count != 2) {
		return;
	}
	for (i = 0; i < x86->op_count; ++i) {
		if (x86->operands[i].type != X86_OP_REG ||
		    !is_mask_register(x86->operands[i].reg))
			return;
	}
	for (i = 0; i < x86->op_count; ++i) {
		x86->operands[i].access =
			writes_destination && i == destination_index ?
				CS_AC_WRITE :
				CS_AC_READ;
	}

	if (is_test) {
		insn->detail->regs_write[0] = X86_REG_EFLAGS;
		insn->detail->regs_write_count = 1;
		x86->eflags = mask_test_eflags;
	}
}

/// The post-printer function. Used to fixup flaws in the disassembly information
/// of certain instructions.
void X86_postprinter(csh handle, cs_insn *insn, SStream *mnem, MCInst *mci)
{
	uint8_t mask_operand_size;

	if (!insn) {
		return;
	}
	repair_vpcmp_id(insn, mnem, mci);
	if (!insn->detail) {
		return;
	}
	repair_avx_broadcast(&insn->detail->x86, mnem);
	mask_operand_size = mask_instruction_operand_size(insn->id);
	if (mask_operand_size != 0) {
		set_mask_register_operand_size(&insn->detail->x86,
					       mask_operand_size);
	} else {
		repair_vector_mask_sizes(&insn->detail->x86, mnem, insn->id);
	}
	repair_vector_mask_conversion_access(&insn->detail->x86, insn->id);
	repair_vector_narrow_access(&insn->detail->x86, insn->id);
	repair_kmask_access(handle, insn);
	repair_vfpclass_mask_access(handle, insn);
	switch (insn->id) {
	default:
		break;
	case X86_INS_RCL:
		// Addmissing 1 immediate
		if (insn->detail->x86.op_count > 1) {
			return;
		}
		insn->detail->x86.operands[1].imm = 1;
		insn->detail->x86.operands[1].type = X86_OP_IMM;
		insn->detail->x86.operands[1].access = CS_AC_READ;
		insn->detail->x86.op_count++;
		break;
	}
}

#endif

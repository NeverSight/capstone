//===-- X86Disassembler.cpp - Disassembler for x86 and x86_64 -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is part of the X86 Disassembler.
// It contains code to translate the data produced by the decoder into
//  MCInsts.
//
// The X86 disassembler is a table-driven disassembler for the 16-, 32-, and
// 64-bit X86 instruction sets.  The main decode sequence for an assembly
// instruction in this disassembler is:
//
// 1. Read the prefix bytes and determine the attributes of the instruction.
//    These attributes, recorded in enum attributeBits
//    (X86DisassemblerDecoderCommon.h), form a bitmask.  The table CONTEXTS_SYM
//    provides a mapping from bitmasks to contexts, which are represented by
//    enum InstructionContext (ibid.).
//
// 2. Read the opcode, and determine what kind of opcode it is.  The
//    disassembler distinguishes four kinds of opcodes, which are enumerated in
//    OpcodeType (X86DisassemblerDecoderCommon.h): one-byte (0xnn), two-byte
//    (0x0f 0xnn), three-byte-38 (0x0f 0x38 0xnn), or three-byte-3a
//    (0x0f 0x3a 0xnn).  Mandatory prefixes are treated as part of the context.
//
// 3. Depending on the opcode type, look in one of four ClassDecision structures
//    (X86DisassemblerDecoderCommon.h).  Use the opcode class to determine which
//    OpcodeDecision (ibid.) to look the opcode in.  Look up the opcode, to get
//    a ModRMDecision (ibid.).
//
// 4. Some instructions, such as escape opcodes or extended opcodes, or even
//    instructions that have ModRM*Reg / ModRM*Mem forms in LLVM, need the
//    ModR/M byte to complete decode.  The ModRMDecision's type is an entry from
//    ModRMDecisionType (X86DisassemblerDecoderCommon.h) that indicates if the
//    ModR/M byte is required and how to interpret it.
//
// 5. After resolving the ModRMDecision, the disassembler has a unique ID
//    of type InstrUID (X86DisassemblerDecoderCommon.h).  Looking this ID up in
//    INSTRUCTIONS_SYM yields the name of the instruction and the encodings and
//    meanings of its operands.
//
// 6. For each operand, its encoding is an entry from OperandEncoding
//    (X86DisassemblerDecoderCommon.h) and its type is an entry from
//    OperandType (ibid.).  The encoding indicates how to read it from the
//    instruction; the type indicates how to interpret the value once it has
//    been read.  For example, a register operand could be stored in the R/M
//    field of the ModR/M byte, the REG field of the ModR/M byte, or added to
//    the main opcode.  This is orthogonal from its meaning (an GPR or an XMM
//    register, for instance).  Given this information, the operands can be
//    extracted and interpreted.
//
// 7. As the last step, the disassembler translates the instruction information
//    and operands into a format understandable by the client - in this case, an
//    MCInst for use by the MC infrastructure.
//
// The disassembler is broken broadly into two parts: the table emitter that
// emits the instruction decode tables discussed above during compilation, and
// the disassembler itself.  The table emitter is documented in more detail in
// utils/TableGen/X86DisassemblerEmitter.h.
//
// X86Disassembler.cpp contains the code responsible for step 7, and for
//   invoking the decoder to execute steps 1-6.
// X86DisassemblerDecoderCommon.h contains the definitions needed by both the
//   table emitter and the disassembler.
// X86DisassemblerDecoder.h contains the public interface of the decoder,
//   factored out into C for possible use by other projects.
// X86DisassemblerDecoder.c contains the source code of the decoder, which is
//   responsible for steps 1-6.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_X86

#ifdef _MSC_VER
// disable MSVC's warning on strncpy()
#pragma warning(disable : 4996)
// disable MSVC's warning on strncpy()
#pragma warning(disable : 28719)
#endif

#include <capstone/platform.h>

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#endif

#include <string.h>

#include "../../cs_priv.h"

#include "X86BaseInfo.h"
#include "X86Disassembler.h"
#include "X86DisassemblerDecoderCommon.h"
#include "X86DisassemblerDecoder.h"
#include "../../MCInst.h"
#include "../../utils.h"
#include "X86FeatureExtension.h"
#include "X86Mapping.h"

#include "X86DisassemblerTranslator.h"

#define GET_REGINFO_MC_DESC
#include "X86GenRegisterInfo.inc"

#ifndef CAPSTONE_X86_REDUCE
static bool gfniAffineBroadcastNeedsDisp8Scale(
	const InternalInstruction *insn)
{
	unsigned int i;

	switch (insn->instructionID) {
	default:
		return false;
	case X86_VGF2P8AFFINEINVQBZ128rmbi:
	case X86_VGF2P8AFFINEINVQBZ128rmbik:
	case X86_VGF2P8AFFINEINVQBZ128rmbikz:
	case X86_VGF2P8AFFINEINVQBZ256rmbi:
	case X86_VGF2P8AFFINEINVQBZ256rmbik:
	case X86_VGF2P8AFFINEINVQBZ256rmbikz:
	case X86_VGF2P8AFFINEINVQBZrmbi:
	case X86_VGF2P8AFFINEINVQBZrmbik:
	case X86_VGF2P8AFFINEINVQBZrmbikz:
	case X86_VGF2P8AFFINEQBZ128rmbi:
	case X86_VGF2P8AFFINEQBZ128rmbik:
	case X86_VGF2P8AFFINEQBZ128rmbikz:
	case X86_VGF2P8AFFINEQBZ256rmbi:
	case X86_VGF2P8AFFINEQBZ256rmbik:
	case X86_VGF2P8AFFINEQBZ256rmbikz:
	case X86_VGF2P8AFFINEQBZrmbi:
	case X86_VGF2P8AFFINEQBZrmbik:
	case X86_VGF2P8AFFINEQBZrmbikz:
		break;
	}

	for (i = 0; i < X86_MAX_OPERANDS; ++i) {
		const OperandSpecifier *operand = &insn->operands[i];

		if (operand->type == TYPE_M)
			return operand->encoding == ENCODING_RM;
	}
	return false;
}
#endif

// copy x86 detail information from internal structure to public structure
static void update_pub_insn(cs_insn *pub, InternalInstruction *inter)
{
	if (inter->hasRex2) {
		/* REX2.M0 selects the generated map internally; 0F is not present
		 * in the architectural encoding. */
		pub->detail->x86.opcode[0] = inter->opcode;
	} else if (inter->vectorExtensionType != 0) {
		memcpy(pub->detail->x86.opcode, inter->vectorExtensionPrefix,
		       sizeof(pub->detail->x86.opcode));
	} else {
		if (inter->twoByteEscape) {
			if (inter->threeByteEscape) {
				pub->detail->x86.opcode[0] =
					inter->twoByteEscape;
				pub->detail->x86.opcode[1] =
					inter->threeByteEscape;
				pub->detail->x86.opcode[2] = inter->opcode;
			} else {
				pub->detail->x86.opcode[0] =
					inter->twoByteEscape;
				pub->detail->x86.opcode[1] = inter->opcode;
			}
		} else {
			pub->detail->x86.opcode[0] = inter->opcode;
		}
	}

	/* rexPrefix carries a synthetic low REX nibble while decoding REX2. */
	pub->detail->x86.rex = inter->hasRex2 ? 0 : inter->rexPrefix;
	pub->detail->x86.rex2 = inter->hasRex2 ? inter->rex2Prefix : 0;

	pub->detail->x86.addr_size = inter->addressSize;

	pub->detail->x86.modrm = inter->orgModRM;
	pub->detail->x86.encoding.modrm_offset = inter->modRMOffset;

	pub->detail->x86.sib = inter->sib;
	pub->detail->x86.sib_index = x86_map_sib_index(inter->sibIndex);
	pub->detail->x86.sib_scale = inter->sibScale;
	pub->detail->x86.sib_base = x86_map_sib_base(inter->sibBase);
	if (inter->apxEvexB4 && inter->sibBase != SIB_BASE_NONE) {
		const unsigned int number =
			16 |
			(bFromEVEX2of4(inter->vectorExtensionPrefix[1]) << 3) |
			(inter->sib & 7);

		pub->detail->x86.sib_base = X86_register_map(
			(unsigned short)X86_featureExtensionMCGPR(
					number, inter->addressSize));
	}
	if (inter->hasRex2 && b4FromREX2(inter->rex2Prefix) &&
	    inter->sibBase != SIB_BASE_NONE) {
		const unsigned int number =
			16 | (b3FromREX2(inter->rex2Prefix) << 3) |
			(inter->sib & 7);

		pub->detail->x86.sib_base = X86_register_map(
			(unsigned short)X86_featureExtensionMCGPR(
				number, inter->addressSize));
	}
	if (inter->apxEvexGprIndex) {
		const unsigned int number =
			16 |
			(xFromEVEX2of4(inter->vectorExtensionPrefix[1]) << 3) |
			((inter->sib >> 3) & 7);

		pub->detail->x86.sib_index = X86_register_map(
			(unsigned short)X86_featureExtensionMCGPR(
					number, inter->addressSize));
	}
	if (inter->hasRex2 && x4FromREX2(inter->rex2Prefix) &&
	    inter->consumedSIB) {
		const unsigned int number =
			16 | (x3FromREX2(inter->rex2Prefix) << 3) |
			((inter->sib >> 3) & 7);

		pub->detail->x86.sib_index = X86_register_map(
			(unsigned short)X86_featureExtensionMCGPR(
				number, inter->addressSize));
	}

	pub->detail->x86.disp = inter->displacement;
	if (inter->consumedDisplacement) {
		pub->detail->x86.encoding.disp_offset =
			inter->displacementOffset;
		pub->detail->x86.encoding.disp_size = inter->displacementSize;
	}

	pub->detail->x86.encoding.imm_offset = inter->immediateOffset;
	if (pub->detail->x86.encoding.imm_size == 0 &&
	    inter->immediateOffset != 0)
		pub->detail->x86.encoding.imm_size = inter->immediateSize;
}

void X86_init(MCRegisterInfo *MRI)
{
	// InitMCRegisterInfo(), X86GenRegisterInfo.inc
	// RI->InitMCRegisterInfo(X86RegDesc, 277,
	//                        RA, PC,
	//                        X86MCRegisterClasses, 86,
	//                        X86RegUnitRoots, 162, X86RegDiffLists, X86LaneMaskLists, X86RegStrings,
	//                        X86RegClassStrings,
	//                        X86SubRegIdxLists, 9,
	//                        X86SubRegIdxRanges, X86RegEncodingTable);
	/*
	   InitMCRegisterInfo(X86RegDesc, 234,
	   RA, PC,
	   X86MCRegisterClasses, 79,
	   X86RegUnitRoots, 119, X86RegDiffLists, X86RegStrings,
	   X86SubRegIdxLists, 7,
	   X86SubRegIdxRanges, X86RegEncodingTable);
	*/

	MCRegisterInfo_InitMCRegisterInfo(MRI, X86RegDesc, 277, 0, 0,
					  X86MCRegisterClasses, 86, 0, 0,
					  X86RegDiffLists, 0, X86SubRegIdxLists,
					  9, 0);
}

static bool is_x86_segment_override(uint8_t prefix)
{
	return prefix == 0x26 || prefix == 0x2e || prefix == 0x36 ||
	       prefix == 0x3e || prefix == 0x64 || prefix == 0x65;
}

static bool scan_x86_evex_prefix(const uint8_t *code, size_t code_len,
				 bool is_64_bit, size_t *evex_offset,
				 unsigned int *segment_count,
				 unsigned int *address_size_count,
				 bool *invalid_prefix)
{
	size_t offset = 0;

	*segment_count = 0;
	*address_size_count = 0;
	*invalid_prefix = false;
	while (offset < code_len) {
		const uint8_t prefix = code[offset];

		if (prefix == 0x62) {
			/* Outside 64-bit mode, 62 /r remains the BOUND opcode unless
			 * the next two bytes have the fixed EVEX structure. */
			if (!is_64_bit &&
			    (code_len - offset < 3 ||
			     (code[offset + 1] & 0xc0) != 0xc0 ||
			     (code[offset + 1] & 0x0c) != 0 ||
			     (code[offset + 2] & 0x04) == 0))
				return false;
			*evex_offset = offset;
			return true;
		}
		if (is_x86_segment_override(prefix))
			++*segment_count;
		else if (prefix == 0x67)
			++*address_size_count;
		else if (prefix == 0x66 || prefix == 0xf0 ||
			 prefix == 0xf2 || prefix == 0xf3 ||
			 (is_64_bit && prefix >= 0x40 && prefix <= 0x4f))
			*invalid_prefix = true;
		else
			return false;
		++offset;
	}
	return false;
}

/* Keep EVEX normalization state off the ordinary decoding path. */
#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static int
decodeEVEXInstruction(InternalInstruction *insn, const uint8_t *code,
		      size_t code_len, cs_mode mode,
		      bool *scalar_compare_p2_normalized,
		      uint8_t *original_scalar_compare_p2)
{
	const uint8_t *decode_code = code;
	size_t decode_size = code_len;
	uint8_t normalized_code[15];
	size_t evex_normalization_limit = 0;
	size_t evex_normalization_offset = 0;
	unsigned int evex_segment_count = 0;
	unsigned int evex_address_size_count = 0;
	bool evex_invalid_prefix = false;
	bool has_evex_normalization_prefix = false;
	uint8_t apx_evex_p0 = 0, apx_evex_p1 = 0;
	bool apx_evex_normalized = false;
	bool apx_evex_b4 = false, apx_evex_x4 = false;
	evex_normalization_limit = code_len < sizeof(normalized_code) ?
					   code_len :
					   sizeof(normalized_code);
	has_evex_normalization_prefix = scan_x86_evex_prefix(
		code, evex_normalization_limit, (mode & CS_MODE_64) != 0,
		&evex_normalization_offset, &evex_segment_count,
		&evex_address_size_count, &evex_invalid_prefix);

	/* Packed VCMPPS/PD uses EVEX.L'L as its vector length unless EVEX.b
	 * selects SAE and a fixed 512-bit length for a register source.  The
	 * generated decoder accepts reserved LL=3 memory and non-SAE register
	 * forms. */
	if (has_evex_normalization_prefix &&
	    evex_normalization_limit - evex_normalization_offset >= 7 &&
	    (code[evex_normalization_offset + 1] & 7) == 1 &&
	    ((code[evex_normalization_offset + 2] & 0x83) == 0x00 ||
	     (code[evex_normalization_offset + 2] & 0x83) == 0x81) &&
	    code[evex_normalization_offset + 4] == 0xc2) {
		const uint8_t p2 = code[evex_normalization_offset + 3];
		const uint8_t ll = (p2 >> 5) & 3;
		const bool b = (p2 & 0x10) != 0;
		const bool memory =
			(code[evex_normalization_offset + 5] & 0xc0) != 0xc0;

		if (evex_invalid_prefix || evex_segment_count > 1 ||
		    evex_address_size_count > 1 || (ll == 3 && !(b && !memory)))
			return -1;
	}

	/* Scalar VCMPSS/SD treats EVEX.L'L as LLIG when EVEX.b is clear.
	 * The generated decoder only contains the LL=0 spelling.  EVEX.b is
	 * SAE for a register source and remains reserved for a memory source. */
	if (has_evex_normalization_prefix &&
	    evex_normalization_limit - evex_normalization_offset >= 7 &&
	    (code[evex_normalization_offset + 1] & 7) == 1 &&
	    ((code[evex_normalization_offset + 2] & 0x83) == 0x02 ||
	     (code[evex_normalization_offset + 2] & 0x83) == 0x83) &&
	    code[evex_normalization_offset + 4] == 0xc2) {
		const uint8_t ll = (code[evex_normalization_offset + 3] >> 5) &
				   3;
		const bool b = (code[evex_normalization_offset + 3] & 0x10) !=
			       0;
		const bool memory =
			(code[evex_normalization_offset + 5] & 0xc0) != 0xc0;

		if (evex_invalid_prefix || evex_segment_count > 1 ||
		    evex_address_size_count > 1 || (memory && b) ||
		    (!b && ll == 3))
			return -1;
		if (!b && ll != 0) {
			memcpy(normalized_code, decode_code,
			       evex_normalization_limit);
			normalized_code[evex_normalization_offset + 3] &= ~0x60;
			decode_code = normalized_code;
			decode_size = evex_normalization_limit;
			*scalar_compare_p2_normalized = true;
		}
	}

	/* AVX512ER uses EVEX.L'L as LLIG for scalar register/memory forms
	 * without EVEX.b.  The generated decoder only has the LL=0 spelling,
	 * so canonicalize the other legal spellings after rejecting reserved
	 * combinations.  Packed forms remain fixed at 512 bits; EVEX.b means
	 * SAE for a register source and broadcast for a memory source. */
	if (has_evex_normalization_prefix &&
	    evex_normalization_limit - evex_normalization_offset >= 6 &&
	    (code[evex_normalization_offset + 1] & 7) == 2 &&
	    (code[evex_normalization_offset + 2] & 3) == 1 &&
	    (code[evex_normalization_offset + 4] == 0xc8 ||
	     (code[evex_normalization_offset + 4] >= 0xca &&
	      code[evex_normalization_offset + 4] <= 0xcd))) {
		const uint8_t ll = (code[evex_normalization_offset + 3] >> 5) &
				   3;
		const bool b = (code[evex_normalization_offset + 3] & 0x10) !=
			       0;
		const bool memory =
			(code[evex_normalization_offset + 5] & 0xc0) != 0xc0;
		const bool scalar = code[evex_normalization_offset + 4] ==
					    0xcb ||
				    code[evex_normalization_offset + 4] == 0xcd;

		if (evex_invalid_prefix || evex_segment_count > 1 ||
		    evex_address_size_count > 1)
			return -1;

		if (scalar) {
			if ((memory && b) || (!b && ll == 3))
				return -1;
			if (!b && ll != 0) {
				memcpy(normalized_code, decode_code,
				       evex_normalization_limit);
				normalized_code[evex_normalization_offset + 3] &=
					~0x60;
				decode_code = normalized_code;
				decode_size = evex_normalization_limit;
			}
		} else if (!(b && !memory) && ll != 2) {
			return -1;
		}
	}
	/* VRCP14/VRSQRT14 scalar forms are LLIG when EVEX.b is clear;
	 * packed forms use LL as their actual vector length.  EVEX.b is only
	 * defined for packed memory broadcast and is reserved for registers and
	 * all scalar forms. */
	if (has_evex_normalization_prefix &&
	    evex_normalization_limit - evex_normalization_offset >= 6 &&
	    (code[evex_normalization_offset + 1] & 7) == 2 &&
	    (code[evex_normalization_offset + 2] & 3) == 1 &&
	    code[evex_normalization_offset + 4] >= 0x4c &&
	    code[evex_normalization_offset + 4] <= 0x4f) {
		const uint8_t ll = (code[evex_normalization_offset + 3] >> 5) &
				   3;
		const bool b = (code[evex_normalization_offset + 3] & 0x10) !=
			       0;
		const bool memory =
			(code[evex_normalization_offset + 5] & 0xc0) != 0xc0;
		const bool scalar = (code[evex_normalization_offset + 4] & 1) !=
				    0;

		if (evex_invalid_prefix || evex_segment_count > 1 ||
		    evex_address_size_count > 1)
			return -1;

		if (ll == 3 || (b && (!memory || scalar)))
			return -1;
		if (scalar && ll != 0) {
			memcpy(normalized_code, decode_code,
			       evex_normalization_limit);
			normalized_code[evex_normalization_offset + 3] &= ~0x60;
			decode_code = normalized_code;
			decode_size = evex_normalization_limit;
		}
	}
	/* Scalar VFPCLASSSS/SD treats EVEX.L'L as LLIG for its register and
	 * m32/m64 source forms.  The generated tables only contain LL=0. */
	if (has_evex_normalization_prefix &&
	    evex_normalization_limit - evex_normalization_offset >= 7 &&
	    (code[evex_normalization_offset + 1] & 7) == 3 &&
	    (code[evex_normalization_offset + 2] & 3) == 1 &&
	    code[evex_normalization_offset + 4] == 0x67) {
		const uint8_t ll = (code[evex_normalization_offset + 3] >> 5) &
				   3;
		const bool b = (code[evex_normalization_offset + 3] & 0x10) !=
			       0;

		if (evex_invalid_prefix || evex_segment_count > 1 ||
		    evex_address_size_count > 1)
			return -1;

		if (ll == 3 || b)
			return -1;
		if (ll != 0) {
			memcpy(normalized_code, decode_code,
			       evex_normalization_limit);
			normalized_code[evex_normalization_offset + 3] &= ~0x60;
			decode_code = normalized_code;
			decode_size = evex_normalization_limit;
		}
	}
	/* Scalar AVX512_4FMAPS encodings are EVEX.LLIG, except that the
	 * reserved L'L = 11 is #UD.  LLVM's generated decoder contains only the
	 * LL=0 spelling, so canonicalize LL without changing EVEX.b, z, aaa, or
	 * any operand bits.  Packed PS opcodes are deliberately excluded because
	 * their vector length remains fixed. */
	{
		if (has_evex_normalization_prefix &&
		    evex_normalization_limit - evex_normalization_offset >= 6 &&
		    (code[evex_normalization_offset + 1] & 7) == 2 &&
		    (code[evex_normalization_offset + 2] & 3) == 3 &&
		    (code[evex_normalization_offset + 4] == 0x9b ||
		     code[evex_normalization_offset + 4] == 0xab)) {
			const uint8_t p2 = code[evex_normalization_offset + 3];
			const uint8_t ll = (p2 >> 5) & 3;
			const uint8_t mask = p2 & 7;
			const bool broadcast = (p2 & 0x10) != 0;
			const bool zeroing = (p2 & 0x80) != 0;

			if (evex_invalid_prefix || evex_segment_count > 1 ||
			    evex_address_size_count > 1 || broadcast ||
			    (zeroing && mask == 0) || ll == 3)
				return -1;
			if (ll != 0) {
				memcpy(normalized_code, decode_code,
				       evex_normalization_limit);
				normalized_code[evex_normalization_offset + 3] &=
					~0x60;
				decode_code = normalized_code;
				decode_size = evex_normalization_limit;
			}
		}
	}

	/* Intel APX extends every existing EVEX instruction so a GPR r/m,
	 * memory base, or ordinary SIB index can address R16-R31.  The generated
	 * decoder predates APX and treats B4=1 or U=0 (X4=1) as a malformed EVEX
	 * prefix.  Normalize only those two bits for table lookup, then retain the
	 * architectural values for operand translation and public raw detail.
	 * VSIB continues to use V4 for its vector index; X4 is ignored there.
	 * A register r/m has no index, so U=0 remains #UD there, as in XED. */
	{
		if (has_evex_normalization_prefix &&
		    evex_normalization_limit - evex_normalization_offset >= 6 &&
		    code[evex_normalization_offset] == 0x62 &&
		    (code[evex_normalization_offset + 1] & 7) >= 1 &&
		    (code[evex_normalization_offset + 1] & 7) <= 3 &&
		    ((code[evex_normalization_offset + 1] & 0x08) != 0 ||
		     (code[evex_normalization_offset + 2] & 0x04) == 0)) {
			const uint8_t modrm =
				code[evex_normalization_offset + 5];

			if (!(mode & CS_MODE_64) || evex_invalid_prefix ||
			    evex_segment_count > 1 ||
			    evex_address_size_count > 1 ||
			    ((modrm & 0xc0) == 0xc0 &&
			     (code[evex_normalization_offset + 2] & 0x04) == 0))
				return -1;
			apx_evex_p0 = code[evex_normalization_offset + 1];
			apx_evex_p1 = code[evex_normalization_offset + 2];
			apx_evex_b4 = (apx_evex_p0 & 0x08) != 0;
			apx_evex_x4 = (modrm & 0xc0) != 0xc0 &&
				      (apx_evex_p1 & 0x04) == 0;
			if (decode_code != normalized_code)
				memcpy(normalized_code, decode_code,
				       evex_normalization_limit);
			normalized_code[evex_normalization_offset + 1] &= ~0x08;
			normalized_code[evex_normalization_offset + 2] |= 0x04;
			decode_code = normalized_code;
			decode_size = evex_normalization_limit;
			apx_evex_normalized = true;
		}
	}

	const int ret = decodeInstruction(insn, decode_code, decode_size, mode);

	/* No further byte reads follow decoding; keep the input pointer valid
	 * when the local normalization buffer goes out of scope. */
	insn->code = code;
	insn->codeSize = code_len;
	if (ret)
		return ret;
	if (apx_evex_normalized) {
		insn->apxEvexB4 = apx_evex_b4;
		insn->apxEvexX4 = apx_evex_x4;
		insn->vectorExtensionPrefix[1] = apx_evex_p0;
		insn->vectorExtensionPrefix[2] = apx_evex_p1;
	}
	if (*scalar_compare_p2_normalized)
		*original_scalar_compare_p2 =
			code[evex_normalization_offset + 3];
	return 0;
}

// Public interface for the disassembler
bool X86_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *_info)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	bool scalar_compare_p2_normalized = false;
	uint8_t original_scalar_compare_p2 = 0;
	uint8_t extension_opcode;
	x86_feature_decode_result extension_result;
	int ret;
	bool result;

	if (instr->flat_insn->detail) {
		// instr->flat_insn->detail initialization: 3 alternatives

		// 1. The whole structure, this is how it's done in other arch disassemblers
		// Probably overkill since cs_detail is huge because of the 36 operands of ARM

		//memset(instr->flat_insn->detail, 0, sizeof(cs_detail));

		// 2. Only the part relevant to x86
		memset(instr->flat_insn->detail, 0,
		       offsetof(cs_detail, x86) + sizeof(cs_x86));

		// 3. The relevant part except for x86.operands
		// sizeof(cs_x86) is 0x1c0, sizeof(x86.operands) is 0x180
		// marginally faster, should be okay since x86.op_count is set to 0

		//memset(instr->flat_insn->detail, 0, offsetof(cs_detail, x86)+offsetof(cs_x86, operands));
	}

	extension_result = X86_FEATURE_NOT_HANDLED;
	if (X86_mayDecodeFeatureExtension(code, code_len,
					  (handle->mode & CS_MODE_64) != 0,
					  &extension_opcode))
		extension_result = X86_decodeFeatureExtension(
			ud, code, code_len, instr, size, extension_opcode);
	if (extension_result == X86_FEATURE_DECODED) {
		return true;
	}
	if (extension_result == X86_FEATURE_INVALID)
		return false;

	InternalInstruction insn = { 0 };
	if (extension_opcode == 0x62)
		ret = decodeEVEXInstruction(&insn, code, code_len, handle->mode,
					    &scalar_compare_p2_normalized,
					    &original_scalar_compare_p2);
	else if (handle->no_text && !handle->detail_opt) {
		ret = decodeInstructionScan(&insn, code, code_len, handle->mode,
					    instr, size);
		if (ret != X86_SCAN_RAW_READY)
			return ret == X86_SCAN_COMPLETE;
		ret = 0;
	} else
		ret = decodeInstruction(&insn, code, code_len, handle->mode);

	if (ret) {
		return false;
	} else {
		*size = (uint16_t)insn.length;

#ifndef CAPSTONE_X86_REDUCE
		if (insn.displacementSize == 1 &&
		    gfniAffineBroadcastNeedsDisp8Scale(&insn))
			insn.displacement *= 8;
#endif

		if (handle->no_text && !handle->detail_opt)
			return !translateInstruction(instr, &insn, false);
		result = !translateInstruction(instr, &insn, true);
		if (result) {
			unsigned Flags = X86_IP_NO_PREFIX;
			if (scalar_compare_p2_normalized)
				insn.vectorExtensionPrefix[3] =
					original_scalar_compare_p2;
			instr->imm_size = insn.immSize;

			// copy all prefixes
			instr->x86_prefix[0] = insn.prefix0;
			instr->x86_prefix[1] = insn.prefix1;
			instr->x86_prefix[2] = insn.prefix2;
			instr->x86_prefix[3] = insn.prefix3;
			instr->xAcquireRelease = insn.xAcquireRelease;
			instr->x86Lock = insn.hasLockPrefix;

			if (handle->detail_opt) {
				update_pub_insn(instr->flat_insn, &insn);
			}

			if (insn.hasAdSize)
				Flags |= X86_IP_HAS_AD_SIZE;

			if (insn.hasOpSize)
				Flags |= X86_IP_HAS_OP_SIZE;

			if (insn.repeatPrefix == 0xf2)
				Flags |= X86_IP_HAS_REPEAT_NE;
			else if (insn.repeatPrefix == 0xf3 &&
				 // It should not be 'pause' f3 90
				 insn.opcode != 0x90)
				Flags |= X86_IP_HAS_REPEAT;
			if (insn.hasLockPrefix)
				Flags |= X86_IP_HAS_LOCK;

			for (int i = 0; i < X86_MAX_OPERANDS; ++i) {
				if (insn.operands[i].encoding ==
				    ENCODING_WRITEMASK) {
					Flags |= X86_IP_HAS_EVEX_OPMASK;
					break;
				}
			}

			instr->flags = Flags;
		}

		return result;
	}
}

#endif

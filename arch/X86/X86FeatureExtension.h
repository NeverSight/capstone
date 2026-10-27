/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_FEATURE_EXTENSION_H
#define CS_X86_FEATURE_EXTENSION_H

#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../cs_priv.h"

/* Keep scan entries and hot tables aligned when adjacent cold code changes. */
#if defined(__GNUC__)
#define X86_DECODE_ALIGN __attribute__((aligned(128)))
#else
#define X86_DECODE_ALIGN
#endif

// Keep source-owned instruction extensions outside the generated opcode range.
#define X86_FEATURE_OPCODE_BASE 0x10000U
#define X86_FEATURE_TILEZERO X86_FEATURE_OPCODE_BASE
#define X86_FEATURE_REX2_MOV 0x10001U
#define X86_FEATURE_REX2_ADD 0x10002U
#define X86_FEATURE_LDTILECFG 0x10003U
#define X86_FEATURE_STTILECFG 0x10004U
#define X86_FEATURE_TILELOADD 0x10005U
#define X86_FEATURE_TILELOADDT1 0x10006U
#define X86_FEATURE_TILERELEASE 0x10007U
#define X86_FEATURE_TILESTORED 0x10008U
#define X86_FEATURE_TDPBSSD 0x10009U
#define X86_FEATURE_TDPBSUD 0x1000aU
#define X86_FEATURE_TDPBUSD 0x1000bU
#define X86_FEATURE_TDPBUUD 0x1000cU
#define X86_FEATURE_TDPBF16PS 0x1000dU
#define X86_FEATURE_TDPFP16PS 0x1000eU
#define X86_FEATURE_TCMMIMFP16PS 0x1000fU
#define X86_FEATURE_TCMMRLFP16PS 0x10010U
#define X86_FEATURE_REX2_SUB 0x10011U
#define X86_FEATURE_REX2_AND 0x10012U
#define X86_FEATURE_REX2_OR 0x10013U
#define X86_FEATURE_REX2_XOR 0x10014U
#define X86_FEATURE_REX2_CMP 0x10015U
#define X86_FEATURE_REX2_TEST 0x10016U
#define X86_FEATURE_TDPBF8PS 0x10017U
#define X86_FEATURE_TDPBHF8PS 0x10018U
#define X86_FEATURE_TDPHBF8PS 0x10019U
#define X86_FEATURE_TDPHF8PS 0x1001aU
#define X86_FEATURE_TMMULTF32PS 0x1001bU
#define X86_FEATURE_JMPABS 0x1001cU
#define X86_FEATURE_PUSH2 0x1001dU
#define X86_FEATURE_PUSH2P 0x1001eU
#define X86_FEATURE_POP2 0x1001fU
#define X86_FEATURE_POP2P 0x10020U
#define X86_FEATURE_REX2_PUSH 0x10021U
#define X86_FEATURE_REX2_POP 0x10022U
#define X86_FEATURE_PUSHP 0x10023U
#define X86_FEATURE_POPP 0x10024U
#define X86_FEATURE_APX_SETCC_BASE 0x10025U
#define X86_FEATURE_APX_SETZUCC_BASE 0x10035U
#define X86_FEATURE_APX_SETCC_COUNT 16U
#define X86_FEATURE_APX_CMOVCC_BASE 0x10045U
#define X86_FEATURE_APX_CFCMOVCC_BASE 0x10055U
#define X86_FEATURE_APX_CMOVCC_COUNT 16U
#define X86_FEATURE_TILELOADDRS 0x10065U
#define X86_FEATURE_TILELOADDRST1 0x10066U
#define X86_FEATURE_TILEMOVROW 0x10067U
#define X86_FEATURE_TCVTROWD2PS 0x10068U
#define X86_FEATURE_TCVTROWPS2BF16H 0x10069U
#define X86_FEATURE_TCVTROWPS2BF16L 0x1006aU
#define X86_FEATURE_TCVTROWPS2PHH 0x1006bU
#define X86_FEATURE_TCVTROWPS2PHL 0x1006cU
#define X86_FEATURE_APX_ROL 0x1006dU
#define X86_FEATURE_APX_ROR 0x1006eU
#define X86_FEATURE_APX_RCL 0x1006fU
#define X86_FEATURE_APX_RCR 0x10070U
#define X86_FEATURE_APX_SHL 0x10071U
#define X86_FEATURE_APX_SHR 0x10072U
#define X86_FEATURE_APX_SAR 0x10073U
#define X86_FEATURE_APX_IMUL 0x10074U
#define X86_FEATURE_APX_ADC 0x10075U
#define X86_FEATURE_APX_SBB 0x10076U
#define X86_FEATURE_APX_ADCX 0x10077U
#define X86_FEATURE_APX_ADOX 0x10078U
#define X86_FEATURE_APX_INC 0x10079U
#define X86_FEATURE_APX_DEC 0x1007aU
#define X86_FEATURE_APX_NEG 0x1007bU
#define X86_FEATURE_APX_NOT 0x1007cU
#define X86_FEATURE_APX_MUL 0x1007dU
#define X86_FEATURE_APX_DIV 0x1007eU
#define X86_FEATURE_APX_IDIV 0x1007fU
#define X86_FEATURE_APX_ANDN 0x10080U
#define X86_FEATURE_APX_BZHI 0x10081U
#define X86_FEATURE_APX_BLSR 0x10082U
#define X86_FEATURE_APX_BLSMSK 0x10083U
#define X86_FEATURE_APX_BLSI 0x10084U
#define X86_FEATURE_APX_BEXTR 0x10085U
#define X86_FEATURE_APX_LZCNT 0x10086U
#define X86_FEATURE_APX_TZCNT 0x10087U
#define X86_FEATURE_APX_POPCNT 0x10088U
#define X86_FEATURE_APX_SARX 0x10089U
#define X86_FEATURE_APX_SHLX 0x1008aU
#define X86_FEATURE_APX_SHRX 0x1008bU
#define X86_FEATURE_APX_RORX 0x1008cU
#define X86_FEATURE_APX_MULX 0x1008dU
#define X86_FEATURE_APX_MOVBE 0x1008eU
#define X86_FEATURE_APX_CRC32 0x1008fU
#define X86_FEATURE_APX_PDEP 0x10090U
#define X86_FEATURE_APX_PEXT 0x10091U
#define X86_FEATURE_APX_SHLD 0x10092U
#define X86_FEATURE_APX_SHRD 0x10093U
#define X86_FEATURE_APX_MOVDIRI 0x10094U
#define X86_FEATURE_APX_WRSSD 0x10095U
#define X86_FEATURE_APX_WRSSQ 0x10096U
#define X86_FEATURE_APX_WRUSSD 0x10097U
#define X86_FEATURE_APX_WRUSSQ 0x10098U
#define X86_FEATURE_APX_ENQCMD 0x10099U
#define X86_FEATURE_APX_ENQCMDS 0x1009aU
#define X86_FEATURE_APX_MOVDIR64B 0x1009bU
#define X86_FEATURE_APX_AADD 0x1009cU
#define X86_FEATURE_APX_AAND 0x1009dU
#define X86_FEATURE_APX_AOR 0x1009eU
#define X86_FEATURE_APX_AXOR 0x1009fU
#define X86_FEATURE_APX_CMPCCXADD_BASE 0x100a0U
#define X86_FEATURE_APX_CCMP_BASE 0x100b0U
#define X86_FEATURE_APX_CTEST_BASE 0x100c0U
#define X86_FEATURE_APX_KMOV_BASE 0x100d0U
#define X86_FEATURE_APX_MOVRS 0x100d4U
#define X86_FEATURE_APX_INV_BASE 0x100d5U
#define X86_FEATURE_APX_IMUL_IMMEDIATE 0x100d8U
#define X86_FEATURE_APX_IMUL_ONE 0x100d9U
#define X86_FEATURE_APX_VPBROADCAST_BASE 0x100daU
#define X86_FEATURE_APX_VPBROADCAST_COUNT 4U
#define X86_FEATURE_APX_RDMSR_IMM 0x100deU
#define X86_FEATURE_APX_WRMSRNS_IMM 0x100dfU
#define X86_FEATURE_APX_URDMSR 0x100e0U
#define X86_FEATURE_APX_UWRMSR 0x100e1U
#define X86_FEATURE_VSHA512MSG1 0x100e2U
#define X86_FEATURE_VSHA512MSG2 0x100e3U
#define X86_FEATURE_VSHA512RNDS2 0x100e4U
#define X86_FEATURE_APX_ADD 0x100e5U
#define X86_FEATURE_APX_OR 0x100e6U
#define X86_FEATURE_APX_AND 0x100e7U
#define X86_FEATURE_APX_SUB 0x100e8U
#define X86_FEATURE_APX_XOR 0x100e9U
#define X86_FEATURE_APX_IMULZU_IMMEDIATE 0x100eaU
#define X86_FEATURE_WRMSRNS 0x100ebU
#define X86_FEATURE_RDMSRLIST 0x100ecU
#define X86_FEATURE_WRMSRLIST 0x100edU
#define X86_FEATURE_CLUI 0x100eeU
#define X86_FEATURE_STUI 0x100efU
#define X86_FEATURE_TESTUI 0x100f0U
#define X86_FEATURE_SENDUIPI 0x100f1U
#define X86_FEATURE_LKGS 0x100f2U
#define X86_FEATURE_HRESET 0x100f3U
#define X86_FEATURE_INVLPGB 0x100f4U
#define X86_FEATURE_TLBSYNC 0x100f5U

// Generated x86 register identifiers stop at R15.  These private MC register
// identifiers let the generated EVEX printer carry APX R16-R31 operands while
// the public API continues to expose the normal X86_REG_R16...R31 values.
#define X86_FEATURE_MC_GPR_BASE 0x8000U
#define X86_FEATURE_MC_GPR_BANK_SIZE 16U
#define X86_FEATURE_MC_GPR_BANK_COUNT 4U

typedef enum x86_feature_decode_result {
	X86_FEATURE_NOT_HANDLED,
	X86_FEATURE_DECODED,
	X86_FEATURE_INVALID,
} x86_feature_decode_result;

/* Keep compact legacy exclusions in the low four bits. */
enum {
	FEATURE_LEGACY_PREFIX = 1,
	FEATURE_REX_PREFIX = 2,
	FEATURE_ESCAPE = 4,
	FEATURE_VEX2_XOP = 8,
	FEATURE_0F_ESCAPE = 16,
};

static const uint8_t feature_prefix_flags[256] X86_DECODE_ALIGN = {
	/* 0x00 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
	/* 0x10 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x20 */ 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
	/* 0x30 */ 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
	/* 0x40 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	/* 0x50 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x60 */ 0, 0, 4, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x70 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0x80 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
	/* 0x90 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0xa0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0xb0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0xc0 */ 0, 0, 0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0xd0 */ 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0xe0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 0xf0 */ 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static inline CS_PRESERVE_MOST bool
may_be_0f_feature_extension(const uint8_t *suffix, size_t size)
{
	return (size >= 1 && suffix[0] == 0x38) ||
	       (size >= 2 &&
		((suffix[0] == 0x00 && (suffix[1] & 0x38) == 0x30) ||
		 (suffix[0] == 0xc7 && (suffix[1] & 0xf8) == 0xf0) ||
		 (suffix[0] == 0x3a && suffix[1] == 0xf0))) ||
	       (size >= 2 && suffix[0] == 0x01 &&
		(suffix[1] == 0xc6 || suffix[1] == 0xca || suffix[1] == 0xed ||
		 suffix[1] == 0xee || suffix[1] == 0xef || suffix[1] == 0xfe ||
		 suffix[1] == 0xff));
}

/* The selector and dispatcher share the source-owned VEX families. */
typedef enum x86_vex_feature_family {
	X86_VEX_FEATURE_NONE,
	X86_VEX_FEATURE_ATOMIC,
	X86_VEX_FEATURE_SHA512,
	X86_VEX_FEATURE_AMX,
	X86_VEX_FEATURE_SYSTEM,
} x86_vex_feature_family;

static inline x86_vex_feature_family X86_vexFeatureFamily(uint8_t map,
							  uint8_t opcode)
{
	switch (map) {
	case 2:
		if (opcode >= 0xe0 && opcode <= 0xef)
			return X86_VEX_FEATURE_ATOMIC;
		if (opcode >= 0xcb && opcode <= 0xcd)
			return X86_VEX_FEATURE_SHA512;
		if ((opcode >= 0x48 && opcode <= 0x4b) || opcode == 0x5c ||
		    opcode == 0x5e || opcode == 0x6c)
			return X86_VEX_FEATURE_AMX;
		return X86_VEX_FEATURE_NONE;
	case 5:
		return opcode == 0xfd ? X86_VEX_FEATURE_AMX :
					X86_VEX_FEATURE_NONE;
	case 7:
		return X86_VEX_FEATURE_SYSTEM;
	default:
		return X86_VEX_FEATURE_NONE;
	}
}

/* Classify prefixes and escapes in one lookup. In 16/32-bit modes the
 * 40..4f opcodes end the scan; subsequent instructions cannot be extensions
 * of the current INC/DEC. opcode receives the first non-prefix byte, or zero
 * if the input is empty or contains only prefixes. */
static inline bool X86_mayDecodeFeatureExtensionImpl(const uint8_t *code,
						     size_t code_len,
						     bool is_64_bit,
						     uint8_t *opcode,
						     size_t *opcodeOffset)
{
	const uint8_t prefix_mask = FEATURE_LEGACY_PREFIX |
				    (is_64_bit ? FEATURE_REX_PREFIX : 0);
	size_t offset = 0;

	*opcode = 0;
	if (opcodeOffset)
		*opcodeOffset = SIZE_MAX;
	while (offset < code_len) {
		uint8_t byte = code[offset];
		uint8_t flags = feature_prefix_flags[byte];
		++offset;
		if (flags & prefix_mask)
			continue;
		*opcode = byte;
		if (opcodeOffset)
			*opcodeOffset = offset - 1;
		if (flags == FEATURE_0F_ESCAPE)
			return may_be_0f_feature_extension(code + offset,
							   code_len - offset);
		if (flags != FEATURE_ESCAPE)
			return false;
		/* VEX map 1 is entirely handled by the generated decoder. */
		return byte != 0xc4 || offset == code_len ||
		       (code[offset] & 0x1f) != 1;
	}
	return false;
}

static inline bool X86_mayDecodeFeatureExtension(const uint8_t *code,
						 size_t code_len,
						 bool is_64_bit,
						 uint8_t *opcode)
{
	return X86_mayDecodeFeatureExtensionImpl(code, code_len, is_64_bit,
						 opcode, NULL);
}

/* Called only after X86_mayDecodeFeatureExtension selects an escape. */
x86_feature_decode_result
X86_decodeFeatureExtension(csh handle, const uint8_t *code, size_t code_len,
			   MCInst *instr, uint16_t *size, uint8_t opcode);
bool X86_printFeatureExtension(MCInst *instr, SStream *stream, bool att_syntax);
bool X86_mapFeatureExtension(cs_insn *insn, unsigned int opcode);
const char *X86_featureExtensionRegisterName(unsigned int reg);
const char *X86_featureExtensionInstructionName(unsigned int id);
unsigned int X86_featureExtensionMCGPR(unsigned int number, uint8_t width);
unsigned int X86_featureExtensionMCRegisterMap(unsigned int reg);
const char *X86_featureExtensionMCRegisterName(unsigned int reg);

#endif

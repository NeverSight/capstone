/*===-- X86DisassemblerDecoder.c - Disassembler decoder ------------*- C -*-===*
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===----------------------------------------------------------------------===*
 *
 * This file is part of the X86 Disassembler.
 * It contains the implementation of the instruction decoder.
 * Documentation for the disassembler can be found in X86Disassembler.h.
 *
 *===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_X86

#include <stdarg.h> /* for va_*()       */
#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stdlib.h> /* for exit()       */
#endif

#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "X86DisassemblerDecoder.h"
#include "X86Disassembler.h"
#include "X86Mapping.h"
#include "X86FeatureExtension.h"
#include "X86DisassemblerTranslator.h"
#include "X86ScanAdapter.h"
#include "X86InstPrinterCommon.h"

#if defined(_MSC_VER)
#define X86_DECODE_INLINE static __forceinline
#elif defined(__GNUC__)
#define X86_DECODE_INLINE static inline __attribute__((always_inline))
#else
#define X86_DECODE_INLINE static inline
#endif

/// Specifies whether a ModR/M byte is needed and (if so) which
/// instruction each possible value of the ModR/M byte corresponds to.  Once
/// this information is known, we have narrowed down to a single instruction.
struct ModRMDecision {
	uint32_t packed;
};

/// Specifies which set of ModR/M->instruction tables to look at
/// given a particular opcode.
struct OpcodeDecision {
	struct ModRMDecision modRMDecisions[256];
};

/// Specifies which opcode->instruction tables to look at given
/// a particular context (set of attributes).  Since there are many possible
/// contexts, the decoder first uses CONTEXTS_SYM to determine which context
/// applies given a specific set of attributes.  Hence there are only IC_max
/// entries in this table, rather than 2^(ATTR_max).
struct ContextDecision {
	struct OpcodeDecision opcodeDecisions[IC_max];
};

#ifdef CAPSTONE_X86_REDUCE
#include "X86GenDisassemblerTables_reduce.inc"
#include "X86GenDisassemblerTablesPacked_reduce.inc"
#include "X86Lookup16_reduce.inc"
#else
#include "X86GenDisassemblerTables.inc"
#include "X86GenDisassemblerTablesPacked.inc"
#include "X86Lookup16.inc"
#endif

/*
 * contextForAttrs - Client for the instruction context table.  Takes a set of
 *   attributes and returns the appropriate decode context.
 *
 * @param attrMask  - Attributes, from the enumeration attributeBits.
 * @return          - The InstructionContext to use when looking up an
 *                    an instruction with these attributes.
 */
static InstructionContext contextForAttrs(uint16_t attrMask)
{
	return CONTEXTS_SYM[attrMask];
}

/* Resolve the context/opcode table once, before consuming ModR/M. */
static const struct ModRMDecision *
getModRMDecision(OpcodeType type, InstructionContext insnContext,
		 uint8_t opcode)
{
	const struct OpcodeDecision *decision;
	const uint8_t *indextable;
	static const struct ModRMDecision emptyDecision = { 0 };
	unsigned int index;

	switch (type) {
	default:
		return NULL;
	case ONEBYTE:
		decision = ONEBYTE_SYM;
		indextable = index_x86DisassemblerOneByteOpcodes;
		break;
	case TWOBYTE:
		decision = TWOBYTE_SYM;
		indextable = index_x86DisassemblerTwoByteOpcodes;
		break;
	case THREEBYTE_38:
		decision = THREEBYTE38_SYM;
		indextable = index_x86DisassemblerThreeByte38Opcodes;
		break;
	case THREEBYTE_3A:
		decision = THREEBYTE3A_SYM;
		indextable = index_x86DisassemblerThreeByte3AOpcodes;
		break;
#ifndef CAPSTONE_X86_REDUCE
	case XOP8_MAP:
		decision = XOP8_MAP_SYM;
		indextable = index_x86DisassemblerXOP8Opcodes;
		break;
	case XOP9_MAP:
		decision = XOP9_MAP_SYM;
		indextable = index_x86DisassemblerXOP9Opcodes;
		break;
	case XOPA_MAP:
		decision = XOPA_MAP_SYM;
		indextable = index_x86DisassemblerXOPAOpcodes;
		break;
	case THREEDNOW_MAP:
		decision = THREEDNOW_MAP_SYM;
		indextable = index_x86Disassembler3DNowOpcodes;
		break;
#endif
	}

	index = indextable[insnContext];
	return index ? &decision[index - 1].modRMDecisions[opcode] :
		       &emptyDecision;
}

#if defined(_MSC_VER)
static __forceinline InstrUID
#else
#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline InstrUID
#endif
decode(uint32_t packed, uint8_t modRM)
{
	unsigned int offset;

	if (!(packed & X86_DECISION_INDEXED)) {
		unsigned int shift = modFromModRM(modRM) == 0x3 ?
					     X86_DECISION_REGISTER_SHIFT :
					     0;
		return (packed >> shift) & X86_DECISION_UID_MASK;
	}
	offset = packed & X86_DECISION_OFFSET_MASK;
	switch ((packed >> X86_DECISION_TYPE_SHIFT) & X86_DECISION_TYPE_MASK) {
	default:
		return 0;
	case MODRM_SPLITREG:
		if (modFromModRM(modRM) == 0x3)
			return modRMTable[offset + ((modRM & 0x38) >> 3) + 8];
		return modRMTable[offset + ((modRM & 0x38) >> 3)];
	case MODRM_SPLITMISC:
		if (modFromModRM(modRM) == 0x3)
			return modRMTable[offset + (modRM & 0x3f) + 8];
		return modRMTable[offset + ((modRM & 0x38) >> 3)];
	case MODRM_FULL:
		return modRMTable[offset + modRM];
	}
}

/*
 * specifierForUID - Given a UID, returns the name and operand specification for
 *   that instruction.
 *
 * @param uid - The unique ID for the instruction.  This should be returned by
 *              decode(); specifierForUID will not check bounds.
 * @return    - A pointer to the specification for that instruction.
 */
static const struct InstructionSpecifier *specifierForUID(InstrUID uid)
{
	return &INSTRUCTIONS_SYM[uid];
}

/*
 * consumeByte - Read one byte from the input and advance the cursor.
 *
 * @param insn  - The instruction with the input buffer to use.  The cursor
 *                for this instruction is advanced.
 * @param byte  - A pointer to a pre-allocated memory buffer to be populated
 *                with the data read.
 * @return      - 0 if the read was successful; nonzero otherwise.
 */
static int consumeByte(struct InternalInstruction *insn, uint8_t *byte)
{
	size_t offset = insn->readerCursor;
	if (offset >= insn->codeSize)
		return -1;
	*byte = insn->code[offset];
	++insn->readerCursor;
	return 0;
}

/*
 * lookAtByte - Like consumeByte, but does not advance the cursor.
 *
 * @param insn  - See consumeByte().
 * @param byte  - See consumeByte().
 * @return      - See consumeByte().
 */
static int lookAtByte(struct InternalInstruction *insn, uint8_t *byte)
{
	size_t offset = insn->readerCursor;
	if (offset >= insn->codeSize)
		return -1;
	*byte = insn->code[offset];
	return 0;
}

static void unconsumeByte(struct InternalInstruction *insn)
{
	insn->readerCursor--;
}

#define CONSUME_FUNC(name, type) \
	X86_DECODE_INLINE int name(struct InternalInstruction *insn, \
				   type *ptr) \
	{ \
		uint64_t combined = 0; \
		size_t cursor = insn->readerCursor; \
		unsigned offset; \
		if (cursor > insn->codeSize || \
		    sizeof(type) > insn->codeSize - cursor) \
			return -1; \
		for (offset = 0; offset < sizeof(type); ++offset) { \
			combined |= (uint64_t)insn->code[cursor + offset] \
				    << (offset * 8); \
		} \
		*ptr = (type)combined; \
		insn->readerCursor += sizeof(type); \
		return 0; \
	}

/*
 * consume* - Read little-endian values with one bounds check per value.
 *   Byte assembly permits unaligned inputs and either host byte order.
 *
 * @param insn    - See consumeByte().
 * @param ptr     - A pointer to a pre-allocated memory of appropriate size to
 *                  be populated with the data read.
 * @return        - See consumeByte().
 */
CONSUME_FUNC(consumeInt8, int8_t)
CONSUME_FUNC(consumeInt16, int16_t)
CONSUME_FUNC(consumeInt32, int32_t)
CONSUME_FUNC(consumeUInt16, uint16_t)
CONSUME_FUNC(consumeUInt32, uint32_t)
CONSUME_FUNC(consumeUInt64, uint64_t)

static bool isREX(struct InternalInstruction *insn, uint8_t prefix)
{
	if (insn->mode == MODE_64BIT)
		return prefix >= 0x40 && prefix <= 0x4f;

	return false;
}

/*
 * setGroup0Prefix - Updates the decoded instruction according to the group 0-prefix.
 *
 * @param insn      - The instruction to be updated.
 * @param prefix    - The group 0 prefix that is present.
 */
static void setGroup0Prefix(struct InternalInstruction *insn, uint8_t prefix)
{
	switch (prefix) {
	case 0xf0: // LOCK
		insn->hasLockPrefix = true;
		break;

	case 0xf2: // REPNE/REPNZ
	case 0xf3: // REP or REPE/REPZ
		insn->repeatPrefix = prefix;
		break;
	}
}

/*
 * setSegmentOverride - Overrides an instruction's prefix1 based on CPU mode.
 *
 * @param insn      - The instruction to be overridden.
 * @param prefix    - The segment override to use.
 * @param byte      - The current decoded prefix byte. Must be a segment override.
 */
static void setSegmentOverride(struct InternalInstruction *insn,
			       SegmentOverride prefix, uint8_t byte)
{
	// In 32-bit or 16-bit mode all segment override prefixes are used.
	if (insn->mode != MODE_64BIT) {
		insn->segmentOverride = prefix;
		insn->prefix1 = byte;
		return;
	}

	// In 64-bit mode, the last FS or GS override takes effect, as in XED.
	switch (byte) {
	case 0x64: // FS
	case 0x65: // GS
		insn->segmentOverride = prefix;
		insn->prefix1 = byte;
		return;
	}

	// The ES/CS/SS/DS segment overrides are ignored, and do not cancel an
	// earlier FS or GS override either.
	switch (insn->prefix1) {
	case 0x64: // FS
	case 0x65: // GS
		return;
	}

	// `prefix1` may later be used to decode the `notrack` prefix.
	// The `notrack` prefix reuses the DS segment override, so we
	// need to store the prefix even if it is ignored for the segment overrides.
	insn->prefix1 = byte;
}

X86_DECODE_INLINE void setOperandSizePrefix(struct InternalInstruction *insn)
{
	insn->hasOpSize = true;
	insn->prefix2 = 0x66;
	insn->rexPrefix = 0;
}

X86_DECODE_INLINE void setAddressSizePrefix(struct InternalInstruction *insn)
{
	insn->hasAdSize = true;
	insn->prefix3 = 0x67;
	insn->rexPrefix = 0;
}

#if defined(_MSC_VER)
static __forceinline void
#elif defined(__GNUC__)
static inline __attribute__((always_inline)) void
#else
static inline void
#endif
setInstructionSizes(struct InternalInstruction *insn, bool hasOpSize,
		    bool hasAdSize)
{
	if (insn->mode == MODE_16BIT) {
		insn->registerSize = (hasOpSize ? 4 : 2);
		insn->addressSize = (hasAdSize ? 4 : 2);
		insn->displacementSize = (hasAdSize ? 4 : 2);
		insn->immediateSize = (hasOpSize ? 4 : 2);
		insn->immSize = (hasOpSize ? 4 : 2);
	} else if (insn->mode == MODE_32BIT) {
		insn->registerSize = (hasOpSize ? 2 : 4);
		insn->addressSize = (hasAdSize ? 2 : 4);
		insn->displacementSize = (hasAdSize ? 2 : 4);
		insn->immediateSize = (hasOpSize ? 2 : 4);
		insn->immSize = (hasOpSize ? 2 : 4);
	} else if (insn->mode == MODE_64BIT) {
		if (insn->rexPrefix && wFromREX(insn->rexPrefix)) {
			insn->registerSize = 8;
			insn->addressSize = (hasAdSize ? 4 : 8);
			insn->displacementSize = 4;
			insn->immediateSize = 4;
			insn->immSize = 4;
		} else {
			insn->registerSize = (hasOpSize ? 2 : 4);
			insn->addressSize = (hasAdSize ? 4 : 8);
			insn->displacementSize = (hasOpSize ? 2 : 4);
			insn->immediateSize = (hasOpSize ? 2 : 4);
			insn->immSize = (hasOpSize ? 4 : 8);
		}
	}
}

typedef enum {
	PREFIX_READ_INVALID = -1,
	PREFIX_READ_GENERIC,
	PREFIX_READ_SIMPLE_LEGACY,
} PrefixReadStatus;

X86_DECODE_INLINE PrefixReadStatus
readSimpleLegacyPrefix(struct InternalInstruction *insn, size_t offset)
{
	if (offset)
		insn->rexPrefix = insn->code[0];
	insn->readerCursor = offset;
	insn->vectorExtensionType = TYPE_NO_VEX_XOP;
	setInstructionSizes(insn, false, false);
	return PREFIX_READ_SIMPLE_LEGACY;
}

X86_DECODE_INLINE bool readVexPrefix(struct InternalInstruction *insn,
				     uint8_t byte)
{
	if (byte == 0xc4) {
		uint8_t byte1;

		if (lookAtByte(insn, &byte1)) {
			// dbgprintf(insn, "Couldn't read second byte of VEX");
			return true;
		}

		if (insn->mode == MODE_64BIT || (byte1 & 0xc0) == 0xc0)
			insn->vectorExtensionType = TYPE_VEX_3B;
		else
			unconsumeByte(insn);

		if (insn->vectorExtensionType == TYPE_VEX_3B) {
			insn->vectorExtensionPrefix[0] = byte;
			consumeByte(insn, &insn->vectorExtensionPrefix[1]);
			consumeByte(insn, &insn->vectorExtensionPrefix[2]);

			/* We simulate the REX prefix for simplicity's sake */
			if (insn->mode == MODE_64BIT)
				insn->rexPrefix =
					0x40 |
					(wFromVEX3of3(
						 insn->vectorExtensionPrefix[2])
					 << 3) |
					(rFromVEX2of3(
						 insn->vectorExtensionPrefix[1])
					 << 2) |
					(xFromVEX2of3(
						 insn->vectorExtensionPrefix[1])
					 << 1) |
					(bFromVEX2of3(
						 insn->vectorExtensionPrefix[1])
					 << 0);

			// dbgprintf(insn, "Found VEX prefix 0x%hhx 0x%hhx 0x%hhx",
			// 		insn->vectorExtensionPrefix[0], insn->vectorExtensionPrefix[1],
			// 		insn->vectorExtensionPrefix[2]);
		}
	} else {
		uint8_t byte1;

		if (lookAtByte(insn, &byte1)) {
			// dbgprintf(insn, "Couldn't read second byte of VEX");
			return true;
		}

		if (insn->mode == MODE_64BIT || (byte1 & 0xc0) == 0xc0)
			insn->vectorExtensionType = TYPE_VEX_2B;
		else
			unconsumeByte(insn);

		if (insn->vectorExtensionType == TYPE_VEX_2B) {
			insn->vectorExtensionPrefix[0] = byte;
			consumeByte(insn, &insn->vectorExtensionPrefix[1]);

			if (insn->mode == MODE_64BIT)
				insn->rexPrefix =
					0x40 |
					(rFromVEX2of2(
						 insn->vectorExtensionPrefix[1])
					 << 2);

			switch (ppFromVEX2of2(insn->vectorExtensionPrefix[1])) {
			default:
				break;
			case VEX_PREFIX_66:
				insn->hasOpSize = true;
				break;
			}

			// dbgprintf(insn, "Found VEX prefix 0x%hhx 0x%hhx",
			// 		insn->vectorExtensionPrefix[0],
			// 		insn->vectorExtensionPrefix[1]);
		}
	}
	return false;
}

/*
 * readPrefixes - Consumes all of an instruction's prefix bytes, and marks the
 *   instruction as having them.  Also sets the instruction's default operand,
 *   address, and other relevant data sizes to report operands correctly.
 *
 * @param insn  - The instruction whose prefixes are to be read.
 * @return      - Invalid on a read/conflict failure. Simple legacy identifies
 *                an ordinary opcode after no prefix or one REX; other successful
 *                prefix sequences return generic.
 */
X86_DECODE_INLINE PrefixReadStatus readPrefixes(struct InternalInstruction *insn)
{
	bool isPrefix = true;
	bool vexForbiddenPrefix;
	unsigned int segmentPrefixCount = 0;
	unsigned int addressSizePrefixCount = 0;
	uint8_t byte = 0;
	uint8_t nextByte;
	size_t offset = 0;
	const uint8_t prefixMask =
		FEATURE_LEGACY_PREFIX |
		(insn->mode == MODE_64BIT ? FEATURE_REX_PREFIX : 0);

	/* Start ordinary opcodes and single-REX encodings without the legacy
	 * prefix loop. Escapes reuse the same payload parser; repeated REX or
	 * legacy prefixes retain their ordering and conflict checks below. */
	if (insn->codeSize == 0)
		return PREFIX_READ_INVALID;
	byte = insn->code[0];
	if (isREX(insn, byte)) {
		offset = 1;
		if (insn->codeSize == offset)
			return PREFIX_READ_INVALID;
		byte = insn->code[offset];
	}
	if (!(feature_prefix_flags[byte] & prefixMask)) {
		if (offset)
			insn->rexPrefix = insn->code[0];
		insn->readerCursor = offset + 1;
		if ((feature_prefix_flags[byte] & FEATURE_ESCAPE) ||
		    byte == 0xc5 || byte == 0x8f)
			goto legacyPrefixesRead;
		return readSimpleLegacyPrefix(insn, offset);
	}

	while (isPrefix) {
		/* If we fail reading prefixes, just stop here and let the opcode reader deal with it */
		if (consumeByte(insn, &byte))
			return PREFIX_READ_INVALID;

		if (insn->readerCursor == 1 && (byte == 0xf2 || byte == 0xf3)) {
			// prefix requires next byte
			if (lookAtByte(insn, &nextByte))
				return PREFIX_READ_INVALID;

			if (isREX(insn, nextByte)) {
				uint8_t nnextByte;

				// Go to REX prefix after the current one
				if (consumeByte(insn, &nnextByte))
					return PREFIX_READ_INVALID;

				// We should be able to read next byte after REX prefix
				if (lookAtByte(insn, &nnextByte))
					return PREFIX_READ_INVALID;

				unconsumeByte(insn);
			}
		}

		switch (byte) {
		case 0xf0: /* LOCK */
		case 0xf2: /* REPNE/REPNZ */
		case 0xf3: /* REP or REPE/REPZ */
			// only accept the last prefix
			setGroup0Prefix(insn, byte);
			insn->prefix0 = byte;
			insn->rexPrefix = 0;
			break;

		case 0x2e: /* CS segment override -OR- Branch not taken */
		case 0x36: /* SS segment override -OR- Branch taken */
		case 0x3e: /* DS segment override */
		case 0x26: /* ES segment override */
		case 0x64: /* FS segment override */
		case 0x65: /* GS segment override */
			++segmentPrefixCount;
			switch (byte) {
			case 0x2e:
				setSegmentOverride(insn, SEG_OVERRIDE_CS, byte);
				break;
			case 0x36:
				setSegmentOverride(insn, SEG_OVERRIDE_SS, byte);
				break;
			case 0x3e:
				setSegmentOverride(insn, SEG_OVERRIDE_DS, byte);
				break;
			case 0x26:
				setSegmentOverride(insn, SEG_OVERRIDE_ES, byte);
				break;
			case 0x64:
				setSegmentOverride(insn, SEG_OVERRIDE_FS, byte);
				break;
			case 0x65:
				setSegmentOverride(insn, SEG_OVERRIDE_GS, byte);
				break;
			default:
				// debug("Unhandled override");
				return PREFIX_READ_INVALID;
			}
			insn->rexPrefix = 0;
			break;

		case 0x66: /* Operand-size override */
			setOperandSizePrefix(insn);
			break;

		case 0x67: /* Address-size override */
			++addressSizePrefixCount;
			setAddressSizePrefix(insn);
			break;
		default:
			if (isREX(insn, byte)) {
				/* REX prefix byte */
				insn->rexPrefix = byte;
			} else {
				/* Not a prefix byte */
				isPrefix = false;
			}
			break;
		}
	}

legacyPrefixesRead:
	insn->vectorExtensionType = TYPE_NO_VEX_XOP;
	/* A 66, F2, F3 or LOCK prefix anywhere before a VEX, EVEX or XOP prefix,
	 * or a REX prefix right before it, makes the instruction #UD, as in
	 * XED.  Record them before the prefixes below rewrite these fields. */
	vexForbiddenPrefix = insn->hasOpSize || insn->prefix0 != 0 ||
			     insn->rexPrefix != 0;

	if (byte == 0xd5 && insn->mode == MODE_64BIT) {
		uint8_t payload;

		/* A legacy REX immediately before REX2 is invalid.  A later legacy
		 * prefix clears an earlier REX in the normal way.  Repeated segment
		 * and address-size prefixes have architecturally undefined behavior,
		 * so accept only the canonical single-prefix spelling. */
		if (insn->rexPrefix || segmentPrefixCount > 1 ||
		    addressSizePrefixCount > 1 || consumeByte(insn, &payload))
			return PREFIX_READ_INVALID;
		insn->hasRex2 = true;
		insn->rex2Prefix = payload;
		/* Reuse the generated legacy tables for W/R3/X3/B3.  R4/X4/B4
		 * remain separate until operand translation because the generated
		 * register enums stop at R15. */
		insn->rexPrefix = 0x40 | (payload & 0x0f);
	} else if (byte == 0x62) {
		uint8_t byte1, byte2;

		if (consumeByte(insn, &byte1)) {
			// dbgprintf(insn, "Couldn't read second byte of EVEX prefix");
			return PREFIX_READ_INVALID;
		}

		if (lookAtByte(insn, &byte2)) {
			// dbgprintf(insn, "Couldn't read third byte of EVEX prefix");
			unconsumeByte(insn); /* unconsume byte1 */
			unconsumeByte(insn); /* unconsume byte  */
		} else {
			if ((insn->mode == MODE_64BIT ||
			     (byte1 & 0xc0) == 0xc0) &&
			    ((~byte1 & 0xc) == 0xc) && ((byte2 & 0x4) == 0x4)) {
				insn->vectorExtensionType = TYPE_EVEX;
			} else {
				unconsumeByte(insn); /* unconsume byte1 */
				unconsumeByte(insn); /* unconsume byte  */
			}
		}

		if (insn->vectorExtensionType == TYPE_EVEX) {
			insn->vectorExtensionPrefix[0] = byte;
			insn->vectorExtensionPrefix[1] = byte1;
			if (consumeByte(insn,
					&insn->vectorExtensionPrefix[2])) {
				// dbgprintf(insn, "Couldn't read third byte of EVEX prefix");
				return PREFIX_READ_INVALID;
			}

			if (consumeByte(insn,
					&insn->vectorExtensionPrefix[3])) {
				// dbgprintf(insn, "Couldn't read fourth byte of EVEX prefix");
				return PREFIX_READ_INVALID;
			}

			/* We simulate the REX prefix for simplicity's sake */
			if (insn->mode == MODE_64BIT) {
				insn->rexPrefix =
					0x40 |
					(wFromEVEX3of4(
						 insn->vectorExtensionPrefix[2])
					 << 3) |
					(rFromEVEX2of4(
						 insn->vectorExtensionPrefix[1])
					 << 2) |
					(xFromEVEX2of4(
						 insn->vectorExtensionPrefix[1])
					 << 1) |
					(bFromEVEX2of4(
						 insn->vectorExtensionPrefix[1])
					 << 0);
			}

			// dbgprintf(insn, "Found EVEX prefix 0x%hhx 0x%hhx 0x%hhx 0x%hhx",
			// 		insn->vectorExtensionPrefix[0], insn->vectorExtensionPrefix[1],
			// 		insn->vectorExtensionPrefix[2], insn->vectorExtensionPrefix[3]);
		}
	} else if (byte == 0xc4 || byte == 0xc5) {
		if (readVexPrefix(insn, byte))
			return PREFIX_READ_INVALID;
	} else if (byte == 0x8f) {
		uint8_t byte1;

		if (lookAtByte(insn, &byte1)) {
			// dbgprintf(insn, "Couldn't read second byte of XOP");
			return PREFIX_READ_INVALID;
		}

		if ((byte1 & 0x38) !=
		    0x0) /* 0 in these 3 bits is a POP instruction. */
			insn->vectorExtensionType = TYPE_XOP;
		else
			unconsumeByte(insn);

		if (insn->vectorExtensionType == TYPE_XOP) {
			insn->vectorExtensionPrefix[0] = byte;
			consumeByte(insn, &insn->vectorExtensionPrefix[1]);
			consumeByte(insn, &insn->vectorExtensionPrefix[2]);

			/* We simulate the REX prefix for simplicity's sake */
			if (insn->mode == MODE_64BIT)
				insn->rexPrefix =
					0x40 |
					(wFromXOP3of3(
						 insn->vectorExtensionPrefix[2])
					 << 3) |
					(rFromXOP2of3(
						 insn->vectorExtensionPrefix[1])
					 << 2) |
					(xFromXOP2of3(
						 insn->vectorExtensionPrefix[1])
					 << 1) |
					(bFromXOP2of3(
						 insn->vectorExtensionPrefix[1])
					 << 0);

			switch (ppFromXOP3of3(insn->vectorExtensionPrefix[2])) {
			default:
				break;
			case VEX_PREFIX_66:
				insn->hasOpSize = true;
				break;
			}

			// dbgprintf(insn, "Found XOP prefix 0x%hhx 0x%hhx 0x%hhx",
			// 		insn->vectorExtensionPrefix[0], insn->vectorExtensionPrefix[1],
			// 		insn->vectorExtensionPrefix[2]);
		}
	} else
		unconsumeByte(insn);

	if (insn->vectorExtensionType != TYPE_NO_VEX_XOP && vexForbiddenPrefix)
		return PREFIX_READ_INVALID;

	if (insn->repeatPrefix != 0) {
		if (lookAtByte(insn, &nextByte))
			return PREFIX_READ_INVALID;

		/*
		* REP prefix is present, and any of the following conditions are
		* met:
		* - it is followed by a LOCK (0xf0) prefix
		* - it is followed by an xchg instruction (except for 0x90 - NOP/PAUSE)
		* then it should be disassembled as a xacquire/xrelease not repne/rep.
		*/
		if ((insn->hasLockPrefix || ((nextByte & 0xfe) == 0x86 ||
					     (nextByte & 0xf8) == 0x90)) &&
		    nextByte != 0x90) {
			insn->xAcquireRelease = insn->repeatPrefix;
		}

		/*
		* Also if the REP prefix is 0xf3, and the following condition is met:
		* - it is followed by a "mov mem, reg" (opcode 0x88/0x89) or
		*                       "mov mem, imm" (opcode 0xc6/0xc7) instructions.
		* then it should be disassembled as an xrelease not rep.
		*/
		if (insn->repeatPrefix == 0xf3 &&
		    (nextByte == 0x88 || nextByte == 0x89 || nextByte == 0xc6 ||
		     nextByte == 0xc7)) {
			insn->xAcquireRelease = insn->repeatPrefix;
		}
	}

	setInstructionSizes(insn, insn->hasOpSize, insn->hasAdSize);

	return PREFIX_READ_GENERIC;
}

static int readModRM(struct InternalInstruction *insn);

X86_DECODE_INLINE bool isRex2Map0PrefixByte(uint8_t byte)
{
	if ((byte >= 0x40 && byte <= 0x4f) || byte == 0xc4 || byte == 0xc5 ||
	    byte == 0xd5 || byte == 0x62)
		return true;
	switch (byte) {
	default:
		return false;
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

/*
 * readOpcode - Reads the opcode (excepting the ModR/M byte in the case of
 *   extended or escape opcodes).
 *
 * @param insn  - The instruction whose opcode is to be read.
 * @return      - 0 on success, -1 on a read failure, or OPCODE_READ_GENERIC
 *                for maps outside terminal tables when terminalOnly is true.
 */
enum { OPCODE_READ_GENERIC = 1 };

X86_DECODE_INLINE int readOpcode(struct InternalInstruction *insn,
				 bool simpleLegacy, bool terminalOnly)
{
	uint8_t current;

	// dbgprintf(insn, "readOpcode()");

	insn->opcodeType = ONEBYTE;
	if (simpleLegacy)
		goto legacyOpcode;
	if (insn->hasRex2) {
		if (consumeByte(insn, &current))
			return -1;
		/* The map is carried by REX2.M0.  An explicit 0F is never an
		 * escape after REX2. */
		if (current == 0x0f)
			return -1;
		if (m0FromREX2(insn->rex2Prefix)) {
			const uint8_t row = current >> 4;

			if (row == 0x3 || row == 0x8)
				return -1;
			insn->opcodeType = TWOBYTE;
			insn->twoByteEscape = 0x0f;
			insn->firstByte = 0x0f;
		} else {
			const uint8_t row = current >> 4;

			if (isRex2Map0PrefixByte(current) || row == 0x4 ||
			    row == 0x7 || row == 0xe ||
			    (row == 0xa && current != 0xa1))
				return -1;
			insn->firstByte = current;
		}
		insn->opcode = current;
		return 0;
	}

	if (insn->vectorExtensionType == TYPE_EVEX) {
		switch (mmFromEVEX2of4(insn->vectorExtensionPrefix[1])) {
		default:
			// dbgprintf(insn, "Unhandled mm field for instruction (0x%hhx)",
			// 		mmFromEVEX2of4(insn->vectorExtensionPrefix[1]));
			return -1;
		case VEX_LOB_0F:
			insn->opcodeType = TWOBYTE;
			return consumeByte(insn, &insn->opcode);
		case VEX_LOB_0F38:
			insn->opcodeType = THREEBYTE_38;
			return consumeByte(insn, &insn->opcode);
		case VEX_LOB_0F3A:
			insn->opcodeType = THREEBYTE_3A;
			return consumeByte(insn, &insn->opcode);
		}
	} else if (insn->vectorExtensionType == TYPE_VEX_3B) {
		switch (mmmmmFromVEX2of3(insn->vectorExtensionPrefix[1])) {
		default:
			// dbgprintf(insn, "Unhandled m-mmmm field for instruction (0x%hhx)",
			// 		mmmmmFromVEX2of3(insn->vectorExtensionPrefix[1]));
			return -1;
		case VEX_LOB_0F:
			//insn->twoByteEscape = 0x0f;
			insn->opcodeType = TWOBYTE;
			return consumeByte(insn, &insn->opcode);
		case VEX_LOB_0F38:
			//insn->twoByteEscape = 0x0f;
			insn->opcodeType = THREEBYTE_38;
			return consumeByte(insn, &insn->opcode);
		case VEX_LOB_0F3A:
			//insn->twoByteEscape = 0x0f;
			insn->opcodeType = THREEBYTE_3A;
			return consumeByte(insn, &insn->opcode);
		}
	} else if (insn->vectorExtensionType == TYPE_VEX_2B) {
		//insn->twoByteEscape = 0x0f;
		insn->opcodeType = TWOBYTE;
		return consumeByte(insn, &insn->opcode);
	} else if (insn->vectorExtensionType == TYPE_XOP) {
		switch (mmmmmFromXOP2of3(insn->vectorExtensionPrefix[1])) {
		default:
			// dbgprintf(insn, "Unhandled m-mmmm field for instruction (0x%hhx)",
			// 		mmmmmFromVEX2of3(insn->vectorExtensionPrefix[1]));
			return -1;
		case XOP_MAP_SELECT_8:
			insn->opcodeType = XOP8_MAP;
			return consumeByte(insn, &insn->opcode);
		case XOP_MAP_SELECT_9:
			insn->opcodeType = XOP9_MAP;
			return consumeByte(insn, &insn->opcode);
		case XOP_MAP_SELECT_A:
			insn->opcodeType = XOPA_MAP;
			return consumeByte(insn, &insn->opcode);
		}
	}

legacyOpcode:
	if (consumeByte(insn, &current))
		return -1;

	// save this first byte for MOVcr, MOVdr, MOVrc, MOVrd
	insn->firstByte = current;

	if (current == 0x0f) {
		// dbgprintf(insn, "Found a two-byte escape prefix (0x%hhx)", current);
		insn->twoByteEscape = current;

		if (consumeByte(insn, &current))
			return -1;

		/* Terminal tables contain only the one- and two-byte maps. Keep
         * operand-bearing 3DNow headers out of compact-only local state. */
		if (terminalOnly &&
		    (current == 0x38 || current == 0x3a || current == 0x0f))
			return OPCODE_READ_GENERIC;

		if (current == 0x38) {
			// dbgprintf(insn, "Found a three-byte escape prefix (0x%hhx)", current);
			if (consumeByte(insn, &current))
				return -1;

			insn->opcodeType = THREEBYTE_38;
		} else if (current == 0x3a) {
			// dbgprintf(insn, "Found a three-byte escape prefix (0x%hhx)", current);
			if (consumeByte(insn, &current))
				return -1;

			insn->opcodeType = THREEBYTE_3A;
		} else if (current == 0x0f) {
			// dbgprintf(insn, "Found a 3dnow escape prefix (0x%hhx)", current);
			// Consume operands before the opcode to comply with the 3DNow encoding
			if (readModRM(insn))
				return -1;

			if (consumeByte(insn, &current))
				return -1;

			insn->opcodeType = THREEDNOW_MAP;
		} else {
			// dbgprintf(insn, "Didn't find a three-byte escape prefix");
			insn->opcodeType = TWOBYTE;
		}
	}

	/*
	 * At this point we have consumed the full opcode.
	 * Anything we consume from here on must be unconsumed.
	 */

	insn->opcode = current;

	return 0;
}

/*
 * getIDWithAttrMask - Determines the ID of an instruction, consuming
 *   the ModR/M byte as appropriate for extended and escape opcodes,
 *   and using a supplied attribute mask.
 *
 * @param instructionID - A pointer whose target is filled in with the ID of the
 *                        instruction.
 * @param insn          - The instruction whose ID is to be determined.
 * @param attrMask      - The attribute mask to search.
 * @return              - 0 if the ModR/M could be read when needed or was not
 *                        needed; nonzero otherwise.
 */
#if defined(_MSC_VER)
static __forceinline int
#else
#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline int
#endif
getIDWithAttrMask(uint16_t *instructionID, struct InternalInstruction *insn,
		  uint16_t attrMask)
{
	const struct ModRMDecision *decision = getModRMDecision(
		insn->opcodeType, contextForAttrs(attrMask), insn->opcode);
	uint32_t packed;
	bool hasModRMExtension;

	if (!decision) {
		*instructionID = 0;
		return 0;
	}
	packed = decision->packed;
	hasModRMExtension =
		(packed & (X86_DECISION_INDEXED | X86_DECISION_SPLIT)) != 0;
#ifndef CAPSTONE_X86_REDUCE
	/* The trailing 3DNow opcode always follows a ModR/M byte. */
	hasModRMExtension |= insn->opcodeType == THREEDNOW_MAP;
#endif
	if (hasModRMExtension && readModRM(insn))
		return -1;
	*instructionID = decode(packed, hasModRMExtension ? insn->modRM : 0);

	return 0;
}

/*
 * is16BitEquivalent - Determines whether two instruction names refer to
 * equivalent instructions but one is 16-bit whereas the other is not.
 *
 * @param orig  - The instruction ID that is not 16-bit
 * @param equiv - The instruction ID that is 16-bit
 */
static bool is16BitEquivalent(unsigned orig, unsigned equiv)
{
	size_t i;
	uint16_t idx;

	if ((idx = x86_16_bit_eq_lookup[orig]) != 0) {
		for (i = idx - 1; i < ARR_SIZE(x86_16_bit_eq_tbl) &&
				  x86_16_bit_eq_tbl[i].first == orig;
		     i++) {
			if (x86_16_bit_eq_tbl[i].second == equiv)
				return true;
		}
	}

	return false;
}

/*
 * is64Bit - Determines whether this instruction is a 64-bit instruction.
 *
 * @param name - The instruction that is not 16-bit
 */
static bool is64Bit(uint16_t id)
{
	unsigned int i = find_insn(id);
	if (i != -1) {
		return insns[i].is64bit;
	}

	// not found??
	return false;
}

typedef enum {
	DO_NOT_RESOLVE = 0,
	IGNORE_REP = 1,
	IGNORE_DATA_SIZE = 2,
} MandatoryPrefixResolution;

/*
 * shouldResolveMandatoryPrefixConflict - Resolves conflicts between the 
 * data size override prefix and the REP/REPNZ prefixes in the attribute 
 * mask when needed.
 *
 * We need to resolve these conflicts, because the TableGen lookups we 
 * perform distinguish between instructions with and without REP.
 * For example, there may be an entry for SHLD with a DATA16 data size 
 * override prefix, but no entry for REP + DATA16.
 * These entries are split, because in some cases the REP and DATA16
 * prefixes are used as mandatory prefixes.
 * When both are mandatory prefixes, the effect of prefixing both 
 * to an instruction at the same time is not specified by
 * reference manuals.
 *
 * Conflicts are resolved by one of these three resolutions:
 *   - If conflicts should not be resolved, take no action.
 *   - If conflicts should be resolved and the instruction has no 
 *     mandatory prefixes, resolves in favor of data size override.
 *   - If conflicts should be resolved and the instruction has mandatory 
 *     prefixes, resolves in favor of REP/REPNZ.
 * 
 * @param insn - The instruction
 * @param attrMask - The current attribute mask.
 */
static uint16_t resolveMandatoryPrefixConflict(struct InternalInstruction *insn,
					       uint16_t attrMask)
{
	MandatoryPrefixResolution resolution = DO_NOT_RESOLVE;

	// We inspect the opcode map and opcode to determine how we need to resolve
	// a mandatory prefix conflict.
	switch (insn->opcodeType) {
	// No one-byte opcodes have mandatory prefixes.
	case ONEBYTE:
		resolution = DO_NOT_RESOLVE;
		break;
	case TWOBYTE:
		// Exceptions for instructions that operate on data size-overridable
		// operands.
		if (
			// XADD
			(insn->opcode & 0xFE) == 0xC0

			// BSWAP
			|| (insn->opcode & 0xF8) == 0xC8

			// CMPXCHG, LSS, BTR, LFS, LGS, MOVZX
			|| (insn->opcode & 0xF8) == 0xB0

			// Group 16, various NOPs
			|| (insn->opcode & 0xF8) == 0x18

			// UD0
			|| insn->opcode == 0xFF) {
			resolution = IGNORE_REP;
			break;
		}

		// We inspect the instruction to determine if it operates on xmm
		// registers or general-purpose registers.
		//
		// If it operates on general purpose registers, the data size override
		// prefix is not a mandatory prefix and should not be ignored.
		// In most cases, this also means that the REP prefix is not a mandatory
		// prefix and should be ignored.
		//
		// If the instruction operates on xmm registers, the data size override
		// is used to select the operation type (SS, SD, PS, or PD).
		// In this case, the REP prefixes take priority over the data size [1]
		// override prefixes, and when both are present the data size override
		// prefix should be ignored.
		//
		// The exception is 0xB0, where the REP prefixes are mandatory prefixes
		// but the data size override prefix should still be respected.
		// For this case we return DO_NOT_RESOLVE, which returns attrMask as-is.
		//
		// [1]: https://stackoverflow.com/a/7197365
		switch (insn->opcode & 0xf0) {
		case 0x10:
		case 0x50:
		case 0x60:
		case 0x70:
		case 0xC0:
		case 0xD0:
		case 0xE0:
		case 0xF0:
			resolution = IGNORE_DATA_SIZE;
			break;
		case 0x00:
		case 0x20:
		case 0x30:
		case 0x40:
		case 0x80:
		case 0x90:
		case 0xA0:
			resolution = IGNORE_REP;
			break;
		default: // 0xB0
			resolution = DO_NOT_RESOLVE;
			break;
		}
		break;
	case THREEBYTE_38:
		// Exception: the ADOX and CRC32 instructions.
		// These ignore the data size override prefix even though they
		// operate on general-purpose registers.
		if ((insn->opcode & 0xF0) == 0xF0) {
			resolution = IGNORE_DATA_SIZE;
			break;
		}

		// Do not need to be resolved, all REP+DATA16 combinations are UD
		// or separately specified.
		resolution = DO_NOT_RESOLVE;
		break;
	case THREEBYTE_3A:
		// Do not need to be resolved, all REP+DATA16 combinations are UD
		// or separately specified.
		resolution = DO_NOT_RESOLVE;
		break;
	case XOP8_MAP:
	case XOP9_MAP:
	case XOPA_MAP:
		// These instructions do not appear to operate on XMM/SSE registers,
		// so the REP prefixes can be safely ignored.
		resolution = IGNORE_REP;
		break;
	case THREEDNOW_MAP:
		// AMD Reference Manual Volume 3, Section 1.2.1, states that all
		// 3DNow! instructions ignore the data size override prefix.
		resolution = IGNORE_DATA_SIZE;
		break;
	}

	switch (resolution) {
	case IGNORE_REP:
		return attrMask & ~(ATTR_XD | ATTR_XS);
	case IGNORE_DATA_SIZE:
		return attrMask & ~ATTR_OPSIZE;
	default:
	case DO_NOT_RESOLVE:
		return attrMask;
	}
}

X86_DECODE_INLINE uint16_t mandatoryPrefixAttributes(uint8_t pp)
{
	switch (pp) {
	case VEX_PREFIX_66:
		return ATTR_OPSIZE;
	case VEX_PREFIX_F3:
		return ATTR_XS;
	case VEX_PREFIX_F2:
		return ATTR_XD;
	default:
		return ATTR_NONE;
	}
}

/*
 * getID - Determines the ID of an instruction, consuming the ModR/M byte as
 *   appropriate for extended and escape opcodes.  Determines the attributes and
 *   context for the instruction before doing so.
 *
 * @param insn  - The instruction whose ID is to be determined.
 * @return      - 0 if the ModR/M could be read when needed or was not needed;
 *                nonzero otherwise.
 */
#if defined(_MSC_VER)
static __forceinline int
#elif defined(__GNUC__)
static inline __attribute__((always_inline)) int
#else
static inline int
#endif
getIDForMode(struct InternalInstruction *insn, cs_mode mode,
	     DisassemblerMode decoderMode)
{
	uint16_t attrMask;
	uint16_t instructionID;
	bool rexWOverridesOpSize;

	/* REX.W overrides the operand-sized prefix for near RET in 64-bit mode */
	rexWOverridesOpSize = decoderMode == MODE_64BIT && insn->hasOpSize &&
			      insn->opcodeType == ONEBYTE &&
			      (insn->opcode == 0xC2 || insn->opcode == 0xC3) &&
			      (insn->rexPrefix & 0x08);

	attrMask = ATTR_NONE;

	if (decoderMode == MODE_64BIT)
		attrMask |= ATTR_64BIT;

	if (insn->vectorExtensionType != TYPE_NO_VEX_XOP) {
		attrMask |= (insn->vectorExtensionType == TYPE_EVEX) ?
				    ATTR_EVEX :
				    ATTR_VEX;

		if (insn->vectorExtensionType == TYPE_EVEX) {
			attrMask |= mandatoryPrefixAttributes(
				ppFromEVEX3of4(insn->vectorExtensionPrefix[2]));

			if (zFromEVEX4of4(insn->vectorExtensionPrefix[3]))
				attrMask |= ATTR_EVEXKZ;
			if (bFromEVEX4of4(insn->vectorExtensionPrefix[3]))
				attrMask |= ATTR_EVEXB;
			if (aaaFromEVEX4of4(insn->vectorExtensionPrefix[3]))
				attrMask |= ATTR_EVEXK;
			if (lFromEVEX4of4(insn->vectorExtensionPrefix[3]))
				attrMask |= ATTR_EVEXL;
			if (l2FromEVEX4of4(insn->vectorExtensionPrefix[3]))
				attrMask |= ATTR_EVEXL2;
		} else if (insn->vectorExtensionType == TYPE_VEX_3B) {
			attrMask |= mandatoryPrefixAttributes(
				ppFromVEX3of3(insn->vectorExtensionPrefix[2]));

			if (lFromVEX3of3(insn->vectorExtensionPrefix[2]))
				attrMask |= ATTR_VEXL;
		} else if (insn->vectorExtensionType == TYPE_VEX_2B) {
			attrMask |= mandatoryPrefixAttributes(
				ppFromVEX2of2(insn->vectorExtensionPrefix[1]));

			if (lFromVEX2of2(insn->vectorExtensionPrefix[1]))
				attrMask |= ATTR_VEXL;
		} else if (insn->vectorExtensionType == TYPE_XOP) {
			attrMask |= mandatoryPrefixAttributes(
				ppFromXOP3of3(insn->vectorExtensionPrefix[2]));

			if (lFromXOP3of3(insn->vectorExtensionPrefix[2]))
				attrMask |= ATTR_VEXL;
		} else {
			return -1;
		}
	} else {
		if (insn->hasOpSize && decoderMode != MODE_16BIT &&
		    !rexWOverridesOpSize) {
			attrMask |= ATTR_OPSIZE;
		}
		if (insn->hasAdSize)
			attrMask |= ATTR_ADSIZE;
		if (insn->opcodeType == ONEBYTE) {
			if (insn->repeatPrefix == 0xf3 &&
			    (insn->opcode == 0x90))
				// Special support for PAUSE
				attrMask |= ATTR_XS;
		} else {
			if (insn->repeatPrefix == 0xf2)
				attrMask |= ATTR_XD;
			else if (insn->repeatPrefix == 0xf3)
				attrMask |= ATTR_XS;
		}

		if ((attrMask & ATTR_OPSIZE) &&
		    (attrMask & (ATTR_XD | ATTR_XS))) {
			attrMask =
				resolveMandatoryPrefixConflict(insn, attrMask);
		}

		/* F2/F3 select the opcode independently of the address size.
		 * Address-dependent opcodes restore ATTR_ADSIZE below. */
		if (attrMask & (ATTR_XD | ATTR_XS))
			attrMask &= ~ATTR_ADSIZE;
	}

	if (insn->rexPrefix & 0x08) {
		attrMask |= ATTR_REXW;
		attrMask &= ~ATTR_ADSIZE;
	}

	/*
	 * JCXZ/JECXZ need special handling for 16-bit mode because the meaning
	 * of the AdSize prefix is inverted w.r.t. 32-bit mode.
	 */
	if (decoderMode == MODE_16BIT && insn->opcodeType == ONEBYTE &&
	    insn->opcode == 0xE3)
		attrMask ^= ATTR_ADSIZE;

	/*
	 * Preserve legacy decoding unless an explicit CPU mode selects its
	 * operand-size rules for relative branches.
	 */
	if ((decoderMode == MODE_64BIT) && insn->hasOpSize) {
		switch (insn->opcode) {
		case 0xE9:
			if (insn->opcodeType == ONEBYTE &&
			    x86_has_feature(mode, CS_MODE_X86_AMD) &&
			    !wFromREX(insn->rexPrefix)) {
				insn->immSize = insn->immediateSize;
				break;
			}
			/* fall through */
		case 0xE8:
			// Take care of psubsb and other mmx instructions.
			if (insn->opcodeType == ONEBYTE) {
				attrMask ^= ATTR_OPSIZE;
				insn->immediateSize = 4;
				insn->displacementSize = 4;
			}
			break;
		case 0x80:
		case 0x81:
		case 0x82:
		case 0x83:
		case 0x84:
		case 0x85:
		case 0x86:
		case 0x87:
		case 0x88:
		case 0x89:
		case 0x8A:
		case 0x8B:
		case 0x8C:
		case 0x8D:
		case 0x8E:
		case 0x8F:
			// Take care of lea and three byte ops.
			if (insn->opcodeType != TWOBYTE)
				break;

			if ((x86_has_feature(mode, CS_MODE_X86_INTEL) ||
			     x86_has_feature(mode, CS_MODE_X86_AMD)) &&
			    insn->vectorExtensionType == TYPE_NO_VEX_XOP) {
				if ((x86_has_feature(mode, CS_MODE_X86_AMD)) &&
				    !wFromREX(insn->rexPrefix)) {
					attrMask |= ATTR_OPSIZE;
					insn->immediateSize = 2;
					insn->displacementSize = 2;
					insn->immSize = 2;
				} else {
					attrMask &= ~ATTR_OPSIZE;
					insn->immediateSize = 4;
					insn->displacementSize = 4;
					insn->immSize = 8;
				}
			} else if (insn->opcode >= 0x82) {
				attrMask ^= ATTR_OPSIZE;
				insn->immediateSize = 4;
				insn->displacementSize = 4;
			}
			break;
		}
	}

	/* The following clauses compensate for limitations of the tables. */
	if (decoderMode != MODE_64BIT &&
	    insn->vectorExtensionType != TYPE_NO_VEX_XOP) {
		if (getIDWithAttrMask(&instructionID, insn, attrMask)) {
			return -1;
		}

		/*
		 * The tables can't distinguish between cases where the W-bit is used to
		 * select register size and cases where it's a required part of the opcode.
		 */
		if ((insn->vectorExtensionType == TYPE_EVEX &&
		     wFromEVEX3of4(insn->vectorExtensionPrefix[2])) ||
		    (insn->vectorExtensionType == TYPE_VEX_3B &&
		     wFromVEX3of3(insn->vectorExtensionPrefix[2])) ||
		    (insn->vectorExtensionType == TYPE_XOP &&
		     wFromXOP3of3(insn->vectorExtensionPrefix[2]))) {
			uint16_t instructionIDWithREXW;

			if (getIDWithAttrMask(&instructionIDWithREXW, insn,
					      attrMask | ATTR_REXW)) {
				insn->instructionID = instructionID;
				insn->spec = specifierForUID(instructionID);
				return 0;
			}

			// If not a 64-bit instruction. Switch the opcode.
			if (!is64Bit(instructionIDWithREXW)) {
				insn->instructionID = instructionIDWithREXW;
				insn->spec =
					specifierForUID(instructionIDWithREXW);

				return 0;
			}
		}
	}

	/*
	 * Absolute moves, umonitor, and movdir64b need special handling.
	 * -For 16-bit mode because the meaning of the AdSize and OpSize prefixes are
	 *  inverted w.r.t.
	 * -For 32-bit mode we need to ensure the ADSIZE prefix is observed in
	 *  any position.
	 */
	if ((insn->opcodeType == ONEBYTE && ((insn->opcode & 0xFC) == 0xA0)) ||
	    (insn->opcodeType == TWOBYTE && (insn->opcode == 0xAE)) ||
	    (insn->opcodeType == THREEBYTE_38 && insn->opcode == 0xF8)) {
		/* Make sure we observed the prefixes in any position. */
		if (insn->hasAdSize)
			attrMask |= ATTR_ADSIZE;

		if (insn->hasOpSize)
			attrMask |= ATTR_OPSIZE;

		/* In 16-bit, invert the attributes. */
		if (decoderMode == MODE_16BIT) {
			attrMask ^= ATTR_ADSIZE;

			/* The OpSize attribute is only valid with the absolute moves. */
			if (insn->opcodeType == ONEBYTE &&
			    ((insn->opcode & 0xFC) == 0xA0))
				attrMask ^= ATTR_OPSIZE;
		}

		if (getIDWithAttrMask(&instructionID, insn, attrMask)) {
			return -1;
		}

		insn->instructionID = instructionID;
		insn->spec = specifierForUID(instructionID);

		return 0;
	}
	if (getIDWithAttrMask(&instructionID, insn, attrMask)) {
		return -1;
	}

	if ((decoderMode == MODE_16BIT ||
	     (insn->hasOpSize && !rexWOverridesOpSize)) &&
	    !(attrMask & ATTR_OPSIZE)) {
		/*
		 * The instruction tables make no distinction between instructions that
		 * allow OpSize anywhere (i.e., 16-bit operations) and that need it in a
		 * particular spot (i.e., many MMX operations).  In general we're
		 * conservative, but in the specific case where OpSize is present but not
		 * in the right place we check if there's a 16-bit operation.
		 */
		const struct InstructionSpecifier *spec;
		uint16_t instructionIDWithOpsize;

		spec = specifierForUID(instructionID);

		if (getIDWithAttrMask(&instructionIDWithOpsize, insn,
				      attrMask | ATTR_OPSIZE)) {
			/*
			 * ModRM required with OpSize but not present; give up and return version
			 * without OpSize set
			 */
			insn->instructionID = instructionID;
			insn->spec = spec;

			return 0;
		}

		if (is16BitEquivalent(instructionID, instructionIDWithOpsize) &&
		    (decoderMode == MODE_16BIT) ^ insn->hasOpSize) {
			insn->instructionID = instructionIDWithOpsize;
			insn->spec = specifierForUID(instructionIDWithOpsize);
		} else {
			insn->instructionID = instructionID;
			insn->spec = spec;
		}

		return 0;
	}

	if (insn->opcodeType == ONEBYTE && insn->opcode == 0x90 &&
	    ((insn->rexPrefix & 0x01) ||
	     (insn->hasRex2 && b4FromREX2(insn->rex2Prefix)))) {
		/*
		 * NOOP shouldn't decode as NOOP if REX.b is set. Instead
		 * it should decode as XCHG %r8, %eax.
		 */
		const struct InstructionSpecifier *spec;
		uint16_t instructionIDWithNewOpcode;
		const struct InstructionSpecifier *specWithNewOpcode;

		spec = specifierForUID(instructionID);

		/* Borrow opcode from one of the other XCHGar opcodes */
		insn->opcode = 0x91;

		if (getIDWithAttrMask(&instructionIDWithNewOpcode, insn,
				      attrMask)) {
			insn->opcode = 0x90;

			insn->instructionID = instructionID;
			insn->spec = spec;

			return 0;
		}

		specWithNewOpcode = specifierForUID(instructionIDWithNewOpcode);

		/* Change back */
		insn->opcode = 0x90;

		insn->instructionID = instructionIDWithNewOpcode;
		insn->spec = specWithNewOpcode;

		return 0;
	}

	insn->instructionID = instructionID;
	insn->spec = specifierForUID(insn->instructionID);

	return 0;
}

X86_DECODE_INLINE int getIDSlow(struct InternalInstruction *insn, cs_mode mode)
{
	switch (insn->mode) {
	case MODE_16BIT:
		return getIDForMode(insn, mode, MODE_16BIT);
	case MODE_32BIT:
		return getIDForMode(insn, mode, MODE_32BIT);
	default:
		return getIDForMode(insn, mode, MODE_64BIT);
	}
}

X86_DECODE_INLINE int getID(struct InternalInstruction *insn, cs_mode mode)
{
	uint16_t attrMask;
	uint16_t instructionID;

	/* Common legacy instructions need no prefix-conflict or size repair. */
	if (insn->mode != MODE_16BIT &&
	    insn->vectorExtensionType == TYPE_NO_VEX_XOP &&
	    !(insn->hasOpSize | insn->hasAdSize | insn->repeatPrefix) &&
	    insn->opcode != 0x90) {
		attrMask = insn->mode == MODE_64BIT ? ATTR_64BIT : ATTR_NONE;
		if (insn->rexPrefix & 0x08)
			attrMask |= ATTR_REXW;
		if (getIDWithAttrMask(&instructionID, insn, attrMask))
			return -1;
		insn->instructionID = instructionID;
		insn->spec = specifierForUID(instructionID);
		return 0;
	}

	return getIDSlow(insn, mode);
}

/* Readers share byte consumption and error ordering. Ordinary scalar scan
 * terminals use a constant false materialization policy after the generator
 * proves their operand classes and ModR/M forms. Other callers retain every
 * raw field, including state left by failed reads. */
/*
 * readSIB - Consumes the SIB byte to determine addressing information for an
 *   instruction.
 *
 * @param insn  - The instruction whose SIB byte is to be read.
 * @return      - 0 if the SIB byte was successfully read; nonzero otherwise.
 */
X86_DECODE_INLINE int readSIB(struct InternalInstruction *insn,
			      bool materialize)
{
	SIBBase sibBaseBase = SIB_BASE_NONE;
	uint8_t index, base;

	// dbgprintf(insn, "readSIB()");

	if (materialize && insn->consumedSIB)
		return 0;

	if (materialize)
		insn->consumedSIB = true;

	switch (insn->addressSize) {
	case 2:
		// dbgprintf(insn, "SIB-based addressing doesn't work in 16-bit mode");
		return -1;
	case 4:
		if (materialize)
			insn->sibIndexBase = SIB_INDEX_EAX;
		sibBaseBase = SIB_BASE_EAX;
		break;
	case 8:
		if (materialize)
			insn->sibIndexBase = SIB_INDEX_RAX;
		sibBaseBase = SIB_BASE_RAX;
		break;
	}

	if (consumeByte(insn, &insn->sib))
		return -1;

	if (materialize) {
		index = indexFromSIB(insn->sib) |
			(xFromREX(insn->rexPrefix) << 3);

		if (index == 0x4) {
			insn->sibIndex = SIB_INDEX_NONE;
		} else {
			insn->sibIndex = (SIBIndex)(insn->sibIndexBase + index);
		}

		insn->sibScale = 1 << scaleFromSIB(insn->sib);
	}

	base = baseFromSIB(insn->sib) | (bFromREX(insn->rexPrefix) << 3);

	switch (base) {
	case 0x5:
	case 0xd:
		switch (modFromModRM(insn->modRM)) {
		case 0x0:
			insn->eaDisplacement = EA_DISP_32;
			if (materialize)
				insn->sibBase = SIB_BASE_NONE;
			break;
		case 0x1:
			insn->eaDisplacement = EA_DISP_8;
			if (materialize)
				insn->sibBase = (SIBBase)(sibBaseBase + base);
			break;
		case 0x2:
			insn->eaDisplacement = EA_DISP_32;
			if (materialize)
				insn->sibBase = (SIBBase)(sibBaseBase + base);
			break;
		case 0x3:
			// debug("Cannot have Mod = 0b11 and a SIB byte");
			return -1;
		}
		break;
	default:
		if (materialize)
			insn->sibBase = (SIBBase)(sibBaseBase + base);
		break;
	}

	return 0;
}

/*
 * readDisplacement - Consumes the displacement of an instruction.
 *
 * @param insn  - The instruction whose displacement is to be read.
 * @return      - 0 if the displacement byte was successfully read; nonzero
 *                otherwise.
 */
X86_DECODE_INLINE int readDisplacement(struct InternalInstruction *insn,
				       bool materialize)
{
	int8_t d8;
	int16_t d16;
	int32_t d32;

	// dbgprintf(insn, "readDisplacement()");

	if (materialize && insn->consumedDisplacement)
		return 0;

	if (materialize) {
		insn->consumedDisplacement = true;
		insn->displacementOffset = insn->readerCursor;
	}

	switch (insn->eaDisplacement) {
	case EA_DISP_NONE:
		if (materialize)
			insn->consumedDisplacement = false;
		break;
	case EA_DISP_8:
		if (consumeInt8(insn, &d8))
			return -1;
		if (materialize) {
			insn->displacementSize = 1;
			insn->displacement = d8;
		}
		break;
	case EA_DISP_16:
		if (consumeInt16(insn, &d16))
			return -1;
		if (materialize) {
			insn->displacementSize = 2;
			insn->displacement = d16;
		}
		break;
	case EA_DISP_32:
		if (consumeInt32(insn, &d32))
			return -1;
		if (materialize) {
			insn->displacementSize = 4;
			insn->displacement = d32;
		}
		break;
	}

	return 0;
}

/*
 * readModRM - Consumes all addressing information (ModR/M byte, SIB byte, and
 *   displacement) for an instruction and interprets it.
 *
 * @param insn  - The instruction whose addressing information is to be read.
 * @return      - 0 if the information was successfully read; nonzero otherwise.
 */
X86_DECODE_INLINE int readModRMImpl(struct InternalInstruction *insn,
				    bool materialize)
{
	uint8_t mod, rm, reg, evexrm;

	// dbgprintf(insn, "readModRM()");

	if (insn->consumedModRM)
		return 0;

	if (materialize)
		insn->modRMOffset = (uint8_t)insn->readerCursor;

	if (consumeByte(insn, &insn->modRM))
		return -1;

	insn->consumedModRM = true;

	// save original ModRM for later reference
	insn->orgModRM = insn->modRM;

	// handle MOVcr, MOVdr, MOVrc, MOVrd by pretending they have MRM.mod = 3
	/* Compact admission excludes control/debug-register operands. */
	if (materialize &&
	    (insn->firstByte == 0x0f && insn->opcodeType == TWOBYTE) &&
	    (insn->opcode >= 0x20 && insn->opcode <= 0x23))
		insn->modRM |= 0xC0;

	mod = modFromModRM(insn->modRM);
	rm = rmFromModRM(insn->modRM);
	evexrm = 0;
	if (materialize) {
		reg = regFromModRM(insn->modRM);

		/*
	 * This goes by insn->registerSize to pick the correct register, which messes
	 * up if we're using (say) XMM or 8-bit register operands.  That gets fixed in
	 * readOperands().
	 */
		switch (insn->registerSize) {
		case 2:
			insn->regBase = MODRM_REG_AX;
			insn->eaRegBase = EA_REG_AX;
			break;
		case 4:
			insn->regBase = MODRM_REG_EAX;
			insn->eaRegBase = EA_REG_EAX;
			break;
		case 8:
			insn->regBase = MODRM_REG_RAX;
			insn->eaRegBase = EA_REG_RAX;
			break;
		}

		reg |= rFromREX(insn->rexPrefix) << 3;
		if (insn->vectorExtensionType == TYPE_EVEX &&
		    insn->mode == MODE_64BIT) {
			reg |= r2FromEVEX2of4(insn->vectorExtensionPrefix[1])
			       << 4;
			evexrm = xFromEVEX2of4(insn->vectorExtensionPrefix[1])
				 << 4;
		}

		insn->reg = (Reg)(insn->regBase + reg);
	}
	rm |= bFromREX(insn->rexPrefix) << 3;

	switch (insn->addressSize) {
	case 2: {
		EABase eaBaseBase = EA_BASE_BX_SI;

		switch (mod) {
		case 0x0:
			if (rm == 0x6) {
				if (materialize) {
					insn->eaBase = EA_BASE_NONE;
				}
				insn->eaDisplacement = EA_DISP_16;
				if (readDisplacement(insn, materialize))
					return -1;
			} else {
				if (materialize) {
					insn->eaBase =
						(EABase)(eaBaseBase + rm);
				}
				insn->eaDisplacement = EA_DISP_NONE;
			}
			break;
		case 0x1:
			if (materialize) {
				insn->eaBase = (EABase)(eaBaseBase + rm);
			}
			insn->eaDisplacement = EA_DISP_8;
			if (materialize) {
				insn->displacementSize = 1;
			}
			if (readDisplacement(insn, materialize))
				return -1;
			break;
		case 0x2:
			if (materialize) {
				insn->eaBase = (EABase)(eaBaseBase + rm);
			}
			insn->eaDisplacement = EA_DISP_16;
			if (readDisplacement(insn, materialize))
				return -1;
			break;
		case 0x3:
			if (materialize) {
				insn->eaBase = (EABase)(insn->eaRegBase + rm);
			}
			if (readDisplacement(insn, materialize))
				return -1;
			break;
		}
		break;
	}

	case 4:
	case 8: {
		EABase eaBaseBase =
			(insn->addressSize == 4 ? EA_BASE_EAX : EA_BASE_RAX);

		switch (mod) {
		default:
			break;
		case 0x0:
			insn->eaDisplacement =
				EA_DISP_NONE; /* readSIB may override this */
			// In determining whether RIP-relative mode is used (rm=5),
			// or whether a SIB byte is present (rm=4),
			// the extension bits (REX.b and EVEX.x) are ignored.
			switch (rm & 7) {
			case 0x4: // SIB byte is present
				if (materialize) {
					insn->eaBase = (insn->addressSize == 4 ?
								EA_BASE_sib :
								EA_BASE_sib64);
				}
				if (readSIB(insn, materialize) ||
				    readDisplacement(insn, materialize))
					return -1;
				break;
			case 0x5: // RIP-relative
				if (materialize) {
					insn->eaBase = EA_BASE_NONE;
				}
				insn->eaDisplacement = EA_DISP_32;
				if (readDisplacement(insn, materialize))
					return -1;
				break;
			default:
				if (materialize) {
					insn->eaBase =
						(EABase)(eaBaseBase + rm);
				}
				break;
			}
			break;
		case 0x1:
			if (materialize) {
				insn->displacementSize = 1;
			}
			/* FALLTHROUGH */
		case 0x2:
			insn->eaDisplacement =
				(mod == 0x1 ? EA_DISP_8 : EA_DISP_32);
			switch (rm & 7) {
			case 0x4: // SIB byte is present
				if (materialize) {
					insn->eaBase = EA_BASE_sib;
				}
				if (readSIB(insn, materialize) ||
				    readDisplacement(insn, materialize))
					return -1;
				break;
			default:
				if (materialize) {
					insn->eaBase =
						(EABase)(eaBaseBase + rm);
				}
				if (readDisplacement(insn, materialize))
					return -1;
				break;
			}
			break;
		case 0x3:
			insn->eaDisplacement = EA_DISP_NONE;
			if (materialize) {
				insn->eaBase =
					(EABase)(insn->eaRegBase + rm + evexrm);
			}
			break;
		}

		break;
	}
	} /* switch (insn->addressSize) */

	return 0;
}

static int readModRM(struct InternalInstruction *insn)
{
	return readModRMImpl(insn, true);
}

X86_DECODE_INLINE int readModRMScan(struct InternalInstruction *insn)
{
	return readModRMImpl(insn, false);
}

/* Specializations below pass constant operand classes to the same readers
 * and validators as the generic operand interpreter. */
#define GENERIC_FIXUP_FUNC(name, base, prefix, mask, rm_field) \
	X86_DECODE_INLINE uint16_t name(struct InternalInstruction *insn, \
					OperandType type, uint8_t index, \
					uint8_t *valid) \
	{ \
		*valid = 1; \
		switch (type) { \
		default: \
			*valid = 0; \
			return 0; \
		case TYPE_Rv: \
			return base + index; \
		case TYPE_R8: \
			index &= mask; \
			if (index > 0xf) \
				*valid = 0; \
			if (insn->rexPrefix && index >= 4 && index <= 7) { \
				return prefix##_SPL + (index - 4); \
			} else { \
				return prefix##_AL + index; \
			} \
		case TYPE_R16: \
			index &= mask; \
			if (index > 0xf) \
				*valid = 0; \
			return prefix##_AX + index; \
		case TYPE_R32: \
			index &= mask; \
			if (index > 0xf) \
				*valid = 0; \
			return prefix##_EAX + index; \
		case TYPE_R64: \
			index &= mask; \
			if (index > 0xf) \
				*valid = 0; \
			return prefix##_RAX + index; \
		case TYPE_ZMM: \
			return prefix##_ZMM0 + index; \
		case TYPE_YMM: \
			return prefix##_YMM0 + index; \
		case TYPE_XMM: \
			return prefix##_XMM0 + index; \
		case TYPE_VK: \
			/* An opmask register in ModRM.reg or VVVV has no \
			 * extension bits; in ModRM.r/m, B and X are ignored. */ \
			if (index > 7 && !(rm_field)) \
				*valid = 0; \
			return prefix##_K0 + (index & 7); \
		case TYPE_MM64: \
			return prefix##_MM0 + (index & 0x7); \
		case TYPE_SEGMENTREG: \
			if ((index & 7) > 5) \
				*valid = 0; \
			return prefix##_ES + (index & 7); \
		case TYPE_DEBUGREG: \
			return prefix##_DR0 + index; \
		case TYPE_CONTROLREG: \
			return prefix##_CR0 + index; \
		case TYPE_BNDR: \
			if (index > 3) \
				*valid = 0; \
			return prefix##_BND0 + index; \
		case TYPE_MVSIBX: \
			return prefix##_XMM0 + index; \
		case TYPE_MVSIBY: \
			return prefix##_YMM0 + index; \
		case TYPE_MVSIBZ: \
			return prefix##_ZMM0 + index; \
		} \
	}

/*
 * fixup*Value - Consults an operand type to determine the meaning of the
 *   reg or R/M field.  If the operand is an XMM operand, for example, an
 *   operand would be XMM0 instead of AX, which readModRM() would otherwise
 *   misinterpret it as.
 *
 * @param insn  - The instruction containing the operand.
 * @param type  - The operand type.
 * @param index - The existing value of the field as reported by readModRM().
 * @param valid - The address of a uint8_t.  The target is set to 1 if the
 *                field is valid for the register class; 0 if not.
 * @return      - The proper value.
 */
GENERIC_FIXUP_FUNC(fixupRegValue, insn->regBase, MODRM_REG, 0x1f, false)
GENERIC_FIXUP_FUNC(fixupRMValue, insn->eaRegBase, EA_REG, 0xf, true)

/*
 * readOpcodeRegister - Reads an operand from the opcode field of an
 *   instruction and interprets it appropriately given the operand width.
 *   Handles AddRegFrm instructions.
 *
 * @param insn  - the instruction whose opcode field is to be read.
 * @param size  - The width (in bytes) of the register being specified.
 *                1 means AL and friends, 2 means AX, 4 means EAX, and 8 means
 *                RAX.
 * @return      - 0 on success; nonzero otherwise.
 */
X86_DECODE_INLINE int readOpcodeRegister(struct InternalInstruction *insn,
					 uint8_t size)
{
	if (size == 0)
		size = insn->registerSize;

	switch (size) {
	case 1:
		insn->opcodeRegister =
			(Reg)(MODRM_REG_AL + ((bFromREX(insn->rexPrefix) << 3) |
					      (insn->opcode & 7)));
		if (insn->rexPrefix &&
		    insn->opcodeRegister >= MODRM_REG_AL + 0x4 &&
		    insn->opcodeRegister < MODRM_REG_AL + 0x8) {
			insn->opcodeRegister =
				(Reg)(MODRM_REG_SPL + (insn->opcodeRegister -
						       MODRM_REG_AL - 4));
		}

		break;
	case 2:
		insn->opcodeRegister =
			(Reg)(MODRM_REG_AX + ((bFromREX(insn->rexPrefix) << 3) |
					      (insn->opcode & 7)));
		break;
	case 4:
		insn->opcodeRegister = (Reg)(MODRM_REG_EAX +
					     ((bFromREX(insn->rexPrefix) << 3) |
					      (insn->opcode & 7)));
		break;
	case 8:
		insn->opcodeRegister = (Reg)(MODRM_REG_RAX +
					     ((bFromREX(insn->rexPrefix) << 3) |
					      (insn->opcode & 7)));
		break;
	}

	return 0;
}

/*
 * readImmediate - Consumes an immediate operand from an instruction, given the
 *   desired operand size.
 *
 * @param insn  - The instruction whose operand is to be read.
 * @param size  - The width (in bytes) of the operand.
 * @return      - 0 if the immediate was successfully consumed; nonzero
 *                otherwise.
 */
X86_DECODE_INLINE int readImmediateImpl(struct InternalInstruction *insn,
					uint8_t size, bool materialize)
{
	uint8_t imm8;
	uint16_t imm16;
	uint32_t imm32;
	uint64_t imm64;

	if (insn->numImmediatesConsumed == 2) {
		// debug("Already consumed two immediates");
		return -1;
	}

	if (size == 0)
		size = insn->immediateSize;
	else
		insn->immediateSize = size;

	if (materialize)
		insn->immediateOffset = insn->readerCursor;

	switch (size) {
	case 1:
		if (consumeByte(insn, &imm8))
			return -1;

		if (materialize)
			insn->immediates[insn->numImmediatesConsumed] = imm8;
		break;
	case 2:
		if (consumeUInt16(insn, &imm16))
			return -1;

		if (materialize)
			insn->immediates[insn->numImmediatesConsumed] = imm16;
		break;
	case 4:
		if (consumeUInt32(insn, &imm32))
			return -1;

		if (materialize)
			insn->immediates[insn->numImmediatesConsumed] = imm32;
		break;
	case 8:
		if (consumeUInt64(insn, &imm64))
			return -1;
		if (materialize)
			insn->immediates[insn->numImmediatesConsumed] = imm64;
		break;
	}

	insn->numImmediatesConsumed++;

	return 0;
}

static int readImmediate(struct InternalInstruction *insn, uint8_t size)
{
	return readImmediateImpl(insn, size, true);
}

X86_DECODE_INLINE int readMemoryOffset(struct InternalInstruction *insn,
				       bool materialize)
{
	if (readImmediateImpl(insn, insn->addressSize, materialize))
		return -1;
	if (materialize) {
		insn->displacementOffset = insn->immediateOffset;
		insn->consumedDisplacement = true;
		insn->displacementSize = insn->immediateSize;
		insn->displacement =
			insn->immediates[insn->numImmediatesConsumed - 1];
		insn->immediateOffset = 0;
	}
	insn->immediateSize = 0;
	return 0;
}

/*
 * readVVVV - Consumes vvvv from an instruction if it has a VEX prefix.
 *
 * @param insn  - The instruction whose operand is to be read.
 * @return      - 0 if the vvvv was successfully consumed; nonzero
 *                otherwise.
 */
static int readVVVV(struct InternalInstruction *insn)
{
	int vvvv;

	if (insn->vectorExtensionType == TYPE_EVEX)
		vvvv = (v2FromEVEX4of4(insn->vectorExtensionPrefix[3]) << 4 |
			vvvvFromEVEX3of4(insn->vectorExtensionPrefix[2]));
	else if (insn->vectorExtensionType == TYPE_VEX_3B)
		vvvv = vvvvFromVEX3of3(insn->vectorExtensionPrefix[2]);
	else if (insn->vectorExtensionType == TYPE_VEX_2B)
		vvvv = vvvvFromVEX2of2(insn->vectorExtensionPrefix[1]);
	else if (insn->vectorExtensionType == TYPE_XOP)
		vvvv = vvvvFromXOP3of3(insn->vectorExtensionPrefix[2]);
	else
		return -1;

	if (insn->mode != MODE_64BIT)
		vvvv &= 0xf; // Can only clear bit 4. Bit 3 must be cleared later.

	insn->vvvv = (Reg)vvvv;

	return 0;
}

/*
 * readMaskRegister - Reads an mask register from the opcode field of an
 *   instruction.
 *
 * @param insn    - The instruction whose opcode field is to be read.
 * @return        - 0 on success; nonzero otherwise.
 */
static int readMaskRegister(struct InternalInstruction *insn)
{
	if (insn->vectorExtensionType != TYPE_EVEX)
		return -1;

	insn->writemask =
		(Reg)(aaaFromEVEX4of4(insn->vectorExtensionPrefix[3]));

	return 0;
}

/* The caller has already consumed ModR/M and any addressing bytes. */
X86_DECODE_INLINE int fixupRegisterOperand(struct InternalInstruction *insn,
					    OperandType type)
{
	uint8_t valid;
	insn->reg = (Reg)fixupRegValue(insn, type, insn->reg - insn->regBase,
				       &valid);
	if (!valid)
		return -1;
	return 0;
}

X86_DECODE_INLINE int fixupRMOperand(struct InternalInstruction *insn,
				      OperandType type,
				      OperandEncoding encoding)
{
	uint8_t valid;
	if (insn->eaBase >= insn->eaRegBase) {
		insn->eaBase = (EABase)fixupRMValue(
			insn, type, insn->eaBase - insn->eaRegBase, &valid);
		if (!valid)
			return -1;
	}

	// Apply the AVX512 compressed displacement scaling factor.
	if (insn->eaDisplacement == EA_DISP_8)
		insn->displacement *= 1 << (encoding - ENCODING_RM);
	return 0;
}

X86_DECODE_INLINE int readVSIBOperand(struct InternalInstruction *insn,
				       OperandType type,
				       OperandEncoding encoding, int hasVVVV,
				       int *needVVVV)
{
	// VSIB can use the V2 bit so check only the other bits.
	if (*needVVVV)
		*needVVVV = hasVVVV & ((insn->vvvv & 0xf) != 0);

	if (readModRM(insn))
		return -1;

	// Reject if SIB wasn't used.
	if (insn->eaBase != EA_BASE_sib && insn->eaBase != EA_BASE_sib64)
		return -1;

	// If sibIndex was set to SIB_INDEX_NONE, index offset is 4.
	if (insn->sibIndex == SIB_INDEX_NONE)
		insn->sibIndex = (SIBIndex)(insn->sibIndexBase + 4);

	// If EVEX.v2 is set this is one of the 16-31 registers.
	if (insn->vectorExtensionType == TYPE_EVEX &&
	    insn->mode == MODE_64BIT &&
	    v2FromEVEX4of4(insn->vectorExtensionPrefix[3]))
		insn->sibIndex = (SIBIndex)(insn->sibIndex + 16);

	// Adjust the index register to the correct size.
	switch (type) {
	default:
		// debug("Unhandled VSIB index type");
		return -1;
	case TYPE_MVSIBX:
		insn->sibIndex =
			(SIBIndex)(SIB_INDEX_XMM0 +
				   (insn->sibIndex - insn->sibIndexBase));
		break;
	case TYPE_MVSIBY:
		insn->sibIndex =
			(SIBIndex)(SIB_INDEX_YMM0 +
				   (insn->sibIndex - insn->sibIndexBase));
		break;
	case TYPE_MVSIBZ:
		insn->sibIndex =
			(SIBIndex)(SIB_INDEX_ZMM0 +
				   (insn->sibIndex - insn->sibIndexBase));
		break;
	}

	// Apply the AVX512 compressed displacement scaling factor.
	if (encoding != ENCODING_REG && insn->eaDisplacement == EA_DISP_8)
		insn->displacement *= 1 << (encoding - ENCODING_VSIB);

	return 0;
}

X86_DECODE_INLINE int readVVVVOperand(struct InternalInstruction *insn,
				       OperandType type, int hasVVVV,
				       int *needVVVV)
{
	uint8_t valid;

	if (!hasVVVV)
		return -1;

	*needVVVV = 0; /* Mark that we have found a VVVV operand. */

	if (insn->mode != MODE_64BIT)
		insn->vvvv = (Reg)(insn->vvvv & 0x7);

	insn->vvvv =
		(Reg)fixupRegValue(insn, (OperandType)type, insn->vvvv, &valid);
	if (!valid)
		return -1;

	return 0;
}

/*
 * readOperands - Consults the specifier for an instruction and consumes all
 *   operands for that instruction, interpreting them as it goes.
 *
 * @param insn  - The instruction whose operands are to be read and interpreted.
 * @return      - 0 if all operands could be read; nonzero otherwise.
 */
static int readOperands(struct InternalInstruction *insn)
{
	static const OperandSpecifier ud1Operands[2][X86_MAX_OPERANDS] = {
		{ { ENCODING_REG, TYPE_R32 }, { ENCODING_RM, TYPE_R32 } },
		{ { ENCODING_REG, TYPE_R32 }, { ENCODING_RM, TYPE_M } },
	};
	int hasVVVV, needVVVV;
	int sawRegImm = 0;
	int i;

	insn->operands = &x86OperandSets[insn->spec->operands][0];
	if (insn->instructionID == X86_UD1) {
		/* The older generated descriptor omits UD1's r32/rm32 operands.
		 * Reuse the normal addressing reader, including REX2 map 1, and
		 * keep operand width independent of 66 and REX.W (SDM UD). */
		insn->registerSize = insn->operandSize = 4;
		insn->displacementSize = insn->addressSize == 2 ? 2 : 4;
		if (readModRM(insn))
			return -1;
		insn->operands = ud1Operands[modFromModRM(insn->modRM) != 3];
	}

	/* If non-zero vvvv specified, need to make sure one of the operands
	   uses it. */
	hasVVVV = !readVVVV(insn);
	needVVVV = hasVVVV && (insn->vvvv != 0);

	/* UD1 overrides its generated operands above. The generated
	 * readers otherwise use exactly the selected operand set. */
	if (insn->instructionID != X86_UD1) {
#include "X86GenOperandRead.inc"
	}

	for (i = 0; i < X86_MAX_OPERANDS &&
		    insn->operands[i].encoding != ENCODING_NONE;
	     ++i) {
		const OperandSpecifier *op = &insn->operands[i];
		switch (op->encoding) {
		case ENCODING_SI:
		case ENCODING_DI:
			break;

CASE_ENCODING_VSIB:
			if (readVSIBOperand(insn, (OperandType)op->type,
					    (OperandEncoding)op->encoding,
					    hasVVVV, &needVVVV))
				return -1;
			break;

		case ENCODING_REG:
			if (readModRM(insn) ||
			    fixupRegisterOperand(insn, (OperandType)op->type))
				return -1;
			break;

CASE_ENCODING_RM:
			if (readModRM(insn) ||
			    fixupRMOperand(insn, (OperandType)op->type,
					   (OperandEncoding)op->encoding))
				return -1;
			break;

		case ENCODING_IB:
			if (sawRegImm) {
				/* Saw a register immediate so don't read again and instead split the
					   previous immediate.  FIXME: This is a hack. */
				insn->immediates[insn->numImmediatesConsumed] =
					insn->immediates
						[insn->numImmediatesConsumed -
						 1] &
					0xf;
				++insn->numImmediatesConsumed;
				break;
			}
			if (readImmediate(insn, 1))
				return -1;
			if (op->type == TYPE_XMM || op->type == TYPE_YMM)
				sawRegImm = 1;
			break;

		case ENCODING_IW:
			if (readImmediate(insn, 2))
				return -1;
			break;

		case ENCODING_ID:
			if (readImmediate(insn, 4))
				return -1;
			break;

		case ENCODING_IO:
			if (readImmediate(insn, 8))
				return -1;
			break;

		case ENCODING_Iv:
			if (readImmediate(insn, insn->immediateSize))
				return -1;
			break;

		case ENCODING_Ia:
			if (readMemoryOffset(insn, true))
				return -1;
			break;

		case ENCODING_IRC:
			insn->RC =
				(l2FromEVEX4of4(insn->vectorExtensionPrefix[3])
				 << 1) |
				lFromEVEX4of4(insn->vectorExtensionPrefix[3]);
			break;

		case ENCODING_RB:
			if (readOpcodeRegister(insn, 1))
				return -1;
			break;

		case ENCODING_RW:
			if (readOpcodeRegister(insn, 2))
				return -1;
			break;

		case ENCODING_RD:
			if (readOpcodeRegister(insn, 4))
				return -1;
			break;

		case ENCODING_RO:
			if (readOpcodeRegister(insn, 8))
				return -1;
			break;

		case ENCODING_Rv:
			if (readOpcodeRegister(insn, 0))
				return -1;
			break;

		case ENCODING_FP:
			break;

		case ENCODING_VVVV:
			if (readVVVVOperand(insn, (OperandType)op->type,
					    hasVVVV, &needVVVV))
				return -1;
			break;

		case ENCODING_WRITEMASK:
			if (readMaskRegister(insn))
				return -1;
			break;

		case ENCODING_DUP:
			break;

		default:
			// dbgprintf(insn, "Encountered an operand with an unknown encoding.");
			return -1;
		}
	}

	/* If we didn't find ENCODING_VVVV operand, but non-zero vvvv present, fail */
	if (needVVVV)
		return -1;

	return 0;
}

/*
 * checkEVEX - Rejects the EVEX encodings that the decode tables accept but
 *   that are #UD, as XED rejects them: zeroing without an opmask, the reserved
 *   vector length L'L = 11 outside a register-form rounding control, and
 *   EVEX.V' outside 64-bit mode.
 *
 * @param insn  - The EVEX instruction whose operands have been read.
 * @return      - 0 if the EVEX prefix is legal; nonzero otherwise.
 */
X86_DECODE_INLINE int checkEVEX(const struct InternalInstruction *insn)
{
	uint8_t p2;
	bool registerForm;

	p2 = insn->vectorExtensionPrefix[3];
	registerForm = insn->consumedModRM && modFromModRM(insn->modRM) == 3;
	if (zFromEVEX4of4(p2) && !aaaFromEVEX4of4(p2))
		return -1;
	if (l2FromEVEX4of4(p2) && lFromEVEX4of4(p2) &&
	    !(bFromEVEX4of4(p2) && registerForm))
		return -1;
	if (insn->mode != MODE_64BIT && v2FromEVEX4of4(p2))
		return -1;
	return 0;
}

/* The architectural number of a vector register, whatever its width. */
static int vectorRegisterNumber(Reg reg)
{
	if (reg >= MODRM_REG_XMM0 && reg <= MODRM_REG_XMM31)
		return reg - MODRM_REG_XMM0;
	if (reg >= MODRM_REG_YMM0 && reg <= MODRM_REG_YMM31)
		return reg - MODRM_REG_YMM0;
	if (reg >= MODRM_REG_ZMM0 && reg <= MODRM_REG_ZMM31)
		return reg - MODRM_REG_ZMM0;
	return -1;
}

static int vectorIndexNumber(SIBIndex index)
{
	if (index >= SIB_INDEX_XMM0 && index <= SIB_INDEX_XMM31)
		return index - SIB_INDEX_XMM0;
	if (index >= SIB_INDEX_YMM0 && index <= SIB_INDEX_YMM31)
		return index - SIB_INDEX_YMM0;
	if (index >= SIB_INDEX_ZMM0 && index <= SIB_INDEX_ZMM31)
		return index - SIB_INDEX_ZMM0;
	return -1;
}

/*
 * checkGatherRegisters - Rejects a gather whose destination shares a register
 *   with its vector index or, in the VEX form, whose mask shares one with
 *   either; the SDM makes both #UD, and XED rejects them.
 *
 * @param insn  - The instruction whose operands have been read.
 * @param index - The decoded vector index register number.
 * @return      - 0 if the registers are distinct; nonzero otherwise.
 */
static int checkGatherRegisters(const struct InternalInstruction *insn,
				int index)
{
	const OperandSpecifier *operands = insn->operands;
	int destination, mask = -1;
	bool reg = false, vsib = false;
	int i;

	/* A gather lists its ModRM.reg destination before its VSIB source; a
	 * scatter lists its VSIB destination first. */
	for (i = 0; i < X86_MAX_OPERANDS; ++i) {
		switch (operands[i].encoding) {
		default:
			break;
		case ENCODING_REG:
			reg = true;
			break;
CASE_ENCODING_VSIB:
			if (!reg)
				return 0;
			vsib = true;
			break;
		case ENCODING_VVVV:
			mask = vectorRegisterNumber(insn->vvvv);
			break;
		}
	}
	if (!vsib)
		return 0;
	destination = vectorRegisterNumber(insn->reg);
	if (destination < 0)
		return 0;
	if (destination == index ||
	    (mask >= 0 && (mask == destination || mask == index)))
		return -1;
	return 0;
}

static bool isRex2ForbiddenExtendedStateInstruction(uint16_t instructionID)
{
	switch (instructionID) {
	default:
		return false;
	case X86_XRSTOR:
	case X86_XRSTOR64:
	case X86_XRSTORS:
	case X86_XRSTORS64:
	case X86_XSAVE:
	case X86_XSAVE64:
	case X86_XSAVEC:
	case X86_XSAVEC64:
	case X86_XSAVEOPT:
	case X86_XSAVEOPT64:
	case X86_XSAVES:
	case X86_XSAVES64:
		return true;
	}
}

// return True if instruction is illegal to use with prefixes
// This also check & fix the isPrefixNN when a prefix is irrelevant.
X86_DECODE_INLINE bool checkPrefix(struct InternalInstruction *insn)
{
	if (insn->hasRex2 &&
	    isRex2ForbiddenExtendedStateInstruction(insn->instructionID))
		return true;

	// LOCK prefix
	if (insn->hasLockPrefix) {
		switch (insn->instructionID) {
		default:
			// invalid LOCK
			return true;

		// DEC
		case X86_DEC16m:
		case X86_DEC32m:
		case X86_DEC64m:
		case X86_DEC8m:

		// ADC
		case X86_ADC16mi:
		case X86_ADC16mi8:
		case X86_ADC16mr:
		case X86_ADC32mi:
		case X86_ADC32mi8:
		case X86_ADC32mr:
		case X86_ADC64mi32:
		case X86_ADC64mi8:
		case X86_ADC64mr:
		case X86_ADC8mi:
		case X86_ADC8mi8:
		case X86_ADC8mr:

		// ADD
		case X86_ADD16mi:
		case X86_ADD16mi8:
		case X86_ADD16mr:
		case X86_ADD32mi:
		case X86_ADD32mi8:
		case X86_ADD32mr:
		case X86_ADD64mi32:
		case X86_ADD64mi8:
		case X86_ADD64mr:
		case X86_ADD8mi:
		case X86_ADD8mi8:
		case X86_ADD8mr:

		// AND
		case X86_AND16mi:
		case X86_AND16mi8:
		case X86_AND16mr:
		case X86_AND32mi:
		case X86_AND32mi8:
		case X86_AND32mr:
		case X86_AND64mi32:
		case X86_AND64mi8:
		case X86_AND64mr:
		case X86_AND8mi:
		case X86_AND8mi8:
		case X86_AND8mr:

		// BTC
		case X86_BTC16mi8:
		case X86_BTC16mr:
		case X86_BTC32mi8:
		case X86_BTC32mr:
		case X86_BTC64mi8:
		case X86_BTC64mr:

		// BTR
		case X86_BTR16mi8:
		case X86_BTR16mr:
		case X86_BTR32mi8:
		case X86_BTR32mr:
		case X86_BTR64mi8:
		case X86_BTR64mr:

		// BTS
		case X86_BTS16mi8:
		case X86_BTS16mr:
		case X86_BTS32mi8:
		case X86_BTS32mr:
		case X86_BTS64mi8:
		case X86_BTS64mr:

		// CMPXCHG
		case X86_CMPXCHG16B:
		case X86_CMPXCHG16rm:
		case X86_CMPXCHG32rm:
		case X86_CMPXCHG64rm:
		case X86_CMPXCHG8rm:
		case X86_CMPXCHG8B:

		// INC
		case X86_INC16m:
		case X86_INC32m:
		case X86_INC64m:
		case X86_INC8m:

		// NEG
		case X86_NEG16m:
		case X86_NEG32m:
		case X86_NEG64m:
		case X86_NEG8m:

		// NOT
		case X86_NOT16m:
		case X86_NOT32m:
		case X86_NOT64m:
		case X86_NOT8m:

		// OR
		case X86_OR16mi:
		case X86_OR16mi8:
		case X86_OR16mr:
		case X86_OR32mi:
		case X86_OR32mi8:
		case X86_OR32mr:
		case X86_OR64mi32:
		case X86_OR64mi8:
		case X86_OR64mr:
		case X86_OR8mi8:
		case X86_OR8mi:
		case X86_OR8mr:

		// SBB
		case X86_SBB16mi:
		case X86_SBB16mi8:
		case X86_SBB16mr:
		case X86_SBB32mi:
		case X86_SBB32mi8:
		case X86_SBB32mr:
		case X86_SBB64mi32:
		case X86_SBB64mi8:
		case X86_SBB64mr:
		case X86_SBB8mi:
		case X86_SBB8mi8:
		case X86_SBB8mr:

		// SUB
		case X86_SUB16mi:
		case X86_SUB16mi8:
		case X86_SUB16mr:
		case X86_SUB32mi:
		case X86_SUB32mi8:
		case X86_SUB32mr:
		case X86_SUB64mi32:
		case X86_SUB64mi8:
		case X86_SUB64mr:
		case X86_SUB8mi8:
		case X86_SUB8mi:
		case X86_SUB8mr:

		// XADD
		case X86_XADD16rm:
		case X86_XADD32rm:
		case X86_XADD64rm:
		case X86_XADD8rm:

		// XCHG
		case X86_XCHG16rm:
		case X86_XCHG32rm:
		case X86_XCHG64rm:
		case X86_XCHG8rm:

		// XOR
		case X86_XOR16mi:
		case X86_XOR16mi8:
		case X86_XOR16mr:
		case X86_XOR32mi:
		case X86_XOR32mi8:
		case X86_XOR32mr:
		case X86_XOR64mi32:
		case X86_XOR64mi8:
		case X86_XOR64mr:
		case X86_XOR8mi8:
		case X86_XOR8mi:
		case X86_XOR8mr:

			// this instruction can be used with LOCK prefix
			return false;
		}
	}

#if 0
	// REPNE prefix
	if (insn->repeatPrefix) {
		// 0xf2 can be a part of instruction encoding, but not really a prefix.
		// In such a case, clear it.
		if (insn->twoByteEscape == 0x0f) {
			insn->prefix0 = 0;
		}
	}
#endif

	// no invalid prefixes
	return false;
}

/* Prefix and opcode reads are shared by generic and generated terminals. */
X86_DECODE_INLINE void
initializeInstructionHeader(struct InternalInstruction *insn,
			    const uint8_t *code, size_t codeSize, cs_mode mode)
{
	insn->code = code;
	insn->codeSize = codeSize;
	insn->readerCursor = 0;
	if (x86_has_feature(mode, CS_MODE_16))
		insn->mode = MODE_16BIT;
	else if (x86_has_feature(mode, CS_MODE_32))
		insn->mode = MODE_32BIT;
	else
		insn->mode = MODE_64BIT;
	insn->numImmediatesConsumed = 0;
}

X86_DECODE_INLINE PrefixReadStatus
readInstructionHeader(struct InternalInstruction *insn, const uint8_t *code,
		      size_t codeSize, cs_mode mode)
{
	initializeInstructionHeader(insn, code, codeSize, mode);

	const PrefixReadStatus prefixResult = readPrefixes(insn);
	if (prefixResult == PREFIX_READ_INVALID)
		return -1;
	const bool simpleLegacy = prefixResult == PREFIX_READ_SIMPLE_LEGACY;
	if (readOpcode(insn, simpleLegacy, false))
		return PREFIX_READ_INVALID;

	return prefixResult;
}

X86_DECODE_INLINE int finishDecodedInstruction(struct InternalInstruction *insn,
					       bool genericChecks)
{
	if (genericChecks) {
		if (insn->vectorExtensionType == TYPE_EVEX && checkEVEX(insn))
			return -1;

		/* Only a decoded VSIB index can participate in a gather conflict. */
		const int index = vectorIndexNumber(insn->sibIndex);
		if (index >= 0 && checkGatherRegisters(insn, index))
			return -1;
	}

	/* Compact terminal admission excludes segment-register operands.
	 * MOV can read CS (8C /1), but loading CS (8E /1) always raises #UD.
	 * Segment selectors ignore REX/REX2 register extension bits. */
	if (genericChecks && insn->opcodeType == ONEBYTE &&
	    insn->opcode == 0x8e && regFromModRM(insn->orgModRM) == 1)
		return -1;

	insn->length = insn->readerCursor;

	// instruction length must be <= 15 to be valid
	if (insn->length > 15)
		return -1;

	if (insn->operandSize == 0)
		insn->operandSize = insn->registerSize;

	return 0;
}

#include "X86GenLegacyTerminal.inc"
#include "X86GenVexScan.inc"

int decodeInstruction(struct InternalInstruction *insn, const uint8_t *code,
		      size_t codeSize, cs_mode mode)
{
	return decodeInstructionScan(insn, code, codeSize, mode, NULL, NULL);
}

/* All selected operands are read and validated within one dispatch. */
static int readOperandsScan(struct InternalInstruction *insn, MCInst *mcInst,
			    uint16_t *size)
{
	if (insn->instructionID != X86_UD1) {
#include "X86GenOperandScan.inc"
	}

	if (readOperands(insn) || finishDecodedInstruction(insn, true))
		return X86_SCAN_INVALID;
	return X86_SCAN_RAW_READY;
}

X86_DECODE_INLINE uint64_t
legacyTerminalDecision(const struct InternalInstruction *insn,
		       bool sizePrefixes, bool publicID)
{
	if (insn->opcodeType != ONEBYTE && insn->opcodeType != TWOBYTE)
		return 0;
	/* Opcode 90 with REX.B is repaired to XCHG by getIDForMode. */
	if (insn->opcodeType == ONEBYTE && insn->opcode == 0x90 &&
	    bFromREX(insn->rexPrefix))
		return 0;
	unsigned int row;
	if (sizePrefixes && insn->mode != MODE_16BIT) {
		/* Preserve address-dependent and relative-branch size repairs. */
		if ((insn->opcodeType == ONEBYTE &&
		     ((insn->mode == MODE_64BIT && insn->opcode >= 0xa0 &&
		       insn->opcode <= 0xa3) ||
		      insn->opcode == 0xe8 || insn->opcode == 0xe9 ||
		      insn->opcode == 0xc2 || insn->opcode == 0xc3)) ||
		    (insn->opcodeType == TWOBYTE &&
		     (insn->opcode == 0xae ||
		      (insn->opcode >= 0x80 && insn->opcode <= 0x8f))))
			return 0;
		if (insn->mode == MODE_64BIT) {
			if (wFromREX(insn->rexPrefix))
				row = insn->hasOpSize ?
					      X86_TERMINAL_64_REXW_OPSIZE :
					      X86_TERMINAL_64_REXW;
			else if (insn->hasAdSize)
				row = insn->hasOpSize ?
					      X86_TERMINAL_64_OPSIZE_ADSIZE :
					      X86_TERMINAL_64_ADSIZE;
			else
				row = insn->hasOpSize ? X86_TERMINAL_64_OPSIZE :
							X86_TERMINAL_64;
		} else if (insn->hasAdSize)
			row = insn->hasOpSize ? X86_TERMINAL_32_OPSIZE_ADSIZE :
						X86_TERMINAL_32_ADSIZE;
		else
			row = insn->hasOpSize ? X86_TERMINAL_32_OPSIZE :
						X86_TERMINAL_32;
	} else if (insn->mode == MODE_64BIT)
		row = X86_TERMINAL_64 + wFromREX(insn->rexPrefix);
	else if (insn->mode == MODE_16BIT)
		row = (sizePrefixes && insn->hasAdSize ? X86_TERMINAL_16_ADSIZE :
					 X86_TERMINAL_16) +
		      (sizePrefixes && insn->hasOpSize);
	else
		row = X86_TERMINAL_32;
	return publicID ? x86LegacyPublicDecisions[row][insn->opcodeType ==
							TWOBYTE][insn->opcode] :
			  x86LegacyDecisions[row][insn->opcodeType == TWOBYTE]
					    [insn->opcode];
}

/* Private to the direct scan entry; existing decoder entries never return it. */
enum { X86_SCAN_UID_READY = 2 };

/* Ordinary legacy terminals have no LOCK, REX2 or vector prefixes. Other
 * encodings retain generic ID selection and prefix validation before operands.
 * EVEX keeps its raw policy and backend restoration order. */
X86_DECODE_INLINE int
decodeInstructionScanImpl(struct InternalInstruction *insn, const uint8_t *code,
			  size_t codeSize, cs_mode mode, MCInst *mcInst,
			  uint16_t *size, bool directTerminal)
{
	const PrefixReadStatus prefixResult =
		readInstructionHeader(insn, code, codeSize, mode);
	if (prefixResult == PREFIX_READ_INVALID)
		return X86_SCAN_INVALID;
	/* getIDForMode restores incoming size flags for absolute moves even
	 * when this header contains no size prefix. Preserve that raw contract. */
	const bool inheritedMoffsSize = insn->opcodeType == ONEBYTE &&
					(insn->opcode & 0xfc) == 0xa0 &&
					(insn->hasOpSize || insn->hasAdSize);
	if (prefixResult == PREFIX_READ_SIMPLE_LEGACY && !inheritedMoffsSize &&
	    (insn->opcodeType == ONEBYTE || insn->opcodeType == TWOBYTE)) {
		const uint64_t decision =
			legacyTerminalDecision(insn, false, false);
		if (decision) {
			int result = decodeLegacyTerminal(
				insn, directTerminal ? NULL : mcInst, size,
				decision, directTerminal || mcInst != NULL,
				NULL, false);
			return directTerminal && result == X86_SCAN_COMPLETE ?
				       X86_SCAN_UID_READY :
				       result;
		}
	}
	if (getID(insn, mode) || insn->instructionID == 0 || checkPrefix(insn))
		return X86_SCAN_INVALID;
	if (mcInst)
		return readOperandsScan(insn, mcInst, size);
	if (readOperands(insn) || finishDecodedInstruction(insn, true))
		return X86_SCAN_INVALID;
	return X86_SCAN_RAW_READY;
}

int decodeInstructionScan(struct InternalInstruction *insn, const uint8_t *code,
			  size_t codeSize, cs_mode mode, MCInst *mcInst,
			  uint16_t *size)
{
	return decodeInstructionScanImpl(insn, code, codeSize, mode, mcInst,
					 size, false);
}

enum { X86_SCAN_NOT_HANDLED = 3 };

/* Only the compact readers see this state. Generic/raw decoding starts its
 * own state if the generated table has no terminal for this header. */
X86_DECODE_INLINE int trySimpleLegacyScan(const uint8_t *code, size_t codeSize,
					  cs_mode mode, uint8_t opcode,
					  size_t opcodeOffset,
					  unsigned *instructionID,
					  uint16_t *size, bool publicID,
					  bool readerFlags)
{
	if (opcodeOffset >= 2)
		return X86_SCAN_NOT_HANDLED;
	InternalInstruction insn = { 0 };
	initializeInstructionHeader(&insn, code, codeSize, mode);
	const uint8_t prefixMask =
		FEATURE_LEGACY_PREFIX | FEATURE_ESCAPE |
		(insn.mode == MODE_64BIT ? FEATURE_REX_PREFIX : 0);
	if ((feature_prefix_flags[opcode] & prefixMask) || opcode == 0xc5 ||
	    opcode == 0x8f || (opcodeOffset && !isREX(&insn, code[0])))
		return X86_SCAN_NOT_HANDLED;
	readSimpleLegacyPrefix(&insn, opcodeOffset);
	int opcodeResult = readOpcode(&insn, true, true);
	if (opcodeResult)
		return opcodeResult == OPCODE_READ_GENERIC ?
			       X86_SCAN_NOT_HANDLED :
			       X86_SCAN_INVALID;
	const uint64_t decision =
		legacyTerminalDecision(&insn, false, publicID);
	if (!decision)
		return X86_SCAN_NOT_HANDLED;
	int result = decodeLegacyTerminal(&insn, NULL, size, decision, true,
					  publicID ? instructionID : NULL,
					  readerFlags);
	if (result == X86_SCAN_COMPLETE && !publicID)
		*instructionID = insn.instructionID;
	return result;
}

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static bool decodeGenericScan(const uint8_t *code, size_t code_len,
			      cs_mode mode, MCInst *instr, uint16_t *size)
{
	InternalInstruction insn = { 0 };
	int ret = decodeInstructionScanImpl(&insn, code, code_len, mode, instr,
					    size, true);
	if (ret == X86_SCAN_UID_READY) {
		MCInst_clear(instr);
		MCInst_setOpcode(instr, insn.instructionID);
		return true;
	}
	if (ret != X86_SCAN_RAW_READY)
		return ret == X86_SCAN_COMPLETE;
	return X86_completeScan(instr, &insn, size);
}

X86_DECODE_INLINE int
tryLegacyPrefixedScan(const uint8_t *code, size_t code_len, cs_mode mode,
		      unsigned *instructionID, uint16_t *size, bool publicID,
		      bool guardExtensions, bool readerFlags)
{
	InternalInstruction insn = { 0 };
	/* Retain the decoder's bitness priority for mixed mode flags. */
	initializeInstructionHeader(&insn, code, code_len, mode);
	size_t offset = 0;
	/* Keep the 16-bit size-prefix loop small; other prefixes use the full reader. */
	while (offset < code_len && (insn.mode == MODE_16BIT || offset < 15)) {
		if (code[offset] == 0x66)
			setOperandSizePrefix(&insn);
		else if (code[offset] == 0x67)
			setAddressSizePrefix(&insn);
		else if (insn.mode != MODE_16BIT && isREX(&insn, code[offset]))
			insn.rexPrefix = code[offset];
		else if (insn.mode != MODE_16BIT &&
			 (code[offset] == 0x26 || code[offset] == 0x2e ||
			  code[offset] == 0x36 || code[offset] == 0x3e ||
			  code[offset] == 0x64 || code[offset] == 0x65))
			insn.rexPrefix = 0;
		else
			break;
		++offset;
	}
	if (!offset || offset == code_len ||
	    (insn.mode != MODE_16BIT && offset == 15))
		return X86_SCAN_NOT_HANDLED;
	const uint8_t opcode = code[offset];
	if ((feature_prefix_flags[opcode] &
	     (FEATURE_LEGACY_PREFIX | FEATURE_ESCAPE |
	      (insn.mode == MODE_64BIT ? FEATURE_REX_PREFIX : 0))) ||
	    opcode == 0xc5 || opcode == 0x8f)
		return X86_SCAN_NOT_HANDLED;
	if (guardExtensions && opcode == 0x0f &&
	    may_be_0f_feature_extension(code + offset + 1,
					code_len - offset - 1))
		return X86_SCAN_NOT_HANDLED;
	insn.readerCursor = offset;
	insn.vectorExtensionType = TYPE_NO_VEX_XOP;
	setInstructionSizes(&insn, insn.hasOpSize, insn.hasAdSize);
	int opcodeResult = readOpcode(&insn, true, true);
	if (opcodeResult == OPCODE_READ_GENERIC)
		return X86_SCAN_NOT_HANDLED;
	if (opcodeResult)
		return X86_SCAN_INVALID;
	const uint64_t decision = legacyTerminalDecision(&insn, true, publicID);
	if (!decision)
		return X86_SCAN_NOT_HANDLED;
	int result = decodeLegacyTerminal(&insn, NULL, size, decision, true,
					  publicID ? instructionID : NULL,
					  readerFlags);
	if (result == X86_SCAN_COMPLETE && !publicID)
		*instructionID = insn.instructionID;
	return result;
}

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static bool decode16BitSizePrefixedScan(const uint8_t *code, size_t code_len,
					cs_mode mode, MCInst *instr,
					uint16_t *size)
{
	unsigned instructionID;
	int result = tryLegacyPrefixedScan(code, code_len, CS_MODE_16,
					   &instructionID, size, false, false,
					   false);
	if (result == X86_SCAN_NOT_HANDLED)
		return decodeGenericScan(code, code_len, mode, instr, size);
	if (result != X86_SCAN_COMPLETE)
		return false;
	MCInst_clear(instr);
	MCInst_setOpcode(instr, instructionID);
	return true;
}

bool X86_getInstructionScan(csh ud, const uint8_t *code, size_t code_len,
			    MCInst *instr, uint16_t *size)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	uint8_t opcode;
	size_t opcodeOffset;
	if (X86_mayDecodeFeatureExtensionImpl(code, code_len,
					      (handle->mode & CS_MODE_64) != 0,
					      &opcode, &opcodeOffset)) {
		x86_feature_decode_result result = X86_decodeFeatureExtension(
			ud, code, code_len, instr, size, opcode);
		if (result == X86_FEATURE_DECODED)
			return true;
		if (result == X86_FEATURE_INVALID)
			return false;
	}
	if (opcode == 0x62)
		return X86_getInstructionAfterExtensions(ud, code, code_len,
							 instr, size, opcode);
	unsigned instructionID;
	int terminal = trySimpleLegacyScan(code, code_len, handle->mode, opcode,
					   opcodeOffset, &instructionID, size,
					   false, false);
	if (terminal != X86_SCAN_NOT_HANDLED) {
		if (terminal != X86_SCAN_COMPLETE)
			return false;
		MCInst_clear(instr);
		MCInst_setOpcode(instr, instructionID);
		return true;
	}
	if ((handle->mode & CS_MODE_16) && code_len &&
	    (code[0] == 0x66 || code[0] == 0x67))
		return decode16BitSizePrefixedScan(code, code_len, handle->mode,
						   instr, size);
	return decodeGenericScan(code, code_len, handle->mode, instr, size);
}

#ifdef CAPSTONE_X86_SCAN_ADAPTER
CAPSTONE_INTERNAL bool X86_setScanAdapter(csh ud, cs_mode mode,
					  X86ScanAdapter adapter,
					  void *user_data)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (!handle || handle->arch != CS_ARCH_X86)
		return false;
	if (adapter && ((mode != CS_MODE_32 && mode != CS_MODE_64) ||
			handle->mode != mode))
		return false;
	handle->x86_scan_adapter = adapter;
	handle->x86_scan_adapter_data = adapter ? user_data : NULL;
	handle->x86_scan_adapter_mode = adapter ? mode : 0;
	return true;
}
#endif

X86_DECODE_INLINE int tryVexTerminalScan(const uint8_t *code, size_t code_len,
					 uint8_t prefix, X86ScanResult *result);

/* Only generic and extension decoding need an MCInst in the core scan path. */
#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static CS_PRESERVE_MOST bool
decodeScanResultFallback(csh ud, const uint8_t *code, size_t code_len,
			 cs_insn *insn, X86ScanResult *result, uint8_t opcode,
			 bool tryExtension)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
#ifdef CAPSTONE_X86_SCAN_ADAPTER
	/* Keep the compact scalar and VEX readers free of adapter overhead. */
	if (code_len && ((code[0] & 0xfe) == 0xc4 || code[0] == 0x62) &&
	    handle->x86_scan_adapter &&
	    handle->x86_scan_adapter_mode == handle->mode) {
		const uint32_t packed = handle->x86_scan_adapter(
			handle->x86_scan_adapter_data, code, code_len);
		const unsigned id = packed >> 8;
		const unsigned length = packed & 0xff;
		if (id && id < X86_INS_ENDING && length && length <= 15 &&
		    length <= code_len) {
			result->opcode = 0;
			result->opcode_pub = id;
			result->length = (uint16_t)length;
			result->popcode_adjust = 0;
			return true;
		}
	}
#endif
	MCInst instr;
	instr.Opcode = 0;
	instr.OpcodePub = 0;
	instr.size = 0;
	instr.popcode_adjust = 0;
	instr.csh = handle;
	instr.address = insn->address;
	instr.flat_insn = insn;
	uint16_t size;
	x86_feature_decode_result extension = X86_FEATURE_NOT_HANDLED;
	if (tryExtension && !(code_len >= 4 && code[0] == 0xc4 &&
			      !(handle->mode & (CS_MODE_16 | CS_MODE_32)) &&
			      X86_vexFeatureFamily(code[1] & 0x1f, code[3]) ==
				      X86_VEX_FEATURE_NONE))
		extension = X86_decodeFeatureExtension(ud, code, code_len,
						       &instr, &size, opcode);
	if (extension == X86_FEATURE_INVALID)
		return false;
	if (extension != X86_FEATURE_DECODED) {
		if (tryExtension &&
		    !(handle->mode & (CS_MODE_16 | CS_MODE_32)) && code_len &&
		    code[0] == 0xc4) {
			const int status = tryVexTerminalScan(code, code_len,
							      code[0], result);
			if (status != X86_SCAN_NOT_HANDLED)
				return status == X86_SCAN_COMPLETE;
		}
		bool decoded = opcode == 0x62 ?
				       X86_getInstructionAfterExtensions(
					       ud, code, code_len, &instr,
					       &size, opcode) :
				       decodeGenericScan(code, code_len,
							 handle->mode, &instr,
							 &size);
		if (!decoded)
			return false;
	}
	result->opcode = instr.Opcode;
	result->opcode_pub = instr.OpcodePub;
	result->length = size;
	result->popcode_adjust = instr.popcode_adjust;
	return true;
}

X86_DECODE_INLINE bool completeTerminalScanResult(X86ScanResult *result,
						  unsigned instructionID,
						  int status)
{
	if (status != X86_SCAN_COMPLETE)
		return false;
	result->opcode = 0;
	result->opcode_pub = instructionID;
	result->popcode_adjust = 0;
	return true;
}

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static CS_PRESERVE_MOST bool
decodeLegacyPrefixedResult(csh ud, const uint8_t *code, size_t code_len,
			   cs_insn *insn, X86ScanResult *result)
{
	unsigned instructionID = 0;
	const cs_mode mode = ((cs_struct *)(uintptr_t)ud)->mode;
	int status;
	if (mode & CS_MODE_16)
		status = tryLegacyPrefixedScan(code, code_len, CS_MODE_16,
					       &instructionID, &result->length,
					       true, false, false);
	else if (mode & CS_MODE_32)
		status = tryLegacyPrefixedScan(code, code_len, CS_MODE_32,
					       &instructionID, &result->length,
					       true, false, false);
	else
		status = tryLegacyPrefixedScan(code, code_len, CS_MODE_64,
					       &instructionID, &result->length,
					       true, false, false);
	if (status == X86_SCAN_NOT_HANDLED)
		return decodeScanResultFallback(ud, code, code_len, insn,
						result, 0, false);
	return completeTerminalScanResult(result, instructionID, status);
}

X86_DECODE_INLINE int tryVexTerminalScan(const uint8_t *code, size_t code_len,
					 uint8_t prefix, X86ScanResult *result)
{
	InternalInstruction insn = { 0 };
	initializeInstructionHeader(&insn, code, code_len, CS_MODE_64);
	insn.readerCursor = 1;
	if (readVexPrefix(&insn, prefix))
		return X86_SCAN_INVALID;
	setInstructionSizes(&insn, insn.hasOpSize, insn.hasAdSize);
	int opcodeResult = readOpcode(&insn, false, true);
	if (opcodeResult)
		return opcodeResult == OPCODE_READ_GENERIC ?
			       X86_SCAN_NOT_HANDLED :
			       X86_SCAN_INVALID;
	/* Keep the generic opcode/size repairs outside this admission. */
	if ((insn.opcodeType == TWOBYTE &&
	     (insn.opcode == 0xae ||
	      (insn.opcode >= 0x82 && insn.opcode <= 0x8f))) ||
	    (insn.opcodeType == THREEBYTE_38 && insn.opcode == 0xf8))
		return X86_SCAN_NOT_HANDLED;
	const uint8_t payload =
		insn.vectorExtensionPrefix[prefix == 0xc4 ? 2 : 1];
	const unsigned row = (payload & 7) | (wFromREX(insn.rexPrefix) << 3);
	const struct ModRMDecision *decisions =
		x86VexScanRows[insn.opcodeType - TWOBYTE][row];
	if (!decisions)
		return X86_SCAN_INVALID;
	const struct ModRMDecision *decision = &decisions[insn.opcode];
	const uint32_t packed = decision->packed;
	const bool decisionModRM =
		(packed & (X86_DECISION_INDEXED | X86_DECISION_SPLIT)) != 0;
	uint8_t modrm = 0;
	if (decisionModRM && lookAtByte(&insn, &modrm))
		return X86_SCAN_INVALID;
	insn.instructionID = decode(packed, modrm);
	if (!insn.instructionID)
		return X86_SCAN_INVALID;
	if (insn.instructionID >= ARR_SIZE(x86VexScanMetadata))
		return X86_SCAN_NOT_HANDLED;
	const uint32_t metadata = x86VexScanMetadata[insn.instructionID];
	const uint8_t flags = (uint8_t)metadata;
	if (!flags)
		return X86_SCAN_NOT_HANDLED;
	if (decisionModRM || (flags & X86_VEX_SCAN_MODRM)) {
		if (readModRMScan(&insn))
			return X86_SCAN_INVALID;
		if (!(flags & (insn.modRM >= 0xc0 ? X86_VEX_SCAN_REGISTER :
						    X86_VEX_SCAN_MEMORY)))
			return X86_SCAN_INVALID;
	}
	if (!(flags & X86_VEX_SCAN_VVVV) &&
	    (prefix == 0xc4 ? vvvvFromVEX3of3(payload) :
			      vvvvFromVEX2of2(payload)))
		return X86_SCAN_INVALID;
	if (readVexScanImmediates(&insn, flags >> X86_VEX_SCAN_PATTERN_SHIFT) !=
		    X86_SCAN_COMPLETE ||
	    finishDecodedInstruction(&insn, false))
		return X86_SCAN_INVALID;
	result->opcode = insn.instructionID;
	result->opcode_pub = metadata >> X86_VEX_SCAN_PUBLIC_SHIFT;
	result->length = (uint16_t)insn.length;
	result->popcode_adjust = 0;
	return X86_SCAN_COMPLETE;
}

/* Constant C5 admission folds the unused three-byte prefix handling. */
X86_DECODE_INLINE bool
decodeVexTerminalResultInline(csh ud, const uint8_t *code, size_t code_len,
			      cs_insn *insn, X86ScanResult *result,
			      uint8_t prefix)
{
	int status = tryVexTerminalScan(code, code_len, prefix, result);
	if (status == X86_SCAN_NOT_HANDLED)
		return decodeScanResultFallback(ud, code, code_len, insn,
						result, prefix, false);
	return status == X86_SCAN_COMPLETE;
}

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__)
__attribute__((noinline))
#endif
static CS_PRESERVE_MOST bool
decodeVexTerminalResult(csh ud, const uint8_t *code, size_t code_len,
			cs_insn *insn, X86ScanResult *result, uint8_t prefix)
{
	return decodeVexTerminalResultInline(ud, code, code_len, insn, result,
					     prefix);
}

/* Common headers enter the shared readers before the general prefix walk.
 * The extension selector observes CS_MODE_64, while raw mode selection gives
 * 16/32-bit flags precedence. Keep their original ordering for mixed flags. */
X86_DECODE_INLINE int tryInitialLegacyScan(const uint8_t *code, size_t code_len,
					   cs_mode mode, bool feature64,
					   unsigned *instructionID,
					   uint16_t *size, bool readerFlags)
{
	if (!code_len || (mode == CS_MODE_64) != feature64)
		return X86_SCAN_NOT_HANDLED;
	uint8_t opcode = code[0];
	size_t offset = 0;
	if (mode == CS_MODE_16 && (opcode == 0x66 || opcode == 0x67))
		return tryLegacyPrefixedScan(code, code_len, CS_MODE_16,
					     instructionID, size, true, true,
					     readerFlags);
	if (mode == CS_MODE_64 && (opcode & 0xf0) == 0x40) {
		if (code_len < 2)
			return X86_SCAN_NOT_HANDLED;
		offset = 1;
		opcode = code[1];
	}
	/* A generated invalid terminal must not reject a source-owned refinement. */
	if (opcode == 0x0f && may_be_0f_feature_extension(
				      code + offset + 1, code_len - offset - 1))
		return X86_SCAN_NOT_HANDLED;
	return trySimpleLegacyScan(code, code_len, mode, opcode, offset,
				   instructionID, size, true, readerFlags);
}

X86_DECODE_INLINE int tryInitialScanResult(cs_struct *handle,
					   const uint8_t *code, size_t code_len,
					   unsigned *instructionID,
					   uint16_t *length, bool readerFlags)
{
	int initial;
	const bool feature64 = (handle->mode & CS_MODE_64) != 0;
	if (!(handle->mode & (CS_MODE_16 | CS_MODE_32)))
		initial = tryInitialLegacyScan(code, code_len, CS_MODE_64,
					       feature64, instructionID, length,
					       readerFlags);
	else if (handle->mode & CS_MODE_16)
		initial = tryInitialLegacyScan(code, code_len, CS_MODE_16,
					       feature64, instructionID, length,
					       readerFlags);
	else
		initial = tryInitialLegacyScan(code, code_len, CS_MODE_32,
					       feature64, instructionID, length,
					       readerFlags);
	return initial;
}

X86_DECODE_INLINE bool
getInstructionScanResultAfterInitial(csh ud, const uint8_t *code,
				     size_t code_len, cs_insn *insn,
				     X86ScanResult *result, bool readerFlags)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	uint8_t opcode;
	size_t opcodeOffset;
	bool extension = X86_mayDecodeFeatureExtensionImpl(
		code, code_len, (handle->mode & CS_MODE_64) != 0, &opcode,
		&opcodeOffset);
	if (extension || opcode == 0x62)
		return decodeScanResultFallback(ud, code, code_len, insn,
						result, opcode, extension);
	if (readerFlags && opcode == 0xc5 && opcodeOffset == 0 &&
	    !(handle->mode & (CS_MODE_16 | CS_MODE_32)))
		return decodeVexTerminalResultInline(ud, code, code_len, insn,
						     result, 0xc5);

	unsigned instructionID = 0;
	/* Constant bitness folds the terminal readers' mode and size tests.
	 * Feature routing above still observes the original mode bits. */
	int status;
	if (!(handle->mode & (CS_MODE_16 | CS_MODE_32)))
		status = trySimpleLegacyScan(code, code_len, CS_MODE_64, opcode,
					     opcodeOffset, &instructionID,
					     &result->length, true,
					     readerFlags);
	else if (handle->mode & CS_MODE_16)
		status = trySimpleLegacyScan(code, code_len, CS_MODE_16, opcode,
					     opcodeOffset, &instructionID,
					     &result->length, true,
					     readerFlags);
	else
		status = trySimpleLegacyScan(code, code_len, CS_MODE_32, opcode,
					     opcodeOffset, &instructionID,
					     &result->length, true,
					     readerFlags);
	if (status != X86_SCAN_NOT_HANDLED)
		return completeTerminalScanResult(result, instructionID,
						  status);
	if (opcodeOffset && opcodeOffset != SIZE_MAX)
		return decodeLegacyPrefixedResult(ud, code, code_len, insn,
						  result);
	if (code_len && (code[0] == 0xc4 || code[0] == 0xc5) &&
	    !(handle->mode & (CS_MODE_16 | CS_MODE_32)))
		return decodeVexTerminalResult(ud, code, code_len, insn, result,
					       opcode);
	return decodeScanResultFallback(ud, code, code_len, insn, result,
					opcode, false);
}

X86_DECODE_INLINE bool getInstructionScanResult(csh ud, const uint8_t *code,
						size_t code_len, cs_insn *insn,
						X86ScanResult *result,
						bool readerFlags)
{
	unsigned instructionID = 0;
	int initial = tryInitialScanResult((cs_struct *)(uintptr_t)ud, code,
					   code_len, &instructionID,
					   &result->length, readerFlags);
	if (initial != X86_SCAN_NOT_HANDLED)
		return completeTerminalScanResult(result, instructionID,
						  initial);
	return getInstructionScanResultAfterInitial(ud, code, code_len, insn,
						    result, readerFlags);
}

bool X86_getInstructionScanResult(csh ud, const uint8_t *code, size_t code_len,
				  cs_insn *insn, X86ScanResult *result)
{
	return getInstructionScanResult(ud, code, code_len, insn, result,
					false);
}

X86_DECODE_INLINE bool decodeIteratorScan(cs_struct *handle,
					  const uint8_t *code, size_t size,
					  cs_insn *insn, uint16_t *insn_size,
					  bool batch);

#define CS_DECODE_SCAN_IMPL decodeIteratorScan
#include "../../cs_disasm_internal.h"
#undef CS_DECODE_SCAN_IMPL

/* Keep the admitted terminal's public ID and zero alias adjustment visible
 * through output completion. Cold helpers can take the fallback result's
 * address without forcing terminal output through that escaped object. */
X86_DECODE_INLINE bool decodeIteratorScan(cs_struct *handle,
					  const uint8_t *code, size_t size,
					  cs_insn *insn, uint16_t *insn_size,
					  bool batch)
{
	unsigned instructionID = 0;
	uint16_t length;
	int initial = tryInitialScanResult(handle, code, size, &instructionID,
					   &length, true);
	if (initial == X86_SCAN_NOT_HANDLED) {
		X86ScanResult result;
		if (!getInstructionScanResultAfterInitial(
			    (csh)(uintptr_t)handle, code, size, insn, &result,
			    true))
			return false;
		*insn_size = result.length;
		finish_x86_scan(handle, insn, &result, code, batch, true);
		return true;
	}
	if (initial != X86_SCAN_COMPLETE)
		return false;
	X86ScanResult result = { 0, instructionID, length, 0 };
	*insn_size = length;
	finish_x86_scan(handle, insn, &result, code, batch, true);
	return true;
}

CAPSTONE_EXPORT
X86_DECODE_ALIGN
bool CAPSTONE_API cs_disasm_iter(csh ud, const uint8_t **code, size_t *size,
				 uint64_t *address, cs_insn *insn)
{
	return cs_disasm_iter_core(ud, code, size, address, insn);
}

X86_DECODE_ALIGN
CAPSTONE_INTERNAL X86ScanBatchResult X86_scanBatch(csh ud, const uint8_t *code,
						   size_t size,
						   uint64_t address,
						   uint32_t *output,
						   size_t capacity)
{
	X86ScanBatchResult batch = { 0, 0 };
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (!handle || !code || !size || !output || !capacity ||
	    !use_x86_scan(handle) || handle->skipdata)
		return batch;
	cs_insn insn = { 0 };
	handle->errnum = CS_ERR_OK;
	while (batch.count < capacity && size) {
		X86ScanResult result;
		insn.address = address;
		if (!getInstructionScanResult(ud, code, size, &insn, &result,
					      false))
			break;
		finish_x86_scan(handle, &insn, &result, code, false, false);
		output[batch.count++] = (insn.id << 8) | result.length;
		batch.bytes += result.length;
		code += result.length;
		size -= result.length;
		address += result.length;
	}
	return batch;
}

CAPSTONE_INTERNAL uint16_t X86_scanCallTarget(csh ud, const uint8_t *code,
					      size_t size, uint64_t address,
					      uint64_t *target)
{
	const cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (!handle || handle->arch != CS_ARCH_X86 || !code || !size || !target)
		return 0;
	InternalInstruction insn = { 0 };
	if (decodeInstruction(&insn, code, size, handle->mode))
		return 0;
	switch (insn.instructionID) {
	case X86_CALLpcrel16:
	case X86_CALLpcrel32:
	case X86_CALL64pcrel32:
		break;
	default:
		return 0;
	}
	*target = X86_relativeBranchTarget(
		handle->mode, address, (uint16_t)insn.length,
		translateRelativeImmediate(insn.immediates[0], insn.operands,
					   insn.displacementSize),
		insn.immSize);
	return (uint16_t)insn.length;
}

#undef CS_DECODE_INLINE
#undef CS_DECODE_LIKELY
#undef CS_DECODE_UNLIKELY

#undef X86_DECODE_INLINE

#endif

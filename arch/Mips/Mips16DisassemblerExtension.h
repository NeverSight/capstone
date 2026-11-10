/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_MIPS16_DISASSEMBLER_EXTENSION_H
#define CS_MIPS16_DISASSEMBLER_EXTENSION_H

/* Physical MIPS16 forms missing from the imported compiler descriptions.
 * MD00076 revision 2.63 and MD01172 revision 1.00 own these encodings. Keep
 * outside translated/generated files; see docs/ARCHITECTURE.md. */
static unsigned mips16CompactReg(unsigned field)
{
	return field < 2 ? field + 16 : field;
}

static void mips16GPR(MCInst *MI, unsigned reg)
{
	MCOperand_CreateReg0(MI, getReg(MI, Mips_GPR32RegClassID, reg));
}

static DecodeStatus decodeMips16Instruction(MCInst *MI, uint64_t *Size,
					    const uint8_t *Bytes,
					    size_t BytesLen, uint64_t Address,
					    bool IsBigEndian)
{
	uint64_t insn;
	if (readInstruction16(Bytes, BytesLen, Address, Size, &insn,
			      IsBigEndian) == MCDisassembler_Fail)
		return MCDisassembler_Fail;
	unsigned first = insn;
	bool extended = (first >> 11) == 0x1e;
	bool direct = (first >> 11) == 3;
	*Size = extended || direct ? 4 : 2;
	if (*Size == 4 &&
	    readInstruction32(Bytes, BytesLen, Address, Size, &insn,
			      IsBigEndian, true) == MCDisassembler_Fail)
		return MCDisassembler_Fail;
	if (direct) {
		MCInst_setOpcode(MI, first & 0x400 ? Mips_JALX : Mips_JAL);
		unsigned target = ((first & 31) << 21) |
				  (((first >> 5) & 31) << 16) | (insn & 0xffff);
		MCOperand_CreateImm0(MI, target << 2);
		return MCDisassembler_Success;
	}
	unsigned half = insn & 0xffff;
	unsigned major = half >> 11;
	unsigned rx = mips16CompactReg((half >> 8) & 7);
	unsigned ry = mips16CompactReg((half >> 5) & 7);
	int offset = extended ? (int16_t)((half & 31) | ((first & 31) << 11) |
					  (first & 0x7e0)) :
				(half & 31);
	unsigned opcode = 0, scale = 0, base = rx, reg = ry;
	bool stack = false, pc = false;
	if (extended) {
		if (first == 0xf0c0 && half == 0x3010) {
			MCInst_setOpcode(MI, Mips_EHB);
			return MCDisassembler_Success;
		}
		if (!(first & 63) && half == 0x3014) {
			MCInst_setOpcode(MI, Mips_SYNC);
			MCOperand_CreateImm0(MI, (first >> 6) & 31);
			return MCDisassembler_Success;
		}
		if (!(first & 0x7e0) && (half & 0xff1f) == 0x300c) {
			MCInst_setOpcode(MI, Mips_RDHWR);
			mips16GPR(MI, ry);
			/* A hardware register number is not a GPR read. The imported
			 * register class only represents HWR29; keep the index explicit. */
			MCOperand_CreateImm0(MI, first & 31);
			MCOperand_CreateImm0(MI, 0);
			return MCDisassembler_Success;
		}
		if ((first == 0xf002 || first == 0xf003 || first == 0xf006 ||
		     first == 0xf007) &&
		    (half & 0xff1f) == 0x670c) {
			if ((first & 4) && (half & 0xe0))
				return MCDisassembler_Fail;
			MCInst_setOpcode(MI, first & 1 ? Mips_EI : Mips_DI);
			mips16GPR(MI, first & 4 ? 0 : ry);
			return MCDisassembler_Success;
		}
		unsigned selector = (half >> 5) & 7;
		switch ((major << 3) | selector) {
#define M16E2_IMMEDIATE(Major, Selector, Opcode, Source) \
	case ((Major) << 3) | (Selector): \
		MCInst_setOpcode(MI, Mips_##Opcode); \
		mips16GPR(MI, rx); \
		if (Mips_##Opcode != Mips_LUi) \
			mips16GPR(MI, Source); \
		MCOperand_CreateImm0(MI, Mips_##Opcode == Mips_ADDiu ? \
						 offset : \
						 (uint16_t)offset); \
		return MCDisassembler_Success;
#define M16E2_MEMORY(Major, Selector, Opcode) \
	case ((Major) << 3) | (Selector): \
		MCInst_setOpcode(MI, Mips_##Opcode); \
		mips16GPR(MI, rx); \
		mips16GPR(MI, 28); \
		MCOperand_CreateImm0(MI, offset); \
		return MCDisassembler_Success;
#include "Mips16E2Encodings.inc"
#undef M16E2_IMMEDIATE
#undef M16E2_MEMORY
		case (0x12 << 3) | 6:
		case (0x1a << 3) | 6:
			if (first & 0x618)
				return MCDisassembler_Fail;
			MCInst_setOpcode(MI, major == 0x12 ? Mips_LL : Mips_SC);
			mips16GPR(MI, rx);
			if (major == 0x1a)
				mips16GPR(MI, rx);
			mips16GPR(MI, mips16CompactReg(first & 7));
			MCOperand_CreateImm0(
				MI,
				(int)(((first & 0x1e0) | (half & 31)) ^ 0x100) -
					0x100);
			return MCDisassembler_Success;
		case (0x12 << 3) | 7:
		case (0x1a << 3) | 7:
			if (first & 0x608)
				return MCDisassembler_Fail;
			opcode = major == 0x12 ?
					 (first & 16 ? Mips_LWR : Mips_LWL) :
					 (first & 16 ? Mips_SWR : Mips_SWL);
			MCInst_setOpcode(MI, opcode);
			mips16GPR(MI, rx);
			mips16GPR(MI, mips16CompactReg(first & 7));
			MCOperand_CreateImm0(
				MI,
				(int)(((first & 0x1e0) | (half & 31)) ^ 0x100) -
					0x100);
			if (major == 0x12)
				mips16GPR(MI, rx);
			return MCDisassembler_Success;
		}
		if (major == 6 && (half & 0x1c)) {
			unsigned sel = (half >> 2) & 7;
			unsigned function = half & 3;
			if (!function && (sel == 1 || sel == 2)) {
				bool insert = sel == 1;
				unsigned pos = (first >> 6) & 31;
				unsigned limit = first & 31;
				bool source = first & 32;
				if ((!source && (!insert || (half & 0x700))) ||
				    (insert ? limit < pos : limit + pos > 31))
					return MCDisassembler_Fail;
				MCInst_setOpcode(MI,
						 insert ? Mips_INS : Mips_EXT);
				mips16GPR(MI, ry);
				mips16GPR(MI, source ? rx : 0);
				MCOperand_CreateImm0(MI, pos);
				MCOperand_CreateImm0(MI,
						     insert ? limit - pos + 1 :
							      limit + 1);
				if (insert)
					mips16GPR(MI, ry);
				return MCDisassembler_Success;
			}
			if (function == 2 &&
			    (sel == 1 || sel == 2 || sel == 5 || sel == 6)) {
				if ((first & 0x7d8) ||
				    (!(first & 32) && (first & 7)) ||
				    (sel >= 5 && (half & 0xe0)))
					return MCDisassembler_Fail;
				MCInst_setOpcode(MI, sel & 1 ? Mips_MOVZ_I_I :
							       Mips_MOVN_I_I);
				mips16GPR(MI, rx);
				mips16GPR(MI, first & 32 ? mips16CompactReg(
								   first & 7) :
							   0);
				mips16GPR(MI, sel >= 5 ? 24 : ry);
				mips16GPR(MI, rx);
				return MCDisassembler_Success;
			}
			return MCDisassembler_Fail;
		}
	}
	switch (major) {
	case 0:
	case 1:
		opcode = Mips_ADDiu;
		stack = major == 0;
		pc = !stack;
		break;
	case 6: // SHFT: short zero count denotes eight; EXTEND carries 0..31.
		if ((half & 3) == 1 ||
		    (extended && ((first & 0x3f) || (half & 0x1c))))
			return MCDisassembler_Fail;
		MCInst_setOpcode(MI, (half & 3) == 0 ? Mips_SLL :
				     (half & 3) == 2 ? Mips_SRL :
						       Mips_SRA);
		mips16GPR(MI, rx);
		mips16GPR(MI, ry);
		unsigned amount = extended ? (first >> 6) & 31 :
					     (half >> 2) & 7;
		MCOperand_CreateImm0(MI, extended || amount ? amount : 8);
		return MCDisassembler_Success;
	case 0x10:
		opcode = Mips_LB;
		break;
	case 0x11:
		opcode = Mips_LH;
		scale = 1;
		break;
	case 0x12:
		opcode = Mips_LW;
		stack = true;
		break;
	case 0x13:
		opcode = Mips_LW;
		scale = 2;
		break;
	case 0x14:
		opcode = Mips_LBu;
		break;
	case 0x15:
		opcode = Mips_LHu;
		scale = 1;
		break;
	case 0x16:
		opcode = Mips_LW;
		pc = true;
		break;
	case 0x18:
		opcode = Mips_SB;
		break;
	case 0x19:
		opcode = Mips_SH;
		scale = 1;
		break;
	case 0x1a:
		opcode = Mips_SW;
		stack = true;
		break;
	case 0x1b:
		opcode = Mips_SW;
		scale = 2;
		break;
	case 0x0c:
		if (((half >> 8) & 7) == 4) {
			unsigned ar = extended ? first & 15 : 0;
			if (ar == 15)
				return MCDisassembler_Fail;
			bool save = half & 0x80;
			MCInst_setOpcode(MI,
					 save ? (extended ? Mips_SaveX16 :
							    Mips_Save16) :
						(extended ? Mips_RestoreX16 :
							    Mips_Restore16));
			unsigned args = ar == 14 ? 4 : ar == 11 ? 0 : ar >> 2;
			unsigned statics = ar == 11 ? 4 : ar == 14 ? 0 : ar & 3;
			// The frame operand separates incoming arguments from statics.
			if (save)
				for (unsigned n = 0; n < args; ++n)
					mips16GPR(MI, 4 + n);
			unsigned frame = (half & 15) |
					 (extended ? first & 0xf0 : 0);
			MCOperand_CreateImm0(
				MI, !extended && !frame ? 128 : frame * 8);
			for (unsigned n = 8 - statics; n < 8; ++n)
				mips16GPR(MI, n);
			if (half & 0x20)
				mips16GPR(MI, 16);
			if (half & 0x10)
				mips16GPR(MI, 17);
			unsigned xs = extended ? (first >> 8) & 7 : 0;
			for (unsigned n = 0; n < xs; ++n)
				mips16GPR(MI, n == 6 ? 30 : 18 + n);
			if (half & 0x40)
				mips16GPR(MI, 31);
			return MCDisassembler_Success;
		} else if (((half >> 8) & 7) == 2) {
			opcode = Mips_SW;
			stack = true;
			reg = 31;
		} else if (!extended &&
			   (((half >> 8) & 7) == 5 || ((half >> 8) & 7) == 7)) {
			bool from_full = ((half >> 8) & 7) == 7;
			MCInst_setOpcode(MI, from_full ? Mips_MoveR3216 :
							 Mips_Move32R16);
			mips16GPR(MI, from_full ? ry :
						  ((half >> 5) & 7) |
							  (half & 0x18));
			mips16GPR(MI, from_full ? half & 31 :
						  mips16CompactReg(half & 7));
			return MCDisassembler_Success;
		}
		break;
	case 0x1d:
		if (!extended && ((half & 31) == 11 || (half & 31) == 24 ||
				  (half & 31) == 25)) {
			MCInst_setOpcode(MI, (half & 31) == 11 ?
						     Mips_NegRxRy16 :
					     (half & 31) == 24 ? Mips_MULT :
								 Mips_MULTu);
			mips16GPR(MI, rx);
			mips16GPR(MI, ry);
			return MCDisassembler_Success;
		}
		if (!extended && !(half & 31)) {
			unsigned kind = (half >> 6) & 3;
			if (half & 0x20) {
				if (((half >> 8) & 7) || (kind & 1))
					return MCDisassembler_Fail;
				MCInst_setOpcode(MI, kind == 0 ? Mips_JrRa16 :
								 Mips_JrcRa16);
			} else {
				MCInst_setOpcode(
					MI, kind == 0 ? Mips_JR :
					    kind == 1 ? Mips_JALR :
					    kind == 2 ? Mips_JrcRx16 :
							Mips_JumpLinkReg16);
				if (kind == 1)
					mips16GPR(MI, 31);
				mips16GPR(MI, rx);
			}
			return MCDisassembler_Success;
		}
		break;
	}
	if (opcode) {
		if (stack || pc) {
			if (extended && (half & 0xe0))
				return MCDisassembler_Fail;
			if (major != 0x0c)
				reg = rx;
			base = 29;
			if (!extended)
				offset = (half & 0xff) << 2;
		} else if (!extended) {
			offset <<= scale;
		}
		MCInst_setOpcode(MI, opcode);
		mips16GPR(MI, reg);
		if (pc)
			MCOperand_CreateReg0(MI, Mips_PC);
		else
			mips16GPR(MI, base);
		MCOperand_CreateImm0(MI, offset);
		return MCDisassembler_Success;
	}
	if (!extended)
		return decodeInstruction_2(DecoderTable16, MI, half, Address,
					   NULL);
	/* I8 overlaps the imported extended-shift patterns. */
	if (major == 0x0c) {
		if (half & 0xe0)
			return MCDisassembler_Fail;
		switch ((half >> 8) & 7) {
		case 0:
			MCInst_setOpcode(MI, Mips_BteqzX16);
			break;
		case 1:
			MCInst_setOpcode(MI, Mips_BtnezX16);
			break;
		case 3:
			MCInst_setOpcode(MI, Mips_AddiuSpImmX16);
			break;
		default:
			return MCDisassembler_Fail;
		}
		return DecodeSImmWithOffsetAndScale_16_0_1(MI, (uint16_t)offset,
							   Address, NULL);
	}
	return decodeInstruction_4(DecoderTable32, MI, insn, Address, NULL);
}

#endif

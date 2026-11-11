/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	uint16_t half;
	unsigned id, reg, base, offset;
	bool store;
} memory_case;

static const memory_case memories[] = {
#define M16_MEMORY(Half, Id, Reg, Base, Offset, Store) \
	{ Half, MIPS_INS_##Id, MIPS_REG_##Reg, MIPS_REG_##Base, Offset, Store },
#include "mips16_memory_cases.inc"
#undef M16_MEMORY
};

static const unsigned registers[] = {
#define MIPS_GPR(Name) MIPS_REG_##Name,
#include "mips_gpr_cases.inc"
#undef MIPS_GPR
};

static void halfword(uint8_t *bytes, uint16_t value, bool big)
{
	bytes[0] = value >> (big ? 8 : 0);
	bytes[1] = value >> (big ? 0 : 8);
}

static bool operand(const cs_insn *i, unsigned n, unsigned reg)
{
	return i->detail->mips.operands[n].type == MIPS_OP_REG &&
	       i->detail->mips.operands[n].reg == reg;
}

static void dump(const cs_insn *i)
{
	fprintf(stderr, "id=%u size=%u %s %s\n", i->id, i->size, i->mnemonic,
		i->op_str);
	if (!i->detail)
		return;
	const cs_mips *m = &i->detail->mips;
	fprintf(stderr, "op_count=%u groups:", m->op_count);
	for (unsigned k = 0; k < i->detail->groups_count; ++k)
		fprintf(stderr, " %u", i->detail->groups[k]);
	fprintf(stderr, "\n");
	for (unsigned k = 0; k < m->op_count; ++k)
		fprintf(stderr,
			"op%u type=%u access=%u reg/base=%u imm/disp=%lld/%lld\n",
			k, m->operands[k].type, m->operands[k].access,
			m->operands[k].reg, (long long)m->operands[k].imm,
			(long long)m->operands[k].mem.disp);
}

static bool inspect(csh h, const cs_insn *i, unsigned id, unsigned size,
		    unsigned output, unsigned reg, unsigned base,
		    int64_t offset, bool memory, bool store)
{
	if (i->id != id || i->size != size)
		return false;
	if (!(output & 2))
		return true;
	const cs_mips *m = &i->detail->mips;
	cs_mips_op zero = { 0 };
	for (unsigned n = m->op_count;
	     n < sizeof(m->operands) / sizeof(m->operands[0]); ++n)
		if (memcmp(&m->operands[n], &zero, sizeof(zero)))
			return false;
	if (output != 3)
		return m->op_count == 0;
	if (m->op_count != (memory ? 2 : 3) || !operand(i, 0, reg))
		return false;
	if (memory) {
		if (m->operands[1].type != MIPS_OP_MEM ||
		    m->operands[1].mem.base != base ||
		    m->operands[1].mem.disp != offset)
			return false;
	} else if (!operand(i, 1, base) || m->operands[2].type != MIPS_OP_IMM ||
		   m->operands[2].imm != offset) {
		return false;
	}
	if (!cs_support(CS_SUPPORT_DIET) &&
	    (!cs_insn_group(h, i, MIPS_FEATURE_INMIPS16MODE) ||
	     cs_insn_group(h, i, MIPS_FEATURE_HASSTDENC) ||
	     m->operands[0].access != (store ? CS_AC_READ : CS_AC_WRITE) ||
	     m->operands[1].access !=
		     (memory && store ? CS_AC_WRITE : CS_AC_READ)))
		return false;
	return true;
}

static bool memory_and_address(csh h, bool big, unsigned output)
{
	cs_insn *one = cs_malloc(h);
	if (!one)
		return false;
	for (unsigned k = 0; k < sizeof(memories) / sizeof(memories[0]) + 2;
	     ++k) {
		const bool memory = k < sizeof(memories) / sizeof(memories[0]);
		const memory_case extra = {
			k == sizeof(memories) / sizeof(memories[0]) ? 0x0203 :
								      0x0a03,
			MIPS_INS_ADDIU,
			MIPS_REG_V0,
			k == sizeof(memories) / sizeof(memories[0]) ?
				MIPS_REG_SP :
				MIPS_REG_PC,
			12,
			false
		};
		const memory_case *test = memory ? &memories[k] : &extra;
		const int offsets[] = { -32768, -1, 0, 32767 };
		for (unsigned ext = 0; ext < 5; ++ext) {
			uint8_t bytes[4];
			unsigned size = ext ? 4 : 2;
			int64_t offset = ext ? offsets[ext - 1] :
					       (int)test->offset;
			if (ext) {
				uint16_t value = offset;
				halfword(bytes,
					 0xf000 | (value & 0x7e0) |
						 (value >> 11),
					 big);
				halfword(bytes + 2,
					 (test->half & ~31) | (value & 31),
					 big);
			} else {
				halfword(bytes, test->half, big);
			}
			for (unsigned api = 0; api < 2; ++api) {
				const uint8_t *cursor = bytes;
				size_t left = size;
				uint64_t pc = 0x10002;
				cs_insn *all = NULL;
				if (output & 2)
					memset(one->detail, 0xa5,
					       sizeof(*one->detail));
				size_t count = api ? cs_disasm(h, bytes, size,
							       pc, 1, &all) :
						     cs_disasm_iter(h, &cursor,
								    &left, &pc,
								    one);
				bool ok = count == 1 &&
					  inspect(h, api ? all : one, test->id,
						  size, output, test->reg,
						  test->base, offset, memory,
						  test->store);
				if (!ok && count == 1)
					dump(api ? all : one);
				if (api)
					cs_free(all, count);
				if (!ok) {
					fprintf(stderr,
						"memory/address case=%u extended=%u api=%u output=%u big=%u\n",
						k, ext, api, output, big);
					cs_free(one, 1);
					return false;
				}
			}
			for (unsigned length = 0; length < size; ++length) {
				const uint8_t *cursor = bytes;
				size_t left = length;
				uint64_t pc = 0x10002;
				if (cs_disasm_iter(h, &cursor, &left, &pc,
						   one)) {
					cs_free(one, 1);
					return false;
				}
			}
		}
	}
	cs_free(one, 1);
	return true;
}

static unsigned compact(unsigned field)
{
	return registers[field < 2 ? field + 16 : field];
}

static bool moves_and_calls(csh h, bool big, unsigned output)
{
	for (unsigned field = 0; field < 8; ++field) {
		for (unsigned full = 0; full < 32; ++full)
			for (unsigned direction = 0; direction < 2;
			     ++direction) {
				uint16_t half =
					direction ?
						0x6700 | (field << 5) | full :
						0x6500 | ((full & 7) << 5) |
							((full >> 3) << 3) |
							field;
				uint8_t bytes[2];
				halfword(bytes, half, big);
				cs_insn *i = NULL;
				size_t count =
					cs_disasm(h, bytes, 2, 0x10002, 1, &i);
				bool ok = count == 1 && i->id == MIPS_INS_MOVE;
				if (ok && output == 3)
					ok = i->detail->mips.op_count == 2 &&
					     operand(i, 0,
						     direction ?
							     compact(field) :
							     registers[full]) &&
					     operand(i, 1,
						     direction ?
							     registers[full] :
							     compact(field));
				if (!ok) {
					fprintf(stderr,
						"move/call output=%u big=%u\n",
						output, big);
					if (count)
						dump(i);
				}
				cs_free(i, count);
				if (!ok)
					return false;
			}
		for (unsigned kind = 0; kind < 4; ++kind) {
			uint8_t bytes[2];
			halfword(bytes, 0xe800 | (field << 8) | (kind << 6),
				 big);
			unsigned id = kind == 0 ? MIPS_INS_JR :
				      kind == 1 ? MIPS_INS_JALR :
				      kind == 2 ? MIPS_INS_JRC :
						  MIPS_INS_JALRC;
			cs_insn *i = NULL;
			size_t count = cs_disasm(h, bytes, 2, 0x10002, 1, &i);
			bool ok = count == 1 && i->id == id && i->size == 2;
			if (ok && output == 3) {
				unsigned n = kind == 1 ? 1 : 0;
				ok = i->detail->mips.op_count == n + 1 &&
				     operand(i, n, compact(field)) &&
				     (!n || operand(i, 0, MIPS_REG_RA));
				if (!cs_support(CS_SUPPORT_DIET))
					ok &= cs_insn_group(
						      h, i,
						      MIPS_FEATURE_INMIPS16MODE) &&
					      cs_insn_group(
						      h, i,
						      kind & 1 ? MIPS_GRP_CALL :
								 MIPS_GRP_JUMP);
			}
			if (!ok) {
				fprintf(stderr, "move/call output=%u big=%u\n",
					output, big);
				if (count)
					dump(i);
			}
			cs_free(i, count);
			if (!ok)
				return false;
		}
	}
	for (unsigned exchange = 0; exchange < 2; ++exchange)
		for (unsigned boundary = 0; boundary < 3; ++boundary) {
			uint8_t bytes[4];
			halfword(bytes,
				 0x1800 | (exchange << 10) | (3 << 5) | 2, big);
			halfword(bytes + 2, 0x1234, big);
			uint64_t address = boundary == 0 ? 0x10002 :
					   boundary == 1 ? 0x0ffffffc :
							   0xfffffffc;
			uint32_t target =
				((uint32_t)(address + 4) & 0xf0000000) |
				(2u << 23) | (3u << 18) | (0x1234u << 2);
			cs_insn *i = NULL;
			size_t count = cs_disasm(h, bytes, 4, address, 1, &i);
			bool ok = count == 1 && i->size == 4 &&
				  i->id == (exchange ? MIPS_INS_JALX :
						       MIPS_INS_JAL);
			if (ok && (output & 1) && !cs_support(CS_SUPPORT_DIET))
				ok = strtoull(i->op_str, NULL, 0) == target;
			if (ok && output == 3)
				ok = cs_support(CS_SUPPORT_DIET) ||
				     (cs_insn_group(h, i, MIPS_GRP_CALL) &&
				      cs_reg_write(h, i, MIPS_REG_RA));
			if (ok && output == 3)
				ok = i->detail->mips.op_count == 1 &&
				     i->detail->mips.operands[0].type ==
					     MIPS_OP_IMM &&
				     (uint64_t)i->detail->mips.operands[0].imm ==
					     target;
			if (!ok) {
				fprintf(stderr, "move/call output=%u big=%u\n",
					output, big);
				if (count)
					dump(i);
			}
			cs_free(i, count);
			if (!ok)
				return false;
		}
	return true;
}

static bool rejected(csh h, const uint8_t *bytes, unsigned length)
{
	cs_insn *i = NULL;
	size_t count = cs_disasm(h, bytes, length, 0x1000, 1, &i);
	cs_free(i, count);
	cs_insn *one = cs_malloc(h);
	const uint8_t *cursor = bytes;
	size_t left = length;
	uint64_t address = 0x1000;
	bool accepted = cs_disasm_iter(h, &cursor, &left, &address, one);
	cs_free(one, 1);
	return !count && !accepted;
}

static bool reserved_and_options(csh h, bool big)
{
	uint8_t bytes[4];
	for (unsigned exchange = 0; exchange < 2; ++exchange) {
		halfword(bytes, exchange ? 0x1c00 : 0x1800, big);
		halfword(bytes + 2, 0x1234, big);
		for (unsigned length = 0; length < 4; ++length)
			if (!rejected(h, bytes, length))
				return false;
	}
	for (unsigned field = 0; field < 8; ++field)
		for (unsigned kind = 0; kind < 4; ++kind) {
			if (!field && !(kind & 1))
				continue; // JR/JRC ra
			halfword(bytes, 0xe820 | (field << 8) | (kind << 6),
				 big);
			if (!rejected(h, bytes, 2))
				return false;
		}
	for (unsigned k = 8; k < sizeof(memories) / sizeof(memories[0]); ++k)
		for (unsigned reserved = 1; reserved < 8; ++reserved) {
			unsigned major = memories[k].half >> 11;
			// These formerly reserved selectors now name MIPS16e2 forms.
			if ((major == 0x12 && (reserved <= 7)) || major == 0x1a)
				continue;
			halfword(bytes, 0xf000, big);
			halfword(bytes + 2, memories[k].half | (reserved << 5),
				 big);
			if (!rejected(h, bytes, 4))
				return false;
		}
	// Canonical and alias options share one memory operand, even on the
	// ordinary opcode descriptors used by the MIPS16 adapter.
	for (unsigned classic = 0; classic < 2; ++classic) {
		cs_option(h, CS_OPT_MODE,
			  CS_MODE_MIPS32R2 | (classic ? 0 : CS_MODE_MIPS16) |
				  (big ? CS_MODE_BIG_ENDIAN : 0));
		unsigned size = classic ? 4 : 2;
		if (classic) {
			const uint32_t word = 0x80820003;
			for (unsigned n = 0; n < 4; ++n)
				bytes[n] = word >> (8 * (big ? 3 - n : n));
		} else
			halfword(bytes, 0x8443, big);
		for (unsigned real = 0; real < 2; ++real) {
			cs_option(h, CS_OPT_DETAIL, CS_OPT_OFF);
			cs_option(h, CS_OPT_DETAIL,
				  CS_OPT_ON | (real ? CS_OPT_DETAIL_REAL : 0));
			cs_option(h, CS_OPT_TEXT, CS_OPT_ON);
			cs_insn *i = NULL;
			size_t count = cs_disasm(h, bytes, size, 0x1000, 1, &i);
			bool ok = count == 1 && i->detail->mips.op_count == 2 &&
				  operand(i, 0, MIPS_REG_V0) &&
				  i->detail->mips.operands[1].type ==
					  MIPS_OP_MEM &&
				  i->detail->mips.operands[1].mem.base ==
					  MIPS_REG_A0 &&
				  i->detail->mips.operands[1].mem.disp == 3;
			if (!ok && count)
				dump(i);
			cs_free(i, count);
			if (!ok)
				return false;
		}
	}
	return true;
}

int main(void)
{
	for (unsigned big = 0; big < 2; ++big)
		for (unsigned output = 0; output < 4; ++output) {
			csh h;
			if (cs_open(CS_ARCH_MIPS,
				    CS_MODE_MIPS32R2 | CS_MODE_MIPS16 |
					    (big ? CS_MODE_BIG_ENDIAN : 0),
				    &h))
				return 1;
			cs_option(h, CS_OPT_DETAIL,
				  output & 2 ? CS_OPT_ON | CS_OPT_DETAIL_REAL :
					       CS_OPT_OFF);
			cs_option(h, CS_OPT_TEXT,
				  output & 1 ? CS_OPT_ON : CS_OPT_OFF);
			bool ok = memory_and_address(h, big, output) &&
				  moves_and_calls(h, big, output) &&
				  reserved_and_options(h, big);
			cs_close(&h);
			if (!ok)
				return 1;
		}
	return 0;
}

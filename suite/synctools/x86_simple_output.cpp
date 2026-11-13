/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

// Generate public x86 output records from the full decoder. Build this tool
// against a normal, non-DIET Capstone library with x86 enabled. A custom name
// for UD2 selects the ordinary printer even when regenerating with these
// tables already compiled in. From the source root, run
// c++ -std=c++17 -Iinclude suite/synctools/x86_simple_output.cpp /path/to/libcapstone.a -o /tmp/gen-x86-output
// /tmp/gen-x86-output > arch/X86/X86GenSimpleOutput.inc
// The exhaustive x86_simple_output unit compares the result to normal decoding.
#include "../../arch/X86/X86SimpleOutput.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
struct Decoder {
	csh handle = 0;
	cs_insn *insn = nullptr;
	explicit Decoder(cs_mode mode)
	{
		cs_opt_mnem ordinary = { X86_INS_UD2, "ud2" };
		if (cs_open(CS_ARCH_X86, mode, &handle) ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) ||
		    cs_option(handle, CS_OPT_MNEMONIC,
			      reinterpret_cast<size_t>(&ordinary)) ||
		    !(insn = cs_malloc(handle)))
			throw std::runtime_error(
				"cannot initialize the full x86 decoder");
	}
	~Decoder()
	{
		cs_free(insn, 1);
		cs_close(&handle);
	}
	void decode(const uint8_t *input, size_t length, unsigned consumed,
		    uint64_t ip)
	{
		const uint8_t *cursor = input;
		if (!cs_disasm_iter(handle, &cursor, &length, &ip, insn) ||
		    insn->size != consumed || cursor != input + consumed)
			throw std::runtime_error(
				"unexpected instruction boundary");
	}
};

bool fixed_opcode(unsigned opcode, bool wide)
{
	if ((!wide && opcode >= 0x40 && opcode <= 0x4f) ||
	    (opcode >= 0x50 && opcode <= 0x5f) ||
	    (opcode >= 0x90 && opcode <= 0x99) ||
	    (opcode >= 0x9c && opcode <= 0x9f) ||
	    (opcode >= 0xf8 && opcode <= 0xfd))
		return true;
	switch (opcode) {
	case 0xc3:
	case 0xc9:
	case 0xcb:
	case 0xcc:
	case 0xcf:
	case 0xd7:
	case 0xec:
	case 0xed:
	case 0xee:
	case 0xef:
	case 0xf4:
	case 0xf5:
		return true;
	default:
		return false;
	}
}

bool pair_opcode(unsigned opcode)
{
	return (opcode < 0x40 && (opcode & 7) <= 3) ||
	       (opcode >= 0x84 && opcode <= 0x8b);
}

template <typename T, size_t N>
void emit_array(std::ostream &out, const T (&values)[N])
{
	out << "{ ";
	for (size_t i = 0; i < N; ++i)
		out << (i ? ", " : "") << unsigned(values[i]);
	out << " }";
}

std::string initializer(const X86SimpleOutput &row)
{
	std::ostringstream out;
	out << "{ " << row.id << ", \"" << row.mnemonic << "\", \""
	    << row.operands << "\", UINT64_C(" << row.flags << "), ";
	emit_array(out, row.reads);
	out << ", ";
	emit_array(out, row.writes);
	out << ", ";
	emit_array(out, row.groups);
	for (unsigned v : { row.read_count, row.write_count, row.group_count,
			    row.operand_count, row.address_size,
			    row.modrm_offset, row.imm_offset, row.imm_size })
		out << ", " << v;
	out << ", { ";
	for (unsigned i = 0; i < 2; ++i) {
		const auto &op = row.ops[i];
		out << (i ? ", " : "") << "{ " << op.reg << ", "
		    << unsigned(op.size) << ", " << unsigned(op.access) << " }";
	}
	return out.str() + " } }";
}

// A pair row owns the operand sizes and access modes. REX and ModR/M supply
// its two register IDs. Every other public byte must be reproduced by the row.
std::string describe(const cs_insn &insn, uint8_t opcode, uint8_t rex,
		     uint8_t modrm, const X86SimpleRegister *first,
		     const X86SimpleRegister *second, bool branch = false,
		     bool lea = false)
{
	const auto &d = *insn.detail;
	const auto &x = d.x86;
	X86SimpleOutput row{};
	if (strlen(insn.mnemonic) >= sizeof(row.mnemonic) ||
	    strlen(insn.op_str) >= sizeof(row.operands) ||
	    strpbrk(insn.mnemonic, "\n\r\t\\\"") ||
	    strpbrk(insn.op_str, "\n\r\t\\\"") || d.regs_read_count > 4 ||
	    d.regs_write_count > 4 || d.groups_count > 4 || x.op_count > 2)
		return {};
	row.id = insn.id;
	strcpy(row.mnemonic, insn.mnemonic);
	if (first) {
		if (x.op_count != 2 || (std::string(first->name) + ", " +
					second->name) != insn.op_str)
			return {};
	} else if (!branch && !lea)
		strcpy(row.operands, insn.op_str);
	row.flags = x.eflags;
	row.read_count = d.regs_read_count;
	row.write_count = d.regs_write_count;
	row.group_count = d.groups_count;
	row.operand_count = x.op_count;
	row.address_size = x.addr_size;
	row.modrm_offset = x.encoding.modrm_offset;
	row.imm_offset = x.encoding.imm_offset;
	row.imm_size = x.encoding.imm_size;
	std::copy_n(d.regs_read, row.read_count, row.reads);
	std::copy_n(d.regs_write, row.write_count, row.writes);
	std::copy_n(d.groups, row.group_count, row.groups);
	for (unsigned i = 0; i < x.op_count; ++i) {
		const auto &op = x.operands[i];
		if (lea && i == 1) {
			if (op.type != X86_OP_MEM)
				return {};
			row.ops[1] = { 0, op.size,
				       static_cast<uint8_t>(op.access) };
			continue;
		}
		if (op.type != (branch ? X86_OP_IMM : X86_OP_REG) ||
		    (!branch && unsigned(op.reg) > UINT16_MAX) ||
		    unsigned(op.access) > UINT8_MAX)
			return {};
		row.ops[i] = { static_cast<uint16_t>(
				       (first || branch || lea) ? 0 : op.reg),
			       op.size, static_cast<uint8_t>(op.access) };
	}
	cs_detail rebuilt;
	X86_writeSimpleDetail(&rebuilt, &row, opcode, rex, modrm,
			      first ? first->reg : row.ops[0].reg,
			      second ? second->reg : row.ops[1].reg);

	if (lea) {
		if (x.op_count != 2 || x.operands[0].type != X86_OP_REG)
			return {};
		rebuilt.x86.operands[0].reg = x.operands[0].reg;
		rebuilt.x86.operands[1].type = X86_OP_MEM;
		rebuilt.x86.operands[1].mem = x.operands[1].mem;
	}
	if (branch) {
		if (x.op_count != 1)
			return {};
		if (row.imm_offset == 2) {
			rebuilt.x86.opcode[0] = 0x0f;
			rebuilt.x86.opcode[1] = opcode;
		}
		rebuilt.x86.operands[0].type = X86_OP_IMM;
		rebuilt.x86.operands[0].imm = x.operands[0].imm;
	}
	if (memcmp(&rebuilt, &d, offsetof(cs_detail, x86) + sizeof(cs_x86)))
		return {};
	return initializer(row);
}

void decode_pair(Decoder &d, uint8_t rex, uint8_t op, uint8_t mr)
{
	uint8_t bytes[] = { rex, op, mr };
	unsigned length = rex ? 3 : 2;
	d.decode(bytes + !rex, length, length, UINT64_MAX - 1);
}

unsigned register_class(unsigned opcode, unsigned rex)
{
	return (opcode & 1) ? ((rex & 8) ? 3 : 2) : (rex != 0);
}
using RegisterTable = X86SimpleRegister[4][16];
using PlanTable = uint16_t[2][4][256];

void describe_registers(Decoder &x64, RegisterTable &regs)
{
	for (unsigned width = 0; width < 4; ++width) {
		for (unsigned i = 0; i < (width ? 16u : 8u); ++i) {
			unsigned rex = width ? (0x40 | (i >= 8 ? 5 : 0) |
						(width == 3 ? 8 : 0)) :
					       0;
			decode_pair(x64, rex, width < 2 ? 0x88 : 0x89,
				    0xc0 | (i & 7) * 9);
			const auto &x = x64.insn->detail->x86;
			if (x.op_count != 2 ||
			    x.operands[0].type != X86_OP_REG ||
			    x.operands[1].type != X86_OP_REG ||
			    x.operands[0].reg != x.operands[1].reg)
				throw std::runtime_error(
					"invalid canonical register");
			auto &reg = regs[width][i];
			reg.reg = x.operands[0].reg;
			const char *name = cs_reg_name(x64.handle, reg.reg);
			if (!name || strlen(name) >= sizeof(reg.name))
				throw std::runtime_error(
					"invalid canonical register");
			strcpy(reg.name, name);
			reg.length = static_cast<uint8_t>(strlen(name));
		}
	}
}

struct CheckedRow {
	std::string fields;
	unsigned encodings = 0;
	void observe(const std::string &actual)
	{
		if (actual.empty() || (encodings && fields != actual))
			throw std::runtime_error(
				"the ordinary decoder changed the output for this encoding");
		fields = actual;
		++encodings;
	}
};

CheckedRow check_fixed(Decoder &decoder, unsigned opcode)
{
	CheckedRow row;
	for (unsigned tail = 0; tail <= 256; ++tail) {
		uint8_t bytes[15];
		memset(bytes, tail, sizeof(bytes));
		bytes[0] = opcode;
		decoder.decode(bytes, tail ? sizeof(bytes) : 1, 1,
			       UINT64_MAX - tail);
		row.observe(describe(*decoder.insn, opcode, 0, 0, nullptr,
				     nullptr));
	}
	return row;
}

CheckedRow check_pair(Decoder &decoder, unsigned opcode, unsigned prefix_class,
		      const RegisterTable &regs, X86SimpleForm &form)
{
	const unsigned start = prefix_class == 0 ? 0 :
			       prefix_class == 1 ? 0x40 :
						   0x48;
	const auto &names = regs[register_class(opcode, start)];
	decode_pair(decoder, start, opcode, 0xc1);
	form = decoder.insn->detail->x86.operands[0].reg == names[0].reg ?
		       X86_SIMPLE_REG_RM :
		       X86_SIMPLE_RM_REG;
	CheckedRow row;
	for (unsigned rex = start; rex <= start + (prefix_class ? 7 : 0);
	     ++rex) {
		for (unsigned mr = 0xc0; mr < 256; ++mr) {
			decode_pair(decoder, rex, opcode, mr);
			unsigned reg = ((rex & 4) << 1) | ((mr >> 3) & 7);
			unsigned rm = ((rex & 1) << 3) | (mr & 7);
			if (form == X86_SIMPLE_RM_REG)
				std::swap(reg, rm);
			row.observe(describe(*decoder.insn, opcode, rex, mr,
					     &names[reg], &names[rm]));
		}
	}
	return row;
}

// The register/imm8 form reuses the register row builder. Reconstruct the
// one varying immediate separately after checking its public value and text.
CheckedRow check_shift(Decoder &decoder, unsigned cls, unsigned group,
		       const RegisterTable &regs)
{
	CheckedRow row;
	const unsigned start = cls == 0 ? 0 : cls == 1 ? 0x40 : 0x48;
	for (unsigned rex = start; rex <= start + (cls ? 7 : 0); ++rex) {
		for (unsigned rm = 0; rm < 8; ++rm) {
			const auto &reg =
				regs[cls == 2 ? 3 : 2][rm | ((rex & 1) << 3)];
			for (unsigned imm : { 0u, 1u, 9u, 10u, 31u, 32u, 63u,
					      64u, 127u, 128u, 255u }) {
				const uint8_t modrm =
					uint8_t(0xc0 | (group << 3) | rm);
				uint8_t bytes[] = { uint8_t(rex), 0xc1, modrm,
						    uint8_t(imm) };
				unsigned length = 3 + !!rex;
				decoder.decode(bytes + !rex, length, length, 0);
				cs_insn projected = *decoder.insn;
				cs_detail detail = *projected.detail;
				auto &x = detail.x86;
				std::ostringstream printed;
				printed << reg.name << ", ";
				if (imm > HEX_THRESHOLD)
					printed << "0x" << std::hex;
				printed << imm;
				if (projected.op_str != printed.str() ||
				    x.op_count != 2 ||
				    x.operands[0].type != X86_OP_REG ||
				    x.operands[0].reg != reg.reg ||
				    x.operands[1].type != X86_OP_IMM ||
				    x.operands[1].imm != imm ||
				    x.encoding.imm_offset != length - 1 ||
				    x.encoding.imm_size != 1)
					throw std::runtime_error(
						"unexpected register shift count or spelling");
				// The runtime assigns this operand's type and value after
				// writing the row. Keep its generated size and access.
				projected.detail = &detail;
				projected.op_str[0] = 0;
				x.operands[0].reg = X86_REG_INVALID;
				x.operands[1].type = X86_OP_REG;
				x.operands[1].imm = 0;
				row.observe(describe(projected, 0xc1,
						     uint8_t(rex), modrm,
						     nullptr, nullptr));
			}
		}
	}
	return row;
}

CheckedRow check_push_immediate(Decoder &d, unsigned op)
{
	CheckedRow row;
	const unsigned width = op == 0x6a ? 1 : 4;
	for (uint32_t value : { 0u, 1u, 9u, 10u, 0x7fu, 0x80u, 0xffu,
				0x7fffffffu, 0x80000000u, 0xffffffffu }) {
		uint8_t data[] = { uint8_t(op), uint8_t(value),
				   uint8_t(value >> 8), uint8_t(value >> 16),
				   uint8_t(value >> 24) };
		d.decode(data, width + 1, width + 1, 0);
		row.observe(
			describe(*d.insn, op, 0, 0, nullptr, nullptr, true));
	}
	return row;
}

CheckedRow check_lea(Decoder &d, unsigned cls, const RegisterTable &regs,
		     bool wide)
{
	CheckedRow row;
	const unsigned start = !cls ? 0 : cls == 1 ? 0x40 : 0x48;
	for (unsigned rex = start; rex <= start + (cls ? 7 : 0); ++rex) {
		for (unsigned mr = 0; mr < 0x40; ++mr) {
			if ((mr & 7) == 4 || (mr & 7) == 5)
				continue;
			decode_pair(d, rex, 0x8d, mr);
			const auto &reg =
				regs[(rex & 8) ? 3 : 2]
				    [((rex & 4) << 1) | ((mr >> 3) & 7)];
			const auto &base =
				regs[wide ? 3 : 2][((rex & 1) << 3) | (mr & 7)];
			if (d.insn->detail->x86.operands[0].reg !=
				    (x86_reg)reg.reg ||
			    d.insn->detail->x86.operands[1].mem.base !=
				    (x86_reg)base.reg ||
			    std::string(reg.name) + ", [" + base.name + "]" !=
				    d.insn->op_str)
				throw std::runtime_error(
					"unexpected effective address");
			row.observe(describe(*d.insn, 0x8d, rex, mr, nullptr,
					     nullptr, false, true));
		}
	}
	return row;
}

bool relative_opcode(unsigned cls, unsigned op)
{
	if (cls == 3)
		return op >= 0x80 && op <= 0x8f;
	return cls == 0 && ((op >= 0x70 && op <= 0x7f) || op == 0xeb ||
			    op == 0xe8 || op == 0xe9);
}

CheckedRow check_relative(Decoder &d, bool wide, unsigned cls, unsigned op)
{
	CheckedRow row;
	const unsigned offset = cls == 3 ? 2 : 1;
	const unsigned width =
		offset == 1 && (op == 0xeb || (op & 0xf0) == 0x70) ? 1 : 4;
	uint8_t bytes[6]{};
	bytes[0] = cls == 3 ? 0x0f : op;
	bytes[offset - 1] = op;
	for (uint32_t bits : { 0u, 1u, 9u, 10u, 127u, 128u, 255u, 0x80000000u,
			       0x7fffffffu, 0xffffffffu }) {
		for (unsigned j = 0; j < width; ++j)
			bytes[offset + j] = uint8_t(bits >> (j * 8));
		const int64_t delta = width == 1 ? int8_t(bits) : int32_t(bits);
		for (uint64_t target :
		     { uint64_t(0), uint64_t(1), uint64_t(9), uint64_t(10),
		       uint64_t(0x12345678), uint64_t(0xffffffffu), UINT64_MAX,
		       UINT64_C(0x8000000000000000) }) {
			const uint64_t address =
				target - delta - offset - width;
			const uint64_t expected = wide ? target :
							 uint32_t(target);
			d.decode(bytes, width + offset, width + offset,
				 address);
			const auto &x = d.insn->detail->x86;
			std::ostringstream text;
			if (expected > 9)
				text << "0x" << std::hex;
			text << expected;
			if (x.op_count != 1 ||
			    x.operands[0].type != X86_OP_IMM ||
			    uint64_t(x.operands[0].imm) != expected ||
			    text.str() != d.insn->op_str ||
			    x.encoding.imm_offset != offset ||
			    x.encoding.imm_size != width)
				throw std::runtime_error(
					"unexpected relative address, rendering or immediate extent");
			row.observe(describe(*d.insn, op, 0, 0, nullptr,
					     nullptr, true));
		}
	}
	return row;
}

void emit_tables(const PlanTable &plans, const RegisterTable &regs,
		 const std::vector<std::string> &rows)
{
	std::cout
		<< "/* Generated by suite/synctools/x86_simple_output.cpp. */\n\n"
		<< "static const uint16_t x86_simple_plans[2][4][256] = {\n";
	for (auto &mode : plans) {
		std::cout << "\t{\n";
		for (auto &prefix : mode) {
			std::cout << "\t\t{\n";
			for (unsigned j = 0; j < 256; j += 16) {
				std::cout << "\t\t\t";
				for (unsigned k = 0; k < 16; ++k)
					std::cout << (k ? " " : "")
						  << prefix[j + k] << ',';
				std::cout << '\n';
			}
			std::cout << "\t\t},\n";
		}
		std::cout << "\t},\n";
	}
	std::cout
		<< "};\n\nstatic const struct X86SimpleOutput x86_simple_outputs[] = {\n";
	for (const auto &v : rows)
		std::cout << '\t' << v << ",\n";
	std::cout
		<< "};\n\nstatic const struct X86SimpleRegister x86_simple_registers[4][16] = {\n";
	for (auto &names : regs) {
		std::cout << "\t{\n";
		for (auto &v : names)
			std::cout << "\t\t{ " << v.reg << ", "
				  << unsigned(v.length) << ", \"" << v.name
				  << "\" },\n";
		std::cout << "\t},\n";
	}
	std::cout << "};\n";
}
} // namespace

int main()
{
	Decoder x86(CS_MODE_32), x64(CS_MODE_64);
	RegisterTable regs{};
	describe_registers(x64, regs);
	PlanTable plans{};
	std::vector<std::string> rows{ initializer(X86SimpleOutput{}) };
	unsigned checked = 0, admitted = 0;
	for (unsigned wide = 0; wide < 2; ++wide) {
		Decoder &decoder = wide ? x64 : x86;
		for (unsigned cls = 0; cls < 4; ++cls) {
			if (!wide && (cls == 1 || cls == 2))
				continue;
			for (unsigned op = 0; op < 256; ++op) {
				X86SimpleForm form = X86_SIMPLE_FIXED;
				CheckedRow row;
				if (!cls && fixed_opcode(op, wide))
					row = check_fixed(decoder, op);
				else if (relative_opcode(cls, op)) {
					form = X86_SIMPLE_RELATIVE;
					row = check_relative(decoder, wide, cls,
							     op);
				} else if (cls != 3 && op == 0x8d) {
					form = X86_SIMPLE_REG_RM;
					row = check_lea(decoder, cls, regs,
							wide);
				} else if (cls != 3 && pair_opcode(op))
					row = check_pair(decoder, op, cls, regs,
							 form);
				else
					continue;
				auto index = static_cast<size_t>(
					std::find(rows.begin(), rows.end(),
						  row.fields) -
					rows.begin());
				if (index == rows.size())
					rows.push_back(row.fields);
				if (index >= (X86_PLAN_PUSH_IMMEDIATE >> 2))
					return 1;
				plans[wide][cls][op] = static_cast<uint16_t>(
					(index << 2) | form);
				checked += row.encodings;
				++admitted;
			}
		}
	}
	// Reserve unprefixed EVEX for its own verified vector output records.
	plans[0][0][0x66] = plans[1][0][0x66] = X86_PLAN_VECTOR;
	plans[1][0][0x62] = X86_PLAN_VECTOR;
	plans[1][0][0xc4] = X86_PLAN_VECTOR;
	plans[1][0][0xc5] = X86_PLAN_VECTOR;
	for (unsigned wide = 0; wide < 2; ++wide) {
		for (unsigned cls = 0; cls < (wide ? 3u : 1u); ++cls) {
			for (unsigned alu = 1; alu < 0x40; alu += 8) {
				if (!plans[wide][cls][alu])
					throw std::runtime_error(
						"missing group-1 register row");
			}
			plans[wide][cls][0x83] = X86_PLAN_GROUP1_IMM8;
		}
	}
	for (unsigned wide = 0; wide < 2; ++wide) {
		// B8+rd with no REX.W uses an unsigned immediate and a 32-bit destination.
		for (unsigned cls = 0; cls <= wide; ++cls) {
			if (!plans[wide][cls][0x8b])
				throw std::runtime_error(
					"missing 32-bit register MOV row");
			for (unsigned opcode = 0xb8; opcode <= 0xbf; ++opcode)
				plans[wide][cls][opcode] =
					X86_PLAN_MOV_REG_IMM32;
		}
	}
	uint16_t shifts[2][3][8]{};
	for (unsigned wide = 0; wide < 2; ++wide) {
		Decoder &decoder = wide ? x64 : x86;
		for (unsigned cls = 0; cls < (wide ? 3u : 1u); ++cls) {
			plans[wide][cls][0xc1] = X86_PLAN_SHIFT_IMM8;
			for (unsigned group = 0; group < 8; ++group) {
				auto row =
					check_shift(decoder, cls, group, regs);
				size_t index = std::find(rows.begin(),
							 rows.end(),
							 row.fields) -
					       rows.begin();
				if (index >= (X86_PLAN_PUSH_IMMEDIATE >> 2))
					return 1;
				if (index == rows.size())
					rows.push_back(row.fields);
				shifts[wide][cls][group] = uint16_t(index);
				checked += row.encodings;
			}
		}
	}
	uint16_t pushes[2][2];
	for (unsigned wide = 0; wide < 2; ++wide) {
		Decoder &decoder = wide ? x64 : x86;
		for (unsigned index = 0; index < 2; ++index) {
			const unsigned op = index ? 0x6a : 0x68;
			CheckedRow row = check_push_immediate(decoder, op);
			if (rows.size() >= (X86_PLAN_PUSH_IMMEDIATE >> 2))
				return 1;
			pushes[wide][index] =
				static_cast<uint16_t>(rows.size());
			rows.push_back(row.fields);
			checked += row.encodings;
			plans[wide][0][op] = X86_PLAN_PUSH_IMMEDIATE;
		}
	}
	emit_tables(plans, regs, rows);
	std::cout << "\nstatic const uint16_t x86_shift_rows[2][3][8] = {\n";
	for (const auto &mode : shifts) {
		std::cout << "\t{\n";
		for (const auto &cls : mode) {
			std::cout << "\t\t";
			emit_array(std::cout, cls);
			std::cout << ",\n";
		}
		std::cout << "\t},\n";
	}
	std::cout << "};\n";

	std::cout << "\nstatic const uint16_t x86_push_rows[2][2] = {\n";
	for (const auto &mode : pushes) {
		std::cout << "\t";
		emit_array(std::cout, mode);
		std::cout << ",\n";
	}
	std::cout << "};\n";

	std::cerr << "records=" << rows.size() - 1 << " plans=" << admitted
		  << " encodings_checked=" << checked << " table_bytes="
		  << sizeof(plans) + sizeof(regs) +
			     rows.size() * sizeof(X86SimpleOutput)
		  << '\n';
}

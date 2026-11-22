/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

// Build against full x86 Capstone and redirect stdout to X86GenVectorOutput.inc.
#include <capstone/capstone.h>
#include "../../arch/X86/X86EvexAdmission.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
struct Form {
	unsigned map, opcode;
	bool immediate;
	bool extract = false;
};

// Three ordinary vector registers, with an optional imm8. Each admitted
// W/LL combination is rebuilt from the output of the canonical decoder.
constexpr Form forms[] = {
	{ 3, 0x19, true, true }, { 3, 0x1b, true, true },
	{ 3, 0x39, true, true }, { 3, 0x3b, true, true },
	{ 1, 0xef, false },	 { 2, 0xdc, false },
	{ 2, 0xdd, false },	 { 2, 0xde, false },
	{ 2, 0xdf, false },	 { 3, 0x44, true },
	{ 3, 0x25, true },	 { 2, 0x00, false },
	{ 1, 0xfe, false },
};

struct Decoder {
	csh handle = 0;
	cs_insn *insn = nullptr;
	uint64_t probes = 0;
	explicit Decoder(cs_mode mode = CS_MODE_64)
	{
		// Text, detail and a custom name make regeneration independent of
		// both the compact scan reader and the optimized output records.
		cs_opt_mnem name = { X86_INS_UD2, "ud2" };
		if (cs_open(CS_ARCH_X86, mode, &handle) ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) ||
		    cs_option(handle, CS_OPT_MNEMONIC,
			      reinterpret_cast<size_t>(&name)) ||
		    !(insn = cs_malloc(handle)))
			throw std::runtime_error(
				"cannot initialize the full x86 decoder");
	}
	~Decoder()
	{
		cs_free(insn, 1);
		cs_close(&handle);
	}
	unsigned decode(const uint8_t *bytes, unsigned length)
	{
		insn->is_alias = false;
		insn->usesAliasDetails = false;
		insn->illegal = false;
		const uint8_t *cursor = bytes;
		uint64_t ip = 0x100000012;
		size_t left = length;
		++probes;
		if (!cs_disasm_iter(handle, &cursor, &left, &ip, insn) ||
		    left || cursor != bytes + length)
			return 0;
		return insn->id;
	}
	std::string symbol(unsigned id) const
	{
		if (!id)
			return "0";
		const char *name = cs_insn_name(handle, id);
		if (!name)
			throw std::runtime_error("missing instruction name");
		std::string result(name);
		for (char &c : result) {
			if (c >= 'a' && c <= 'z')
				c = char(c - 'a' + 'A');
		}
		return "X86_INS_" + result;
	}
};

using Bytes4 = std::array<unsigned, 4>;
using WidthRows = std::array<std::array<unsigned, 3>, 2>;
std::string fields(const Bytes4 &array)
{
	return "{ " + std::to_string(array[0]) + ", " +
	       std::to_string(array[1]) + ", " + std::to_string(array[2]) +
	       ", " + std::to_string(array[3]) + " }";
}

// Reconstruct both explicit registers and the immediate from the canonical
// decoder. Extracts take their destination from r/m. Immediate shifts take
// it from vvvv/V' and use the ModR/M reg field as an opcode extension.
std::string pair_immediate_record(Decoder &decoder, const Form &form,
				  unsigned w, unsigned ll, unsigned group = 0)
{
	const unsigned dst_width = form.extract ? ((form.opcode & 2) ? 1 : 0) :
						  ll;
	const char *names[] = { "xmm", "ymm", "zmm" };
	const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0, X86_REG_ZMM0 };
	std::string row;
	for (unsigned i = 0; i < 1024; ++i) {
		unsigned dst = i & 31, src = i >> 5, value = (i * 37) & 255;
		unsigned ext = ((src & 8) << 4) | ((dst & 16) << 2) |
			       ((dst & 8) << 2) | (src & 16);
		uint8_t bytes[] = { 0x62,
				    uint8_t((0xf0 ^ ext) | 3),
				    uint8_t(w << 7 | 0x7d),
				    uint8_t(ll << 5 | 8),
				    uint8_t(form.opcode),
				    uint8_t(0xc0 | (src & 7) << 3 | (dst & 7)),
				    uint8_t(value) };
		if (!form.extract) {
			ext = (src & 24) << 2;
			bytes[1] = uint8_t((0xf0 ^ ext) | form.map);
			bytes[2] = uint8_t(w << 7 | ((~dst & 15) << 3) | 5);
			bytes[3] = uint8_t(ll << 5 | ((~dst & 16) >> 1));
			bytes[5] = uint8_t(0xc0 | (group << 3) | (src & 7));
		}
		unsigned id = decoder.decode(bytes, sizeof(bytes));
		if (!id)
			return {};
		const auto &insn = *decoder.insn;
		const auto &d = *insn.detail;
		if (insn.is_alias || insn.usesAliasDetails || insn.illegal ||
		    std::strlen(insn.mnemonic) >= 16 || d.regs_read_count ||
		    d.regs_write_count || d.groups_count > 4)
			return {};
		cs_x86 x{};
		std::memcpy(x.opcode, bytes, 4);
		x.rex = uint8_t(0x40 | (w << 3) | (ext >> 5));
		x.addr_size = 8;
		x.modrm = bytes[5];
		x.encoding.modrm_offset = 5;
		x.encoding.imm_offset = 6;
		x.encoding.imm_size = 1;
		x.op_count = 3;
		Bytes4 access{}, groups{};
		std::copy_n(d.groups, d.groups_count, groups.begin());
		for (unsigned n = 0; n < 3; ++n) {
			x.operands[n].access = d.x86.operands[n].access;
			access[n] = unsigned(x.operands[n].access);
		}
		x.operands[0].type = X86_OP_REG;
		x.operands[0].reg = x86_reg(bases[dst_width] + dst);
		x.operands[0].size = uint8_t(16 << dst_width);
		x.operands[1].type = X86_OP_REG;
		x.operands[1].reg = x86_reg(bases[ll] + src);
		x.operands[1].size = uint8_t(16 << ll);
		x.operands[2].type = X86_OP_IMM;
		x.operands[2].size = 1;
		x.operands[2].imm = value;
		char text[64];
		std::snprintf(text, sizeof(text),
			      value <= 9 ? "%s%u, %s%u, %u" :
					   "%s%u, %s%u, 0x%x",
			      names[dst_width], dst, names[ll], src, value);
		if (std::strcmp(text, insn.op_str) ||
		    std::memcmp(&x, &d.x86, sizeof(x)))
			return {};
		std::string record =
			"{ " + decoder.symbol(id) + ", \"" + insn.mnemonic +
			"\", " + std::to_string(d.groups_count) + ", " +
			fields(groups) + ", " + fields(access) + ", 1 }";
		if (i && record != row)
			return {};
		row = record;
	}
	return row;
}

std::string output_record(Decoder &decoder, const Form &form, unsigned w,
			  unsigned ll)
{
	if (form.extract)
		return pair_immediate_record(decoder, form, w, ll);
	uint8_t bytes[] = { 0x62,
			    uint8_t(0xf0 | form.map),
			    uint8_t(w << 7 | 0x6d),
			    uint8_t(ll << 5 | 8),
			    uint8_t(form.opcode),
			    0xd9,
			    0x80 };
	const unsigned size = 6 + form.immediate;
	const unsigned id = decoder.decode(bytes, size);
	if (!id)
		return {};
	const cs_insn &insn = *decoder.insn;
	const auto &detail = *insn.detail;
	const auto &x = detail.x86;
	const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0, X86_REG_ZMM0 };
	const std::string prefix[] = { "xmm", "ymm", "zmm" };
	const std::string &vec = prefix[ll];
	const std::string rendered = vec + "3, " + vec + "2, " + vec + "1" +
				     (form.immediate ? ", 0x80" : "");
	if (rendered != insn.op_str || std::strlen(insn.mnemonic) >= 16 ||
	    std::strcmp(cs_insn_name(decoder.handle, id), insn.mnemonic) ||
	    detail.regs_read_count || detail.regs_write_count ||
	    detail.groups_count > 4 || x.op_count != 3 + form.immediate ||
	    x.eflags || x.addr_size != 8 || std::memcmp(x.opcode, bytes, 4) ||
	    x.rex != (0x40 | w << 3) || x.modrm != bytes[5] ||
	    x.encoding.modrm_offset != 5)
		throw std::runtime_error("unexpected EVEX register output");
	Bytes4 groups{}, access{};
	for (unsigned i = 0; i < detail.groups_count; ++i)
		groups[i] = detail.groups[i];
	for (unsigned i = 0; i < 3; ++i) {
		const auto &op = x.operands[i];
		if (op.type != X86_OP_REG ||
		    unsigned(op.reg) != unsigned(bases[ll]) + 3 - i ||
		    op.size != (16u << ll))
			throw std::runtime_error(
				"unexpected EVEX register operand");
		access[i] = op.access;
	}
	if (form.immediate) {
		const auto &op = x.operands[3];
		if (op.type != X86_OP_IMM || op.imm != 0x80 || op.size != 1 ||
		    x.encoding.imm_offset != 6 || x.encoding.imm_size != 1)
			throw std::runtime_error("unexpected EVEX immediate");
		access[3] = op.access;
	}
	return "{ " + decoder.symbol(id) + ", \"" + insn.mnemonic + "\", " +
	       std::to_string(detail.groups_count) + ", " + fields(groups) +
	       ", " + fields(access) + ", " + std::to_string(form.immediate) +
	       " }";
}

void emit_vex_indexed(Decoder &decoder)
{
	std::puts(
		"static const struct VectorOutputRow vex_indexed_rows[2][2] = {");
	for (unsigned fma = 0; fma < 2; ++fma) {
		std::puts("\t{");
		for (unsigned ll = 0; ll < 2; ++ll) {
			const uint8_t move[] = { 0xc5, uint8_t(0xf8 | ll << 2),
						 0x28, 0x44,
						 0x17, 0xa0 };
			const uint8_t add[] = {
				0xc4, 0xe2, uint8_t(0x71 | ll << 2), 0xa8, 0x44,
				0x17, 0xa0
			};
			const auto id = decoder.decode(fma ? add : move,
						       fma ? sizeof(add) :
							     sizeof(move));
			if (!id)
				throw std::runtime_error(
					"missing VEX indexed operand");
			const auto &insn = *decoder.insn;
			const auto &d = *insn.detail;
			const auto &x = d.x86;
			const std::string vec = ll ? "ymm" : "xmm";
			const auto text = vec + "0, " +
					  (fma ? vec + "1, " : "") + vec +
					  "word ptr [rdi + rdx - 0x60]";
			if (insn.op_str != text ||
			    std::strlen(insn.mnemonic) >= 16 ||
			    d.regs_read_count || d.regs_write_count ||
			    d.groups_count > 4 || x.eflags ||
			    x.op_count != 2 + fma)
				throw std::runtime_error(
					"unexpected VEX indexed output");
			Bytes4 groups{}, access{};
			std::copy_n(d.groups, d.groups_count, groups.begin());
			for (unsigned i = 0; i < x.op_count; ++i) {
				const auto &op = x.operands[i];
				if (op.size != (16u << ll) ||
				    op.type != (i + 1 == x.op_count ?
							X86_OP_MEM :
							X86_OP_REG))
					throw std::runtime_error(
						"unexpected VEX indexed operand");
				access[i] = unsigned(op.access);
			}
			std::printf("\t\t{ %s, \"%s\", %u, %s, %s, 0 },\n",
				    decoder.symbol(id).c_str(), insn.mnemonic,
				    unsigned(d.groups_count),
				    fields(groups).c_str(),
				    fields(access).c_str());
		}
		std::puts("\t},");
	}
	std::puts("};");
}

// Describe only legacy 66 0F register operations whose entire public x86 detail
// can be recovered from the prefix, opcode and ModR/M. Generate against
// the ordinary decoder so special encodings and aliases retain its behavior.
std::string legacy_register_row(Decoder &decoder, bool wide, unsigned rex,
				unsigned opcode, unsigned modrm, bool reverse,
				int immediate = -1, bool map38 = false)
{
	uint8_t bytes[7];
	unsigned length = 0;
	bytes[length++] = 0x66;
	if (rex)
		bytes[length++] = uint8_t(rex);
	bytes[length++] = 0x0f;
	if (map38)
		bytes[length++] = 0x38;
	bytes[length++] = uint8_t(opcode);
	bytes[length++] = uint8_t(modrm);
	const unsigned header = length;
	const bool has_imm = immediate >= 0;
	if (has_imm)
		bytes[length++] = uint8_t(immediate);
	const unsigned size = length;
	const unsigned registers = has_imm && opcode != 0x70 ? 1 : 2;
	const unsigned id = decoder.decode(bytes, size);
	if (!id)
		return {};
	const cs_insn &insn = *decoder.insn;
	const auto &d = *insn.detail;
	const auto &x = d.x86;
	if (insn.is_alias || insn.usesAliasDetails || insn.illegal ||
	    std::strlen(insn.mnemonic) >= 16 || d.regs_read_count ||
	    d.regs_write_count || d.groups_count > 4 ||
	    x.op_count != registers + has_imm)
		return {};
	const unsigned reg = ((modrm >> 3) & 7) + ((rex & 4) << 1);
	const unsigned rm = (modrm & 7) + ((rex & 1) << 3);
	const unsigned nums[] = { reverse ? rm : reg, reverse ? reg : rm };
	cs_x86 expected{};
	expected.prefix[2] = 0x66;
	expected.opcode[0] = 0x0f;
	expected.opcode[1] = map38 ? 0x38 : uint8_t(opcode);
	if (map38)
		expected.opcode[2] = uint8_t(opcode);
	expected.rex = uint8_t(rex);
	expected.addr_size = wide ? 8 : 4;
	expected.modrm = uint8_t(modrm);
	expected.encoding.modrm_offset = uint8_t(header - 1);
	expected.op_count = uint8_t(registers + has_imm);
	Bytes4 access{}, groups{};
	std::copy_n(d.groups, d.groups_count, groups.begin());
	for (unsigned i = 0; i < registers; ++i) {
		auto &op = expected.operands[i];
		op.type = X86_OP_REG;
		op.reg = x86_reg(X86_REG_XMM0 + nums[i]);
		op.size = 16;
		op.access = x.operands[i].access;
		access[i] = unsigned(op.access);
	}
	std::string text = "xmm" + std::to_string(nums[0]);
	if (registers == 2)
		text += ", xmm" + std::to_string(nums[1]);
	if (has_imm) {
		auto &op = expected.operands[registers];
		op.type = X86_OP_IMM;
		op.size = 1;
		op.imm = immediate;
		op.access = x.operands[registers].access;
		access[registers] = unsigned(op.access);
		expected.encoding.imm_offset = uint8_t(header);
		expected.encoding.imm_size = 1;
		char digits[12];
		std::snprintf(digits, sizeof(digits),
			      immediate <= 9 ? ", %u" : ", 0x%x",
			      unsigned(immediate));
		text += digits;
	}
	if (text != insn.op_str || std::memcmp(&expected, &x, sizeof(x)))
		return {};
	return "{ " + decoder.symbol(id) + ", \"" + insn.mnemonic + "\", " +
	       std::to_string(d.groups_count) + ", " + fields(groups) + ", " +
	       fields(access) + (has_imm ? ", 1 }" : ", 0 }");
}

void emit_legacy_immediates(Decoder &decoder)
{
	std::vector<std::string> rows;
	std::array<std::array<unsigned, 8>, 4> plans{};
	for (unsigned opcode = 0x70; opcode <= 0x73; ++opcode) {
		// PSHUFD selects its destination with ModR/M.reg. The shift groups
		// use the same field as the opcode extension and update ModR/M.r/m.
		const bool group_opcode = opcode != 0x70;
		for (unsigned group = 0; group < 8; ++group) {
			const unsigned mr = 0xc0 | (group << 3);
			const auto row = legacy_register_row(
				decoder, true, 0, opcode, mr, group_opcode, 0);
			if (row.empty())
				continue;
			for (unsigned p = 0; p <= 16; ++p) {
				const unsigned rex = p ? 0x3f + p : 0;
				for (unsigned value = 0; value <= 255; ++value)
					if (legacy_register_row(
						    decoder, true, rex, opcode,
						    mr | (value & 7),
						    group_opcode, value) != row)
						throw std::runtime_error(
							"nonuniform legacy immediate operands");
			}
			auto i = std::find(rows.begin(), rows.end(), row);
			plans[opcode - 0x70][group] =
				unsigned(i - rows.begin()) + 1;
			if (i == rows.end())
				rows.push_back(row);
		}
	}
	if (rows.size() != 11)
		throw std::runtime_error(
			"missing legacy shuffle or packed shift rows");
	std::puts(
		"/* Generated by suite/synctools/x86_vector_output.cpp --legacy-register-immediates. */");
	std::puts(
		"static const struct VectorOutputRow legacy_immediate_rows[] = {");
	for (const auto &row : rows)
		std::printf("\t%s,\n", row.c_str());
	std::puts("};\nstatic const uint8_t legacy_immediate_plans[4][8] = {");
	for (const auto &plan : plans) {
		std::cout << "\t";
		std::cout << "{ ";
		for (auto n : plan)
			std::cout << n << ", ";
		std::cout << "}";
		std::cout << ",\n";
	}
	std::puts("};");
}

void emit_legacy_registers(Decoder &wide, bool map38 = false)
{
	Decoder narrow(CS_MODE_32);
	std::vector<std::string> rows;
	std::array<unsigned, 256> plans{};
	for (unsigned opcode = 0; opcode < plans.size(); ++opcode) {
		bool reverse = false;
		auto row = legacy_register_row(narrow, false, 0, opcode, 0xd9,
					       reverse, -1, map38);
		if (row.empty()) {
			reverse = true;
			row = legacy_register_row(narrow, false, 0, opcode,
						  0xd9, reverse, -1, map38);
		}
		if (row.empty())
			continue;
		bool uniform = true;
		for (unsigned prefix = 0; prefix < 18 && uniform; ++prefix) {
			const bool mode64 = prefix != 0;
			const unsigned rex = prefix >= 2 ? 0x40 + prefix - 2 :
							   0;
			for (unsigned mr = 0xc0; mr <= 0xff; ++mr) {
				if (legacy_register_row(mode64 ? wide : narrow,
							mode64, rex, opcode, mr,
							reverse, -1,
							map38) != row) {
					uniform = false;
					break;
				}
			}
		}
		if (!uniform)
			continue;
		const auto it = std::find(rows.begin(), rows.end(), row);
		const unsigned index = unsigned(it - rows.begin()) + 1;
		if (index >= 128)
			throw std::runtime_error(
				"too many legacy register output rows");
		if (it == rows.end())
			rows.push_back(row);
		plans[opcode] = index | (reverse ? 128 : 0);
	}
	if (map38 && (!plans[0] || !plans[0xdc] || !plans[0xde]))
		throw std::runtime_error("missing AES or SSSE3 register forms");
	if (!map38 &&
	    (!plans[0x6f] || !plans[0x7f] || !plans[0x61] || !plans[0xfe]))
		throw std::runtime_error("missing SSE2 register forms");
	const char *table = map38 ? "legacy_map38" : "legacy_register";
	std::printf(
		"static const struct VectorOutputRow %s_rows[] = {\n\t{ 0 },\n",
		table);
	for (const auto &row : rows)
		std::printf("\t%s,\n", row.c_str());
	std::printf(
		"};\n/* Low seven bits index %s_rows; bit 7 reverses the operands. */\nstatic const uint8_t %s_plans[256] = {\n",
		table, table);
	for (unsigned i = 0; i < plans.size(); i += 16) {
		std::putchar('\t');
		for (unsigned j = 0; j < 16; ++j)
			std::printf("%s%u,", j ? " " : "", plans[i + j]);
		std::putchar('\n');
	}
	std::puts("};");
	std::fprintf(stderr, "%zu legacy register rows, %llu 32-bit probes\n",
		     rows.size(),
		     static_cast<unsigned long long>(narrow.probes));
	if (map38)
		std::fprintf(stderr, "%zu register rows from %llu canonical map 0F 38 probes\n",
			     rows.size(), static_cast<unsigned long long>(wide.probes + narrow.probes));
}

/* Derive the unmasked EVEX.66.0F38 1A memory forms from the canonical
 * decoder, including the disp8 tuple multiplier and both operand sizes. */
void emit_broadcast_rows(Decoder &decoder)
{
	std::puts(
		"static const struct VectorOutputRow broadcast_rows[2][3] = {");
	for (unsigned w = 0; w != 2; ++w) {
		std::puts("\t{");
		for (unsigned ll = 0; ll != 3; ++ll) {
			uint8_t bytes[] = { 0x62,
					    0xf2,
					    uint8_t(0x7d | w << 7),
					    uint8_t(8 | ll << 5),
					    0x1a,
					    0x58,
					    1 };
			unsigned id = decoder.decode(bytes, sizeof(bytes));
			if (!id) {
				std::puts("\t\t{ 0 },");
				continue;
			}
			const cs_insn &insn = *decoder.insn;
			const cs_detail &detail = *insn.detail;
			const cs_x86 &x = detail.x86;
			const char *mnemonic = w ? "vbroadcastf64x2" :
						   "vbroadcastf32x4";
			const std::string dest = std::string(ll == 2 ? "zmm" :
							     ll == 1 ? "ymm" :
								       "xmm") +
						 "3";
			x86_reg vec[] = { X86_REG_XMM0, X86_REG_YMM0,
					  X86_REG_ZMM0 };
			cs_x86 expect{};
			std::copy_n(bytes, 4, expect.opcode);
			expect.rex = uint8_t(0x40 | w << 3);
			expect.addr_size = 8;
			expect.modrm = bytes[5];
			expect.disp = 16;
			expect.encoding.modrm_offset = 5;
			expect.encoding.disp_offset = 6;
			expect.encoding.disp_size = 1;
			expect.op_count = 2;
			auto &reg = expect.operands[0];
			reg.type = X86_OP_REG;
			reg.reg = x86_reg(vec[ll] + 3);
			reg.size = uint8_t(16 << ll);
			reg.access = CS_AC_WRITE;
			auto &mem = expect.operands[1];
			mem.type = X86_OP_MEM;
			mem.size = 16;
			mem.mem.base = X86_REG_RAX;
			mem.mem.scale = 1;
			mem.mem.disp = 16;
			mem.access = CS_AC_READ;
			if (insn.illegal || insn.is_alias ||
			    insn.usesAliasDetails ||
			    std::strcmp(insn.mnemonic, mnemonic) ||
			    insn.op_str !=
				    dest + ", xmmword ptr [rax + 0x10]" ||
			    detail.regs_read_count || detail.regs_write_count ||
			    detail.groups_count > 4 ||
			    std::memcmp(&x, &expect, sizeof(x))) {
				std::puts("\t\t{ 0 },");
				continue;
			}
			Bytes4 groups{}, access{ unsigned(reg.access),
						 unsigned(mem.access), 0, 0 };
			std::copy_n(detail.groups, detail.groups_count,
				    groups.begin());
			const std::string symbol = decoder.symbol(id);
			std::printf("\t\t{ %s, \"%s\", %u, %s, %s, 0 },\n",
				    symbol.c_str(), mnemonic,
				    unsigned(detail.groups_count),
				    fields(groups).c_str(),
				    fields(access).c_str());
		}
		std::puts("\t},");
	}
	std::puts("};");
}

template <class T, size_t N> void emit_array(std::ostream &out, const T (&v)[N])
{
	out << "{ ";
	for (unsigned i = 0; i < N; ++i)
		out << (i ? ", " : "") << unsigned(v[i]);
	out << " }";
}
// These literal byte sequences occur as function-entry markers or assembler
// alignment. Emit their length, spelling and operand detail from the decoder.
void emit_padding_rows(Decoder &decoder32, Decoder &decoder64)
{
	const std::vector<std::vector<uint8_t> > forms = {
		{ 0x0f, 0x1f, 0x00 },
		{ 0x0f, 0x1f, 0x40, 0x00 },
		{ 0x0f, 0x1f, 0x44, 0x00, 0x00 },
		{ 0x0f, 0x1f, 0x80, 0, 0, 0, 0 },
		{ 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0 },
		{ 0x66, 0x90 },
		{ 0x66, 0x0f, 0x1f, 0x44, 0, 0 },
		{ 0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0 },
		{ 0xf3, 0x0f, 0x1e, 0xfa },
		{ 0xf3, 0x0f, 0x1e, 0xfb }
	};
	std::cout
		<< "static const struct PaddingOutput padding_rows[2][10] = {\n";
	for (unsigned wide = 0; wide < 2; ++wide) {
		Decoder &d = wide ? decoder64 : decoder32;
		std::cout << "\t{\n";
		for (const auto &bytes : forms) {
			if (!d.decode(bytes.data(), unsigned(bytes.size())))
				throw std::runtime_error(
					"unexpected padding boundary");
			const cs_insn &insn = *d.insn;
			const auto &detail = *insn.detail;
			const auto &x = detail.x86;
			cs_x86 expected{};
			std::copy_n(x.prefix, 4, expected.prefix);
			std::copy_n(x.opcode, 4, expected.opcode);
			expected.modrm = x.modrm;
			expected.addr_size = x.addr_size;
			expected.encoding = x.encoding;
			expected.sib = x.sib;
			expected.sib_index = x.sib_index;
			expected.sib_base = x.sib_base;
			expected.sib_scale = x.sib_scale;
			expected.op_count = x.op_count;
			cs_x86_op op{};
			if (x.op_count == 1) {
				op = x.operands[0];
				expected.operands[0].type = op.type;
				expected.operands[0].size = op.size;
				expected.operands[0].access = op.access;
				expected.operands[0].mem.base = op.mem.base;
				expected.operands[0].mem.index = op.mem.index;
				expected.operands[0].mem.scale = op.mem.scale;
			}
			if ((insn.id != X86_INS_NOP &&
			     insn.id != X86_INS_ENDBR32 &&
			     insn.id != X86_INS_ENDBR64) ||
			    insn.illegal || insn.is_alias ||
			    insn.usesAliasDetails ||
			    std::strlen(insn.mnemonic) >= 8 ||
			    std::strlen(insn.op_str) >= 48 || x.op_count > 1 ||
			    (x.op_count && op.type != X86_OP_MEM) ||
			    detail.regs_read_count || detail.regs_write_count ||
			    detail.groups_count > 4 ||
			    std::memcmp(&x, &expected, sizeof(x)))
				throw std::runtime_error(
					"unrepresentable alignment or entry record");
			uint8_t groups[4]{};
			std::copy_n(detail.groups, detail.groups_count, groups);
			std::cout << "\t\t{ " << insn.id << ", " << bytes.size()
				  << ", \"" << insn.mnemonic << "\", \""
				  << insn.op_str << "\", ";
			emit_array(std::cout, expected.prefix);
			std::cout << ", ";
			emit_array(std::cout, expected.opcode);
			std::cout << ", ";
			emit_array(std::cout, groups);
			for (unsigned v :
			     { unsigned(detail.groups_count),
			       unsigned(x.addr_size), unsigned(x.modrm),
			       unsigned(x.sib), unsigned(x.sib_base),
			       unsigned(x.sib_index), unsigned(x.sib_scale),
			       unsigned(x.encoding.modrm_offset),
			       unsigned(x.encoding.disp_offset),
			       unsigned(x.encoding.disp_size),
			       unsigned(op.size), unsigned(op.access),
			       unsigned(op.mem.base), unsigned(op.mem.index),
			       unsigned(op.mem.scale) })
				std::cout << ", " << v;
			std::cout << " },\n";
		}
		std::cout << "\t},\n";
	}
	std::cout << "};\n";
}

// RIP-relative loads from VEX.0F maps 10, 28 and 6F. Verify the complete
// Intel record before assigning a table entry for a prefix and vector length.
void emit_vex_rip_loads(Decoder &decoder)
{
	std::puts(
		"struct VexRipLoad {\n\tunsigned id; char mnemonic[12], address[20];\n\tuint8_t address_length, length_code, reg_size, mem_size, reg_access, mem_access, group_count, groups[4];\n};");
	std::puts("static const struct VexRipLoad vex_rip_loads[3][8] = {");
	for (unsigned opcode : { 0x10u, 0x28u, 0x6fu }) {
		std::puts("\t{");
		for (unsigned bits = 0; bits < 8; ++bits) {
			uint8_t bytes[] = { 0xc5,
					    uint8_t(0xf8 | bits),
					    uint8_t(opcode),
					    0x1d,
					    0x99,
					    0xba,
					    0xdc,
					    0xfe };
			unsigned id = decoder.decode(bytes, sizeof(bytes));
			if (!id) {
				std::puts("\t\t{ 0 },");
				continue;
			}
			const auto &insn = *decoder.insn;
			const auto &d = *insn.detail;
			const auto &x = d.x86;
			const auto &dest = x.operands[0],
				   &source = x.operands[1];
			const char *ptr = source.size == 4  ? "dword" :
					  source.size == 8  ? "qword" :
					  source.size == 16 ? "xmmword" :
					  source.size == 32 ? "ymmword" :
							      nullptr;
			const bool ymm = dest.reg == X86_REG_YMM3;
			if (!ptr || (!ymm && dest.reg != X86_REG_XMM3)) {
				std::puts("\t\t{ 0 },");
				continue;
			}
			cs_x86 expected{};
			std::copy_n(bytes, 2, expected.opcode);
			expected.addr_size = 8;
			expected.rex = 0x40;
			expected.modrm = bytes[3];
			expected.disp = -0x1234567;
			expected.op_count = 2;
			expected.encoding.modrm_offset = 3;
			expected.encoding.disp_offset = 4;
			expected.encoding.disp_size = 4;
			auto &reg = expected.operands[0];
			reg.type = X86_OP_REG;
			reg.reg = dest.reg;
			reg.size = dest.size;
			reg.access = CS_AC_WRITE;
			auto &mem = expected.operands[1];
			mem.type = X86_OP_MEM;
			mem.size = source.size;
			mem.access = CS_AC_READ;
			mem.mem.scale = 1;
			mem.mem.base = X86_REG_RIP;
			mem.mem.disp = expected.disp;
			std::string address =
				std::string(", ") + ptr + " ptr [rip";
			if (std::strlen(insn.mnemonic) >= 12 ||
			    std::strcmp(insn.mnemonic,
					cs_insn_name(decoder.handle, id)) ||
			    insn.illegal || insn.is_alias ||
			    insn.usesAliasDetails || d.groups_count > 4 ||
			    d.regs_read_count || d.regs_write_count ||
			    std::memcmp(&expected, &x, sizeof(x)) ||
			    insn.op_str != std::string(ymm ? "ymm3" : "xmm3") +
						   address + " - 0x1234567]") {
				std::puts("\t\t{ 0 },");
				continue;
			}
			Bytes4 groups{};
			std::copy_n(d.groups, d.groups_count, groups.begin());
			std::printf(
				"\t\t{ %s, \"%s\", \"%s\", %u, %u, %u, %u, %u, %u, %u, %s },\n",
				decoder.symbol(id).c_str(), insn.mnemonic,
				address.c_str(), unsigned(address.size()),
				unsigned(ymm), unsigned(dest.size),
				unsigned(source.size), unsigned(dest.access),
				unsigned(source.access),
				unsigned(d.groups_count),
				fields(groups).c_str());
		}
		std::puts("\t},");
	}
	std::puts("};");
}

struct VexRegisterOperand {
	x86_reg reg;
	uint8_t size;
};

std::string checked_vex_registers(Decoder &decoder, const uint8_t *bytes,
				  unsigned prefix, bool mode32,
				  unsigned rex_bits, unsigned ll,
				  const unsigned *numbers, unsigned reg_count,
				  bool immediate,
				  const VexRegisterOperand *selected = nullptr)
{
	unsigned id = decoder.decode(bytes, prefix + 2 + immediate);
	if (!id)
		return {};
	const cs_insn &insn = *decoder.insn;
	const cs_detail &detail = *insn.detail;
	const cs_x86 &x = detail.x86;
	if (insn.illegal || insn.is_alias || insn.usesAliasDetails ||
	    std::strlen(insn.mnemonic) >= 16 || detail.regs_read_count ||
	    detail.regs_write_count || detail.groups_count > 4 ||
	    x.op_count != reg_count + immediate)
		return {};
	cs_x86 expected{};
	std::memcpy(expected.opcode, bytes, prefix);
	expected.addr_size = mode32 ? 4 : 8;
	expected.rex = mode32 ? 0 : uint8_t(0x40 | rex_bits);
	expected.modrm = bytes[prefix + 1];
	expected.encoding.modrm_offset = uint8_t(prefix + 1);
	expected.op_count = uint8_t(reg_count + immediate);
	Bytes4 access{}, groups{};
	std::copy_n(detail.groups, detail.groups_count, groups.begin());
	std::string text;
	for (unsigned i = 0; i < reg_count; ++i) {
		auto &op = expected.operands[i];
		op.type = X86_OP_REG;
		if (selected) {
			op.reg = selected[i].reg;
			op.size = selected[i].size;
		} else {
			op.reg = x86_reg((ll ? X86_REG_YMM0 : X86_REG_XMM0) +
					 numbers[i]);
			op.size = uint8_t(16 << ll);
		}
		op.access = x.operands[i].access;
		access[i] = unsigned(op.access);
		if (i)
			text += ", ";
		if (selected) {
			text += cs_reg_name(decoder.handle, op.reg);
		} else {
			text += ll ? "ymm" : "xmm";
			text += std::to_string(numbers[i]);
		}
	}
	if (immediate) {
		const unsigned value = bytes[prefix + 2];
		auto &op = expected.operands[reg_count];
		op.type = X86_OP_IMM;
		op.imm = value;
		op.size = 1;
		op.access = x.operands[reg_count].access;
		access[reg_count] = unsigned(op.access);
		expected.encoding.imm_offset = uint8_t(prefix + 2);
		expected.encoding.imm_size = 1;
		char digits[8];
		std::snprintf(digits, sizeof(digits),
			      value <= 9 ? "%u" : "0x%x", value);
		text += ", ";
		text += digits;
	}
	if (text != insn.op_str || std::memcmp(&expected, &x, sizeof(x)))
		return {};
	return "{ " + decoder.symbol(id) + ", \"" + insn.mnemonic + "\", " +
	       std::to_string(detail.groups_count) + ", " + fields(groups) +
	       ", " + fields(access) + ", " + std::to_string(immediate) + " }";
}

using VexRegisterBanks = std::array<std::array<x86_reg, 16>, 4>;

VexRegisterBanks vex_register_banks(Decoder &decoder)
{
	VexRegisterBanks banks{};
	for (unsigned reg = 0; reg < 16; ++reg) {
		banks[0][reg] = x86_reg(X86_REG_XMM0 + reg);
		banks[1][reg] = x86_reg(X86_REG_YMM0 + reg);
		for (unsigned wide = 0; wide < 2; ++wide) {
			uint8_t mov[10] = { uint8_t(0x40 | (wide << 3) |
						    (reg >> 3)),
					    uint8_t(0xb8 | (reg & 7)) };
			if (!decoder.decode(mov, wide ? 10 : 6) ||
			    decoder.insn->detail->x86.operands[0].type !=
				    X86_OP_REG)
				throw std::runtime_error(
					"missing immediate MOV register");
			banks[2 + wide][reg] =
				decoder.insn->detail->x86.operands[0].reg;
		}
	}
	return banks;
}

using VexImmediateBytes = std::array<uint8_t, 6>;

VexImmediateBytes vex_immediate_bytes(unsigned opcode, unsigned wlpp,
				      unsigned reg, unsigned src, unsigned rm,
				      unsigned x, unsigned imm)
{
	const unsigned rxb = ((reg >> 3) << 2) | x | (rm >> 3);
	return { 0xc4,
		 uint8_t(((7 ^ rxb) << 5) | 3),
		 uint8_t(((wlpp & 8) << 4) | ((15 ^ src) << 3) | (wlpp & 7)),
		 uint8_t(opcode),
		 uint8_t(0xc0 | ((reg & 7) << 3) | (rm & 7)),
		 uint8_t(imm) };
}

// A row describes two or three registers plus an unsigned imm8. The source
// fields (ModR/M.reg, vvvv, ModR/M.r/m) and register classes are independent.
std::string vex_mixed_immediate_row(Decoder &decoder,
				    const VexRegisterBanks &banks, bool mode32,
				    unsigned opcode, unsigned wlpp)
{
	constexpr unsigned widths[] = { 16, 32, 4, 8 };
	unsigned sample_src = 2;
	auto sample =
		vex_immediate_bytes(opcode, wlpp, 3, sample_src, 1, 0, 0x80);
	if (!decoder.decode(sample.data(), sample.size())) {
		sample_src = 0;
		sample = vex_immediate_bytes(opcode, wlpp, 3, 0, 1, 0, 0x80);
		if (!decoder.decode(sample.data(), sample.size()))
			return {};
	}
	const cs_x86 &x = decoder.insn->detail->x86;
	if (x.op_count < 3 || x.op_count > 4 ||
	    x.operands[x.op_count - 1].type != X86_OP_IMM)
		return {};
	const unsigned reg_count = x.op_count - 1;
	const std::array<unsigned, 3> numbers = { 3, sample_src, 1 };
	std::array<unsigned, 3> operands{};
	bool uses_vvvv = false;
	for (unsigned i = 0; i < reg_count; ++i) {
		const cs_x86_op &op = x.operands[i];
		if (op.type != X86_OP_REG)
			return {};
		bool found = false;
		for (unsigned source = 0; source < numbers.size(); ++source) {
			for (unsigned bank = 0; bank < banks.size(); ++bank) {
				if (banks[bank][numbers[source]] == op.reg &&
				    widths[bank] == op.size) {
					operands[i] = source * 4 + bank;
					uses_vvvv |= source == 1;
					found = true;
				}
			}
		}
		if (!found)
			return {};
	}
	const auto probe = [&](unsigned reg, unsigned src, unsigned rm,
			       unsigned xbit, unsigned imm) {
		const auto bytes = vex_immediate_bytes(opcode, wlpp, reg, src,
						       rm, xbit, imm);
		const unsigned rxb = ((reg >> 3) << 2) | xbit | (rm >> 3);
		const unsigned ids[] = { reg, src, rm };
		VexRegisterOperand selected[3]{};
		for (unsigned i = 0; i < reg_count; ++i) {
			const unsigned bank = operands[i] & 3;
			selected[i] = { banks[bank][ids[operands[i] >> 2]],
					uint8_t(widths[bank]) };
		}
		return checked_vex_registers(decoder, bytes.data(), 3, mode32,
					     (wlpp & 8) | rxb, 0, nullptr,
					     reg_count, true, selected);
	};
	const auto row = probe(3, uses_vvvv ? 2 : 0, 1, 0, 0x80);
	if (row.empty())
		return {};
	const unsigned limit = mode32 ? 8 : 16;
	for (unsigned value = 0; value < 256; ++value)
		if (probe(limit - 1, uses_vvvv ? limit - 2 : 0, 0, 0, value) !=
		    row)
			return {};
	for (unsigned reg = 0; reg < limit; ++reg)
		for (unsigned src = 0; src < (uses_vvvv ? limit : 1); ++src)
			for (unsigned rm = 0; rm < limit; ++rm)
				for (unsigned xb = 0; xb < (mode32 ? 1 : 3);
				     xb += 2)
					if (probe(reg, src, rm, xb,
						  (31 * reg + 13 * src + rm) &
							  255) != row)
						return {};
	return "{ " + row + ", { " + std::to_string(operands[0]) + ", " +
	       std::to_string(operands[1]) + ", " +
	       std::to_string(operands[2]) + " }, " +
	       std::to_string(reg_count) + ", " +
	       (uses_vvvv ? "true" : "false") + " }";
}

void emit_vex_mixed_immediates(Decoder &decoder64)
{
	Decoder decoder32(CS_MODE_32);
	const auto banks = vex_register_banks(decoder64);
	constexpr unsigned opcodes[] = { 0x00, 0x01, 0x14, 0x15, 0x16, 0x17,
					 0x18, 0x19, 0x38, 0x39, 0xf0 };
	using PrefixRows = std::array<unsigned, 16>;
	std::vector<std::string> rows;
	std::vector<PrefixRows> prefixes(1);
	std::array<std::array<unsigned, 256>, 2> plans{};
	for (unsigned wide = 0; wide < 2; ++wide) {
		for (auto opcode : opcodes) {
			PrefixRows p{};
			for (unsigned key = 0; key < p.size(); ++key) {
				const auto row = vex_mixed_immediate_row(
					wide ? decoder64 : decoder32, banks,
					!wide, opcode, key);
				if (row.empty())
					continue;
				const auto it = std::find(rows.begin(),
							  rows.end(), row);
				p[key] = unsigned(it - rows.begin()) + 1;
				if (it == rows.end())
					rows.push_back(row);
			}
			const auto it =
				std::find(prefixes.begin(), prefixes.end(), p);
			plans[wide][opcode] = unsigned(it - prefixes.begin());
			if (it == prefixes.end())
				prefixes.push_back(p);
		}
	}
	if (!plans[0][0x38] || !plans[1][0x18] || !plans[1][0xf0] ||
	    rows.size() > UINT8_MAX || prefixes.size() > UINT8_MAX + 1u)
		throw std::runtime_error(
			"unrepresentable VEX register-immediate plans");
	std::puts(
		"/* Generated by x86_vector_output.cpp --vex-register-immediates. */");
	std::puts(
		"static const struct VexRegisterImmediateRow vex_immediate_rows[] = {");
	for (const auto &row : rows)
		std::printf("\t%s,\n", row.c_str());
	std::puts("};\nstatic const uint8_t vex_immediate_prefixes[][16] = {");
	for (const auto &p : prefixes) {
		std::printf("\t{");
		for (auto x : p)
			std::printf(" %u,", x);
		std::puts(" },");
	}
	std::puts("};\nstatic const uint8_t vex_immediate_opcodes[2][256] = {");
	for (const auto &map : plans) {
		std::puts("\t{");
		for (unsigned i = 0; i < map.size(); i += 16) {
			std::printf("\t\t");
			for (unsigned j = 0; j < 16; ++j)
				std::printf("%s%u,", j ? " " : "", map[i + j]);
			std::putchar('\n');
		}
		std::puts("\t},");
	}
	std::puts("};");
	std::fprintf(stderr,
		     "%zu VEX register-immediate rows, %zu prefix plans\n",
		     rows.size(), prefixes.size() - 1);
}

// Match ordinary NDS register operands against the complete canonical record.
// Opcodes with aliases, exceptional register sizes or immediate-dependent text
// keep using the general decoder.
std::string vex_register_row(Decoder &decoder, unsigned map, unsigned opcode,
			     unsigned w, unsigned ll, unsigned rxb,
			     unsigned dst, unsigned src, unsigned rm,
			     bool short_prefix, bool immediate, unsigned value,
			     bool group_shift = false, bool mode32 = false)
{
	const unsigned prefix = short_prefix ? 2 : 3;
	uint8_t bytes[6] = {};
	bytes[0] = short_prefix ? 0xc5 : 0xc4;
	bytes[1] = uint8_t((~rxb & 7) << 5 | map);
	bytes[prefix - 1] = uint8_t((short_prefix ? (~rxb & 4) << 5 : w << 7) |
				    (~src & 15) << 3 | ll << 2 | 1);
	bytes[prefix] = uint8_t(opcode);
	bytes[prefix + 1] = uint8_t(0xc0 | dst << 3 | rm);
	bytes[prefix + 2] = uint8_t(value);
	const unsigned reg_count = group_shift ? 2 : 3;
	const unsigned numbers[] = { group_shift ? src : dst | ((rxb & 4) << 1),
				     group_shift ? rm | ((rxb & 1) << 3) : src,
				     rm | ((rxb & 1) << 3) };
	return checked_vex_registers(decoder, bytes, prefix, mode32,
				     (w << 3) | rxb, ll, numbers, reg_count,
				     immediate);
}

// VEX groups 12-14 encode the operation in ModR/M.reg, the destination
// in vvvv and the only source register in ModR/M.r/m.
void emit_vex_shifts(Decoder &decoder)
{
	Decoder decoder32(CS_MODE_32);
	unsigned plans[3][8][4] = {};
	std::vector<std::string> rows;
	for (unsigned op = 0x71; op <= 0x73; ++op) {
		for (unsigned group = 0; group < 8; ++group) {
			for (unsigned wl = 0; wl < 4; ++wl) {
				auto probe = [&](unsigned k,
						 bool short_prefix) {
					return vex_register_row(
						decoder, 1, op, wl >> 1, wl & 1,
						short_prefix ? ((k >> 3) & 4) :
							       ((k >> 2) & 7),
						group, k & 15, (k >> 1) & 7,
						short_prefix, true, k, true);
				};
				const std::string value = probe(0, false);
				if (value.empty())
					continue;
				bool valid = true;
				for (unsigned k = 0; k < 256 && valid; ++k)
					valid = probe(k, false) == value &&
						(wl >= 2 ||
						 probe(k, true) == value);
				if (valid && wl < 2) {
					for (unsigned k = 0; k < 512; ++k)
						if (vex_register_row(
							    decoder32, 1, op, 0,
							    wl, 0, group,
							    (k >> 3) & 7, k & 7,
							    true, true, k & 255,
							    true,
							    true) != value)
							throw std::runtime_error(
								"32-bit VEX shift row differs");
				}
				if (!valid)
					continue;
				auto index = static_cast<unsigned>(
					std::find(rows.begin(), rows.end(),
						  value) -
					rows.begin());
				if (index == rows.size())
					rows.push_back(value);
				plans[op - 0x71][group][wl] = index + 1;
			}
		}
	}
	if (!plans[2][7][0] || !plans[2][3][1] || rows.size() > UINT8_MAX)
		throw std::runtime_error(
			"missing VEX byte-shift register rows");
	std::puts(
		"static const struct VectorOutputRow vex_shift_rows[] = { { 0 },");
	for (const auto &row : rows)
		std::printf("\t%s,\n", row.c_str());
	std::puts("};\nstatic const uint8_t vex_shift_plans[3][8][4] = {");
	for (const auto &op : plans) {
		std::puts("\t{");
		for (const auto &group : op)
			std::printf("\t\t{ %u, %u, %u, %u },\n", group[0],
				    group[1], group[2], group[3]);
		std::puts("\t},");
	}
	std::puts("};");
	std::fprintf(stderr, "%zu VEX immediate shift rows\n", rows.size());
}

void emit_vex_registers(Decoder &decoder)
{
	Decoder decoder32(CS_MODE_32);
	std::vector<std::string> rows;
	std::vector<Bytes4> widths(1);
	std::array<std::array<unsigned, 256>, 3> plans{};
	for (unsigned map = 1; map <= 3; ++map) {
		for (unsigned opcode = 0; opcode < 256; ++opcode) {
			Bytes4 by_width{};
			for (unsigned wl = 0; wl < 4; ++wl) {
				const unsigned w = wl >> 1, ll = wl & 1;
				auto probe = [&](unsigned rxb, unsigned dst,
						 unsigned src, unsigned rm,
						 bool short_prefix, bool imm,
						 unsigned value) {
					return vex_register_row(
						decoder, map, opcode, w, ll,
						rxb, dst, src, rm, short_prefix,
						imm, value);
				};
				bool imm = false;
				auto row = probe(0, 3, 2, 1, false, false, 0);
				if (row.empty()) {
					imm = true;
					row = probe(0, 3, 2, 1, false, true,
						    0x80);
				}
				if (row.empty())
					continue;
				bool uniform = true;
				for (unsigned n = 0; n < 256 && uniform; ++n) {
					const unsigned rxb = (n >> 3) & 7,
						       dst = (n >> 1) & 7;
					const unsigned src = n & 15,
						       rm = n >> 5;
					uniform = probe(rxb, dst, src, rm,
							false, imm, n) == row;
					if (uniform && map == 1 && !w)
						uniform = probe(rxb & 4, dst,
								src, rm, true,
								imm, n) == row;
				}
				if (uniform && map == 1 && !w) {
					for (unsigned k = 0; k < 512; ++k)
						if (vex_register_row(
							    decoder32, 1,
							    opcode, 0, ll, 0,
							    (k >> 6) & 7,
							    (k >> 3) & 7, k & 7,
							    true, imm, k & 255,
							    false, true) != row)
							throw std::runtime_error(
								"32-bit VEX register row differs");
				}
				if (!uniform)
					continue;
				const auto it = std::find(rows.begin(),
							  rows.end(), row);
				const unsigned index =
					unsigned(it - rows.begin()) + 1;
				if (index > UINT16_MAX)
					throw std::runtime_error(
						"too many VEX register rows");
				if (it == rows.end())
					rows.push_back(row);
				by_width[wl] = index;
			}
			const auto it = std::find(widths.begin(), widths.end(),
						  by_width);
			const unsigned plan = unsigned(it - widths.begin());
			if (plan > UINT8_MAX)
				throw std::runtime_error(
					"too many VEX register plans");
			if (it == widths.end())
				widths.push_back(by_width);
			plans[map - 1][opcode] = plan;
		}
	}
	if (!plans[0][0xef] || !plans[1][0xdc] || !plans[2][0x44])
		throw std::runtime_error(
			"missing the common VEX xor, AES or carry-less multiply form");
	std::puts(
		"static const struct VectorOutputRow vex_register_rows[] = {\n\t{ 0 },");
	for (const auto &row : rows)
		std::printf("\t%s,\n", row.c_str());
	std::printf("};\nstatic const %s vex_register_widths[][4] = {\n",
		    rows.size() <= UINT8_MAX ? "uint8_t" : "uint16_t");
	for (const auto &row : widths)
		std::printf("\t%s,\n", fields(row).c_str());
	std::puts("};\nstatic const uint8_t vex_register_plans[3][256] = {");
	for (const auto &map : plans) {
		std::puts("\t{");
		for (unsigned i = 0; i < map.size(); i += 16) {
			std::printf("\t\t");
			for (unsigned j = 0; j < 16; ++j)
				std::printf("%s%u,", j ? " " : "", map[i + j]);
			std::putchar('\n');
		}
		std::puts("\t},");
	}
	std::puts("};");
	std::fprintf(stderr, "%zu VEX register rows, %zu opcode plans\n",
		     rows.size(), widths.size() - 1);
}
void emit_evex_transfer_scan(Decoder &decoder)
{
	// The pair of directions must have the same public ID for every
	// admitted register, ModR/M and SIB combination.
	struct TransferForm {
		uint8_t map, pp, load, store;
	};
	constexpr TransferForm transfers[] = {
		{ 2, 1, 0x1a, 0 },       // Broadcast from memory only
		{ 1, 1, 0x6f, 0x7f }, { 1, 2, 0x6f, 0x7f },
		{ 1, 3, 0x6f, 0x7f },
		{ 1, 0, 0x10, 0x11 }, { 1, 1, 0x10, 0x11 },
		{ 1, 0, 0x28, 0x29 }, { 1, 1, 0x28, 0x29 },
	};
	std::puts("static const uint16_t evex_transfer_scan_ids[][2][3]\n\tX86_EVEX_SECTION(X86_EVEX_TRANSFER_RODATA) = {");
	for (const auto &form : transfers) {
		if (form.load == 0x10 && !form.pp)
			std::puts("#ifdef X86_EVEX_BATCH_PACKED");
		std::puts("\t{");
		for (unsigned w = 0; w < 2; ++w) {
			std::printf("\t\t{ ");
			for (unsigned ll = 0; ll < 3; ++ll) {
				const unsigned pp = form.pp, map = form.map;
				uint8_t bytes[11] = {
					0x62, uint8_t(0xf0 | map),
					uint8_t(0x7c | pp | w << 7),
					uint8_t(8 | ll << 5),
					form.load, 0x58, 0x80
				};
				unsigned id = decoder.decode(bytes, 7);
				if (id > UINT16_MAX)
					throw std::runtime_error("EVEX transfer ID exceeds uint16_t");
				if (id) {
					for (auto opcode : { form.load, form.store }) {
						if (!opcode)
							continue;
						bytes[4] = opcode;
						for (unsigned ext = 0; ext < 16; ++ext) {
							bytes[1] = uint8_t(ext << 4 | map);
							for (unsigned modrm = 0; modrm < (form.store ? 256u : 192u); ++modrm) {
								bytes[5] = uint8_t(modrm);
								const unsigned mod = modrm >> 6, rm = modrm & 7;
								const bool sib = mod < 3 && rm == 4;
								for (unsigned address = 0; address < (sib ? 256u : 1u); ++address) {
									unsigned length = 6;
									if (sib)
										bytes[length++] = uint8_t(address);
									unsigned displacement = 0;
									if (mod == 1)
										displacement = 1;
									else if (mod == 2 || (mod == 0 && (sib ? (address & 7) == 5 : rm == 5)))
										displacement = 4;
									for (unsigned j = 0; j < displacement; ++j)
										bytes[length++] = uint8_t(0x81 + j * 37);
									if (decoder.decode(bytes, length) != id)
										throw std::runtime_error("EVEX transfer ID depends on address or register fields");
								}
							}
						}
					}
				}
				std::printf("%s%s", ll ? ", " : "", decoder.symbol(id).c_str());
			}
			std::puts(" },");
		}
		std::puts("\t},");
	}
	std::puts("#endif\n};");
	std::fprintf(stderr, "%llu canonical EVEX transfer probes\n", static_cast<unsigned long long>(decoder.probes));
}

void emit_evex_scan(Decoder &decoder, const std::map<unsigned, WidthRows> &ids)
{
	std::array<unsigned, 256> index{};
	std::map<unsigned, Form> descriptions;
	for (const auto &form : forms) {
		const unsigned key = form.map << 8 | form.opcode;
		if (form.map < 1 || form.map > 3 ||
		    form.extract != X86_EVEX_REGISTER_EXTRACT(key))
			throw std::runtime_error("unsupported EVEX scan form");
		descriptions.emplace(key, form);
	}
	unsigned plan = 0;
	for (const auto &[key, widths] : ids) {
		(void)widths;
		if (index[key & 255] || ++plan > UINT8_MAX)
			throw std::runtime_error("EVEX scan opcode plan collision");
		index[key & 255] = plan;
	}
	if (index[0x6f] || index[0x7f] || index[0x1a] || index[0x10] ||
	    index[0x11] || index[0x28] || index[0x29] || plan >= 128)
		throw std::runtime_error("EVEX transfer opcode plan collision");
	index[0x6f] = index[0x7f] = 128;
	index[0x1a] = 129;
	index[0x10] = index[0x11] = 130;
	index[0x28] = index[0x29] = 131;
	std::puts("enum { EVEX_SCAN_RESERVED_SOURCE = 128 };\nenum { EVEX_SCAN_MOVE = 128, EVEX_SCAN_BROADCAST = 129 };\n#ifdef X86_EVEX_BATCH_PACKED\nenum { EVEX_SCAN_PACKED = 130, EVEX_SCAN_ALIGNED = 131 };\n#else\nenum { EVEX_SCAN_PACKED = 0, EVEX_SCAN_ALIGNED = 0 };\n#endif");
	std::puts("struct EvexScanPlan {\n\tuint8_t map, length_flags;\n\tuint16_t ids[2][3];\n};");
	std::puts("static const struct EvexScanPlan evex_scan_plans[]\n\tX86_EVEX_SECTION(X86_EVEX_SCAN_RODATA) = {\n\t{ 0 },");
	for (const auto &[key, widths] : ids) {
		const auto &form = descriptions.at(key);
		std::printf("\t{ %u, %u%s, { ", form.map, 6 + form.immediate, form.extract ? " | EVEX_SCAN_RESERVED_SOURCE" : "");
		for (unsigned w = 0; w < 2; ++w) {
			std::printf("%s{ ", w ? ", " : "");
			for (unsigned ll = 0; ll < 3; ++ll) {
				if (widths[w][ll] > UINT16_MAX)
					throw std::runtime_error("EVEX scan ID exceeds uint16_t");
				std::printf("%s%s", ll ? ", " : "",
					    decoder.symbol(widths[w][ll]).c_str());
			}
			std::printf(" }");
		}
		std::puts(" } },");
	}
	std::puts("};\nstatic const uint8_t evex_scan_index[256]\n\tX86_EVEX_SECTION(X86_EVEX_SCAN_RODATA) = {");
	for (unsigned i = 0; i < index.size(); i += 16) {
		std::printf("\t");
		for (unsigned j = 0; j < 16; ++j)
			if (index[i+j] == 130 || index[i+j] == 131)
				std::printf("%s%s,", j ? " " : "", index[i+j] == 130 ? "EVEX_SCAN_PACKED" : "EVEX_SCAN_ALIGNED");
			else
				std::printf("%s%u,", j ? " " : "", index[i + j]);
		std::putchar('\n');
	}
	std::puts("};");
	emit_evex_transfer_scan(decoder);
	std::puts("static const uint8_t evex_transfer_lengths[32]\n\tX86_EVEX_SECTION(X86_EVEX_TRANSFER_RODATA) = {\n\t6, 6, 6, 6, 0, 10, 6, 6,\n\t7, 7, 7, 7, 8, 7, 7, 7,\n\t10, 10, 10, 10, 11, 10, 10, 10,\n\t6, 6, 6, 6, 6, 6, 6, 6,\n};");
}

// Derive the metadata and verify the complete operand record for the
// unmasked EVEX packed load and store forms with full-vector memory tuples.
void emit_evex_memory(Decoder &decoder)
{
	constexpr uint8_t opcodes[][2] = { { 0x6f, 0x7f },
					   { 0x10, 0x11 },
					   { 0x28, 0x29 } };
	// Each form requires the reserved vvvv field and its exact W and pp.
	struct FormPrefix {
		unsigned pair;
		uint8_t prefix;
	};
	constexpr FormPrefix forms[] = {
		{ 0, 0xfd }, { 0, 0xfe }, { 0, 0x7d }, { 0, 0x7e }, { 0, 0x7f },
		{ 0, 0xff }, { 1, 0x7c }, { 1, 0xfd }, { 2, 0x7c }, { 2, 0xfd },
	};
	// Zero in either index denotes an opcode or prefix handled by the general printer.
	std::array<unsigned, 256> opcode_index{};
	std::array<std::array<unsigned, 8>, 4> prefix_index{};
	for (unsigned pair = 0; pair < 3; ++pair)
		for (unsigned store = 0; store < 2; ++store)
			opcode_index[opcodes[pair][store]] =
				2 * (pair + 1) + store;
	for (unsigned i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i) {
		const auto &form = forms[i];
		const auto key = ((form.prefix >> 5) & 4) | (form.prefix & 3);
		prefix_index[form.pair + 1][key] = i + 1;
	}
	std::puts(
		"const uint8_t x86_evex_memory_opcodes[256] X86_EVEX_MEMORY_DATA = {");
	for (unsigned i = 0; i < opcode_index.size(); i += 16) {
		std::printf("\t");
		for (unsigned j = 0; j < 16; ++j)
			std::printf("%s%u,", j ? " " : "", opcode_index[i + j]);
		std::putchar('\n');
	}
	std::puts(
		"};\nconst uint8_t x86_evex_memory_prefixes[][8] X86_EVEX_MEMORY_DATA = {");
	for (const auto &prefixes : prefix_index) {
		std::printf("\t{");
		for (auto plan : prefixes)
			std::printf(" %u,", plan);
		std::puts(" },");
	}
	std::puts("};");
	std::puts(
		"const struct EvexMemoryOutputRow x86_evex_memory_rows[][2][3] X86_EVEX_MEMORY_DATA = {");
	for (const auto &form : forms) {
		std::puts("\t{");
		for (unsigned store = 0; store < 2; ++store) {
			std::puts("\t\t{");
			for (unsigned ll = 0; ll < 3; ++ll) {
				uint8_t bytes[] = { 0x62,
						    0xf1,
						    form.prefix,
						    uint8_t(ll << 5 | 8),
						    opcodes[form.pair][store],
						    0x58,
						    1 };
				unsigned id =
					decoder.decode(bytes, sizeof(bytes));
				if (!id)
					throw std::runtime_error(
						"missing EVEX packed move memory form");
				const auto &insn = *decoder.insn;
				const auto &d = *insn.detail;
				if (insn.illegal || insn.is_alias ||
				    insn.usesAliasDetails ||
				    std::strlen(insn.mnemonic) >= 16 ||
				    d.regs_read_count || d.regs_write_count ||
				    d.groups_count > 4)
					throw std::runtime_error(
						"unexpected EVEX packed move metadata");
				cs_x86 x{};
				std::copy_n(bytes, 4, x.opcode);
				x.rex = uint8_t(0x40 | (form.prefix >> 7) << 3);
				x.addr_size = 8;
				x.modrm = bytes[5];
				x.disp = 16 << ll;
				x.encoding.modrm_offset = 5;
				x.encoding.disp_offset = 6;
				x.encoding.disp_size = 1;
				x.op_count = 2;
				const x86_reg bases[] = { X86_REG_XMM0,
							  X86_REG_YMM0,
							  X86_REG_ZMM0 };
				auto &reg = x.operands[store];
				reg.type = X86_OP_REG;
				reg.reg = x86_reg(bases[ll] + 3);
				reg.size = uint8_t(16 << ll);
				reg.access = d.x86.operands[store].access;
				auto &mem = x.operands[!store];
				mem.type = X86_OP_MEM;
				mem.size = reg.size;
				mem.access = d.x86.operands[!store].access;
				mem.mem.base = X86_REG_RAX;
				mem.mem.scale = 1;
				mem.mem.disp = x.disp;
				const std::string name =
					std::string(ll == 2 ? "zmm" :
						    ll == 1 ? "ymm" :
							      "xmm");
				char address[64];
				std::snprintf(address, sizeof(address),
					      "%sword ptr [rax + 0x%x]",
					      name.c_str(), 16 << ll);
				const std::string text =
					store ? std::string(address) + ", " +
							name + "3" :
						name + "3, " + address;
				if (text != insn.op_str ||
				    std::memcmp(&x, &d.x86, sizeof(x)))
					throw std::runtime_error(
						"unexpected EVEX packed move record");
				Bytes4 groups{};
				std::copy_n(d.groups, d.groups_count,
					    groups.begin());
				std::printf(
					"\t\t\t{ %s, \"%s\", %u, %s, { %u, %u } },\n",
					decoder.symbol(id).c_str(),
					insn.mnemonic, unsigned(d.groups_count),
					fields(groups).c_str(),
					unsigned(x.operands[0].access),
					unsigned(x.operands[1].access));
			}
			std::puts("\t\t},");
		}
		std::puts("\t},");
	}
	std::puts("};");
}

// Admit only ordinary 32-bit base-memory records reproduced in full by the
// compact writer. Prefixes, SIB, absolute addresses and exceptional widths keep
// their canonical path.
std::string vex32_memory_record(Decoder &decoder, unsigned opcode, unsigned pp,
				unsigned ll, unsigned dst, unsigned src,
				unsigned base, unsigned mod, int32_t disp)
{
	const unsigned disp_size = mod == 2 ? 4 : mod;
	uint8_t bytes[8] = { 0xc5,
			     uint8_t(0x80 | ((~src & 15) << 3) | ll << 2 | pp),
			     uint8_t(opcode),
			     uint8_t(mod << 6 | dst << 3 | base) };
	for (unsigned i = 0; i < disp_size; ++i)
		bytes[4 + i] = uint8_t(uint32_t(disp) >> (8 * i));
	unsigned id = decoder.decode(bytes, 4 + disp_size);
	if (!id)
		return {};
	const auto &insn = *decoder.insn;
	const auto &d = *insn.detail;
	const auto &actual = d.x86;
	if (insn.illegal || insn.is_alias || insn.usesAliasDetails ||
	    std::strlen(insn.mnemonic) >= 16 || d.regs_read_count ||
	    d.regs_write_count || d.groups_count > 4)
		return {};
	unsigned form;
	if (actual.op_count == 3 && actual.operands[0].type == X86_OP_REG &&
	    actual.operands[1].type == X86_OP_REG &&
	    actual.operands[2].type == X86_OP_MEM)
		form = 0;
	else if (actual.op_count == 2 &&
		 actual.operands[0].type == X86_OP_REG &&
		 actual.operands[1].type == X86_OP_MEM)
		form = 1;
	else if (actual.op_count == 2 &&
		 actual.operands[0].type == X86_OP_MEM &&
		 actual.operands[1].type == X86_OP_REG)
		form = 2;
	else
		return {};
	if (form && src)
		return {};
	const x86_reg gprs[] = { X86_REG_EAX, X86_REG_ECX, X86_REG_EDX,
				 X86_REG_EBX, X86_REG_ESP, X86_REG_EBP,
				 X86_REG_ESI, X86_REG_EDI };
	cs_detail expected{};
	expected.groups_count = d.groups_count;
	std::copy_n(d.groups, d.groups_count, expected.groups);
	auto &x = expected.x86;
	std::memcpy(x.opcode, bytes, 2);
	x.addr_size = 4;
	x.modrm = bytes[3];
	x.encoding.modrm_offset = 3;
	x.disp = disp;
	if (disp_size) {
		x.encoding.disp_offset = 4;
		x.encoding.disp_size = uint8_t(disp_size);
	}
	x.op_count = actual.op_count;
	const unsigned memory = form == 0 ? 2 : form == 1 ? 1 : 0;
	Bytes4 access{}, groups{};
	std::copy_n(d.groups, d.groups_count, groups.begin());
	std::string text;
	for (unsigned i = 0; i < x.op_count; ++i) {
		if (i)
			text += ", ";
		auto &op = x.operands[i];
		op.size = uint8_t(16u << ll);
		op.access = actual.operands[i].access;
		access[i] = unsigned(op.access);
		if (i == memory) {
			op.type = X86_OP_MEM;
			op.mem.base = gprs[base];
			op.mem.scale = 1;
			op.mem.disp = disp;
			text += ll ? "ymmword ptr [" : "xmmword ptr [";
			text += cs_reg_name(decoder.handle, gprs[base]);
			if (disp) {
				const auto magnitude = uint32_t(
					disp < 0 ? -int64_t(disp) : disp);
				char digits[16];
				std::snprintf(digits, sizeof(digits),
					      magnitude <= 9 ? "%u" : "0x%x",
					      magnitude);
				text += disp < 0 ? " - " : " + ";
				text += digits;
			}
			text += ']';
		} else {
			const unsigned number = form == 0 && i == 1 ? src : dst;
			op.type = X86_OP_REG;
			op.reg = x86_reg((ll ? X86_REG_YMM0 : X86_REG_XMM0) +
					 number);
			text += ll ? "ymm" : "xmm";
			text += std::to_string(number);
		}
	}
	if (text != insn.op_str ||
	    std::memcmp(&expected, &d,
			offsetof(cs_detail, x86) + sizeof(cs_x86)))
		return {};
	return "{ " + decoder.symbol(id) + ", \"" + insn.mnemonic + "\", " +
	       std::to_string(d.groups_count) + ", " + fields(groups) + ", " +
	       fields(access) + ", " + std::to_string(form) + " }";
}

// Both VEX2 opcode directions share a public row for register-to-register moves.
void emit_vex32_moves(Decoder &decoder)
{
	std::puts("static const struct VectorOutputRow vex32_move_rows[2] = {");
	for (unsigned pp : { 1u, 2u }) {
		std::string row;
		for (unsigned ll : { 0u, 1u }) {
			for (unsigned opcode : { 0x6fu, 0x7fu }) {
				for (unsigned mr = 0xc0; mr <= 0xff; ++mr) {
					const unsigned reg = (mr >> 3) & 7,
						       rm = mr & 7;
					const uint8_t bytes[] = {
						0xc5,
						uint8_t(0xf8 | ll << 2 | pp),
						uint8_t(opcode), uint8_t(mr)
					};
					const unsigned operands[] = {
						opcode == 0x6f ? reg : rm,
						opcode == 0x6f ? rm : reg
					};
					const auto value =
						checked_vex_registers(
							decoder, bytes, 2, true,
							0, ll, operands, 2,
							false);
					if (value.empty() ||
					    (!row.empty() && row != value))
						throw std::runtime_error(
							"inconsistent i386 VEX2 register move");
					row = value;
				}
			}
		}
		std::printf("\t%s,\n", row.c_str());
	}
	std::puts("};");
}

void emit_vex32_memory()
{
	Decoder decoder(CS_MODE_32);
	std::vector<std::string> rows(1, "{ 0 }");
	unsigned plans[8][256] = {};
	for (unsigned selector = 0; selector < 8; ++selector) {
		const unsigned pp = selector & 3, ll = selector >> 2;
		for (unsigned opcode = 0; opcode < 256; ++opcode) {
			const auto row = vex32_memory_record(
				decoder, opcode, pp, ll, 0, 0, 0, 0, 0);
			if (row.empty())
				continue;
			const unsigned sources =
				decoder.insn->detail->x86.op_count == 3 ? 8 : 1;
			bool uniform = true;
			for (unsigned mod = 0; mod < 3 && uniform; ++mod)
				for (unsigned base = 0; base < 8 && uniform;
				     ++base) {
					if (base == 4 || (!mod && base == 5))
						continue;
					const std::vector<int32_t> disps =
						!mod ?
							std::vector<int32_t>{
								0
							} :
						mod == 1 ?
							std::vector<int32_t>{
								0, 9, -1, -128,
								127
							} :
							std::vector<int32_t>{
								0,
								9,
								-1,
								0x12345678,
								INT32_MIN,
								INT32_MAX
							};
					for (unsigned dst = 0;
					     dst < 8 && uniform; ++dst)
						for (unsigned src = 0;
						     src < sources && uniform;
						     ++src)
							for (int32_t disp :
							     disps)
								if (vex32_memory_record(
									    decoder,
									    opcode,
									    pp,
									    ll,
									    dst,
									    src,
									    base,
									    mod,
									    disp) !=
								    row) {
									uniform =
										false;
									break;
								}
				}
			if (!uniform)
				continue;
			auto pos = std::find(rows.begin(), rows.end(), row);
			if (pos == rows.end()) {
				plans[selector][opcode] = unsigned(rows.size());
				rows.push_back(row);
			} else
				plans[selector][opcode] =
					unsigned(pos - rows.begin());
		}
	}
	for (unsigned opcode : { 0x6fu, 0x7fu, 0xf5u, 0xfeu })
		if (!plans[5][opcode])
			throw std::runtime_error(
				"missing canonical VEX32 memory plan");
	std::puts(
		"/* Generated by suite/synctools/x86_vector_output.cpp --vex32-memory. */");
	std::puts("#ifdef X86_VEX32_REGISTER_MOVES");
	emit_vex32_moves(decoder);
	std::puts("#else");
	std::puts(
		"struct Vex32MemoryRow {\n\tuint16_t id;\n\tchar mnemonic[16];\n\tuint8_t group_count, groups[4], access[4], form;\n};\nstatic const struct Vex32MemoryRow vex32_memory_rows[] = {");
	for (const auto &row : rows)
		std::printf("\t%s,\n", row.c_str());
	std::puts("};");
	std::printf("static const %s vex32_memory_plans[8][256] = {\n",
		    rows.size() <= 256 ? "uint8_t" : "uint16_t");
	for (const auto &block : plans) {
		std::puts("\t{");
		for (unsigned i = 0; i < 256; i += 16) {
			std::printf("\t\t");
			for (unsigned j = 0; j < 16; ++j)
				std::printf("%u,%s", block[i + j],
					    j == 15 ? "" : " ");
			std::puts("");
		}
		std::puts("\t},");
	}
	std::puts("};");
	const x86_reg gprs[] = { X86_REG_EAX, X86_REG_ECX, X86_REG_EDX,
				 X86_REG_EBX, X86_REG_ESP, X86_REG_EBP,
				 X86_REG_ESI, X86_REG_EDI };
	std::puts(
		"static const struct X86SimpleRegister vex32_base_registers[] = {");
	for (auto reg : gprs) {
		const char *name = cs_reg_name(decoder.handle, reg);
		if (!name || std::strlen(name) != 3)
			throw std::runtime_error(
				"unexpected canonical base register name");
		std::printf("\t{ %u, 3, \"%s\" },\n", unsigned(reg), name);
	}
	std::puts("};");
	std::fprintf(stderr, "%zu VEX32 memory rows; %llu full-record probes\n",
		     rows.size() - 1,
		     static_cast<unsigned long long>(decoder.probes));
	std::puts("#endif");
}

enum class EvexRegisterOrder { Three, Pair, ReversePair, Rounded };

struct EvexRegisterRecord {
	unsigned id = 0;
	std::string mnemonic;
	Bytes4 groups{}, access{};
	unsigned group_count = 0;
};

bool observe_evex_registers(Decoder &decoder, unsigned map, unsigned opcode,
			    unsigned pp, unsigned w, unsigned rc, unsigned dst,
			    unsigned src, unsigned rm, EvexRegisterOrder order,
			    EvexRegisterRecord &row)
{
	const bool rounded = order == EvexRegisterOrder::Rounded;
	const bool pair = order == EvexRegisterOrder::Pair ||
			  order == EvexRegisterOrder::ReversePair;
	const unsigned count = pair ? 2 : 3;
	const unsigned ll = rounded ? 2 : rc;
	const uint8_t code[] = {
		0x62,
		uint8_t(map | ((dst & 8) ? 0 : 0x80) | ((rm & 16) ? 0 : 0x40) |
			((rm & 8) ? 0 : 0x20) | (~dst & 16)),
		uint8_t((w << 7) | ((~src & 15) << 3) | 4 | pp),
		uint8_t((rc << 5) | (rounded ? 0x10 : 0) |
			((src & 16) ? 0 : 8)),
		uint8_t(opcode),
		uint8_t(0xc0 | ((dst & 7) << 3) | (rm & 7))
	};
	const unsigned id = decoder.decode(code, sizeof(code));
	if (!id)
		return false;
	const cs_insn &insn = *decoder.insn;
	const cs_detail &detail = *insn.detail;
	if (insn.illegal || insn.is_alias || insn.usesAliasDetails ||
	    std::strlen(insn.mnemonic) >= 16 || detail.groups_count > 4)
		return false;
	if (!row.id) {
		row.id = id;
		row.mnemonic = insn.mnemonic;
		row.group_count = detail.groups_count;
		std::copy_n(detail.groups, row.group_count, row.groups.begin());
		for (unsigned n = 0; n < count; ++n)
			row.access[n] = detail.x86.operands[n].access;
	}
	const char *const endings[] = { ", {rn-sae}", ", {rd-sae}",
					", {ru-sae}", ", {rz-sae}" };
	const x86_avx_rm modes[] = { X86_AVX_RM_RN, X86_AVX_RM_RD,
				     X86_AVX_RM_RU, X86_AVX_RM_RZ };
	const bool reverse = order == EvexRegisterOrder::ReversePair;
	const unsigned numbers[] = { reverse ? rm : dst,
				     pair ? (reverse ? dst : rm) : src, rm };
	const char *const names[] = { "xmm", "ymm", "zmm" };
	const char *name = names[ll];
	char text[64];
	if (pair)
		std::snprintf(text, sizeof(text), "%s%u, %s%u", name,
			      numbers[0], name, numbers[1]);
	else
		std::snprintf(text, sizeof(text), "%s%u, %s%u, %s%u%s", name,
			      dst, name, src, name, rm,
			      rounded ? endings[rc] : "");
	if (row.id != id || row.mnemonic != insn.mnemonic ||
	    std::strcmp(text, insn.op_str))
		return false;
	cs_detail expected{};
	expected.groups_count = uint8_t(row.group_count);
	std::copy_n(row.groups.begin(), row.group_count, expected.groups);
	cs_x86 &x = expected.x86;
	std::memcpy(x.opcode, code, 4);
	x.modrm = code[5];
	x.rex = uint8_t(0x40 | (w << 3) | ((~unsigned(code[1]) >> 5) & 7));
	x.addr_size = 8;
	if (rounded) {
		x.avx_sae = true;
		x.avx_rm = modes[rc];
	}
	x.encoding.modrm_offset = 5;
	x.op_count = uint8_t(count);
	const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0, X86_REG_ZMM0 };
	for (unsigned n = 0; n < count; ++n) {
		auto &op = x.operands[n];
		op.type = X86_OP_REG;
		op.size = uint8_t(16u << ll);
		op.reg = x86_reg(bases[ll] + numbers[n]);
		op.access = cs_ac_type(row.access[n]);
	}
	return std::memcmp(&expected, &detail,
			   offsetof(cs_detail, x86) + sizeof(cs_x86)) == 0;
}

void emit_plain_evex_registers(Decoder &decoder)
{
	using Prefix = std::array<unsigned, 24>;
	std::array<std::array<unsigned, 256>, 3> plans{};
	std::vector<Prefix> prefixes(1);
	std::vector<std::string> rows;
	for (unsigned map = 1; map <= plans.size(); ++map) {
		for (unsigned opcode = 0; opcode < 256; ++opcode) {
			Prefix prefix{};
			for (unsigned key = 0; key < prefix.size(); ++key) {
				const unsigned w = key / 12, pp = key / 3 % 4,
					       ll = key % 3;
				for (auto order :
				     { EvexRegisterOrder::Three,
				       EvexRegisterOrder::Pair,
				       EvexRegisterOrder::ReversePair }) {
					EvexRegisterRecord row;
					auto same = [&](unsigned dst,
							unsigned src,
							unsigned rm) {
						return observe_evex_registers(
							decoder, map, opcode,
							pp, w, ll, dst, src, rm,
							order, row);
					};
					const bool three =
						order ==
						EvexRegisterOrder::Three;
					if (!same(3, three ? 2 : 0, 1))
						continue;
					// For a register pair vvvv and V' are reserved. All other
					// allowed EVEX bits enumerate the architectural registers.
					bool uniform = true;
					for (unsigned dst = 0;
					     dst < 32 && uniform; ++dst)
						for (unsigned src = 0;
						     src < (three ? 32u : 1u) &&
						     uniform;
						     ++src)
							for (unsigned rm = 0;
							     rm < 32 && uniform;
							     ++rm)
								uniform = same(
									dst,
									src,
									rm);
					if (!uniform)
						continue;
					const char *tag =
						three ? "EVEX_REGISTERS_THREE" :
						order == EvexRegisterOrder::Pair ?
							"EVEX_REGISTERS_PAIR" :
							"EVEX_REGISTERS_REVERSED";
					const std::string value =
						"{ { " +
						decoder.symbol(row.id) +
						", \"" + row.mnemonic + "\", " +
						std::to_string(
							row.group_count) +
						", " + fields(row.groups) +
						", " + fields(row.access) +
						", 0 }, " + tag + " }";
					const auto i = std::find(rows.begin(),
								 rows.end(),
								 value);
					prefix[key] =
						unsigned(i - rows.begin()) + 1;
					if (i == rows.end())
						rows.push_back(value);
					break;
				}
			}
			const auto i = std::find(prefixes.begin(),
						 prefixes.end(), prefix);
			plans[map - 1][opcode] = unsigned(i - prefixes.begin());
			if (i == prefixes.end())
				prefixes.push_back(prefix);
		}
	}
	if (rows.empty() || rows.size() > UINT16_MAX ||
	    prefixes.size() > UINT16_MAX || !plans[0][0x28] ||
	    !plans[0][0x58] || !plans[1][0xa8])
		throw std::runtime_error(
			"missing ordinary EVEX register plans");
	std::puts(
		"/* Generated by suite/synctools/x86_vector_output.cpp --plain-evex-registers. */");
	std::puts(
		"static const struct EvexRegisterOutput plain_evex_rows[] = {");
	for (const auto &v : rows)
		std::printf("\t%s,\n", v.c_str());
	std::printf("};\nstatic const %s plain_evex_opcodes[3][256] = {\n",
		    prefixes.size() <= 256 ? "uint8_t" : "uint16_t");
	for (const auto &map : plans) {
		std::puts("\t{");
		for (unsigned i = 0; i < map.size(); i += 16) {
			std::printf("\t\t");
			for (unsigned j = 0; j < 16; ++j)
				std::printf("%u,%s", map[i + j],
					    j == 15 ? "" : " ");
			std::puts("");
		}
		std::puts("\t},");
	}
	std::puts("};\nstatic const uint16_t plain_evex_prefixes[][24] = {");
	for (const auto &prefix : prefixes) {
		std::printf("\t{");
		for (auto k : prefix)
			std::printf(" %u,", k);
		std::puts(" },");
	}
	std::puts("};");
	std::fprintf(
		stderr,
		"%zu EVEX rows and %zu prefix plans from %llu canonical observations\n",
		rows.size(), prefixes.size() - 1,
		static_cast<unsigned long long>(decoder.probes));
}

/* A register row is reusable for RIP-relative memory only when the canonical
 * memory operands, text, access, groups and all other x86 fields agree. */
bool observe_evex_rip(Decoder &decoder, unsigned map, unsigned opcode,
		      unsigned pp, unsigned w, unsigned ll, unsigned dst,
		      unsigned src, unsigned xb, int32_t displacement,
		      const char *suffix, const EvexRegisterRecord &row)
{
	const uint32_t disp = uint32_t(displacement);
	const uint8_t code[] = {
		0x62,
		uint8_t(map | ((dst & 8) ? 0 : 0x80) | (xb << 5) | (~dst & 16)),
		uint8_t((w << 7) | ((~src & 15) << 3) | 4 | pp),
		uint8_t((ll << 5) | ((src & 16) ? 0 : 8)),
		uint8_t(opcode),
		uint8_t(((dst & 7) << 3) | 5),
		uint8_t(disp),
		uint8_t(disp >> 8),
		uint8_t(disp >> 16),
		uint8_t(disp >> 24)
	};
	if (decoder.decode(code, sizeof(code)) != row.id)
		return false;
	const auto &insn = *decoder.insn;
	const char *const names[] = { "xmm", "ymm", "zmm" };
	char text[80];
	std::snprintf(text, sizeof(text), "%s%u, %s%u, %sword ptr [rip%s]",
		      names[ll], dst, names[ll], src, names[ll], suffix);
	if (insn.illegal || insn.is_alias || insn.usesAliasDetails ||
	    row.mnemonic != insn.mnemonic || std::strcmp(insn.op_str, text))
		return false;
	cs_detail expected{};
	expected.groups_count = uint8_t(row.group_count);
	std::copy_n(row.groups.begin(), row.group_count, expected.groups);
	auto &x = expected.x86;
	std::memcpy(x.opcode, code, 4);
	x.rex = uint8_t(0x40 | (w << 3) | ((~unsigned(code[1]) >> 5) & 7));
	x.addr_size = 8;
	x.modrm = code[5];
	x.encoding.modrm_offset = 5;
	x.encoding.disp_offset = 6;
	x.encoding.disp_size = 4;
	x.disp = displacement;
	x.op_count = 3;
	const x86_reg bases[] = { X86_REG_XMM0, X86_REG_YMM0, X86_REG_ZMM0 };
	for (unsigned n = 0; n != 3; ++n) {
		auto &op = x.operands[n];
		op.size = uint8_t(16u << ll);
		op.access = cs_ac_type(row.access[n]);
		if (n == 2) {
			op.type = X86_OP_MEM;
			op.mem.base = X86_REG_RIP;
			op.mem.scale = 1;
			op.mem.disp = displacement;
		} else {
			op.type = X86_OP_REG;
			op.reg = x86_reg(bases[ll] + (n ? src : dst));
		}
	}
	return std::memcmp(&expected, insn.detail,
			   offsetof(cs_detail, x86) + sizeof(cs_x86)) == 0;
}

void emit_evex_rip_memory(Decoder &decoder)
{
	std::array<std::array<uint32_t, 256>, 3> masks{};
	unsigned forms = 0;
	for (unsigned map = 1; map <= masks.size(); ++map) {
		for (unsigned opcode = 0; opcode < 256; ++opcode) {
			for (unsigned key = 0; key < 24; ++key) {
				const unsigned w = key / 12, pp = key / 3 % 4,
					       ll = key % 3;
				EvexRegisterRecord row;
				if (!observe_evex_registers(
					    decoder, map, opcode, pp, w, ll, 3,
					    2, 1, EvexRegisterOrder::Three,
					    row))
					continue;
				auto same = [&](unsigned dst, unsigned src,
						unsigned xb, int32_t disp,
						const char *suffix) {
					return observe_evex_rip(decoder, map,
								opcode, pp, w,
								ll, dst, src,
								xb, disp,
								suffix, row);
				};
				if (!same(3, 2, 3, 0, "") ||
				    !same(31, 17, 0, -9, " - 9") ||
				    !same(11, 30, 2, 10, " + 0xa") ||
				    !same(16, 0, 1, INT32_MIN,
					  " - 0x80000000") ||
				    !same(0, 31, 3, INT32_MAX, " + 0x7fffffff"))
					continue;
				bool uniform = true;
				for (unsigned dst = 0; dst < 32 && uniform;
				     ++dst)
					for (unsigned src = 0;
					     src < 32 && uniform; ++src)
						for (unsigned xb = 0;
						     xb < 4 && uniform; ++xb)
							uniform = same(
								dst, src, xb,
								0x1234,
								" + 0x1234");
				if (uniform) {
					masks[map - 1][opcode] |= uint32_t(1)
								  << key;
					++forms;
				}
			}
		}
	}
	if (!masks[0][0xfe] || !masks[1][0xa8])
		throw std::runtime_error(
			"missing RIP-relative EVEX integer or floating-point rows");
	std::puts(
		"/* Generated by suite/synctools/x86_vector_output.cpp --evex-rip-memory. */");
	std::puts("static const uint32_t evex_rip_forms[3][256] = {");
	for (const auto &map : masks) {
		std::puts("\t{");
		for (unsigned i = 0; i < map.size(); i += 8) {
			std::printf("\t\t");
			for (unsigned j = 0; j < 8; ++j)
				std::printf("0x%06xu,%s", unsigned(map[i + j]),
					    j == 7 ? "" : " ");
			std::puts("");
		}
		std::puts("\t},");
	}
	std::puts("};");
	std::fprintf(
		stderr,
		"%u RIP-relative EVEX forms from %llu canonical observations\n",
		forms, static_cast<unsigned long long>(decoder.probes));
}

void emit_rounded_vectors(Decoder &decoder)
{
	using PrefixRow = std::array<unsigned, 8>;
	std::array<std::array<unsigned, 256>, 3> plans{};
	std::vector<PrefixRow> prefixes(1);
	std::vector<std::string> rows;
	std::vector<unsigned> public_ids;
	for (unsigned map = 1; map <= plans.size(); ++map) {
		for (unsigned opcode = 0; opcode < 256; ++opcode) {
			PrefixRow prefix{};
			for (unsigned key = 0; key < prefix.size(); ++key) {
				EvexRegisterRecord row;
				auto same = [&](unsigned rc, unsigned dst,
						unsigned src, unsigned rm) {
					return observe_evex_registers(decoder, map,
							       opcode, key & 3,
							       key >> 2, rc,
							       dst, src, rm,
							       EvexRegisterOrder::Rounded, row);
				};
				if (!same(0, 3, 2, 1))
					continue;
				bool uniform = true;
				for (unsigned rc = 0; rc < 4 && uniform; ++rc)
					for (unsigned n = 0;
					     n < 32768 && uniform; ++n)
						uniform = same(rc, n >> 10,
							       (n >> 5) & 31,
							       n & 31);
				if (!uniform)
					continue;
				const std::string value =
					"{ " + decoder.symbol(row.id) + ", \"" +
					row.mnemonic + "\", " +
					std::to_string(row.group_count) + ", " +
					fields(row.groups) + ", " +
					fields(row.access) + ", 0 }";
				const auto i = std::find(rows.begin(),
							 rows.end(), value);
				const unsigned idx =
					unsigned(i - rows.begin()) + 1;
				if (i == rows.end()) {
					rows.push_back(value);
					public_ids.push_back(row.id);
				}
				prefix[key] = idx;
			}
			const auto i = std::find(prefixes.begin(),
						 prefixes.end(), prefix);
			const unsigned idx = unsigned(i - prefixes.begin());
			if (i == prefixes.end())
				prefixes.push_back(prefix);
			plans[map - 1][opcode] = idx;
		}
	}
	if (!plans[0][0x58] || !plans[1][0xa8] || prefixes.size() > 256 ||
	    rows.size() > UINT8_MAX)
		throw std::runtime_error("invalid rounded EVEX register plans");
	std::puts("#ifdef X86_ROUNDED_SCAN_IDS\nstatic const uint16_t evex_rounded_ids[] = {\n\t0,");
	for (unsigned id : public_ids) {
		if (id > UINT16_MAX)
			throw std::runtime_error("rounded register public ID exceeds uint16_t");
		std::printf("\t%s,\n", decoder.symbol(id).c_str());
	}
	std::puts("};\n#else");
	std::puts(
		"static const struct VectorOutputRow evex_rounded_rows[] = {\n\t{ 0 },");
	for (const auto &row : rows)
		std::printf("\t%s,\n", row.c_str());
	std::puts("};\n#endif\nstatic const uint8_t evex_rounded_prefixes[][8] = {");
	for (const auto &p : prefixes) {
		std::printf("\t{");
		for (const auto v : p)
			std::printf(" %u,", v);
		std::puts(" },");
	}
	std::puts("};\nstatic const uint8_t evex_rounded_plans[3][256] = {");
	for (const auto &p : plans) {
		std::puts("\t{");
		for (unsigned n = 0; n < p.size(); n += 16) {
			std::printf("\t\t");
			for (unsigned k = 0; k < 16; ++k)
				std::printf("%s%u,", k ? " " : "", p[n + k]);
			std::putchar('\n');
		}
		std::puts("\t},");
	}
	std::puts("};");
	std::fprintf(stderr,
		     "%zu rounded EVEX register rows, %zu prefix plans\n",
		     rows.size(), prefixes.size() - 1);
}

void emit_evex_shifts(Decoder &decoder)
{
	std::vector<std::string> records;
	std::vector<unsigned> ids;
	unsigned plans[3][8][6] = {};
	for (unsigned op = 0; op < 3; ++op) {
		const Form form{ 1, 0x71 + op, true };
		for (unsigned group = 0; group < 8; ++group) {
			for (unsigned wl = 0; wl < 6; ++wl) {
				const auto row = pair_immediate_record(
					decoder, form, wl / 3, wl % 3, group);
				if (row.empty())
					continue;
				const auto it = std::find(records.begin(),
							  records.end(), row);
				plans[op][group][wl] =
					unsigned(it - records.begin()) + 1;
				if (it == records.end()) {
					records.push_back(row);
					ids.push_back(decoder.insn->id);
				}
			}
		}
	}
	if (records.size() > UINT8_MAX || !plans[2][3][2] || !plans[2][7][2])
		throw std::runtime_error(
			"missing EVEX byte shift or too many shift records");
	std::puts("#ifdef X86_SHIFT_SCAN_IDS\nstatic const uint16_t evex_shift_ids[] = {\n\t0,");
	for (unsigned id : ids) {
		if (id > UINT16_MAX)
			throw std::runtime_error("EVEX shift ID exceeds uint16_t");
		std::printf("\t%s,\n", decoder.symbol(id).c_str());
	}
	std::puts("};\n#else");
	std::puts(
		"static const struct VectorOutputRow evex_shift_rows[] = {");
	for (const auto &row : records)
		std::printf("\t%s,\n", row.c_str());
	std::puts(
		"};\n#endif\nstatic const uint8_t evex_shift_plans[3][8][6] = {");
	for (const auto &op : plans) {
		std::puts("\t{");
		for (const auto &group : op)
			std::printf("\t\t{ %u, %u, %u, %u, %u, %u },\n",
				    group[0], group[1], group[2], group[3],
				    group[4], group[5]);
		std::puts("\t},");
	}
	std::puts("};");
}

void emit_output(Decoder &decoder, bool scan_only)
{
	std::vector<std::string> records;
	std::map<unsigned, WidthRows> plans, scan_ids;
	for (const auto &form : forms) {
		auto &rows = plans[form.map << 8 | form.opcode];
		auto &ids = scan_ids[form.map << 8 | form.opcode];
		for (unsigned ll = 0; ll < 3; ++ll) {
			for (unsigned w = 0; w < 2; ++w) {
				auto row = output_record(decoder, form, w, ll);
				if (row.empty()) {
					rows[w][ll] = UINT8_MAX;
					ids[w][ll] = 0;
					continue;
				}
				ids[w][ll] = decoder.insn->id;
				const auto i = std::find(records.begin(),
							 records.end(), row);
				const auto index = static_cast<size_t>(
					i - records.begin());
				if (index >= UINT8_MAX)
					throw std::runtime_error(
						"too many EVEX output rows");
				rows[w][ll] = unsigned(index);
				if (i == records.end())
					records.push_back(row);
			}
		}
	}
	if (scan_only) {
		emit_evex_scan(decoder, scan_ids);
		return;
	}
	if (plans.at(0x339)[0][1] == UINT8_MAX ||
	    plans.at(0x33b)[1][2] == UINT8_MAX)
		throw std::runtime_error("missing EVEX extract register forms");
	std::puts("static const struct VectorOutputRow evex_output_rows[] = {");
	for (const auto &row : records)
		std::printf("\t%s,\n", row.c_str());
	std::puts(
		"};\nstatic const struct VectorOutputRow *evexOutputRow(unsigned key, unsigned w, unsigned ll)\n{\n\tswitch (key) {");
	for (auto &[key, rows] : plans) {
		std::printf(
			"\tcase 0x%x: {\n\t\tstatic const uint8_t rows[2][3] = { { %u, %u, %u }, { %u, %u, %u } };\n",
			key, rows[0][0], rows[0][1], rows[0][2], rows[1][0],
			rows[1][1], rows[1][2]);
		std::puts(
			"\t\treturn rows[w][ll] == UINT8_MAX ? NULL : &evex_output_rows[rows[w][ll]];\n\t}");
	}
	std::puts("\tdefault: return NULL;\n\t}\n}");
	emit_vex_indexed(decoder);
	emit_vex_registers(decoder);
	emit_vex_shifts(decoder);
	emit_broadcast_rows(decoder);
	emit_vex_rip_loads(decoder);
	Decoder padding32(CS_MODE_32);
	emit_padding_rows(padding32, decoder);
	emit_legacy_registers(decoder);
}
}

int main(int argc, char **argv)
{
	if (argc == 2 && !std::strcmp(argv[1], "--evex-rip-memory")) {
		Decoder decoder;
		emit_evex_rip_memory(decoder);
		return 0;
	}
	if (argc == 2 && !std::strcmp(argv[1], "--plain-evex-registers")) {
		Decoder decoder;
		emit_plain_evex_registers(decoder);
		return 0;
	}
	if (argc == 2 && !std::strcmp(argv[1], "--legacy-map38-registers")) {
		Decoder wide;
		std::puts("/* Generated by suite/synctools/x86_vector_output.cpp --legacy-map38-registers. */");
		emit_legacy_registers(wide, true);
		return 0;
	}
	if (argc == 2 && !std::strcmp(argv[1], "--legacy-register-immediates")) {
		Decoder decoder;
		emit_legacy_immediates(decoder);
		return 0;
	}
	if (argc == 2 && !std::strcmp(argv[1], "--evex-shifts")) {
		Decoder decoder;
		std::puts("/* Generated by suite/synctools/x86_vector_output.cpp --evex-shifts. */");
		emit_evex_shifts(decoder);
		std::fprintf(stderr, "%llu canonical EVEX shift probes\n",
			     static_cast<unsigned long long>(decoder.probes));
		return 0;
	}
	if (argc == 2 && !std::strcmp(argv[1], "--rounded-registers64")) {
		Decoder decoder;
		std::puts(
			"/* Generated by suite/synctools/x86_vector_output.cpp --rounded-registers64. */");
		emit_rounded_vectors(decoder);
		std::fprintf(stderr, "%llu ordinary decoder probes\n",
			     static_cast<unsigned long long>(decoder.probes));
		return 0;
	}
	if (argc == 2 && !std::strcmp(argv[1], "--vex32-memory")) {
		emit_vex32_memory();
		return 0;
	}
	if (argc == 2 && !std::strcmp(argv[1], "--vex-register-immediates")) {
		Decoder decoder;
		emit_vex_mixed_immediates(decoder);
		return 0;
	}
	if (argc == 2 && !std::strcmp(argv[1], "--evex-memory")) {
		Decoder decoder;
		std::puts(
			"/* Generated by suite/synctools/x86_vector_output.cpp --evex-memory. */");
		emit_evex_memory(decoder);
		return 0;
	}
	const bool scan_only = argc == 2 && !std::strcmp(argv[1], "--evex-scan");
	if (argc > 1 && !scan_only)
		throw std::runtime_error(
			"usage: x86_vector_output [--evex-scan|--evex-memory|--vex-register-immediates|--vex32-memory|--rounded-registers64|--evex-shifts|--plain-evex-registers|--legacy-register-immediates|--evex-rip-memory|--legacy-map38-registers]");
	Decoder decoder;
	std::puts("/* Generated by suite/synctools/x86_vector_output.cpp. */");
	emit_output(decoder, scan_only);
	std::fprintf(stderr, "%llu ordinary decoder probes\n",
		     static_cast<unsigned long long>(decoder.probes));
}

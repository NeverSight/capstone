/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

// Build against full x86 Capstone and redirect stdout to X86GenVectorOutput.inc.
#include <capstone/capstone.h>
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

// EVEX extracts have a narrower r/m destination, a full-width reg source,
// and a reserved vvvv field. Reconstruct the entire public record before
// admitting a width, including the ignored or effective W bit in REX.
std::string extract_record(Decoder &decoder, const Form &form, unsigned w,
			   unsigned ll)
{
	const unsigned dst_width = (form.opcode & 2) ? 1 : 0;
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
		return extract_record(decoder, form, w, ll);
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

// Describe only legacy 66 0F register pairs whose entire public x86 detail
// can be recovered from the prefix, opcode and ModR/M. Generate against
// the ordinary decoder so special encodings and aliases retain its behavior.
std::string legacy_register_row(Decoder &decoder, bool wide, unsigned rex,
				unsigned opcode, unsigned modrm, bool reverse)
{
	uint8_t bytes[5] = { 0x66, uint8_t(rex), 0x0f, uint8_t(opcode),
			     uint8_t(modrm) };
	const unsigned size = rex ? 5 : 4;
	if (!rex)
		std::memmove(bytes + 1, bytes + 2, 3);
	const unsigned id = decoder.decode(bytes, size);
	if (!id)
		return {};
	const cs_insn &insn = *decoder.insn;
	const auto &d = *insn.detail;
	const auto &x = d.x86;
	if (insn.is_alias || insn.usesAliasDetails || insn.illegal ||
	    std::strlen(insn.mnemonic) >= 16 || d.regs_read_count ||
	    d.regs_write_count || d.groups_count > 4 || x.op_count != 2)
		return {};
	const unsigned reg = ((modrm >> 3) & 7) + ((rex & 4) << 1);
	const unsigned rm = (modrm & 7) + ((rex & 1) << 3);
	const unsigned nums[] = { reverse ? rm : reg, reverse ? reg : rm };
	cs_x86 expected{};
	expected.prefix[2] = 0x66;
	expected.opcode[0] = 0x0f;
	expected.opcode[1] = uint8_t(opcode);
	expected.rex = uint8_t(rex);
	expected.addr_size = wide ? 8 : 4;
	expected.modrm = uint8_t(modrm);
	expected.encoding.modrm_offset = uint8_t(size - 1);
	expected.op_count = 2;
	Bytes4 access{}, groups{};
	std::copy_n(d.groups, d.groups_count, groups.begin());
	for (unsigned i = 0; i < 2; ++i) {
		auto &op = expected.operands[i];
		op.type = X86_OP_REG;
		op.reg = x86_reg(X86_REG_XMM0 + nums[i]);
		op.size = 16;
		op.access = x.operands[i].access;
		access[i] = unsigned(op.access);
	}
	const auto text = "xmm" + std::to_string(nums[0]) + ", xmm" +
			  std::to_string(nums[1]);
	if (text != insn.op_str || std::memcmp(&expected, &x, sizeof(x)))
		return {};
	return "{ " + decoder.symbol(id) + ", \"" + insn.mnemonic + "\", " +
	       std::to_string(d.groups_count) + ", " + fields(groups) + ", " +
	       fields(access) + ", 0 }";
}

void emit_legacy_registers(Decoder &wide)
{
	Decoder narrow(CS_MODE_32);
	std::vector<std::string> rows;
	std::array<unsigned, 256> plans{};
	for (unsigned opcode = 0; opcode < plans.size(); ++opcode) {
		bool reverse = false;
		auto row = legacy_register_row(narrow, false, 0, opcode, 0xd9,
					       reverse);
		if (row.empty()) {
			reverse = true;
			row = legacy_register_row(narrow, false, 0, opcode,
						  0xd9, reverse);
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
							reverse) != row) {
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
	if (!plans[0x6f] || !plans[0x7f] || !plans[0x61] || !plans[0xfe])
		throw std::runtime_error("missing SSE2 register forms");
	std::puts(
		"static const struct VectorOutputRow legacy_register_rows[] = {\n\t{ 0 },");
	for (const auto &row : rows)
		std::printf("\t%s,\n", row.c_str());
	std::puts(
		"};\n/* Low seven bits index legacy_register_rows; bit 7 reverses the operands. */\nstatic const uint8_t legacy_register_plans[256] = {");
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

// Match ordinary NDS register operands against the complete canonical record.
// Opcodes with aliases, exceptional register sizes or immediate-dependent text
// keep using the general decoder.
std::string vex_register_row(Decoder &decoder, unsigned map, unsigned opcode,
			     unsigned w, unsigned ll, unsigned rxb,
			     unsigned dst, unsigned src, unsigned rm,
			     bool short_prefix, bool immediate, unsigned value,
			     bool group_shift = false)
{
	const unsigned prefix = short_prefix ? 2 : 3;
	const unsigned length = prefix + 2 + immediate;
	uint8_t bytes[6] = {};
	bytes[0] = short_prefix ? 0xc5 : 0xc4;
	bytes[1] = uint8_t((~rxb & 7) << 5 | map);
	bytes[prefix - 1] = uint8_t((short_prefix ? (~rxb & 4) << 5 : w << 7) |
				    (~src & 15) << 3 | ll << 2 | 1);
	bytes[prefix] = uint8_t(opcode);
	bytes[prefix + 1] = uint8_t(0xc0 | dst << 3 | rm);
	bytes[prefix + 2] = uint8_t(value);
	unsigned id = decoder.decode(bytes, length);
	if (!id)
		return {};
	const cs_insn &insn = *decoder.insn;
	const cs_detail &detail = *insn.detail;
	const cs_x86 &x = detail.x86;
	if (insn.illegal || insn.is_alias || insn.usesAliasDetails ||
	    std::strlen(insn.mnemonic) >= 16 || detail.regs_read_count ||
	    detail.regs_write_count || detail.groups_count > 4 ||
	    x.op_count != (group_shift ? 2u : 3u) + immediate)
		return {};
	const unsigned reg_count = group_shift ? 2 : 3;
	const unsigned numbers[] = { group_shift ? src : dst | ((rxb & 4) << 1),
				     group_shift ? rm | ((rxb & 1) << 3) : src,
				     rm | ((rxb & 1) << 3) };
	cs_x86 expected{};
	std::memcpy(expected.opcode, bytes, prefix);
	expected.addr_size = 8;
	expected.rex = uint8_t(0x40 | w << 3 | rxb);
	expected.modrm = bytes[prefix + 1];
	expected.encoding.modrm_offset = uint8_t(prefix + 1);
	expected.op_count = uint8_t(reg_count + immediate);
	Bytes4 access{}, groups{};
	std::copy_n(detail.groups, detail.groups_count, groups.begin());
	std::string text;
	for (unsigned i = 0; i < reg_count; ++i) {
		auto &op = expected.operands[i];
		op.type = X86_OP_REG;
		op.reg = x86_reg((ll ? X86_REG_YMM0 : X86_REG_XMM0) +
				 numbers[i]);
		op.size = uint8_t(16 << ll);
		op.access = x.operands[i].access;
		access[i] = unsigned(op.access);
		if (i)
			text += ", ";
		text += ll ? "ymm" : "xmm";
		text += std::to_string(numbers[i]);
	}
	if (immediate) {
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

// VEX groups 12-14 encode the operation in ModR/M.reg, the destination
// in vvvv and the only source register in ModR/M.r/m.
void emit_vex_shifts(Decoder &decoder)
{
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
void emit_output(Decoder &decoder)
{
	std::vector<std::string> records;
	std::map<unsigned, WidthRows> plans;
	for (const auto &form : forms) {
		auto &rows = plans[form.map << 8 | form.opcode];
		for (unsigned ll = 0; ll < 3; ++ll) {
			for (unsigned w = 0; w < 2; ++w) {
				auto row = output_record(decoder, form, w, ll);
				if (row.empty()) {
					rows[w][ll] = UINT8_MAX;
					continue;
				}
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
	if (plans.at(0x339)[0][1] == UINT8_MAX ||
	    plans.at(0x33b)[1][2] == UINT8_MAX)
		throw std::runtime_error("missing EVEX extract register forms");
	std::puts(
		"struct VectorOutputRow {\n\tuint16_t id;\n\tchar mnemonic[16];\n\tuint8_t group_count, groups[4], access[4], immediate;\n};\nstatic const struct VectorOutputRow evex_output_rows[] = {");
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

int main()
{
	Decoder decoder;
	std::puts("/* Generated by suite/synctools/x86_vector_output.cpp. */");
	emit_output(decoder);
	std::fprintf(stderr, "%llu ordinary decoder probes\n",
		     static_cast<unsigned long long>(decoder.probes));
}

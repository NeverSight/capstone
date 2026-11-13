/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

// Build against full x86 Capstone and redirect stdout to X86GenVectorOutput.inc.
#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
struct Form {
	unsigned map, opcode;
	bool immediate;
};

// Three ordinary vector registers, with an optional imm8. Each admitted
// W/LL combination is rebuilt from the output of the canonical decoder.
constexpr Form forms[] = {
	{ 1, 0xef, false }, { 2, 0xdc, false }, { 2, 0xdd, false },
	{ 2, 0xde, false }, { 2, 0xdf, false }, { 3, 0x44, true },
	{ 3, 0x25, true },  { 2, 0x00, false }, { 1, 0xfe, false },
};

struct Decoder {
	csh handle = 0;
	cs_insn *insn = nullptr;
	uint64_t probes = 0;
	Decoder()
	{
		// Text, detail and a custom name make regeneration independent of
		// both the compact scan reader and the optimized output records.
		cs_opt_mnem name = { X86_INS_UD2, "ud2" };
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) ||
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

std::string output_record(Decoder &decoder, const Form &form, unsigned w,
			  unsigned ll)
{
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

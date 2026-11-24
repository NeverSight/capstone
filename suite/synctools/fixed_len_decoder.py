#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Lower LLVM fixed-width decoder tables without interpreting them at runtime."""
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
import argparse
import hashlib
import re

# The supported backends have the same driver. Refuse changed driver semantics until
# its state transitions, failure handling and integer widths have been reviewed.
DRIVER = "294f3d96b91037ef613f4e036e91dc055861c901fc3a741f5708908ad4452ab3"
ROOT = Path(__file__).resolve().parents[2]
# Encoded table width maps to (helper suffix, C input width). These differ for
# widened halfwords, NanoMIPS 48-bit words, PowerPC prefixed instructions and
# the shared 64-bit inputs of SystemZ and Xtensa.
BACKENDS = (
    ("AArch64", "AArch64", {32: (4, 32)}),
    ("ARM", "ARM", {16: (2, 16), 32: (4, 32)}),
    ("ARC", "ARC", {16: (2, 16), 32: (4, 32), 48: (8, 64), 64: (8, 64)}),
    ("RISCV", "RISCV", {16: (2, 16), 32: (4, 32)}),
    ("TriCore", "TriCore", {16: (2, 16), 32: (4, 32)}),
    ("LoongArch", "LoongArch", {32: (4, 32)}),
    ("Sparc", "Sparc", {32: (4, 32)}),
    ("PowerPC", "PPC", {32: (4, 64), 64: (4, 64)}),
    ("Mips", "Mips", {16: (2, 32), 32: (4, 32), 48: (8, 64)}),
    ("SystemZ", "SystemZ", {16: (8, 64), 32: (8, 64), 48: (8, 64)}),
    (
        "Xtensa",
        "Xtensa",
        {16: (3, 64), 24: (3, 64), 32: (3, 64), 48: (3, 64), 64: (3, 64)},
    ),
)
OPS = {
    s: i + 1
    for i, s in enumerate(
        (
            "ExtractField",
            "FilterValue",
            "CheckField",
            "CheckPredicate",
            "Decode",
            "TryDecode",
            "SoftFail",
            "Fail",
        )
    )
}


@dataclass
class Node:
    op: str
    args: tuple
    end: int
    target: Optional[int] = None


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(body):
    # The unnumbered zero terminates the array, not a reachable VM instruction.
    rest = re.sub(r"/\*\s*\d+\s*\*/[^\n]*", "", body).strip()
    require(rest == "0", "Unexpected table contents outside numbered rows")
    lines = re.findall(r"/\*\s*(\d+)\s*\*/\s*(.*)", body)
    data = []
    positions = []
    for offset, row in lines:
        row = re.sub(r"/\*.*?\*/", "", row.split("//")[0]).strip().rstrip(",")
        require(int(offset) == len(data), "Non-contiguous table offsets")
        positions.append(len(data))
        for token in row.split(","):
            token = token.strip()
            data.append(
                OPS[token[len("MCD_OPC_") :]]
                if token.startswith("MCD_OPC_")
                else int(token, 0)
            )
    require(all(0 <= n <= 255 for n in data), "Non-byte table element")
    p = 0

    def byte():
        nonlocal p
        v = data[p]
        p += 1
        return v

    def uleb():
        v = shift = 0
        while True:
            b = byte()
            require(shift < 64, "ULEB128 exceeds 64 bits")
            v |= (b & 127) << shift
            if not b & 128:
                require(v <= (1 << 64) - 1, "ULEB128 exceeds 64 bits")
                return v
            shift += 7

    nodes = {}
    while p < len(data):
        start = p
        opcode = byte()
        require(1 <= opcode <= len(OPS), "Unknown decoder operation")
        op = tuple(OPS)[opcode - 1]
        args = []
        if op in ("ExtractField", "CheckField"):
            args += [byte(), byte()]
        if op in (
            "FilterValue",
            "CheckField",
            "CheckPredicate",
            "Decode",
            "TryDecode",
            "SoftFail",
        ):
            args.append(uleb())
        if op in ("Decode", "TryDecode", "SoftFail"):
            args.append(uleb())
        target = None
        if op in ("FilterValue", "CheckField", "CheckPredicate", "TryDecode"):
            skip = byte() | (byte() << 8) | (byte() << 16)
            target = p + skip
        nodes[start] = Node(op, tuple(args), p, target)
    require(list(nodes) == positions, "Table row does not match operation width")
    for start, node in nodes.items():
        if node.target is not None:
            require(
                node.target in nodes and node.target >= node.end,
                "Invalid forward branch target",
            )
        if node.op not in ("Decode", "TryDecode", "Fail"):
            require(node.end in nodes, "Invalid fallthrough target")
    return nodes


def successors(n):
    if n.op in ("Decode", "Fail"):
        return []
    if n.op == "TryDecode":
        return [n.target]
    return [n.end] + ([] if n.target is None else [n.target])


def observable_field_values(nodes, offset, bits):
    """Admit every value of the selected bits that could reach an MCInst mutation."""
    result = set()
    selected = ((1 << bits) - 1) << offset
    for value in range(1 << bits):
        pending = [(0, None)]
        seen = set()
        while pending:
            position, field = pending.pop()
            state = (position, field)
            if state in seen:
                continue
            seen.add(state)
            node = nodes[position]
            if node.op in ('Decode', 'TryDecode'):
                result.add(value)
                break
            if node.op == 'Fail':
                continue
            if node.op == 'ExtractField':
                pending.append((node.end, node.args))
                continue
            if node.op in ('FilterValue', 'CheckField'):
                if node.op == 'FilterValue':
                    compared, expected = field, node.args[0]
                else:
                    compared, expected = node.args[:2], node.args[2]
                if compared is None:
                    match, mismatch = expected == 0, expected != 0
                else:
                    start, length = compared
                    field_mask = (1 << length) - 1
                    known = (selected >> start) & field_mask
                    observed = ((value << offset) >> start) & known
                    match = expected <= field_mask and (expected & known) == observed
                    mismatch = not match or known != field_mask
                if match:
                    pending.append((node.end, field))
                if mismatch:
                    pending.append((node.target, field))
                continue
            # Predicates are pure queries; either answer remains possible.
            assert node.op in ('CheckPredicate', 'SoftFail'), node.op
            pending.append((node.end, field))
            if node.target is not None:
                pending.append((node.target, field))
    return result


def primary_opcode_mask(nodes):
    """A top-level miss must reach Fail without modifying the instruction."""
    root = nodes[0]
    require(root.op == "ExtractField" and root.args == (26, 6),
            "Review MIPS primary opcode field")
    node = nodes[root.end]
    mask = 0
    while node.op == "FilterValue":
        value = node.args[0]
        require(value < 64, "Invalid MIPS primary opcode")
        mask |= 1 << value
        node = nodes[node.target]
    require(node.op == "Fail", "Review MIPS primary opcode fallback")
    return mask


def riscv_compressed_entry(nodes, groups):
    """Combine the funct3 and quadrant filters when every miss reaches Fail."""
    root = nodes[0]
    if root.op != "ExtractField" or root.args != (13, 3):
        return []
    majors = groups.get(root.end, [])
    if {nodes[p].args[0] for p in majors} != set(range(8)):
        return []
    fail = nodes[majors[-1]].target
    if nodes[fail].op != "Fail":
        return []
    cases = []
    for major in majors:
        quadrant = nodes[nodes[major].end]
        if quadrant.op != "ExtractField" or quadrant.args != (0, 2):
            return []
        filters = groups.get(quadrant.end, [])
        if not filters or nodes[filters[-1]].target != fail:
            return []
        for position in filters:
            value = nodes[position].args[0]
            if value >= 4:
                return []
            key = (nodes[major].args[0] << 2) | value
            cases.append(f"\tcase {key}: goto L{nodes[position].end};")
    # Targets see the same last extracted value as in the two original filters.
    return [
        "#ifdef RISCV_USE_COMPRESSED_DISPATCH",
        "\tCurFieldValue = fieldFromInstruction_2(insn, 0, 2);",
        "\tswitch ((fieldFromInstruction_2(insn, 13, 3) << 2) | CurFieldValue) {",
        *cases,
        f"\tdefault: goto L{fail};",
        "\t}",
        "#endif",
    ]


def emit(name, nodes, width, w, compressed=False):
    incoming = {p: set() for p in nodes}
    for p, n in nodes.items():
        for dst in successors(n):
            incoming[dst].add(p)
    absorbed = set()
    groups = {}
    # A mismatch-only filter chain leaves CurFieldValue and all other state
    # unchanged. Merge it only when no other edge can enter its interior.
    for p, n in nodes.items():
        if p in absorbed or n.op != "FilterValue":
            continue
        group = [p]
        seen = {n.args[0]}
        while nodes[group[-1]].target is not None:
            dst = nodes[group[-1]].target
            nn = nodes[dst]
            if (
                nn.op != "FilterValue"
                or incoming[dst] != {group[-1]}
                or nn.args[0] in seen
            ):
                break
            group.append(dst)
            seen.add(nn.args[0])
            absorbed.add(dst)
        groups[p] = group
    out = [
        f"static DecodeStatus direct_{name}(MCInst *MI, uint{width}_t insn, uint64_t Address, const void *Decoder)",
        "{",
        "\tuint64_t CurFieldValue = 0;",
        "\tDecodeStatus S = MCDisassembler_Success;",
        "\tunsigned Opc, DecodeIdx;",
        "\tbool DecodeComplete;",
        "\t(void)CurFieldValue;",
        *(riscv_compressed_entry(nodes, groups) if compressed else []),
        "\tgoto L0;",
    ]

    def line(s):
        out.append("\t" + s)

    for p, n in nodes.items():
        if p in absorbed:
            continue
        out.append(f"L{p}:;")
        a = n.args
        if n.op == "ExtractField":
            line(f"CurFieldValue = fieldFromInstruction_{w}(insn, {a[0]}, {a[1]});")
        elif n.op == "FilterValue":
            group = groups[p]
            if len(group) > 1:
                line("switch (CurFieldValue) {")
                for q in group:
                    line(f"case UINT64_C({nodes[q].args[0]}): goto L{nodes[q].end};")
                line(f"default: goto L{nodes[group[-1]].target};")
                line("}")
                continue
            line(f"if (CurFieldValue != UINT64_C({a[0]})) goto L{n.target};")
        elif n.op == "CheckField":
            line(
                f"if (fieldFromInstruction_{w}(insn, {a[0]}, {a[1]}) != UINT64_C({a[2]})) goto L{n.target};"
            )
        elif n.op == "CheckPredicate":
            line(f"if (!checkDecoderPredicate(MI, {a[0]})) goto L{n.target};")
        elif n.op == "Decode":
            line(f"Opc = {a[0]}; DecodeIdx = {a[1]}; goto Decode;")
            continue
        elif n.op == "TryDecode":
            line(f"MCInst_setOpcode(MI, {a[0]});")
            line(
                f"S = decodeToMCInst_{w}(S, {a[1]}, insn, MI, Address, Decoder, &DecodeComplete);"
            )
            line("if (DecodeComplete) return S;")
            line("MCInst_clear(MI);")
            line("S = MCDisassembler_Success;")
            line(f"goto L{n.target};")
            continue
        elif n.op == "SoftFail":
            line(
                f"if ((insn & UINT64_C({a[0]})) != 0 || (~insn & UINT64_C({a[1]})) != 0) S = MCDisassembler_SoftFail;"
            )
        elif n.op == "Fail":
            line("return MCDisassembler_Fail;")
            continue
        else:
            raise AssertionError(n.op)
        line(f"goto L{n.end};")
    out += [
        "Decode:",
        "\tMCInst_clear(MI);",
        "\tMCInst_setOpcode(MI, Opc);",
        f"\treturn decodeToMCInst_{w}(S, DecodeIdx, insn, MI, Address, Decoder, &DecodeComplete);",
        "}",
    ]
    return "\n".join(out)


def riscv_scan_decoders(text):
    """Recognize operand readers that always succeed for a non-E hart."""
    readers = text.split("#define DecodeToMCInst(", 1)[1].split("#define DecodeInstruction(", 1)[0]
    cases = re.split(r"^\s*case (\d+):\s*\\$", readers, flags=re.M)
    result = set()
    for index, body in zip(cases[1::2], cases[2::2]):
        bits = None
        for source in body.splitlines():
            line = source.rstrip("\\").strip()
            if not line:
                continue
            if line == "return S;":
                result.add(int(index))
                break
            if line == "tmp = 0x0;":
                bits = 0
                continue
            field = re.fullmatch(r"tmp (=|\|=) fieldname\(insn, (\d+), (\d+)\)(?: << (\d+))?;", line)
            if field:
                op, start, width, shift = field.groups()
                if int(start) + int(width) > 32 or (op == "|=" and bits is None):
                    break
                value = ((1 << int(width)) - 1) << int(shift or 0)
                bits = value if op == "=" else bits | value
                continue
            reader = re.fullmatch(
                r"if \(!Check\(&S, (DecodeGPRRegisterClass|decode[SU]ImmOperand(?:AndLsl1)?_(\d+))"
                r"\(MI, tmp, Address, Decoder\)\)\) \{ return MCDisassembler_Fail; \}", line
            )
            if not reader or bits is None or bits.bit_length() > int(reader[2] or 5):
                break
    return result


def riscv_scan_opcodes(nodes, decoders, extension_majors):
    """Resolve the base row only if opcode and funct3 determine every decision."""
    known = 0x707f
    def resolve(major, funct3):
        if extension_majors & (1 << major):
            return 0
        word = (major << 2) | 3 | (funct3 << 12)
        pos, field = 0, 0
        while True:
            n = nodes[pos]
            if n.op == "Decode":
                return n.args[0] if n.args[1] in decoders else 0
            if n.op in ("CheckField", "ExtractField"):
                start, size = n.args[:2]
                mask = (1 << size) - 1
                if ((known >> start) & mask) != mask:
                    return 0
                value = (word >> start) & mask
                if n.op == "CheckField":
                    pos = n.end if value == n.args[2] else n.target
                else:
                    field, pos = value, n.end
            elif n.op == "FilterValue":
                pos = n.end if field == n.args[0] else n.target
            else:
                return 0

    rows = [[resolve(major, f) for f in range(8)] for major in range(32)]
    require(max(max(row) for row in rows) <= 0xffff, "RISC-V scan opcode exceeds table width")
    return "\n".join(["#ifdef CAPSTONE_RISCV_ONLY",
                      "static const uint16_t RISCVScanOpcodes[32][8] = {",
                      *["\t{ " + ", ".join(map(str, row)) + " }," for row in rows],
                      "};", "#endif"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    for arch, prefix, inputs in BACKENDS:
        src = ROOT / f"arch/{arch}/{prefix}GenDisassemblerTables.inc"
        text = src.read_text(encoding="utf-8")
        start = text.index("#define DecodeInstruction(")
        end = text.index("\nFieldFromInstruction(fieldFromInstruction_", start)
        require(
            hashlib.sha256(text[start:end].encode()).hexdigest() == DRIVER,
            "Review changed decoder driver semantics before regenerating",
        )
        tables = re.findall(
            r"static const uint8_t (DecoderTable\w+)\[\] = \{(.*?)\n\};", text, re.S
        )
        require(bool(tables), "No decoder tables found")
        output = [
            text.split('#include "../../MCInst.h"', 1)[0].rstrip(),
            "/* Branch lowering generated by suite/synctools/fixed_len_decoder.py. */",
            f"/* Source SHA256: {hashlib.sha256(text.encode('utf-8')).hexdigest()} */",
        ]
        counts = []
        extension_majors = 0
        ppc_extension_majors = 0
        for name, body in tables:
            encoded_width = int(name[-2:])
            require(encoded_width in inputs, "Unsupported instruction width")
            w, width = inputs[encoded_width]
            require(
                f"DecodeInstruction(decodeInstruction_{w},fieldFromInstruction_{w},"
                f"decodeToMCInst_{w},uint{width}_t)" in re.sub(r"\s+", "", text[end:]),
                "Review changed decoder input width before regenerating",
            )
            nodes = parse(body)
            if arch == "RISCV" and name == "DecoderTable32":
                riscv_base = nodes
            if arch == "RISCV" and encoded_width == 32 and name != "DecoderTable32":
                for opcode_prefix in observable_field_values(nodes, 0, 7):
                    extension_majors |= 1 << (opcode_prefix >> 2)
            if arch == "PowerPC" and name != "DecoderTable32":
                if encoded_width == 64:
                    # The first word in memory occupies bits 63:32, for either endianness.
                    majors = observable_field_values(nodes, 58, 6)
                    require(len(majors) == 1, "Review the prefixed PowerPC primary opcodes")
                    output.append(f"#define PPC_PREFIX_MAJOR {next(iter(majors))}u")
                else:
                    for major in observable_field_values(nodes, 26, 6):
                        ppc_extension_majors |= 1 << major
            if arch == "Mips" and name in (
                "DecoderTableMips6432", "DecoderTableMipsFP6432", "DecoderTableMipsDSP32"
            ):
                mask = primary_opcode_mask(nodes)
                output.append(f"#define {name}_MAJOR_MASK UINT64_C(0x{mask:016x})")
            output.append(emit(name, nodes, width, w, arch == "RISCV" and name == "DecoderTable16"))
            counts.append((name, len(nodes)))
        if arch == "RISCV":
            output.append(riscv_scan_opcodes(riscv_base, riscv_scan_decoders(text), extension_majors))
            output.append(
                f"#define RISCV_EXTENSION_MAJORS UINT32_C(0x{extension_majors:08x})"
            )
        if arch == "PowerPC":
            output.append(
                f"#define PPC_EXTENSION_MAJORS UINT64_C(0x{ppc_extension_majors:016x})"
            )
        for w, width in sorted(set(inputs.values())):
            selected = [n for n, _ in tables if inputs[int(n[-2:])] == (w, width)]
            if not selected:
                continue
            output += [
                f"static DecodeStatus directInstruction_{w}(const uint8_t *Table, MCInst *MI, uint{width}_t insn, uint64_t Address, const void *Decoder)",
                "{",
            ]
            for name in selected:
                output.append(
                    f"\tif (Table == {name}) return direct_{name}(MI, insn, Address, Decoder);"
                )
            output += [
                f"\treturn decodeInstruction_{w}(Table, MI, insn, Address, Decoder);",
                "}",
                f"#define decodeInstruction_{w} directInstruction_{w}",
            ]
        if arch == "ARC":
            output.insert(1, "#if !defined(__GNUC__) || defined(__clang__) || __GNUC__ != 11")
            output.append("#endif")
        if arch == "TriCore":
            output.insert(1, "#ifdef CAPSTONE_TRICORE_DIRECT_DECODER")
            output.append("#endif")
        generated = "\n\n".join(output) + "\n"
        dst = ROOT / f"arch/{arch}/{prefix}GenDirectDecoder.inc"
        if args.check:
            require(
                dst.read_text(encoding="utf-8") == generated,
                f"Stale generated decoder: {dst}",
            )
        else:
            dst.write_text(generated, encoding="utf-8")
        print(
            arch,
            len(tables),
            "tables",
            sum(c for _, c in counts),
            "nodes",
            len(generated),
            "bytes",
        )


if __name__ == "__main__":
    main()

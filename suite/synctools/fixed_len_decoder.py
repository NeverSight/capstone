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
    ("RISCV", "RISCV", {16: (2, 16), 32: (4, 32)}),
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


def emit(name, nodes, width, w):
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
            output.append(emit(name, nodes, width, w))
            counts.append((name, len(nodes)))
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

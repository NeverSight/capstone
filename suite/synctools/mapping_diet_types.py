#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Project DIET operand types from the checked-in full operand mapping tables."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
ARCHITECTURES = (
    ("AArch64", "AArch64"),
    ("ARM", "ARM"),
    ("Alpha", "Alpha"),
    ("ARC", "ARC"),
    ("Mips", "Mips"),
    ("PPC", "PowerPC"),
    ("Sparc", "Sparc"),
    ("LoongArch", "LoongArch"),
    ("RISCV", "RISCV"),
)
COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
TOKEN = re.compile(
    r"\s+|/\*.*?\*/|//[^\n]*|0[xX][0-9a-fA-F]+|\d+|[A-Za-z_]\w*|<<|[{},()|]", re.S
)
HEADER = re.compile(r"(?m)^\{+[ \t]*/\*\s*(\w+)\s*\((\d+)\)")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer_expression(expression, values):
    """The emitter uses named constants, integer literals, OR, and shifts."""
    # C enum expressions may continue after an operator on the next line.
    expression = " ".join(expression.split())

    def value(node):
        if isinstance(node, ast.Expression):
            return value(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and node.id in values:
            return values[node.id]
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.BitOr):
                return value(node.left) | value(node.right)
            if isinstance(node.op, ast.LShift):
                return value(node.left) << value(node.right)
        raise ValueError("Unknown integer expression: " + expression)

    return value(ast.parse(expression, mode="eval"))


def enum_values(text, name):
    clean = COMMENT.sub("", text)
    match = re.search(r"typedef enum " + name + r"\s*\{(.*?)\}", clean, re.S)
    require(match is not None, "Missing " + name)
    values = {}
    for entry in match[1].split(","):
        if not entry.strip():
            continue
        parts = entry.split("=", 1)
        require(len(parts) == 2, "Expected explicit enum value: " + entry)
        symbol, expression = (part.strip() for part in parts)
        require(
            re.fullmatch(r"\w+", symbol) and symbol not in values,
            "Invalid/duplicate enum name: " + symbol,
        )
        values[symbol] = integer_expression(expression, values)
    return values


class Initializers:
    """Small strict parser for this emitter's aggregate initializer grammar."""

    def __init__(self, text):
        self.tokens = []
        offset = 0
        while offset < len(text):
            match = TOKEN.match(text, offset)
            require(match is not None, "Unknown mapping syntax at byte " + str(offset))
            token = match[0]
            if not token.isspace() and not token.startswith(("/*", "//")):
                self.tokens.append((token, offset))
            offset = match.end()
        self.at = 0

    def peek(self):
        return self.tokens[self.at][0] if self.at < len(self.tokens) else None

    def take(self, expected):
        require(
            self.peek() == expected, "Expected %s, got %s" % (expected, self.peek())
        )
        self.at += 1

    def aggregate(self):
        self.take("{")
        fields = []
        while self.peek() != "}":
            require(self.peek() is not None, "Unterminated aggregate")
            if self.peek() == "{":
                fields.append(self.aggregate())
            else:
                tokens = []
                while self.peek() not in (None, ",", "}"):
                    require(
                        self.peek() != "{", "Unexpected aggregate inside expression"
                    )
                    tokens.append(self.peek())
                    self.at += 1
                require(tokens, "Missing scalar field")
                fields.append(" ".join(tokens))
            if self.peek() != "}":
                self.take(",")
        self.take("}")
        return fields


def instruction_enum(text, arch):
    match = re.search(r"#ifdef GET_INSTRINFO_ENUM(.*?)#endif", text, re.S)
    require(match is not None, "Missing instruction enumeration: " + arch)
    body = COMMENT.sub("", match[1])
    match = re.search(r"enum\s*\{(.*?)\}", body, re.S)
    require(match is not None, "Missing instruction enum body: " + arch)
    entries = []
    for item in match[1].split(","):
        if not item.strip():
            continue
        entry = re.fullmatch(r"\s*(\w+)\s*=\s*(\d+)\s*", item)
        require(entry is not None, "Unknown instruction enum syntax: " + item)
        entries.append((entry[1], int(entry[2])))
    require(
        entries and entries[-1][0] == "INSTRUCTION_LIST_END",
        "Missing instruction enum sentinel: " + arch,
    )
    end = entries.pop()[1]
    require(end == len(entries), "Instruction enum extent differs from sentinel")
    require(
        len({name for name, _ in entries}) == len(entries),
        "Instruction enum contains duplicate names",
    )
    require(
        all(
            value == i and name.upper().startswith(arch.upper() + "_")
            for i, (name, value) in enumerate(entries)
        ),
        "Instruction enum is not contiguous or has a foreign name",
    )
    return [name for name, _ in entries]


def read_mapping(text, enum_names, arch, types, accesses, capacity, dtype_capacity):
    headers = {
        match.start(): (match[1], int(match[2])) for match in HEADER.finditer(text)
    }
    parser = Initializers(text)
    rows = []
    while parser.peek() is not None:
        position = parser.tokens[parser.at][1]
        require(position in headers, "Mapping row lacks its owning opcode header")
        symbol, ordinal = headers[position]
        require(
            ordinal == len(rows) and ordinal < len(enum_names),
            "Mapping opcode order/extent differs from enum",
        )
        expected = arch.upper() + enum_names[ordinal][len(arch) :]
        require(symbol == expected, "Mapping opcode name differs from enum: " + symbol)
        record = parser.aggregate()
        parser.take(",")
        require(
            len(record) == 1 and isinstance(record[0], list),
            "Expected one operand array",
        )
        operands = record[0]
        require(
            0 < len(operands) <= capacity and operands[-1] == ["0"],
            "Missing terminator or operand mapping exceeds capacity: " + symbol,
        )
        row = []
        for operand in operands[:-1]:
            require(
                isinstance(operand, list) and len(operand) == 3,
                "Expected type/access/dtypes fields: " + symbol,
            )
            op_type, access, dtypes = operand
            require(
                isinstance(op_type, str) and isinstance(access, str),
                "Expected scalar type/access fields: " + symbol,
            )
            number = integer_expression(op_type, types)
            require(0 <= number <= 255, "Operand type does not fit uint8_t: " + symbol)
            access_number = integer_expression(access, accesses)
            require(0 <= access_number <= 255, "Invalid access field: " + symbol)
            require(
                isinstance(dtypes, list)
                and 0 < len(dtypes) <= dtype_capacity
                and dtypes[-1] == "CS_DATA_TYPE_LAST"
                and all(
                    isinstance(dtype, str) and re.fullmatch(r"CS_DATA_TYPE_\w+", dtype)
                    for dtype in dtypes
                ),
                "Unknown data-type initializer: " + symbol,
            )
            row.append(number)
        rows.append(tuple(row + [0] * (capacity - len(row))))
    require(
        len(rows) == len(headers) == len(enum_names),
        "Mapping table does not cover every opcode exactly once",
    )
    return rows


def generate(rows, capacity, source_digest):
    zero = (0,) * capacity
    unique = [zero]
    indices = {zero: 0}
    lookup = []
    for row in rows:
        if row not in indices:
            indices[row] = len(unique)
            unique.append(row)
        lookup.append(indices[row])
    require(len(unique) <= 65536, "DIET type row index exceeds uint16_t")
    require(
        all(unique[index] == row for index, row in zip(lookup, rows)),
        "DIET type projection changed an operand",
    )
    lines = [
        "/* Capstone Disassembly Engine */",
        "/* SPDX-License-Identifier: BSD-3-Clause */",
        "/* Generated by suite/synctools/mapping_diet_types.py; do not edit. */",
        "/* Source SHA256: " + source_digest + " */",
        "",
        "static const uint8_t insn_operand_types[][MAX_NO_INSN_MAP_OPS] = {",
    ]
    for index, row in enumerate(unique):
        lines.append("\t{ " + ", ".join(map(str, row)) + " }, /* %d */" % index)
    lines += ["};", "", "static const uint16_t insn_operand_type_index[] = {"]
    for index in range(0, len(lookup), 16):
        lines.append(
            "\t"
            + ", ".join(map(str, lookup[index : index + 16]))
            + ", /* %d */" % index
        )
    lines += ["};", ""]
    return "\n".join(lines), len(unique)


def project(root, arch, folder):
    mapping_header = (root / "Mapping.h").read_text()
    capacity = int(re.search(r"#define MAX_NO_INSN_MAP_OPS (\d+)", mapping_header)[1])
    dtype_capacity = int(
        re.search(r"#define MAX_NO_DATA_TYPES (\d+)", mapping_header)[1]
    )
    constants = (root / "include/capstone/cs_operand.h").read_text()
    types = enum_values(constants, "cs_op_type")
    accesses = enum_values(constants, "cs_ac_type")
    source = root / "arch" / folder / (arch + "GenCSMappingInsnOp.inc")
    text = source.read_text()
    enum_text = (source.parent / (arch + "GenInstrInfo.inc")).read_text()
    names = instruction_enum(enum_text, arch)
    rows = read_mapping(text, names, arch, types, accesses, capacity, dtype_capacity)
    digest = hashlib.sha256(
        (text + "\0" + enum_text + "\0" + constants + "\0" + str(capacity)).encode()
    ).hexdigest()
    generated, unique_count = generate(rows, capacity, digest)
    stats = {
        "architecture": arch,
        "opcodes": len(rows),
        "unique_type_rows": unique_count,
        "row_width": capacity,
        "flat_type_bytes": len(rows) * capacity,
        "deduplicated_type_bytes": len(rows) * 2 + unique_count * capacity,
        "full_mapping_bytes": len(rows) * capacity * (2 + dtype_capacity),
        "maximum_type_value": max(max(row) for row in rows),
    }
    return generated, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    output_root = args.output_root or args.root
    reports = []
    pending = []
    for arch, folder in ARCHITECTURES:
        generated, stats = project(args.root, arch, folder)
        output = output_root / "arch" / folder / (arch + "GenCSMappingInsnOpDiet.inc")
        if args.check:
            require(
                output.is_file() and output.read_text() == generated,
                "Stale DIET type projection: " + str(output),
            )
        else:
            pending.append((output, generated))
        reports.append(stats)
    # Parse and validate all owners before writing any generated artifact.
    for path, generated in pending:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(generated)
    if args.report:
        args.report.write_text(json.dumps(reports, indent=2) + "\n")
    print(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()

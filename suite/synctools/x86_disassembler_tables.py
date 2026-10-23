#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Derive packed x86 decision tables without modifying their semantic inputs.

The existing X86GenDisassemblerTables*.inc files remain authoritative. This
script changes representation only: direct decisions embed their instruction
IDs, indexed decisions retain their ModR/M-table offset, and identical complete
opcode rows may share storage. Every source context/opcode is checked against
all 256 ModR/M values, including whether consuming ModR/M is required.
"""

import argparse
from functools import lru_cache
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
UID_BITS = 15
OFFSET_BITS = 16
TYPE_BITS = 3
TYPE_SHIFT = OFFSET_BITS
REGISTER_SHIFT = UID_BITS
INDEXED = 1 << 31
SPLIT = 1 << 30
UID_MASK = (1 << UID_BITS) - 1
OFFSET_MASK = (1 << OFFSET_BITS) - 1
TYPE_MASK = (1 << TYPE_BITS) - 1
OPCODE_COUNT = 256
MODRM_COUNT = 256
REGISTER_MODRM = 0xC0
MAP_ALIASES = (
    "ONEBYTE_SYM",
    "TWOBYTE_SYM",
    "THREEBYTE38_SYM",
    "THREEBYTE3A_SYM",
    "XOP8_MAP_SYM",
    "XOP9_MAP_SYM",
    "XOPA_MAP_SYM",
    "THREEDNOW_MAP_SYM",
)
KNOWN_TYPES = {
    "MODRM_ONEENTRY",
    "MODRM_SPLITRM",
    "MODRM_SPLITMISC",
    "MODRM_SPLITREG",
    "MODRM_FULL",
}
BLOCK = re.compile(
    r"\s*static const unsigned char index_(\w+)\[\] = \{(.*?)\};\s*"
    r"static const struct OpcodeDecision (\w+)\[\] = \{(.*?)\};",
    re.S,
)
ROW = re.compile(r"\s*\{\s*\{(.*?)\}\s*\}\s*,", re.S)
ENTRY = re.compile(r"\s*\{\s*(MODRM_\w+)\s*,\s*(\d+)\s*\}\s*,")
C_STRING = r'"(?:\\.|[^"\\])*"'
CONTEXT_ENTRY = re.compile(
    r"\s*ENUM_ENTRY\(\s*(IC\w*)\s*,\s*\d+\s*,\s*(?:" + C_STRING + r"\s*)+\)"
)
TYPE_ENTRY = re.compile(r"\s*ENUM_ENTRY\(\s*(MODRM_\w+)\s*\)")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uncomment(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def macro_body(text, name):
    matches = list(
        re.finditer(r"^\s*#define[ \t]+" + re.escape(name) + r"\b([^\n]*)", text, re.M)
    )
    require(len(matches) == 1, f"Expected one definition of {name}")
    match = matches[0]
    parts = [match[1]]
    rest = text[match.end() :].splitlines()
    # match.end() is immediately before the first newline.
    if rest and not rest[0]:
        rest.pop(0)
    while parts[-1].rstrip().endswith("\\"):
        parts[-1] = parts[-1].rstrip()[:-1]
        require(bool(rest), f"Unterminated macro {name}")
        parts.append(rest.pop(0))
    return " ".join(parts).strip()


def scan_entries(body, pattern, label):
    result = []
    pos = 0
    while body[pos:].strip():
        match = pattern.match(body, pos)
        require(
            match is not None, f"Unexpected {label} syntax near {body[pos:pos + 80]!r}"
        )
        result.append(match.groups())
        pos = match.end()
    return result


def parse_common(text):
    clean = uncomment(text)
    context_names = [
        item[0]
        for item in scan_entries(
            macro_body(clean, "INSTRUCTION_CONTEXTS"),
            CONTEXT_ENTRY,
            "instruction context",
        )
    ]
    type_names = [
        item[0]
        for item in scan_entries(
            macro_body(clean, "MODRMTYPES"), TYPE_ENTRY, "ModR/M type"
        )
    ]
    require(
        context_names and len(set(context_names)) == len(context_names),
        "Duplicate or missing contexts",
    )
    require(
        set(type_names) == KNOWN_TYPES and len(type_names) == len(KNOWN_TYPES),
        "Unknown, missing, or duplicate ModR/M type",
    )
    require(
        re.search(
            r"#define[ \t]+ENUM_ENTRY\(n\)[ \t]+n,\s+typedef\s+enum\s*\{\s*MODRMTYPES\s+MODRM_max\s*\}\s*ModRMDecisionType",
            clean,
        ),
        "Unexpected ModR/M enum declaration",
    )
    require(
        re.search(
            r"#define[ \t]+ENUM_ENTRY\(n, r, d\)[ \t]+n,\s+typedef\s+enum\s*\{\s*INSTRUCTION_CONTEXTS\s+IC_max\s*\}\s*InstructionContext",
            clean,
        ),
        "Unexpected context enum declaration",
    )
    types = dict(zip(type_names, range(len(type_names))))
    require(
        types["MODRM_ONEENTRY"] == 0, "The empty decision requires MODRM_ONEENTRY == 0"
    )
    require(
        max(types.values()) <= TYPE_MASK, "ModR/M type exceeds packed representation"
    )
    maps = [macro_body(clean, name) for name in MAP_ALIASES]
    require(
        all(re.fullmatch(r"\w+", name) for name in maps)
        and len(set(maps)) == len(maps),
        "Invalid opcode-map aliases",
    )
    return context_names, types, maps


def comma_values(body, label):
    values = body.split(",")
    if values and not values[-1].strip():
        values.pop()
    require(
        values and all(value.strip() for value in values), f"Empty value in {label}"
    )
    return [value.strip() for value in values]


def integer_value(token, label):
    # The source uses decimal and hexadecimal literals. Reject leading zeros
    # rather than interpreting a C octal literal as a different decimal value.
    require(
        re.fullmatch(r"0[xX][0-9a-fA-F]+|0|[1-9][0-9]*", token),
        f"Invalid or unsupported integer {token!r} in {label}",
    )
    return int(token, 16 if token.lower().startswith("0x") else 10)


def numeric_values(body, label):
    return tuple(integer_value(token, label) for token in comma_values(body, label))


def parse_ids(text, context_names):
    clean = uncomment(text)
    arrays = list(
        re.finditer(r"static const InstrUID modRMTable\[\] = \{(.*?)\};", clean, re.S)
    )
    require(len(arrays) == 1, "Expected exactly one modRMTable")
    ids = numeric_values(arrays[0][1], "modRMTable")
    require(ids[0] == 0, "The empty ModR/M table entry must reject")
    require(
        all(value <= 0xFFFF for value in ids), "Instruction ID exceeds InstrUID storage"
    )
    specifiers = re.findall(
        r"static const struct InstructionSpecifier x86DisassemblerInstrSpecifiers\[(\d+)\]",
        clean,
    )
    require(len(specifiers) == 1, "Expected exactly one instruction-specifier array")
    require(
        max(ids) < integer_value(specifiers[0], "instruction-specifier bound"),
        "Instruction ID exceeds instruction-specifier table",
    )
    contexts = list(
        re.finditer(
            r"static const uint8_t x86DisassemblerContexts\[(\d+)\] = \{(.*?)\};",
            clean,
            re.S,
        )
    )
    require(len(contexts) == 1, "Expected exactly one attribute-context table")
    context_values = comma_values(contexts[0][2], "attribute-context table")
    require(
        len(context_values) == integer_value(contexts[0][1], "attribute-context bound"),
        "Attribute-context array length mismatch",
    )
    require(set(context_values) <= set(context_names), "Unknown instruction context")
    return ids


def parse_maps(text, expected_names, context_count):
    clean = uncomment(text)
    result = []
    pos = 0
    for expected in expected_names:
        match = BLOCK.match(clean, pos)
        require(match is not None, f"Missing or malformed opcode map {expected}")
        name, index_body, row_name, row_body = match.groups()
        require(
            name == row_name == expected,
            f"Unexpected opcode-map order or name: {name}/{row_name}",
        )
        index = numeric_values(index_body, f"index_{name}")
        require(len(index) == context_count, f"Context count mismatch in {name}")
        rows = []
        for (entry_body,) in scan_entries(row_body, ROW, f"{name} row"):
            entries = tuple(
                (kind, integer_value(offset, f"{name} decision offset"))
                for kind, offset in scan_entries(entry_body, ENTRY, f"{name} decision")
            )
            require(len(entries) == OPCODE_COUNT, f"Opcode count mismatch in {name}")
            require(
                all(kind in KNOWN_TYPES for kind, _ in entries),
                f"Unknown decision kind in {name}",
            )
            rows.append(entries)
        require(rows and max(index) <= len(rows), f"Row index outside {name}")
        require(max(index) <= 255, f"Row index exceeds unsigned char in {name}")
        result.append((name, index, tuple(rows)))
        pos = match.end()
    require(
        not clean[pos:].strip(),
        f"Unexpected trailing opcode-table content: {clean[pos:pos + 80]!r}",
    )
    return result


def source_id(ids, kind, offset, modrm):
    if kind == "MODRM_ONEENTRY":
        delta = 0
    elif kind == "MODRM_SPLITRM":
        delta = int(modrm >= REGISTER_MODRM)
    elif kind == "MODRM_SPLITREG":
        delta = ((modrm & 0x38) >> 3) + (8 if modrm >= REGISTER_MODRM else 0)
    elif kind == "MODRM_SPLITMISC":
        delta = (
            ((modrm & 0x3F) + 8) if modrm >= REGISTER_MODRM else ((modrm & 0x38) >> 3)
        )
    elif kind == "MODRM_FULL":
        delta = modrm
    else:
        raise ValueError(f"Unknown decision kind {kind}")
    require(
        0 <= offset + delta < len(ids),
        f"ModR/M offset outside table: {kind}/{offset}/{modrm}",
    )
    return ids[offset + delta]


def pack(ids, types, kind, offset):
    require(kind in types, f"Unknown decision kind {kind}")
    require(
        0 <= offset <= OFFSET_MASK, f"ModR/M offset exceeds packed storage: {offset}"
    )
    first = source_id(ids, kind, offset, 0)
    if kind in ("MODRM_ONEENTRY", "MODRM_SPLITRM"):
        second = source_id(ids, kind, offset, REGISTER_MODRM)
        require(
            max(first, second) <= UID_MASK,
            f"Direct UID exceeds {UID_BITS}-bit storage: {kind}/{offset}",
        )
        return (
            first
            | (second << REGISTER_SHIFT)
            | (SPLIT if kind == "MODRM_SPLITRM" else 0)
        )
    return INDEXED | (types[kind] << TYPE_SHIFT) | offset


def packed_id(ids, reverse_types, word, modrm):
    if not word & INDEXED:
        shift = REGISTER_SHIFT if modrm >= REGISTER_MODRM else 0
        return (word >> shift) & UID_MASK
    kind = reverse_types.get((word >> TYPE_SHIFT) & TYPE_MASK)
    require(
        kind in ("MODRM_SPLITREG", "MODRM_SPLITMISC", "MODRM_FULL"),
        "Invalid indexed packed decision",
    )
    return source_id(ids, kind, word & OFFSET_MASK, modrm)


def check_integer_literals():
    require(
        numeric_values("0, 7, 10, 255, 0x10, 0Xff,", "integer check")
        == (0, 7, 10, 255, 16, 255),
        "Integer parser changed supported literal values",
    )
    for token in ("00", "010", "08", "0x", "0xg", "-1", "+1", "1u", "1 + 2"):
        try:
            numeric_values(token, "integer check")
        except ValueError:
            continue
        raise ValueError(f"Integer parser accepted unsupported literal {token!r}")

    def offset_map(token):
        entries = [f"{{ MODRM_ONEENTRY, {token} }},"]
        entries.extend(["{ MODRM_ONEENTRY, 0 },"] * (OPCODE_COUNT - 1))
        return (
            "static const unsigned char index_literal[] = { 1, };"
            "static const struct OpcodeDecision literal[] = { { {"
            + " ".join(entries)
            + "} }, };"
        )

    parsed = parse_maps(offset_map("10"), ["literal"], 1)
    require(parsed[0][2][0][0][1] == 10, "Decision-offset parser changed decimal value")
    for token in ("00", "010", "08", "-1", "+1", "1u", "1 + 2"):
        try:
            parse_maps(offset_map(token), ["literal"], 1)
        except ValueError:
            continue
        raise ValueError(
            f"Decision-offset parser accepted unsupported literal {token!r}"
        )

    for specifier_bound, context_bound in (("010", "1"), ("1", "01")):
        source = (
            "static const InstrUID modRMTable[] = { 0, };"
            "static const struct InstructionSpecifier "
            f"x86DisassemblerInstrSpecifiers[{specifier_bound}];"
            "static const uint8_t "
            f"x86DisassemblerContexts[{context_bound}] = {{ IC, }};"
        )
        try:
            parse_ids(source, ["IC"])
        except ValueError:
            continue
        raise ValueError("Array-bound parser accepted unsupported integer literal")


def check_direct_boundaries(types):
    reverse_types = {value: key for key, value in types.items()}
    # Equal IDs, rejected branches, and all-zero split decisions must preserve
    # ModR/M consumption. Equality is never grounds for dropping SPLIT.
    for first, second in ((0, 0), (0, 7), (7, 0), (7, 7), (7, 9), (UID_MASK, UID_MASK)):
        for kind in ("MODRM_ONEENTRY", "MODRM_SPLITRM"):
            ids = (first, second)
            word = pack(ids, types, kind, 0)
            require(
                bool(word & (INDEXED | SPLIT)) == (kind != "MODRM_ONEENTRY"),
                "Direct boundary consumption mismatch",
            )
            for modrm in range(MODRM_COUNT):
                require(
                    packed_id(ids, reverse_types, word, modrm)
                    == source_id(ids, kind, 0, modrm),
                    "Direct boundary result mismatch",
                )


def format_header(suffix):
    return [
        "/* Capstone Disassembly Engine, http://www.capstone-engine.org */",
        "/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */",
        "",
        "/* Generated by suite/synctools/x86_disassembler_tables.py; do not edit. */",
        f"/* Inputs: X86GenDisassemblerTables{suffix}.inc and X86GenDisassemblerTables{suffix}2.inc. */",
        "/* Their instruction semantics remain authoritative; this is a packed representation. */",
        f"#define X86_DECISION_INDEXED 0x{INDEXED:08x}u",
        f"#define X86_DECISION_SPLIT 0x{SPLIT:08x}u",
        f"#define X86_DECISION_UID_MASK 0x{UID_MASK:x}u",
        f"#define X86_DECISION_OFFSET_MASK 0x{OFFSET_MASK:x}u",
        f"#define X86_DECISION_TYPE_SHIFT {TYPE_SHIFT}",
        f"#define X86_DECISION_TYPE_MASK {TYPE_MASK}u",
        f"#define X86_DECISION_REGISTER_SHIFT {REGISTER_SHIFT}",
        "",
    ]


def render(source_dir, suffix, context_names, types, map_names, deduplicate):
    ids = parse_ids(
        (source_dir / f"X86GenDisassemblerTables{suffix}.inc").read_text(),
        context_names,
    )
    maps = parse_maps(
        (source_dir / f"X86GenDisassemblerTables{suffix}2.inc").read_text(),
        map_names,
        len(context_names),
    )
    reverse_types = {value: key for key, value in types.items()}

    @lru_cache(None)
    def old_results(kind, offset):
        return tuple(
            source_id(ids, kind, offset, modrm) for modrm in range(MODRM_COUNT)
        )

    @lru_cache(None)
    def new_results(word):
        return tuple(
            packed_id(ids, reverse_types, word, modrm) for modrm in range(MODRM_COUNT)
        )

    lines = format_header(suffix)
    source_count = emitted_count = comparisons = 0
    empty_old = (("MODRM_ONEENTRY", 0),) * OPCODE_COUNT
    empty_new = (0,) * OPCODE_COUNT
    for name, old_index, old_rows in maps:
        rows = []
        row_numbers = {}
        remap = [0]
        for old_row in old_rows:
            row = tuple(pack(ids, types, kind, offset) for kind, offset in old_row)
            # Validate even a source row that no current context references.
            for (kind, offset), word in zip(old_row, row):
                require(
                    bool(word & (INDEXED | SPLIT)) == (kind != "MODRM_ONEENTRY"),
                    f"ModR/M consumption changed in {name}",
                )
                require(
                    old_results(kind, offset) == new_results(word),
                    f"ModR/M results changed in {name}/{kind}/{offset}",
                )
            if not deduplicate or row not in row_numbers:
                rows.append(row)
                row_numbers[row] = len(rows)
            remap.append(row_numbers[row])
        index = tuple(remap[number] for number in old_index)
        require(max(index) <= 255, f"Packed row index exceeds unsigned char in {name}")
        for context, old_number in enumerate(old_index):
            original = old_rows[old_number - 1] if old_number else empty_old
            number = index[context]
            replacement = rows[number - 1] if number else empty_new
            for opcode, ((kind, offset), word) in enumerate(zip(original, replacement)):
                require(
                    bool(word & (INDEXED | SPLIT)) == (kind != "MODRM_ONEENTRY"),
                    f"Consumption changed at {name}/{context}/{opcode}",
                )
                require(
                    old_results(kind, offset) == new_results(word),
                    f"Results changed at {name}/{context}/{opcode}",
                )
                comparisons += MODRM_COUNT
        lines.append(f"static const unsigned char index_{name}[] = {{")
        for start in range(0, len(index), 16):
            lines.append("  " + ", ".join(map(str, index[start : start + 16])) + ",")
        lines.extend(["};", "", f"static const struct OpcodeDecision {name}[] = {{"])
        for row in rows:
            lines.append("  { {")
            for start in range(0, OPCODE_COUNT, 8):
                values = []
                for word in row[start : start + 8]:
                    if word & INDEXED:
                        kind = reverse_types[(word >> TYPE_SHIFT) & TYPE_MASK]
                        value = f"X86_DECISION_INDEXED | ({kind} << X86_DECISION_TYPE_SHIFT) | {word & OFFSET_MASK}u"
                    else:
                        value = f"0x{word:08x}u"
                    values.append("{ " + value + " }")
                lines.append("    " + ", ".join(values) + ",")
            lines.append("  } },")
        lines.extend(["};", ""])
        source_count += len(old_rows)
        emitted_count += len(rows)
    return "\n".join(lines), source_count, emitted_count, comparisons


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="Verify checked-in outputs without writing"
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=ROOT / "arch" / "X86",
        help="Authoritative x86 input directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory; defaults to the source directory",
    )
    parser.add_argument(
        "--no-deduplicate",
        action="store_true",
        help="Retain duplicate rows for controlled representation comparisons",
    )
    args = parser.parse_args()
    source_dir = args.source_dir.resolve()
    output_dir = (args.output_dir or source_dir).resolve()
    try:
        check_integer_literals()
        context_names, types, map_names = parse_common(
            (source_dir / "X86DisassemblerDecoderCommon.h").read_text()
        )
        check_direct_boundaries(types)
        outputs = []
        for suffix in ("", "_reduce"):
            result = render(
                source_dir,
                suffix,
                context_names,
                types,
                map_names[:4] if suffix else map_names,
                not args.no_deduplicate,
            )
            path = output_dir / f"X86GenDisassemblerTablesPacked{suffix}.inc"
            outputs.append((path, result))
        # Parse and validate both variants before writing either output.
        stale = []
        for path, (content, before, after, comparisons) in outputs:
            if args.check:
                if not path.exists() or path.read_text() != content:
                    stale.append(str(path))
            else:
                path.write_text(content)
            print(
                f"{path.name}: {before} -> {after} rows; {comparisons:,} context/opcode/ModR/M comparisons"
            )
        if stale:
            raise ValueError(
                "Stale or missing generated files: "
                + ", ".join(stale)
                + "; regenerate with suite/synctools/x86_disassembler_tables.py"
            )
    except (ValueError, OSError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()

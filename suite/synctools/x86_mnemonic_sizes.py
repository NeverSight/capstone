#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Store x86 mnemonic lengths in unused bits of the existing printer tables.

AsmStrs and the operand fragment masks remain the authorities. The full Intel
and AT&T tables have enough unused storage bits; reduced tables retain their
original writer. Run after regenerating any X86GenAsmWriter*.inc file.
"""

import argparse
import ast
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
MARKER = re.compile(
    r"  /\* Mnemonic lengths: x86_mnemonic_sizes\.py; shift (\d+), bits (\d+)\. \*/\n"
)
TABLE = re.compile(
    r"static const uint(8|16|32)_t (OpInfo\d+)\[\] = \{\n(.*?)  \};", re.S
)
ROW = re.compile(r"(\s*)(\d+)U,(\s*// (\w+)\n)")
APPEND = re.compile(r"  SStream_concat0\(O, AsmStrs\+\(Bits & (\d+)\)-1\);")
SIZED_APPEND = re.compile(
    r"  SStream_concat0_n\(O, AsmStrs\+\(Bits & (\d+)\)-1, "
    r"\(size_t\)\(\(Bits >> (\d+)\) & (\d+)\)\);"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def without_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def string_bytes(text):
    match = re.search(r"static const char AsmStrs\[\] = \{(.*?)\};", text, re.S)
    require(match is not None, "Missing AsmStrs")
    body = without_comments(match[1])
    token = re.compile(r"\s*('(?:\\.|[^'\\])*'|\d+)\s*,")
    values = []
    pos = 0
    while body[pos:].strip():
        item = token.match(body, pos)
        require(item is not None, f"Unexpected string table byte: {body[pos:pos+40]!r}")
        value = ast.literal_eval(item[1])
        if isinstance(value, str):
            require(len(value) == 1, "Expected a single byte character")
            value = ord(value)
        require(0 <= value <= 255, "String byte out of range")
        values.append(value)
        pos = item.end()
    require(values and values[-1] == 0, "Unterminated AsmStrs")
    return bytes(values)


def generate(text, enum_text, optimize):
    markers = list(MARKER.finditer(text))
    require(len(markers) <= 1, "Duplicate mnemonic length marker")
    marker = markers[0] if markers else None
    if marker:
        require(optimize, "Unexpected packed reduced table")
        sized = list(SIZED_APPEND.finditer(text))
        require(len(sized) == 1, "Missing packed mnemonic append")
        require(
            int(sized[0][2]) == int(marker[1])
            and int(sized[0][3]) == (1 << int(marker[2])) - 1,
            "Packed append does not match its metadata",
        )
        text = SIZED_APPEND.sub(
            lambda m: f"  SStream_concat0(O, AsmStrs+(Bits & {m[1]})-1);", text
        )
        text = MARKER.sub("", text)
    else:
        require("SStream_concat0_n" not in text, "Unmarked packed mnemonic append")

    appends = list(APPEND.finditer(text))
    require(len(appends) == 1, "Expected one mnemonic append")
    string_mask = int(appends[0][1])
    require(string_mask & (string_mask + 1) == 0, "Noncontiguous string mask")
    used_bits = string_mask.bit_length()
    fragment_masks = []
    source = without_comments(text)
    # Every use of Bits must be recognized before choosing a supposedly free bit.
    for line in source.splitlines():
        if not re.search(r"\bBits\b", line):
            continue
        line = line.strip()
        fragment = re.fullmatch(
            r"(?:switch \(\(uint32_t\)\(\(Bits >> (\d+)\) & (\d+)\)\)"
            r"|if \(\(Bits >> (\d+)\) & (\d+)\)) \{",
            line,
        )
        if fragment:
            shift, mask = [int(x) for x in fragment.groups() if x is not None]
            require(mask > 0 and mask & (mask + 1) == 0, "Noncontiguous fragment mask")
            require(shift == used_bits, "Noncontiguous or reordered operand fragments")
            used_bits += mask.bit_length()
            fragment_masks.append((shift, mask))
        else:
            require(
                re.fullmatch(r"uint(?:32|64)_t Bits = 0;", line)
                or re.fullmatch(
                    r"Bits \|= (?:\(uint64_t\))?OpInfo\d+\[opcode\] << \d+;", line
                )
                or APPEND.fullmatch("  " + line),
                f"Unrecognized Bits consumer: {line}",
            )
    require(fragment_masks, "Missing operand fragments")
    canonical_mask = (1 << used_bits) - 1

    arrays = list(TABLE.finditer(text))
    require(arrays, "Missing OpInfo tables")
    enum = dict(
        (name, int(index))
        for name, index in re.findall(r"\b(X86_\w+)\s*=\s*(\d+)", enum_text)
    )
    row_count = enum["X86_INSTRUCTION_LIST_END"]
    first_opcode = min(enum.values())
    names = None
    combined = [0] * row_count
    chunks = []
    storage_bits = 0
    for number, array in enumerate(arrays):
        width = int(array[1])
        require(array[2] == f"OpInfo{number}", "Unexpected OpInfo table order")
        rows = list(ROW.finditer(array[3]))
        require(
            "".join(row[0] for row in rows) == array[3], "Unexpected OpInfo row syntax"
        )
        require(len(rows) == row_count, "OpInfo and enum sizes differ")
        row_names = [row[4] for row in rows]
        require(
            names is None or names == row_names,
            "OpInfo tables name different instructions",
        )
        names = row_names
        assembly = re.findall(
            rf"Bits \|= (?:\(uint64_t\))?{array[2]}\[opcode\] << (\d+);", source
        )
        require(assembly == [str(storage_bits)], "Unexpected OpInfo assembly shift")
        for index, row in enumerate(rows):
            value = int(row[2])
            require(value < 1 << width, "OpInfo value exceeds storage width")
            require(
                index < first_opcode or enum.get("X86_" + row[4]) == index,
                "OpInfo instruction order differs from enum",
            )
            combined[index] |= value << storage_bits
        chunks.append((array, rows, width, storage_bits))
        storage_bits += width
    require(storage_bits <= 64, "OpInfo exceeds 64 bits")

    strings = string_bytes(text)
    old_length_mask = 0
    if marker:
        old_shift, old_width = int(marker[1]), int(marker[2])
        require(
            old_shift == used_bits,
            "Operand masks changed; regenerate the original tables first",
        )
        old_length_mask = ((1 << old_width) - 1) << old_shift
    canonical = []
    lengths = []
    for value in combined:
        require(
            value & ~(canonical_mask | old_length_mask) == 0,
            "Unexpected nonzero unconsumed bits",
        )
        value &= canonical_mask
        canonical.append(value)
        offset = (value & string_mask) - 1
        if offset < 0:
            require(value == 0, "Nonzero printer record with missing string")
            lengths.append(0)
        else:
            require(offset < len(strings), "String offset outside AsmStrs")
            end = strings.find(b"\0", offset)
            require(end >= 0, "Unterminated mnemonic suffix")
            lengths.append(end - offset)
    length_bits = max(lengths).bit_length()
    if not optimize:
        require(marker is None, "Reduced writer unexpectedly packed")
        return text
    require(
        used_bits + length_bits <= storage_bits, "No spare storage for mnemonic lengths"
    )
    require(
        marker is None or int(marker[2]) == length_bits,
        "Length width changed; regenerate original tables first",
    )
    packed = [
        value | (length << used_bits) for value, length in zip(canonical, lengths)
    ]
    for old, new, length in zip(canonical, packed, lengths):
        require(new & string_mask == old & string_mask, "Mnemonic offset changed")
        require(new >> used_bits == length, "Mnemonic length was truncated")
        for shift, mask in fragment_masks:
            require(
                (new >> shift) & mask == (old >> shift) & mask,
                "Operand fragment changed",
            )

    replacements = []
    for array, rows, width, shift in chunks:
        new_body = "".join(
            row[1] + str((value >> shift) & ((1 << width) - 1)) + "U," + row[3]
            for row, value in zip(rows, packed)
        )
        replacements.append((array.start(3), array.end(3), new_body))
    for start, end, body in reversed(replacements):
        text = text[:start] + body + text[end:]
    replacement = (
        f"  /* Mnemonic lengths: x86_mnemonic_sizes.py; shift {used_bits}, bits {length_bits}. */\n"
        f"  SStream_concat0_n(O, AsmStrs+(Bits & {string_mask})-1, "
        f"(size_t)((Bits >> {used_bits}) & {(1 << length_bits) - 1}));"
    )
    return APPEND.sub(lambda _: replacement, text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = ROOT / "arch/X86"
    for reduced in (False, True):
        suffix = "_reduce" if reduced else ""
        enum = (directory / f"X86GenInstrInfo{suffix}.inc").read_text()
        for syntax in ("", "1"):
            path = directory / f"X86GenAsmWriter{syntax}{suffix}.inc"
            original = path.read_text()
            expected = generate(original, enum, not reduced)
            require(
                generate(expected, enum, not reduced) == expected,
                f"Non-idempotent generation: {path}",
            )
            if args.check:
                require(
                    original == expected, f"Stale {path}; rerun {Path(__file__).name}"
                )
            elif original != expected:
                path.write_text(expected)


if __name__ == "__main__":
    main()

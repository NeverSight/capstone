#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Project Intel x86 register-name lengths into the existing uint16 offsets.

Run after regenerating X86GenRegisterName1.inc. The strings and original offsets
remain authoritative; AT&T and public register-name tables are unchanged.
"""

import argparse
from pathlib import Path
import re

from x86_mnemonic_sizes import require, string_bytes


ROOT = Path(__file__).resolve().parents[2]
SHIFT = 13
MASK = (1 << SHIFT) - 1
MARKER = "/* Register lengths: x86_register_name_sizes.py; shift 13, bits 3. */\n"
TABLE = re.compile(
    r"^(?:  )?static const uint16_t RegAsmOffset\[\] = \{\n(.*?)^(?:  )?\};\n",
    re.M | re.S,
)
GET_LENGTH = """static inline unsigned getRegisterNameLength(unsigned RegNo)
{
#ifndef CAPSTONE_DIET
  return RegAsmOffset[RegNo-1] >> 13;
#else
  (void)RegNo;
  return 0;
#endif
}
"""
RETURN = "return AsmStrs+RegAsmOffset[RegNo-1];"
PACKED_RETURN = "return AsmStrs+(RegAsmOffset[RegNo-1] & 8191);"


def register_count(enum_text):
    enum = re.search(r"enum\s*\{(.*?)X86_NUM_TARGET_REGS", enum_text, re.S)
    require(enum is not None, "Missing x86 register enum")
    zero = re.match(r"\s*X86_NoRegister(?:\s*=\s*0)?\s*,", enum[1])
    require(zero is not None, "Missing register-zero sentinel")
    entries = [x.strip() for x in enum[1][zero.end() :].split(",") if x.strip()]
    values = []
    for entry in entries:
        value = re.fullmatch(r"X86_\w+\s*=\s*(\d+)", entry)
        require(value is not None, "Unexpected register enum expression")
        values.append(int(value[1]))
    require(
        values and values == list(range(1, len(values) + 1)),
        "Nonconsecutive register IDs",
    )
    return len(values)  # Register zero has no printable table entry.


def generate(text, enum_text):
    strings = string_bytes(text)
    tables = list(TABLE.finditer(text))
    require(len(tables) == 1, "Expected one uint16 register offset table")
    table = tables[0]
    body = table[1]
    require(re.fullmatch(r"[\s\d,]+", body) is not None, "Unexpected offset expression")
    values = [int(x.strip()) for x in body.split(",") if x.strip()]
    require(len(values) == register_count(enum_text), "Register/table count mismatch")
    require(all(0 <= x < 65536 for x in values), "Register record exceeds uint16")
    require(
        text.count("Register lengths:") == text.count(MARKER),
        "Unknown projection marker",
    )
    require(text.count(MARKER) <= 1, "Duplicate projection marker")
    packed = MARKER in text

    if packed:
        block = MARKER + "#ifndef CAPSTONE_DIET\n" + table[0] + "#endif\n\n"
        require(text.count(block) == 1, "Invalid packed-table placement")
        require(text.endswith("\n\n" + GET_LENGTH), "Missing length accessor")
        require(text.count(PACKED_RETURN) == 1, "Packed offset mask changed")
        text = text.replace(block, "", 1)
        text = text[: -len("\n\n" + GET_LENGTH)]
        text = text.replace(PACKED_RETURN, RETURN, 1)
        offsets = [x & MASK for x in values]
    else:
        require("getRegisterNameLength" not in text, "Unmarked length accessor")
        require(text.count(RETURN) == 1, "Original register lookup changed")
        text = text[: table.start()] + text[table.end() :]
        offsets = values

    records = []
    for offset in offsets:
        require(
            offset < len(strings) and offset <= MASK, "Register offset out of range"
        )
        end = strings.find(b"\0", offset)
        require(end >= 0, "Unterminated register name")
        length = end - offset
        require(0 < length < 8, "Register name does not fit the short-copy contract")
        record = offset | (length << SHIFT)
        require(
            record & MASK == offset and record >> SHIFT == length, "Truncated record"
        )
        records.append(record)

    rows = [
        "  " + ", ".join(str(x) for x in records[i : i + 14]) + ","
        for i in range(0, len(records), 14)
    ]
    block = (
        MARKER
        + "#ifndef CAPSTONE_DIET\nstatic const uint16_t RegAsmOffset[] = {\n"
        + "\n".join(rows)
        + "\n};\n#endif\n\n"
    )
    anchor = "/// getRegisterName -"
    require(text.count(anchor) == 1, "Missing register getter anchor")
    text = text.replace(anchor, block + anchor, 1)
    text = text.replace(RETURN, PACKED_RETURN, 1)
    result = text.rstrip() + "\n\n" + GET_LENGTH
    require(string_bytes(result) == strings, "Register string bytes changed")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = ROOT / "arch/X86"
    path = directory / "X86GenRegisterName1.inc"
    enum = (directory / "X86GenRegisterInfo.inc").read_text()
    original = path.read_text()
    expected = generate(original, enum)
    require(generate(expected, enum) == expected, "Non-idempotent register projection")
    if args.check:
        require(original == expected, f"Stale {path}; rerun {Path(__file__).name}")
    elif original != expected:
        path.write_text(expected)


if __name__ == "__main__":
    main()

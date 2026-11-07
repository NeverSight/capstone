#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check the register-length projection's input and regeneration boundaries."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "suite/synctools"))
import x86_register_name_sizes as names


ENUM = "enum { X86_NoRegister, X86_A = 1, X86_B = 2, X86_NUM_TARGET_REGS };"


def source(offsets=(0, 1), spelling="abc"):
    strings = ", ".join(repr(x) for x in spelling) + ", 0,"
    values = ", ".join(str(x) for x in offsets) + ","
    return f"""/// getRegisterName - generated getter
static const char *getRegisterName(unsigned RegNo)
{{
#ifndef CAPSTONE_DIET
  static const char AsmStrs[] = {{ {strings} }};
  static const uint16_t RegAsmOffset[] = {{
    {values}
  }};
  return AsmStrs+RegAsmOffset[RegNo-1];
#else
  return NULL;
#endif
}}
"""


class RegisterNameSizes(unittest.TestCase):
    def test_suffix_sharing_and_idempotence(self):
        original = source()
        projected = names.generate(original, ENUM)
        self.assertEqual(names.generate(projected, ENUM), projected)
        self.assertEqual(names.string_bytes(projected), b"abc\0")
        values = [
            int(x) for x in names.TABLE.search(projected)[1].split(",") if x.strip()
        ]
        self.assertEqual(values, [3 << 13, (2 << 13) | 1])

    def test_explicit_register_zero(self):
        self.assertEqual(
            names.generate(source(), ENUM),
            names.generate(
                source(), ENUM.replace("X86_NoRegister,", "X86_NoRegister = 0,")
            ),
        )

    def test_bad_offsets_and_width(self):
        for offset in [3, 4, 8192, 65536]:
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                names.generate(source((0, offset)), ENUM)

    def test_name_too_long(self):
        with self.assertRaisesRegex(ValueError, "short-copy contract"):
            names.generate(source(spelling="abcdefgh"), ENUM)

    def test_table_count_and_enum_gap(self):
        with self.assertRaisesRegex(ValueError, "count mismatch"):
            names.generate(source((0,)), ENUM)
        with self.assertRaisesRegex(ValueError, "Nonconsecutive"):
            names.generate(source(), ENUM.replace("X86_B = 2", "X86_B = 3"))

    def test_stale_length_is_recomputed(self):
        projected = names.generate(source(), ENUM)
        stale = projected.replace(str(3 << 13), str(2 << 13), 1)
        self.assertNotEqual(stale, projected)
        self.assertEqual(names.generate(stale, ENUM), projected)

    def test_malformed_packed_layout(self):
        projected = names.generate(source(), ENUM)
        variants = [
            projected.replace(names.MARKER, names.MARKER * 2, 1),
            projected.replace("& 8191", "& 4095", 1),
            projected[: -len(names.GET_LENGTH)],
        ]
        for text in variants:
            with self.subTest(text=text[-50:]), self.assertRaises(ValueError):
                names.generate(text, ENUM)

    def test_current_table(self):
        directory = ROOT / "arch/X86"
        text = (directory / "X86GenRegisterName1.inc").read_text()
        enum = (directory / "X86GenRegisterInfo.inc").read_text()
        self.assertEqual(names.generate(text, enum), text)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Reject control flow that cannot be projected as a fixed printer call path."""

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "suite/synctools"))
SPEC = importlib.util.spec_from_file_location(
    "x86_printer_dispatch", ROOT / "suite/synctools/x86_printer_dispatch.py"
)
PRINTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRINTER)

FRAGMENT = """switch ((uint32_t)((Bits >> 14) & 3)) {
  default: // unreachable
  case 0:
    return;
    break;
  case 1:
    printOperand(MI, 0, O);
    SStream_concat0(O, ", ");
    op_addReg(MI, X86_REG_AX);
    op_addAvxSae(MI);
    return;
    break;
  }
"""


class PrinterProjection(unittest.TestCase):
    def test_changed_opcode_setup_cannot_use_precomputed_paths(self):
        directory = ROOT / "arch/X86"
        source = (directory / "X86GenAsmWriter1.inc").read_text()
        enum = (directory / "X86GenInstrInfo.inc").read_text()
        for replacement in [
            "uint64_t Bits = 16384;",
            "uint64_t Bits = 0;\n  opcode++;",
            "uint64_t Bits = 0;\n  Bits ^= MI->flags;",
        ]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                PRINTER.generate(
                    source.replace("uint64_t Bits = 0;", replacement), enum
                )

    def test_calls_literals_and_comments_keep_order(self):
        source = FRAGMENT.replace("return;", "/* case 99: } */ return;", 1) + "}\n"
        result = PRINTER.fragments(source)
        self.assertEqual(result[0][:2], (14, 3))
        self.assertEqual(
            result[0][2][1],
            (
                "printOperand(MI, 0, O);",
                'SStream_concat0(O, ", ");',
                "op_addReg(MI, X86_REG_AX);",
                "op_addAvxSae(MI);",
                "return;",
            ),
        )

    def test_conditional_or_dynamic_calls_are_rejected(self):
        for replacement in [
            "if (MI->flags) printOperand(MI, 0, O);",
            "printOperand(MI, MI->Opcode, O);",
            "MI->flags = 0;",
            "unknown(MI, 0, O);",
            "#ifdef FEATURE\nprintOperand(MI, 0, O);\n#endif",
            "return;\nprintOperand(MI, 0, O);",
        ]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                PRINTER.fragments(
                    FRAGMENT.replace("printOperand(MI, 0, O);", replacement) + "}"
                )

    def test_unowned_and_ambiguous_control_flow_is_rejected(self):
        invalid = [
            FRAGMENT.replace("default:", "default: op_addAvxSae(MI);"),
            FRAGMENT.replace("case 1:", "case 0:"),
            FRAGMENT.replace("case 1:", "case 2:"),
            FRAGMENT.replace("break;", "", 1),
            FRAGMENT.replace("Bits >> 14", "MI->Opcode >> 14"),
            FRAGMENT + "op_addAvxSae(MI);",
            "op_addAvxSae(MI);" + FRAGMENT,
            FRAGMENT[:-4],
        ]
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(ValueError):
                PRINTER.fragments(source + "}")

    def test_generation_include_pair_has_one_owner(self):
        source = PRINTER.TABLE_INCLUDE + "writer\n" + PRINTER.INCLUDE
        self.assertEqual(PRINTER.original_writer(source), "writer\n")
        self.assertEqual(PRINTER.original_writer("writer\n"), "writer\n")
        for invalid in [
            PRINTER.TABLE_INCLUDE,
            PRINTER.INCLUDE,
            source + PRINTER.INCLUDE,
            source + PRINTER.TABLE_INCLUDE,
        ]:
            with self.subTest(source=invalid), self.assertRaises(ValueError):
                PRINTER.original_writer(invalid)


if __name__ == "__main__":
    unittest.main()

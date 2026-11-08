#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check the boundary that makes skipping implicit-register repairs safe."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "x86_mapping_counts", ROOT / "suite/synctools/x86_mapping_counts.py"
)
MAPPING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MAPPING)

GUARD = """if (!(x86_mapping_counts[i] & X86_MAPPING_IMPLICIT_REPAIR))
    goto implicit_registers_done;
"""
LABEL = "implicit_registers_done:\n"
SWITCH = """switch (insn->id) {
default: break;
case X86_INS_LOOP:
case X86_INS_LOOPE:
    switch (mode) { default: break; case CS_MODE_16: repair(); break; }
    break;
case X86_INS_XADD: { set_flags(); break; }
}
"""


class RepairProjection(unittest.TestCase):
    def parse(self, body):
        return MAPPING.implicit_repair_ids(GUARD + body + LABEL)

    def test_nested_modes_comments_and_multiple_switches(self):
        other = """switch (insn->id) {
        case X86_INS_JMP: repair(); break;
        default: /* This default intentionally does nothing. */ break;
        }"""
        self.assertEqual(
            self.parse("/* case X86_INS_MOV: } */\n" + SWITCH + other),
            {"X86_INS_LOOP", "X86_INS_LOOPE", "X86_INS_XADD", "X86_INS_JMP"},
        )

    def test_default_work_cannot_be_skipped(self):
        for replacement in ["default: repair(); break;", "default:"]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.parse(SWITCH.replace("default: break;", replacement, 1))

    def test_unowned_or_conditional_statements_are_rejected(self):
        invalid = [
            "repair();" + SWITCH,
            SWITCH + "repair();",
            SWITCH.replace("switch (insn->id)", "switch (mode)", 1),
            SWITCH.replace(
                "case X86_INS_LOOP:", "#ifdef FEATURE\ncase X86_INS_LOOP:\n#endif"
            ),
            SWITCH.replace("case X86_INS_LOOP:", "case 12:"),
            SWITCH.replace("case X86_INS_LOOP:", "case X86_INS_LOOP + 1:"),
            SWITCH.replace("set_flags();", 'log("}");'),
            SWITCH.replace("default: break;", "", 1),
            SWITCH[:-2],
        ]
        for body in invalid:
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.parse(body)

    def test_missing_or_ambiguous_boundary_is_rejected(self):
        for source in [
            SWITCH,
            GUARD + SWITCH,
            GUARD + SWITCH + LABEL + LABEL,
            GUARD + SWITCH + LABEL + GUARD,
            LABEL + GUARD + SWITCH,
        ]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                MAPPING.implicit_repair_ids(source)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Regression fixtures for the strict type-only mapping projection."""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "mapping_diet_types", ROOT / "suite/synctools/mapping_diet_types.py"
)
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)

TYPES = {
    "CS_OP_INVALID": 0,
    "CS_OP_REG": 1,
    "CS_OP_IMM": 2,
    "CS_OP_MEM": 128,
    "CS_OP_BOUND": 64,
}
ACCESS = {"CS_AC_READ": 1, "CS_AC_WRITE": 2}
ENUM = """#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM
enum { Demo_PHI = 0, Demo_ADD = 1, Demo_DUP = 2, INSTRUCTION_LIST_END = 3 };
#endif
"""
SOURCE = """/* Fixture intentionally includes pseudo, bound, memory, and trailing commas. */
{{{ /* DEMO_PHI (0) - DEMO_INS_INVALID */
0
}}},
{ /* DEMO_ADD (1) - DEMO_INS_ADD */
{
 { CS_OP_REG | CS_OP_BOUND, CS_AC_WRITE, { CS_DATA_TYPE_i64, CS_DATA_TYPE_LAST }, },
 { CS_OP_MEM | CS_OP_IMM | CS_OP_MEM, CS_AC_READ, { CS_DATA_TYPE_i64, CS_DATA_TYPE_LAST } },
 { 0 }
}},
{ /* DEMO_DUP (2) - DEMO_INS_ADD */
{
 { CS_OP_REG | CS_OP_BOUND, CS_AC_WRITE, { CS_DATA_TYPE_i64, CS_DATA_TYPE_LAST } },
 { CS_OP_MEM | CS_OP_IMM, CS_AC_READ, { CS_DATA_TYPE_i64, CS_DATA_TYPE_LAST } },
 { 0 }
}},
"""


def parse(source=SOURCE, enumeration=ENUM, types=TYPES, capacity=16):
    names = GEN.instruction_enum(enumeration, "Demo")
    return GEN.read_mapping(source, names, "Demo", types, ACCESS, capacity, 32)


class MappingDietTypes(unittest.TestCase):
    def test_projection_preserves_flags_and_zero_padding(self):
        rows = parse()
        self.assertEqual(
            rows, [(0,) * 16, (65, 130) + (0,) * 14, (65, 130) + (0,) * 14]
        )
        _, count = GEN.generate(rows, 16, "fixture")
        self.assertEqual(count, 2)

    def test_newlines_do_not_change_rows(self):
        self.assertEqual(parse(), parse(SOURCE.replace("\n", "\r\n")))

    def test_rejects_silent_data_loss(self):
        mutations = [
            SOURCE.replace("DEMO_ADD (1)", "DEMO_ADD (2)"),
            SOURCE.replace("DEMO_ADD (1)", "DEMO_OTHER (1)"),
            SOURCE.replace("CS_OP_BOUND", "CS_OP_UNKNOWN"),
            SOURCE.replace("{ 0 }", "{ CS_OP_REG }", 1),
            SOURCE.replace("CS_DATA_TYPE_LAST", "0", 1),
            SOURCE + "unknown_suffix;\n",
            SOURCE.replace("CS_AC_WRITE", "CS_AC_UNKNOWN", 1),
        ]
        for source in mutations:
            with self.subTest(source=source):
                with self.assertRaises((ValueError, SyntaxError)):
                    parse(source)

    def test_rejects_bad_extents(self):
        with self.assertRaises(ValueError):
            parse(capacity=2)
        with self.assertRaises(ValueError):
            parse(
                enumeration=ENUM.replace(
                    "INSTRUCTION_LIST_END = 3", "INSTRUCTION_LIST_END = 4"
                )
            )
        with self.assertRaises(ValueError):
            parse(types=dict(TYPES, CS_OP_BOUND=256))

    def test_enum_flags_are_derived(self):
        values = GEN.enum_values(
            """typedef enum cs_op_type {
            CS_OP_REG = 1, CS_OP_MEM = 1 << 7,
            CS_OP_MEM_REG = CS_OP_MEM | // Multi-line C enum expression.
                            CS_OP_REG,
        } cs_op_type;""",
            "cs_op_type",
        )
        self.assertEqual(values["CS_OP_MEM_REG"], 129)

    def test_common_enum_header_syntax(self):
        header = (ROOT / "include/capstone/cs_operand.h").read_text()
        types = GEN.enum_values(header, "cs_op_type")
        accesses = GEN.enum_values(header, "cs_ac_type")
        self.assertEqual(
            types["CS_OP_MEM_REG"], types["CS_OP_MEM"] | types["CS_OP_REG"]
        )
        self.assertEqual(
            types["CS_OP_MEM_IMM"], types["CS_OP_MEM"] | types["CS_OP_IMM"]
        )
        self.assertEqual(
            accesses["CS_AC_READ_WRITE"],
            accesses["CS_AC_READ"] | accesses["CS_AC_WRITE"],
        )

    def test_opcode_enum_names(self):
        upper = ENUM.replace("Demo_", "DEMO_")
        self.assertEqual(
            GEN.instruction_enum(upper, "Demo"), ["DEMO_PHI", "DEMO_ADD", "DEMO_DUP"]
        )
        for enumeration in (
            ENUM.replace("Demo_DUP", "Demo_ADD"),
            ENUM.replace("Demo_DUP", "Demo"),
        ):
            with self.subTest(enumeration=enumeration):
                with self.assertRaises(ValueError):
                    GEN.instruction_enum(enumeration, "Demo")


if __name__ == "__main__":
    unittest.main()

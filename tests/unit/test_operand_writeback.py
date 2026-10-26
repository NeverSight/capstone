#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "operand_writeback", ROOT / "suite/synctools/operand_writeback.py"
)
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class WritebackGeneration(unittest.TestCase):
    def test_checkout_newlines(self):
        for arch in ["ARM", "RISCV"]:
            with self.subTest(arch=arch):
                source = ROOT / "arch" / arch / f"{arch}GenInstrInfo.inc"
                expected = GENERATOR.generated_flags(arch, source)
                with tempfile.TemporaryDirectory() as directory:
                    crlf = Path(directory) / source.name
                    crlf.write_bytes(source.read_text().replace("\n", "\r\n").encode())
                    self.assertEqual(GENERATOR.generated_flags(arch, crlf), expected)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "suite/synctools"))
SPEC = importlib.util.spec_from_file_location(
    "aarch64_postprocess", ROOT / "suite/synctools/aarch64_postprocess.py"
)
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class PostprocessGeneration(unittest.TestCase):
    def test_checkout_newlines(self):
        source = ROOT / "arch/AArch64/AArch64GenInstrInfo.inc"
        expected = GENERATOR.generated_flags(source)
        with tempfile.TemporaryDirectory() as directory:
            crlf_source = Path(directory) / source.name
            crlf_source.write_bytes(source.read_text().replace("\n", "\r\n").encode())
            self.assertEqual(GENERATOR.generated_flags(crlf_source), expected)


if __name__ == "__main__":
    unittest.main()

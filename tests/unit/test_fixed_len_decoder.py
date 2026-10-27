#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Generated decoder checks must not depend on checkout newline conversion."""

import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "fixed_len_decoder", ROOT / "suite/synctools/fixed_len_decoder.py"
)
DECODER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DECODER
SPEC.loader.exec_module(DECODER)


class CheckoutNewlines(unittest.TestCase):
    def fixture(self, root, source_newline, generated_newline):
        for arch, prefix, _ in DECODER.BACKENDS:
            for suffix, newline in (
                ("GenDisassemblerTables.inc", source_newline),
                ("GenDirectDecoder.inc", generated_newline),
            ):
                relative = Path("arch") / arch / (prefix + suffix)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                text = (ROOT / relative).read_text(encoding="utf-8")
                path.write_bytes(text.replace("\n", newline).encode("utf-8"))

    def check(self, root):
        with patch.object(DECODER, "ROOT", root):
            with patch.object(sys, "argv", ["fixed_len_decoder.py", "--check"]):
                with contextlib.redirect_stdout(io.StringIO()):
                    DECODER.main()

    def test_lf_and_crlf_checkouts(self):
        for source in ("\n", "\r\n"):
            for generated in ("\n", "\r\n"):
                with self.subTest(source=repr(source), generated=repr(generated)):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        self.fixture(root, source, generated)
                        self.check(root)

    def test_changed_source_still_requires_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "\n", "\n")
            source = root / "arch/AArch64/AArch64GenDisassemblerTables.inc"
            with source.open("a", encoding="utf-8") as stream:
                stream.write("\n/* Changed source. */\n")
            with self.assertRaisesRegex(ValueError, "Stale generated decoder"):
                self.check(root)

    def test_widened_input_contracts_cannot_be_narrowed(self):
        for arch, prefix, suffix, old_type, new_type in (
            ("PowerPC", "PPC", 4, "uint64_t", "uint32_t"),
            ("Mips", "Mips", 2, "uint32_t", "uint16_t"),
            ("Mips", "Mips", 8, "uint64_t", "uint32_t"),
            ("SystemZ", "SystemZ", 8, "uint64_t", "uint32_t"),
        ):
            with self.subTest(arch=arch, suffix=suffix):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.fixture(root, "\n", "\n")
                    source = (
                        root / "arch" / arch / (prefix + "GenDisassemblerTables.inc")
                    )
                    declaration = (
                        f"DecodeInstruction(decodeInstruction_{suffix}, "
                        f"fieldFromInstruction_{suffix}, decodeToMCInst_{suffix}, "
                    )
                    text = source.read_text(encoding="utf-8")
                    self.assertIn(declaration + old_type + ")", text)
                    source.write_text(
                        text.replace(
                            declaration + old_type + ")", declaration + new_type + ")"
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "input width"):
                        self.check(root)


if __name__ == "__main__":
    unittest.main()

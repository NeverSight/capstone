"""Exercise the public CLI extension spelling, including rejected extensions."""

import pathlib
import subprocess
import sys
import unittest

CSTOOL = str(pathlib.Path(sys.argv.pop(1)).resolve())


class BitManipulationOption(unittest.TestCase):
    def run_tool(self, arch, code):
        return subprocess.run([CSTOOL, arch, code], capture_output=True, text=True)

    def test_b_extension_members(self):
        for bits in (32, 64):
            for code, mnemonic in (
                ("b3227320", "sh1add"),
                ("b3727340", "andn"),
                ("b3127348", "bclr"),
            ):
                with self.subTest(bits=bits, mnemonic=mnemonic):
                    result = self.run_tool(f"riscv{bits}+bitmanip", code)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertRegex(result.stdout, rf"\b{mnemonic}\s+t0, t1, t2\b")
                    disabled = self.run_tool(f"riscv{bits}", code)
                    self.assertNotEqual(disabled.returncode, 0, disabled.stdout)

    def test_carryless_multiply_remains_a_separate_extension(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                disabled = self.run_tool(f"riscv{bits}+bitmanip", "b312730a")
                self.assertNotEqual(disabled.returncode, 0, disabled.stdout)
                enabled = self.run_tool(f"riscv{bits}+bitmanip+zbc", "b312730a")
                self.assertEqual(enabled.returncode, 0, enabled.stderr)
                self.assertRegex(enabled.stdout, r"\bclmul\s+t0, t1, t2\b")

    def test_a_extension_is_not_selected_by_a_letter_in_another_option(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                for suffix in ("+bitmanip", "+zba"):
                    disabled = self.run_tool(f"riscv{bits}{suffix}", "af227300")
                    self.assertNotEqual(disabled.returncode, 0, disabled.stdout)
                enabled = self.run_tool(f"riscv{bits}+bitmanip+a", "af227300")
                self.assertEqual(enabled.returncode, 0, enabled.stderr)
                self.assertRegex(enabled.stdout, r"\bamoadd\.w\s+t0, t2, \(t1\)")


if __name__ == "__main__":
    unittest.main()

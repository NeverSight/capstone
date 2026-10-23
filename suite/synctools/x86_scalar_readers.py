#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Specialize scalar operand reading and translation from x86 descriptors."""

import argparse
from collections import defaultdict
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
X86 = ROOT / "arch" / "X86"
OUTPUT = X86 / "X86GenScalarOperandRead.inc"
TRANSLATE_OUTPUT = X86 / "X86GenScalarOperandTranslate.inc"

# Register-immediates, scaled displacements, VSIB, and implicit operands stay
# with the generic reader. These types cannot split an immediate into operands.
TYPES = {
    "TYPE_R8",
    "TYPE_R16",
    "TYPE_R32",
    "TYPE_R64",
    "TYPE_Rv",
    "TYPE_M",
    "TYPE_REL",
    "TYPE_RELv",
    "TYPE_IMM",
    "TYPE_UIMM8",
}
IMMEDIATES = {
    "ENCODING_IB": "1",
    "ENCODING_IW": "2",
    "ENCODING_ID": "4",
    "ENCODING_IO": "8",
    "ENCODING_Iv": "insn->immediateSize",
}
REGISTERS = {
    "ENCODING_RB": "1",
    "ENCODING_RW": "2",
    "ENCODING_RD": "4",
    "ENCODING_RO": "8",
    "ENCODING_Rv": "0",
}
ENCODINGS = {"ENCODING_REG", "ENCODING_RM"} | IMMEDIATES.keys() | REGISTERS.keys()


def read_sets(path, *, include_duplicates=False):
    text = path.read_text(encoding="utf-8")
    body = text.split(
        "static const struct OperandSpecifier x86OperandSets[][6] = {", 1
    )[1].split("\n};", 1)[0]
    rows = re.findall(r"\{ /\* (\d+) \*/(.*?)\n  \}", body, re.S)
    if not rows:
        raise ValueError(f"No operand sets in {path}")
    result = []
    for expected, (index, row) in enumerate(rows):
        if int(index) != expected:
            raise ValueError(f"Non-contiguous operand sets in {path}: {index}")
        operands = re.findall(r"\{ (ENCODING_\w+), (TYPE_\w+) \}", row)
        if len(operands) != 6:
            raise ValueError(f"Expected six operands in {path}, set {index}")
        active = []
        ended = False
        for encoding, operand_type in operands:
            if encoding == "ENCODING_NONE":
                ended = True
            elif ended:
                raise ValueError(f"Non-trailing padding in {path}, set {index}")
            elif encoding != "ENCODING_DUP" or include_duplicates:
                # DUP does not read bytes or change state; translation still
                # expands it through the original operand descriptor.
                active.append((encoding, operand_type))
        result.append(tuple(active))
    return result


def emit_switch(suffix):
    groups = defaultdict(list)
    for index, operands in enumerate(
        read_sets(X86 / f"X86GenDisassemblerTables{suffix}.inc")
    ):
        if len(operands) <= 2 and all(
            encoding in ENCODINGS and operand_type in TYPES
            for encoding, operand_type in operands
        ):
            groups[operands].append(index)

    lines = ["switch (insn->spec->operands) {"]
    for operands, indices in groups.items():
        lines.extend(f"case {index}:" for index in indices)
        calls = []
        has_modrm = False
        for encoding, operand_type in operands:
            if encoding in {"ENCODING_REG", "ENCODING_RM"} and not has_modrm:
                calls.append("(!insn->consumedModRM && readModRM(insn))")
                has_modrm = True
            if encoding == "ENCODING_REG":
                calls.append(f"fixupRegisterOperand(insn, {operand_type})")
            elif encoding == "ENCODING_RM":
                calls.append(f"fixupRMOperand(insn, {operand_type}, ENCODING_RM)")
            elif encoding in IMMEDIATES:
                calls.append(f"readImmediate(insn, {IMMEDIATES[encoding]})")
            else:
                calls.append(f"readOpcodeRegister(insn, {REGISTERS[encoding]})")
        if calls:
            lines.append("\tif (" + " ||\n\t    ".join(calls) + ")")
            lines.append("\t\treturn -1;")
        lines.append("\treturn needVVVV ? -1 : 0;")
    lines.extend(["default:", "\tbreak;", "}"])
    return "\n".join(lines)


def resolve_duplicates(operands):
    def resolve(index, visited=()):
        if index < 0 or index >= len(operands) or index in visited:
            raise ValueError("Invalid duplicate operand reference")
        encoding, operand_type = operands[index]
        if encoding == "ENCODING_DUP":
            if not re.fullmatch(r"TYPE_DUP[0-5]", operand_type):
                raise ValueError(f"Invalid duplicate type: {operand_type}")
            return resolve(int(operand_type[len("TYPE_DUP") :]), visited + (index,))
        return encoding, operand_type

    return tuple(resolve(index) for index in range(len(operands)))


def emit_translation(suffix):
    groups = defaultdict(list)
    for index, operands in enumerate(
        read_sets(
            X86 / f"X86GenDisassemblerTables{suffix}.inc", include_duplicates=True
        )
    ):
        # Translation emits duplicates in their original positions, including
        # forward references. Scalar immediate types cannot change the opcode.
        operands = resolve_duplicates(operands)
        if (
            len(operands) <= 3
            and sum(encoding in IMMEDIATES for encoding, _ in operands) <= 2
            and all(
                encoding in ENCODINGS and operand_type in TYPES
                for encoding, operand_type in operands
            )
        ):
            groups[operands].append(index)

    lines = ["switch (insn->spec->operands) {"]
    for operands, indices in groups.items():
        lines.extend(f"case {index}:" for index in indices)
        lines.append("{")
        for index, (encoding, operand_type) in enumerate(operands):
            lines.append(
                f"\tstatic const OperandSpecifier op{index} = "
                f"{{ {encoding}, {operand_type} }};"
            )
        for index, (encoding, _) in enumerate(operands):
            if encoding in IMMEDIATES:
                lines.extend(
                    [
                        "\ttranslateImmediate(",
                        "\t\tmcInst, insn->immediates[insn->numImmediatesTranslated++],",
                        f"\t\t&op{index}, insn);",
                    ]
                )
                continue
            function = (
                "translateRegRegister"
                if encoding == "ENCODING_REG"
                else (
                    "translateRM"
                    if encoding == "ENCODING_RM"
                    else "translateOpcodeRegister"
                )
            )
            lines.extend(
                [
                    f"\tif ({function}(mcInst, &op{index}, insn))",
                    "\t\treturn true;",
                ]
            )
        lines.extend(["\treturn false;", "}"])
    lines.extend(["default:", "\tbreak;", "}"])
    return "\n".join(lines)


def generated_output(emit):
    return (
        "/* Capstone Disassembly Engine */\n"
        "/* SPDX-License-Identifier: BSD-3-Clause */\n"
        "/* Generated by suite/synctools/x86_scalar_readers.py; do not edit. */\n\n"
        "#ifdef CAPSTONE_X86_REDUCE\n"
        + emit("_reduce")
        + "\n#else\n"
        + emit("")
        + "\n#endif\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="reject stale output")
    args = parser.parse_args()
    outputs = [(OUTPUT, emit_switch), (TRANSLATE_OUTPUT, emit_translation)]
    for path, emit in outputs:
        output = generated_output(emit)
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != output:
                parser.exit(1, f"{path} is stale; run {Path(__file__).name}\n")
        else:
            path.write_text(output, encoding="utf-8")


if __name__ == "__main__":
    main()

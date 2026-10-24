#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Specialize operand reading and translation from x86 descriptors."""

import argparse
from collections import defaultdict
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
X86 = ROOT / "arch" / "X86"
OUTPUT = X86 / "X86GenOperandRead.inc"
TRANSLATE_OUTPUT = X86 / "X86GenOperandTranslate.inc"
SCAN_OUTPUT = X86 / "X86GenOperandScan.inc"

# These scalar immediate types cannot split an immediate into registers.
# Register-immediates and opcode-changing predicates stay with the generic reader.
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


RM_ENCODINGS = {"ENCODING_RM"} | {f"ENCODING_RM_CD{n}" for n in (2, 4, 8, 16, 32, 64)}
VSIB_ENCODINGS = {"ENCODING_VSIB"} | {
    f"ENCODING_VSIB_CD{n}" for n in (2, 4, 8, 16, 32, 64)
}
VECTOR_ENCODINGS = (
    RM_ENCODINGS - {"ENCODING_RM"}
    | VSIB_ENCODINGS
    | {"ENCODING_VVVV", "ENCODING_WRITEMASK"}
)


def read_specializations(suffix):
    for index, operands in enumerate(
        read_sets(X86 / f"X86GenDisassemblerTables{suffix}.inc")
    ):
        vector = any(t in VECTOR_TYPES or e in VECTOR_ENCODINGS for e, t in operands)
        if (
            len(operands) <= (4 if vector else 2)
            and sum(e in IMMEDIATES for e, _ in operands) <= 2
            and all(
                encoding in (ENCODINGS | VECTOR_ENCODINGS)
                and operand_type in (TYPES | VECTOR_TYPES)
                and (encoding not in IMMEDIATES or operand_type in TYPES)
                for encoding, operand_type in operands
            )
        ):
            yield index, operands


def read_operand_calls(operands):
    calls = []
    has_modrm = False
    for encoding, operand_type in operands:
        if encoding in ({"ENCODING_REG"} | RM_ENCODINGS) and not has_modrm:
            calls.append("(!insn->consumedModRM && readModRM(insn))")
            has_modrm = True
        if encoding == "ENCODING_REG":
            calls.append(f"fixupRegisterOperand(insn, {operand_type})")
        elif encoding in RM_ENCODINGS:
            calls.append(f"fixupRMOperand(insn, {operand_type}, {encoding})")
        elif encoding in VSIB_ENCODINGS:
            calls.append(
                f"readVSIBOperand(insn, {operand_type}, {encoding}, hasVVVV, &needVVVV)"
            )
            has_modrm = True
        elif encoding == "ENCODING_VVVV":
            calls.append(f"readVVVVOperand(insn, {operand_type}, hasVVVV, &needVVVV)")
        elif encoding == "ENCODING_WRITEMASK":
            calls.append("readMaskRegister(insn)")
        elif encoding in IMMEDIATES:
            calls.append(f"readImmediate(insn, {IMMEDIATES[encoding]})")
        else:
            calls.append(f"readOpcodeRegister(insn, {REGISTERS[encoding]})")
    return calls


def emit_switch(suffix):
    groups = defaultdict(list)
    for index, operands in read_specializations(suffix):
        groups[operands].append(index)

    lines = ["switch (insn->spec->operands) {"]
    for operands, indices in groups.items():
        lines.extend(f"case {index}:" for index in indices)
        calls = read_operand_calls(operands)
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


VECTOR_TYPES = {
    "TYPE_XMM",
    "TYPE_YMM",
    "TYPE_ZMM",
    "TYPE_MM64",
    "TYPE_VK",
    "TYPE_MVSIBX",
    "TYPE_MVSIBY",
    "TYPE_MVSIBZ",
}


def translation_operand(operand):
    encoding, operand_type = operand
    if encoding in (RM_ENCODINGS - {"ENCODING_RM"}) | VSIB_ENCODINGS:
        encoding = "ENCODING_RM"
    return encoding, operand_type


def translation_specializations(suffix):
    for index, operands in enumerate(
        read_sets(
            X86 / f"X86GenDisassemblerTables{suffix}.inc", include_duplicates=True
        )
    ):
        # Translation emits duplicates in their original positions, including
        # forward references. Selected immediate types cannot change the opcode.
        operands = tuple(translation_operand(op) for op in resolve_duplicates(operands))
        vector = any(
            t in VECTOR_TYPES or e in {"ENCODING_VVVV", "ENCODING_WRITEMASK"}
            for e, t in operands
        )
        if (
            len(operands) <= (5 if vector else 3)
            and sum(encoding in IMMEDIATES for encoding, _ in operands) <= 2
            and all(
                encoding in (ENCODINGS | {"ENCODING_VVVV", "ENCODING_WRITEMASK"})
                and operand_type in (TYPES | VECTOR_TYPES)
                and (encoding not in IMMEDIATES or operand_type in TYPES)
                for encoding, operand_type in operands
            )
        ):
            yield index, operands


def translation_body(operands, *, emit_operands="emitOperands", failure_result="true"):
    lines = []
    for index, (encoding, operand_type) in enumerate(operands):
        if encoding in {"ENCODING_VVVV", "ENCODING_WRITEMASK"}:
            continue
        lines.append(
            f"\tstatic const OperandSpecifier op{index} = "
            f"{{ {encoding}, {operand_type} }};"
        )
    for index, (encoding, _) in enumerate(operands):
        if encoding == "ENCODING_VVVV":
            lines.append(f"\ttranslateRegister(mcInst, insn->vvvv, {emit_operands});")
            continue
        if encoding == "ENCODING_WRITEMASK":
            lines.extend(
                [
                    f"\tif (translateMaskRegister(mcInst, insn->writemask, {emit_operands}))",
                    f"\t\treturn {failure_result};",
                ]
            )
            continue
        if encoding in IMMEDIATES:
            lines.extend(
                [
                    "\ttranslateImmediate(",
                    "\t\tmcInst, insn->immediates[insn->numImmediatesTranslated++],",
                    f"\t\t&op{index}, insn, {emit_operands});",
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
                f"\tif ({function}(mcInst, &op{index}, insn, {emit_operands}))",
                f"\t\treturn {failure_result};",
            ]
        )
    return lines


def emit_translation(suffix):
    groups = defaultdict(list)
    for index, operands in translation_specializations(suffix):
        groups[operands].append(index)

    lines = ["switch (insn->spec->operands) {"]
    for operands, indices in groups.items():
        lines.extend(f"case {index}:" for index in indices)
        lines.append("{")
        lines.extend(translation_body(operands))
        lines.extend(["\treturn false;", "}"])
    lines.extend(["default:", "\tbreak;", "}"])
    return "\n".join(lines)


def emit_scan(suffix):
    translations_by_index = dict(translation_specializations(suffix))
    groups = defaultdict(list)
    for index, operands in read_specializations(suffix):
        # Bound the fused code to scalar and three-operand VEX shapes.
        scalar = all(
            encoding in ENCODINGS and operand_type in TYPES
            for encoding, operand_type in operands
        )
        vex = (
            len(operands) == 3
            and {encoding for encoding, _ in operands}
            in (
                {"ENCODING_REG", "ENCODING_VVVV", "ENCODING_RM"},
                {"ENCODING_REG", "ENCODING_VVVV", "ENCODING_VSIB"},
            )
            and all(
                operand_type
                in TYPES | {"TYPE_XMM", "TYPE_YMM", "TYPE_MVSIBX", "TYPE_MVSIBY"}
                for _, operand_type in operands
            )
        )
        if index in translations_by_index and (scalar or vex):
            # DUP is absent from the read sequence but remains significant to
            # translation order and multiplicity. Both sequences identify a case.
            groups[(operands, translations_by_index[index])].append(index)

    lines = ["switch (insn->spec->operands) {"]
    for (reads, translations), indices in groups.items():
        lines.extend(f"case {index}:" for index in indices)
        lines.append("{")
        # A selection miss goes directly to the generic reader's own setup.
        lines.extend(
            [
                "\tint hasVVVV, needVVVV;",
                "",
                "\tinsn->operands = &x86OperandSets[insn->spec->operands][0];",
                "\thasVVVV = !readVVVV(insn);",
                "\tneedVVVV = hasVVVV && (insn->vvvv != 0);",
            ]
        )
        calls = read_operand_calls(reads)
        if calls:
            lines.append("\tif (" + " ||\n\t    ".join(calls) + ")")
            lines.append("\t\treturn X86_SCAN_INVALID;")
        lines.extend(
            [
                "\tif (needVVVV || finishDecodedInstruction(insn))",
                "\t\treturn X86_SCAN_INVALID;",
                "\t*size = (uint16_t)insn->length;",
                "\tif (beginTranslation(mcInst, insn))",
                "\t\treturn X86_SCAN_INVALID;",
            ]
        )
        lines.extend(
            translation_body(
                translations, emit_operands="false", failure_result="X86_SCAN_INVALID"
            )
        )
        lines.extend(["\treturn X86_SCAN_COMPLETE;", "}"])
    lines.extend(["default:", "\tbreak;", "}"])
    return "\n".join(lines)


def generated_output(emit):
    return (
        "/* Capstone Disassembly Engine */\n"
        "/* SPDX-License-Identifier: BSD-3-Clause */\n"
        "/* Generated by suite/synctools/x86_operand_specializations.py; do not edit. */\n\n"
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
    outputs = [
        (OUTPUT, emit_switch),
        (TRANSLATE_OUTPUT, emit_translation),
        (SCAN_OUTPUT, emit_scan),
    ]
    for path, emit in outputs:
        output = generated_output(emit)
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != output:
                parser.exit(1, f"{path} is stale; run {Path(__file__).name}\n")
        else:
            path.write_text(output, encoding="utf-8")


if __name__ == "__main__":
    main()

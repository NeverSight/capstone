#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Specialize operand reading and translation from x86 descriptors."""

import argparse
from collections import defaultdict
from pathlib import Path
import re

import x86_disassembler_tables as tables

ROOT = Path(__file__).resolve().parents[2]
X86 = ROOT / "arch" / "X86"
OUTPUT = X86 / "X86GenOperandRead.inc"
TRANSLATE_OUTPUT = X86 / "X86GenOperandTranslate.inc"
SCAN_OUTPUT = X86 / "X86GenOperandScan.inc"
TERMINAL_OUTPUT = X86 / "X86GenLegacyTerminal.inc"
TERMINAL_UID_BITS = 14
TERMINAL_OPERAND_BITS = 10
TERMINAL_HANDLER_SHIFT = TERMINAL_UID_BITS + TERMINAL_OPERAND_BITS
TERMINAL_BITS = 31
TERMINAL_SPLIT = 1 << 62
TERMINAL_INDEXED = 1 << 63
# Row name, primary attributes, 16-bit mode, operand-size override.
TERMINAL_ROWS = (
    ("X86_TERMINAL_32", 0, False, False),
    ("X86_TERMINAL_64", 1, False, False),
    ("X86_TERMINAL_64_REXW", 9, False, False),
    ("X86_TERMINAL_32_OPSIZE", 16, False, True),
    ("X86_TERMINAL_32_ADSIZE", 32, False, False),
    ("X86_TERMINAL_32_OPSIZE_ADSIZE", 48, False, True),
    ("X86_TERMINAL_64_OPSIZE", 17, False, True),
    ("X86_TERMINAL_64_ADSIZE", 33, False, False),
    ("X86_TERMINAL_64_OPSIZE_ADSIZE", 49, False, True),
    ("X86_TERMINAL_64_REXW_OPSIZE", 25, False, True),
    ("X86_TERMINAL_16", 0, True, False),
    ("X86_TERMINAL_16_OPSIZE", 0, True, True),
    ("X86_TERMINAL_16_ADSIZE", 32, True, False),
    ("X86_TERMINAL_16_OPSIZE_ADSIZE", 32, True, True),
)

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
    "TYPE_MOFFS",
}
IMMEDIATES = {
    "ENCODING_IB": "1",
    "ENCODING_IW": "2",
    "ENCODING_ID": "4",
    "ENCODING_IO": "8",
    "ENCODING_Iv": "insn->immediateSize",
    "ENCODING_Ia": "insn->addressSize",
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


def read_operand_calls(operands, *, materialize=True):
    calls = []
    has_modrm = False
    for encoding, operand_type in operands:
        if not materialize:
            tables.require(
                encoding in ENCODINGS and operand_type in TYPES,
                "Compact readers require ordinary scalar operands",
            )
        if encoding in ({"ENCODING_REG"} | RM_ENCODINGS) and not has_modrm:
            reader = "readModRM" if materialize else "readModRMScan"
            calls.append(f"(!insn->consumedModRM && {reader}(insn))")
            has_modrm = True
        if encoding == "ENCODING_REG":
            if materialize:
                calls.append(f"fixupRegisterOperand(insn, {operand_type})")
        elif encoding in RM_ENCODINGS:
            if materialize:
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
        elif encoding == "ENCODING_Ia":
            calls.append(
                f"readMemoryOffset(insn, {'true' if materialize else 'false'})"
            )
        elif encoding in IMMEDIATES:
            reader = (
                f"readImmediate(insn, {IMMEDIATES[encoding]})"
                if materialize
                else f"readImmediateImpl(insn, {IMMEDIATES[encoding]}, false)"
            )
            calls.append(reader)
        elif materialize:
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
                "\tif (needVVVV || finishDecodedInstruction(insn, true))",
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


def instruction_specifiers(source):
    matches = re.findall(
        r"static const struct InstructionSpecifier x86DisassemblerInstrSpecifiers"
        r"\[(\d+)\] = \{(.*?)\n\};",
        source,
        re.S,
    )
    tables.require(len(matches) == 1, "Expected one instruction specifier table")
    bound, body = matches[0]
    entries = tables.scan_entries(
        tables.uncomment(body),
        re.compile(r"\s*\{\s*(\d+)\s*,\s*\}\s*,"),
        "instruction specifier",
    )
    tables.require(len(entries) == int(bound), "Instruction specifier count changed")
    return [tables.integer_value(value, "operand set") for (value,) in entries]


def equivalents16(suffix):
    lookup16 = (X86 / f"X86Lookup16{suffix}.inc").read_text()
    pair_body = lookup16.split(
        "static const x86_op_id_pair x86_16_bit_eq_tbl[] = {", 1
    )[1].split("};", 1)[0]
    pairs = [
        tuple(tables.integer_value(value, "16-bit equivalence pair") for value in pair)
        for pair in tables.scan_entries(
            tables.uncomment(pair_body),
            re.compile(r"\s*\{\s*(\d+),\s*(\d+)\s*\}\s*,"),
            "16-bit equivalence pair",
        )
    ]
    lookup_body = lookup16.split("static const uint16_t x86_16_bit_eq_lookup[] = {", 1)[
        1
    ].split("};", 1)[0]
    lookup = tables.numeric_values(
        tables.uncomment(lookup_body), "16-bit equivalence index"
    )
    equivalent = set()
    # Follow the actual lookup ranges, just as is16BitEquivalent does.
    for uid, first in enumerate(lookup):
        tables.require(first <= len(pairs), "16-bit equivalence index out of bounds")
        if first:
            i = first - 1
            while i < len(pairs) and pairs[i][0] == uid:
                equivalent.add(pairs[i])
                i += 1
    return equivalent


def packed_terminal(terminal):
    uid, operands, handler = terminal
    tables.require(0 <= uid < (1 << TERMINAL_UID_BITS), "Terminal UID exceeds storage")
    tables.require(
        0 <= operands < (1 << TERMINAL_OPERAND_BITS),
        "Terminal operand set exceeds storage",
    )
    tables.require(
        0 <= handler < (1 << (TERMINAL_BITS - TERMINAL_HANDLER_SHIFT)),
        "Terminal handler exceeds storage",
    )
    return uid | (operands << TERMINAL_UID_BITS) | (handler << TERMINAL_HANDLER_SHIFT)


def packed_terminal_decision(first, kind, words, kinds):
    if not first:
        return 0
    if kind == "MODRM_ONEENTRY":
        return words[first]
    if kind == "MODRM_SPLITRM":
        return words[first] | (words[first + 1] << TERMINAL_BITS) | TERMINAL_SPLIT
    tables.require(first <= tables.OFFSET_MASK, "Terminal offset exceeds storage")
    return TERMINAL_INDEXED | (kinds[kind] << tables.TYPE_SHIFT) | first


def public_instruction_ids(suffix):
    header = (ROOT / "include/capstone/x86.h").read_text()
    body = header.split("typedef enum x86_insn {", 1)[1].split("} x86_insn;", 1)[0]
    public = {}
    value = -1
    for name, assigned in tables.scan_entries(
        tables.uncomment(body),
        re.compile(r"\s*(X86_INS_\w+)(?:\s*=\s*(0x[0-9a-fA-F]+|\d+))?\s*,"),
        "public instruction ID",
    ):
        value = int(assigned, 0) if assigned is not None else value + 1
        tables.require(name not in public, "Duplicate public instruction ID")
        public[name] = value
    tables.require(public["X86_INS_INVALID"] == 0, "Invalid public ID changed")
    source = (X86 / f"X86GenInstrInfo{suffix}.inc").read_text()
    body = source.split("enum {", 1)[1].split("};", 1)[0]
    internal = {
        name: int(value)
        for name, value in tables.scan_entries(
            tables.uncomment(body),
            re.compile(r"\s*(X86_\w+)\s*=\s*(\d+)\s*(?:,|$)"),
            "internal instruction ID",
        )
    }
    mapping = {}
    source = tables.uncomment((X86 / f"X86MappingInsn{suffix}.inc").read_text())
    for name, public_name in re.findall(
        r"\{\s*(X86_\w+)\s*,\s*(X86_INS_\w+)\s*,", source
    ):
        uid, mapid = internal[name], public[public_name]
        tables.require(uid not in mapping, "Duplicate mapped instruction ID")
        tables.require(
            0 < mapid < (1 << TERMINAL_UID_BITS), "Public ID exceeds terminal storage"
        )
        mapping[uid] = mapid
    return mapping


def emit_terminal_tables(name, words, rows, kinds):
    alignment = " X86_DECODE_ALIGN" if name == "LegacyPublic" else ""
    lines = [f"static const uint32_t x86{name}Terminals[]{alignment} = {{"]
    lines += [
        "\t" + ", ".join(f"0x{word:08x}u" for word in words[start : start + 8]) + ","
        for start in range(0, len(words), 8)
    ]
    lines += [
        "};",
        f"static const uint64_t x86{name}Decisions[X86_TERMINAL_ROW_COUNT][2][256]{alignment} = {{",
    ]
    for row_maps in rows:
        lines.append("{")
        for row in row_maps:
            lines.append("{")
            values = []
            for first, kind in row:
                word = packed_terminal_decision(first, kind, words, kinds)
                values.append(f"UINT64_C(0x{word:016x})" if word else "0")
            lines += [
                "\t" + ", ".join(values[start : start + 4]) + ","
                for start in range(0, 256, 4)
            ]
            lines.append("},")
        lines.append("},")
    return lines + ["};", ""]


def scalar_terminal_form(operands, modrm):
    """Prove that checked ordinary-legacy reads produce legal scan operands.

    REX extends GPR indices only to 15, and 16-bit addressing cannot have REX.
    Every successfully read legacy address has a valid base/index. Explicitly
    exclude operand classes that require a further check or change the opcode.
    """
    gprs = {"TYPE_R8", "TYPE_R16", "TYPE_R32", "TYPE_R64", "TYPE_Rv"}
    immediates = {"TYPE_REL", "TYPE_RELv", "TYPE_IMM", "TYPE_UIMM8"}
    for encoding, operand_type in operands:
        if encoding == "ENCODING_RM":
            if operand_type not in gprs | {"TYPE_M"}:
                return False
            if (operand_type == "TYPE_M") == (modrm >= 0xC0):
                return False
        elif encoding == "ENCODING_REG" or encoding in REGISTERS:
            if operand_type not in gprs:
                return False
        elif encoding == "ENCODING_Ia":
            if operand_type != "TYPE_MOFFS":
                return False
        elif encoding in IMMEDIATES:
            if operand_type not in immediates:
                return False
        else:
            return False
    return True


def legacy_terminal_model(suffix):

    common = (X86 / "X86DisassemblerDecoderCommon.h").read_text()
    contexts, kinds, names = tables.parse_common(common)
    source = (X86 / f"X86GenDisassemblerTables{suffix}.inc").read_text()
    ids = tables.parse_ids(source, contexts)
    maps = tables.parse_maps(
        (X86 / f"X86GenDisassemblerTables{suffix}2.inc").read_text(),
        names[:4] if suffix else names,
        len(contexts),
    )
    specifiers = instruction_specifiers(source)
    reads = dict(read_specializations(suffix))
    translations = dict(translation_specializations(suffix))
    selected = {
        i: (ops, translations[i])
        for i, ops in reads.items()
        if i in translations and all(e in ENCODINGS and t in TYPES for e, t in ops)
    }
    ud1 = int(
        re.search(
            r"X86_UD1\s*=\s*(\d+)", (X86 / f"X86GenInstrInfo{suffix}.inc").read_text()
        )[1]
    )
    groups = {}
    terminals = [(0, 0, 0)]
    sequences = {}
    rows = []
    selected_counts = []
    # Match the primary and secondary contexts of getIDForMode.
    context_body = (
        source.split("static const uint8_t x86DisassemblerContexts[", 1)[1]
        .split("\n};", 1)[0]
        .split("{", 1)[1]
    )
    context_values = tables.comma_values(
        tables.uncomment(context_body), "attribute contexts"
    )
    # Keep the runtime row selector tied to the attribute definitions. A change
    # to these attributes must update the selector and generator together.
    attributes = dict(re.findall(r"ENUM_ENTRY\((ATTR_\w+),\s*([^\n]+?)\)", common))
    tables.require(
        [
            attributes.get(name)
            for name in (
                "ATTR_NONE",
                "ATTR_64BIT",
                "ATTR_REXW",
                "ATTR_OPSIZE",
                "ATTR_ADSIZE",
            )
        ]
        == ["0x00", "(0x1 << 0", "(0x1 << 3", "(0x1 << 4", "(0x1 << 5"],
        "Terminal attribute values changed",
    )
    tables.require(
        [context_values[i] for i in (0, 1, 9, 16, 32, 48)]
        == [
            "IC",
            "IC_64BIT",
            "IC_64BIT_REXW",
            "IC_OPSIZE",
            "IC_ADSIZE",
            "IC_OPSIZE_ADSIZE",
        ],
        "Terminal attribute contexts changed",
    )
    equivalent = equivalents16(suffix)
    for _, attr_mask, mode16, has_op_size in TERMINAL_ROWS:
        context_name = context_values[attr_mask]
        row_maps = []
        for name, indices, source_rows in maps[:2]:
            number = indices[contexts.index(context_name)]
            source_row = (
                source_rows[number - 1] if number else (("MODRM_ONEENTRY", 0),) * 256
            )
            if mode16:
                second_number = indices[contexts.index(context_values[attr_mask | 16])]
                second_row = (
                    source_rows[second_number - 1]
                    if second_number
                    else (("MODRM_ONEENTRY", 0),) * 256
                )
            row = []
            for opcode, (kind, offset) in enumerate(source_row):
                count = {
                    "MODRM_ONEENTRY": 1,
                    "MODRM_SPLITRM": 2,
                    "MODRM_SPLITREG": 16,
                    "MODRM_SPLITMISC": 72,
                    "MODRM_FULL": 256,
                }[kind]
                uids = tuple(ids[offset : offset + count])
                tables.require(len(uids) == count, "Incomplete terminal sequence")
                if mode16:
                    second_kind, second_offset = second_row[opcode]
                    # Equal kinds preserve both lookups' ordered reads: either
                    # neither reads ModR/M, or the second reuses the first read.
                    # A secondary read that could fail independently stays in
                    # getIDForMode, as do its address-size repairs.
                    if (
                        kind != second_kind
                        or (
                            name == names[0]
                            and (opcode == 0xE3 or 0xA0 <= opcode <= 0xA3)
                        )
                        or (name == names[1] and opcode == 0xAE)
                    ):
                        row.append((0, "MODRM_ONEENTRY"))
                        continue
                    other_uids = ids[second_offset : second_offset + count]
                    tables.require(
                        len(other_uids) == count,
                        "Incomplete secondary terminal sequence",
                    )
                    uids = tuple(
                        b if not has_op_size and (a, b) in equivalent else a
                        for a, b in zip(uids, other_uids)
                    )
                if (
                    # UD1 overrides its generated descriptor at runtime.
                    ud1 in uids
                    or not any(uids)
                    or any(uid and specifiers[uid] not in selected for uid in uids)
                ):
                    row.append((0, "MODRM_ONEENTRY"))
                    continue
                # Prove both reader and translator requirements for every
                # selected ModR/M, including duplicates. A future descriptor
                # that needs another validation keeps the generic path.
                safe = True
                for modrm in range(256):
                    uid = uids[tables.source_id(range(256), kind, 0, modrm)]
                    if uid:
                        read_ops, translate_ops = selected[specifiers[uid]]
                        safe &= scalar_terminal_form(read_ops + translate_ops, modrm)
                if not safe:
                    row.append((0, "MODRM_ONEENTRY"))
                    continue
                key = (kind, uids)
                if key not in sequences:
                    sequences[key] = len(terminals)
                    for uid in uids:
                        operands = specifiers[uid]
                        shape = selected.get(operands)
                        if uid and shape not in groups:
                            groups[shape] = len(groups) + 1
                        terminals.append((uid, operands, groups[shape] if uid else 0))
                first = sequences[key]
                row.append((first, kind))
                # Exhaust every ModR/M selection, including invalid IDs. The
                # decision kind separately retains the ordered read requirement.
                for modrm in range(256):
                    delta = tables.source_id(range(256), kind, 0, modrm)
                    expected = tables.source_id(ids, kind, offset, modrm)
                    if mode16:
                        second = tables.source_id(
                            ids, second_kind, second_offset, modrm
                        )
                        if not has_op_size and (expected, second) in equivalent:
                            expected = second
                    tables.require(
                        terminals[first + delta][0] == expected,
                        "Terminal ID mismatch",
                    )
                    tables.require(
                        terminals[first + delta][1]
                        == specifiers[terminals[first + delta][0]],
                        "Terminal descriptor mismatch",
                    )
            selected_counts.append(sum(bool(first) for first, _ in row))
            row_maps.append(row)
        rows.append(row_maps)
    words = [packed_terminal(t) for t in terminals]
    reverse_kinds = {value: key for key, value in kinds.items()}
    for row_maps in rows:
        for row in row_maps:
            for first, kind in row:
                if not first:
                    continue
                word = packed_terminal_decision(first, kind, words, kinds)
                tables.require(
                    bool(word & (TERMINAL_INDEXED | TERMINAL_SPLIT))
                    == (kind != "MODRM_ONEENTRY"),
                    "Terminal read requirement changed",
                )
                for modrm in range(256):
                    expected = terminals[
                        first + tables.source_id(range(256), kind, 0, modrm)
                    ]
                    if word & TERMINAL_INDEXED:
                        offset = word & tables.OFFSET_MASK
                        packed_kind = reverse_kinds[
                            (word >> tables.TYPE_SHIFT) & tables.TYPE_MASK
                        ]
                        result = words[
                            offset + tables.source_id(range(256), packed_kind, 0, modrm)
                        ]
                    else:
                        shift = (
                            TERMINAL_BITS
                            if word & TERMINAL_SPLIT and modrm >= 0xC0
                            else 0
                        )
                        result = (word >> shift) & ((1 << TERMINAL_BITS) - 1)
                    tables.require(
                        result == packed_terminal(expected), "Packed terminal changed"
                    )
    return groups, terminals, rows, selected_counts, words, kinds


def emit_terminal(suffix):
    groups, terminals, rows, selected_counts, words, kinds = legacy_terminal_model(
        suffix
    )
    lines = [
        f"/* {len(terminals)} terminals, {len(groups)} operand handlers; selected opcodes {selected_counts}. */",
        f"#define X86_TERMINAL_INDEXED UINT64_C(0x{TERMINAL_INDEXED:x})",
        f"#define X86_TERMINAL_SPLIT UINT64_C(0x{TERMINAL_SPLIT:x})",
        f"#define X86_TERMINAL_MASK UINT64_C(0x{(1 << TERMINAL_BITS) - 1:x})",
        f"#define X86_TERMINAL_REGISTER_SHIFT {TERMINAL_BITS}",
        f"#define X86_TERMINAL_UID_MASK 0x{(1 << TERMINAL_UID_BITS) - 1:x}u",
        f"#define X86_TERMINAL_OPERAND_SHIFT {TERMINAL_UID_BITS}",
        f"#define X86_TERMINAL_OPERAND_MASK 0x{(1 << TERMINAL_OPERAND_BITS) - 1:x}u",
        f"#define X86_TERMINAL_HANDLER_SHIFT {TERMINAL_HANDLER_SHIFT}",
        "enum {",
    ]
    lines += [f"\t{name}," for name, _, _, _ in TERMINAL_ROWS]
    lines += ["\tX86_TERMINAL_ROW_COUNT,", "};"]
    mapping = public_instruction_ids(suffix)
    public_words = []
    for uid, _, handler in terminals:
        tables.require(not uid or uid in mapping, "Unmapped scalar terminal")
        public_words.append(packed_terminal((mapping[uid] if uid else 0, 0, handler)))
    # Both projections retain the same decision kind, invalid entries and readers.
    lines += emit_terminal_tables("Legacy", words, rows, kinds)
    lines += emit_terminal_tables("LegacyPublic", public_words, rows, kinds)
    lines += [
        "X86_DECODE_INLINE int decodeLegacyTerminal(struct InternalInstruction *insn,",
        "\t\t\t\tMCInst *mcInst, uint16_t *size, uint64_t decision, bool scan, unsigned *publicID)",
        "{",
        "\tuint32_t terminal;",
        "\tif ((decision & (X86_TERMINAL_INDEXED | X86_TERMINAL_SPLIT)) && (scan ? readModRMScan(insn) : readModRM(insn)))",
        "\t\treturn X86_SCAN_INVALID;",
        "\tif (decision & X86_TERMINAL_INDEXED) {",
        "\t\tunsigned int index = decision & X86_DECISION_OFFSET_MASK;",
        "\t\tswitch ((decision >> X86_DECISION_TYPE_SHIFT) & X86_DECISION_TYPE_MASK) {",
        "\t\tcase MODRM_SPLITREG:",
        "\t\t\tindex += regFromModRM(insn->modRM) + (insn->modRM >= 0xc0 ? 8 : 0);",
        "\t\t\tbreak;",
        "\t\tcase MODRM_SPLITMISC:",
        "\t\t\tindex += insn->modRM >= 0xc0 ? (insn->modRM & 0x3f) + 8 : regFromModRM(insn->modRM);",
        "\t\t\tbreak;",
        "\t\tcase MODRM_FULL:",
        "\t\t\tindex += insn->modRM;",
        "\t\t\tbreak;",
        "\t\tdefault:",
        "\t\t\treturn X86_SCAN_INVALID;",
        "\t\t}",
        "\t\tterminal = publicID ? x86LegacyPublicTerminals[index] : x86LegacyTerminals[index];",
        "\t} else {",
        "\t\tunsigned int shift = (decision & X86_TERMINAL_SPLIT) && insn->modRM >= 0xc0 ?",
        "\t\t\tX86_TERMINAL_REGISTER_SHIFT : 0;",
        "\t\tterminal = (decision >> shift) & X86_TERMINAL_MASK;",
        "\t}",
        "\tunsigned instructionID = terminal & X86_TERMINAL_UID_MASK;",
        "\tif (publicID) {",
        "\t\tif (!instructionID)",
        "\t\t\treturn X86_SCAN_INVALID;",
        "\t\tint status = scanLegacyOperands(insn, NULL, size, terminal >> X86_TERMINAL_HANDLER_SHIFT);",
        "\t\tif (status == X86_SCAN_COMPLETE)",
        "\t\t\t*publicID = instructionID;",
        "\t\treturn status;",
        "\t}",
        "\tinsn->instructionID = instructionID;",
        "\tinsn->spec = specifierForUID(insn->instructionID);",
        "\tif (!instructionID)",
        "\t\treturn X86_SCAN_INVALID;",
        "\tif (scan)",
        "\t\treturn scanLegacyOperands(insn, mcInst, size, terminal >> X86_TERMINAL_HANDLER_SHIFT);",
        "\tinsn->operands = x86OperandSets[(terminal >> X86_TERMINAL_OPERAND_SHIFT) & X86_TERMINAL_OPERAND_MASK];",
        "\treturn x86LegacyHandlers[terminal >> X86_TERMINAL_HANDLER_SHIFT](insn);",
        "}",
    ]
    handlers = []
    scan_groups = {}
    scan_handlers = []
    for (read_ops, _), handler in groups.items():
        handlers += [
            f"static int readLegacyShape{handler}(struct InternalInstruction *insn)",
            "{",
        ]
        calls = read_operand_calls(read_ops)
        if calls:
            handlers += [
                "\tif (" + " ||\n\t    ".join(calls) + ")",
                "\t\treturn X86_SCAN_INVALID;",
            ]
        handlers += [
            "\tif (finishDecodedInstruction(insn, false))",
            "\t\treturn X86_SCAN_INVALID;",
            "\treturn X86_SCAN_RAW_READY;",
            "}",
        ]
        scan_calls = tuple(read_operand_calls(read_ops, materialize=False))
        if scan_calls not in scan_groups:
            scan_groups[scan_calls] = len(scan_groups) + 1
        scan_handlers.append(scan_groups[scan_calls])
    handlers += [
        "X86_DECODE_INLINE int scanLegacyOperands(struct InternalInstruction *insn,",
        "\t\tMCInst *mcInst, uint16_t *size, unsigned int handler)",
        "{",
        "\tswitch (handler) {",
    ]
    for calls, handler in scan_groups.items():
        handlers += [
            f"\tcase {raw_handler}:"
            for raw_handler, pattern in enumerate(scan_handlers, 1)
            if pattern == handler
        ]
        if calls:
            handlers += [
                "\t\tif (" + " ||\n\t\t    ".join(calls) + ")",
                "\t\t\treturn X86_SCAN_INVALID;",
            ]
        handlers.append("\t\tbreak;")
    handlers += [
        "\tdefault:",
        "\t\treturn X86_SCAN_INVALID;",
        "\t}",
        "\tif (finishDecodedInstruction(insn, false))",
        "\t\treturn X86_SCAN_INVALID;",
        "\t*size = (uint16_t)insn->length;",
        "\tif (mcInst && beginTranslation(mcInst, insn))",
        "\t\treturn X86_SCAN_INVALID;",
        "\treturn X86_SCAN_COMPLETE;",
        "}",
        "",
    ]
    handlers += [
        "static int (*const x86LegacyHandlers[])(struct InternalInstruction *) = {",
        "\tNULL,",
    ]
    handlers += [f"\treadLegacyShape{handler}," for handler in groups.values()]
    handlers += ["};", ""]
    return "\n".join(handlers + lines)


def vex_scan_form(operands, register_form):
    registers = {
        "TYPE_R8",
        "TYPE_R16",
        "TYPE_R32",
        "TYPE_R64",
        "TYPE_Rv",
        "TYPE_XMM",
        "TYPE_YMM",
    }
    immediates = {"TYPE_REL", "TYPE_RELv", "TYPE_IMM", "TYPE_UIMM8"}
    for encoding, operand_type in operands:
        if encoding == "ENCODING_RM":
            if operand_type not in registers | {"TYPE_M"}:
                return False
            if (operand_type == "TYPE_M") == register_form:
                return False
        elif encoding in {"ENCODING_REG", "ENCODING_VVVV"}:
            if operand_type not in registers:
                return False
        elif encoding in REGISTERS:
            if operand_type not in registers - {"TYPE_XMM", "TYPE_YMM"}:
                return False
        elif encoding in IMMEDIATES:
            if operand_type not in immediates:
                return False
        else:
            return False
    return True


def emit_vex_scan(suffix):
    # MODE_64BIT ordinary VEX registers are at most 15. Admitted classes have
    # no gather, mask, register-limit or predicate-dependent opcode checks.
    reads = dict(read_specializations(suffix))
    translations = dict(translation_specializations(suffix))
    source = (X86 / f"X86GenDisassemblerTables{suffix}.inc").read_text()
    specifiers = instruction_specifiers(source)
    patterns = {(): 0}
    flags = []
    for operands in specifiers:
        if operands not in reads or operands not in translations:
            flags.append(0)
            continue
        read_ops, translate_ops = reads[operands], translations[operands]
        forms = int(vex_scan_form(read_ops + translate_ops, False)) | (
            int(vex_scan_form(read_ops + translate_ops, True)) << 1
        )
        if not forms:
            flags.append(0)
            continue
        immediates = tuple(IMMEDIATES[e] for e, _ in read_ops if e in IMMEDIATES)
        if immediates not in patterns:
            patterns[immediates] = len(patterns)
        tables.require(len(patterns) <= 16, "VEX scan read patterns exceed storage")
        has_modrm = any(e in {"ENCODING_RM", "ENCODING_REG"} for e, _ in read_ops)
        has_vvvv = any(e == "ENCODING_VVVV" for e, _ in read_ops)
        flags.append(
            forms
            | (int(has_modrm) << 2)
            | (int(has_vvvv) << 3)
            | (patterns[immediates] << 4)
        )
    ud1 = int(
        re.search(
            r"X86_UD1\s*=\s*(\d+)", (X86 / f"X86GenInstrInfo{suffix}.inc").read_text()
        )[1]
    )
    flags[ud1] = 0
    tables.require(all(0 <= f <= 255 for f in flags), "VEX scan flags exceed a byte")
    mapping = public_instruction_ids(suffix)
    metadata = [
        f | (mapping.get(uid, 0) << 8) if f else 0 for uid, f in enumerate(flags)
    ]
    lines = [
        f"/* {sum(bool(f) for f in flags)} admitted UIDs, {len(patterns)} immediate patterns. */",
        "enum { X86_VEX_SCAN_MEMORY = 1, X86_VEX_SCAN_REGISTER = 2,",
        "       X86_VEX_SCAN_MODRM = 4, X86_VEX_SCAN_VVVV = 8,",
        "       X86_VEX_SCAN_PATTERN_SHIFT = 4, X86_VEX_SCAN_PUBLIC_SHIFT = 8 };",
        "static const uint32_t x86VexScanMetadata[] X86_DECODE_ALIGN = {",
    ]
    lines += [
        "\t" + ", ".join(f"0x{f:08x}u" for f in metadata[i : i + 8]) + ","
        for i in range(0, len(metadata), 8)
    ]
    lines += [
        "};",
        "",
        "X86_DECODE_INLINE int readVexScanImmediates(struct InternalInstruction *insn, unsigned pattern)",
        "{",
        "\tswitch (pattern) {",
    ]
    for immediates, pattern in patterns.items():
        lines.append(f"\tcase {pattern}:")
        if immediates:
            calls = [f"readImmediateImpl(insn, {size}, false)" for size in immediates]
            lines += [
                "\t\tif (" + " ||\n\t\t    ".join(calls) + ")",
                "\t\t\treturn X86_SCAN_INVALID;",
            ]
        lines.append("\t\treturn X86_SCAN_COMPLETE;")
    lines += ["\tdefault:", "\t\treturn X86_SCAN_INVALID;", "\t}", "}"]
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
        (TERMINAL_OUTPUT, emit_terminal),
        (X86 / "X86GenVexScan.inc", emit_vex_scan),
    ]
    generated = [(path, generated_output(emit)) for path, emit in outputs]
    for path, output in generated:
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != output:
                parser.exit(1, f"{path} is stale; run {Path(__file__).name}\n")
        else:
            path.write_text(output, encoding="utf-8")


if __name__ == "__main__":
    main()

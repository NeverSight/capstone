#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Project short x86 Intel printer paths from the existing fragment tables.

Run after x86_mnemonic_sizes.py when regenerating X86GenAsmWriter1.inc.
The original tables and fragment bodies remain the instruction authority.
"""

import argparse
import ast
from collections import Counter
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
INCLUDE = '#include "X86GenPrinterQuick.inc"\n'
TABLE_INCLUDE = (
    "#define CAPSTONE_X86_QUICK_PRINTER_TABLE\n"
    + INCLUDE
    + "#undef CAPSTONE_X86_QUICK_PRINTER_TABLE\n"
)
FRAGMENT = re.compile(
    r"switch \(\(uint32_t\)\(\(Bits >> (\d+)\) & (\d+)\)\) \{(.*?)\n  \}",
    re.S,
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def without_comments(text):
    tokens = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"', re.S)
    return tokens.sub(lambda m: m[0] if m[0].startswith('"') else "", text)


def original_writer(text):
    table_count = text.count(TABLE_INCLUDE)
    require(table_count <= 1, "Duplicate quick-printer table include")
    text = text.replace(TABLE_INCLUDE, "")
    require(text.count(INCLUDE) == table_count, "Incomplete quick-printer includes")
    return text.replace(INCLUDE, "")


def fragments(text):
    """Accept only unconditional helper calls and the existing terminal forms."""
    result = []
    for match in FRAGMENT.finditer(text):
        body = without_comments(match[3])
        require(re.match(r"\s*default:\s*case 0:", body), "Unexpected fragment default")
        cases = {}
        cursor = body.index("case 0:")
        for case in re.finditer(r"case (\d+):\s*(.*?)(?=\n  case \d+:|\Z)", body, re.S):
            require(
                not body[cursor : case.start()].strip(), "Unowned fragment statement"
            )
            number = int(case[1])
            require(number not in cases, "Duplicate fragment case")
            lines = [line.strip() for line in case[2].splitlines() if line.strip()]
            require(lines and lines[-1] == "break;", "Missing fragment break")
            lines.pop()
            require(lines, "Empty fragment body")
            for index, line in enumerate(lines):
                if line == "return;":
                    require(index == len(lines) - 1, "Nonterminal fragment return")
                    continue
                call = re.fullmatch(r"(\w+)\((.*)\);", line)
                require(call, f"Unsupported fragment statement: {line}")
                function, args = call.groups()
                if function == "SStream_concat0":
                    valid = re.fullmatch(r'O, "(?:\\.|[^"\\])*"', args)
                elif function.startswith("print"):
                    valid = re.fullmatch(r"MI, \d+, O", args)
                elif function.startswith("op_add"):
                    valid = re.fullmatch(r"MI(?:, (?:\d+|X86_\w+))?", args)
                else:
                    valid = False
                require(valid, f"Unsupported fragment call: {line}")
            cases[number] = tuple(lines)
            cursor = case.end()
        require(not body[cursor:].strip(), "Trailing fragment statement")
        require(set(cases) == set(range(len(cases))), "Noncontiguous fragment cases")
        result.append((int(match[1]), int(match[2]), cases))
    require(result, "Missing operand fragments")
    require(
        without_comments(FRAGMENT.sub("", text)).strip() == "}",
        "Unowned printer control flow",
    )
    return result


def path_extent(path, prefix_length):
    """Conservative bytes appended after X86_lockrep; see the Intel helpers.

    A scalar needs at most 32 bytes (sign + 20 digits, or a register/token).
    A memory helper needs at most 192: segment/base/index/displacement scalars,
    scale and separators total at most 159, plus at most 12 qualifier bytes.
    New helpers must establish a bound before entering the prechecked printer.
    """
    scalar = {
        "printOperand",
        "printU8Imm",
        "printPCRelImm",
        "printSSEAVXCC",
        "printXOPCC",
        "printRoundingControl",
    }
    memory = {
        "printi8mem",
        "printi16mem",
        "printi32mem",
        "printi64mem",
        "printi128mem",
        "printi256mem",
        "printi512mem",
        "printf32mem",
        "printf64mem",
        "printf80mem",
        "printf128mem",
        "printf256mem",
        "printf512mem",
        "printanymem",
        "printopaquemem",
        "printMemOffs8",
        "printMemOffs16",
        "printMemOffs32",
        "printMemOffs64",
        "printSrcIdx8",
        "printSrcIdx16",
        "printSrcIdx32",
        "printSrcIdx64",
        "printDstIdx8",
        "printDstIdx16",
        "printDstIdx32",
        "printDstIdx64",
    }
    detail = {
        "op_addReg",
        "op_addImm",
        "op_addAvxBroadcast",
        "op_addAvxZeroOpmask",
        "op_addAvxSae",
    }
    length = prefix_length
    for line in path:
        if line == "return;":
            continue
        call = re.fullmatch(r"(\w+)\((.*)\);", line)
        require(call, f"Unbounded printer statement: {line}")
        function, args = call.groups()
        if function == "SStream_concat0":
            require(args.startswith('O, "'), "Unbounded printer string")
            length += len(ast.literal_eval(args[3:]).encode("ascii"))
        elif function in scalar:
            length += 32
        elif function in memory:
            length += 192
        else:
            require(function in detail, f"Unbounded printer helper: {function}")
    return length


def generate(text, enum_text):
    # Reuse the original table owner's enum, bounds and packed-bit validation.
    import x86_mnemonic_sizes as mnemonic

    text = original_writer(text)
    require(
        mnemonic.generate(text, enum_text, True) == text,
        "Run x86_mnemonic_sizes.py first",
    )
    arrays = list(mnemonic.TABLE.finditer(text))
    names = None
    values = None
    setup = ["unsigned int opcode = MCInst_getOpcode(MI);", "uint64_t Bits = 0;"]
    for array in arrays:
        rows = list(mnemonic.ROW.finditer(array[3]))
        row_names = [re.search(r"// (\w+)", row[3])[1] for row in rows]
        if names is None:
            names = row_names
            values = [0] * len(rows)
        require(names == row_names, "Mismatched opcode rows")
        shift = re.search(
            r"Bits \|= \(uint64_t\)" + array[2] + r"\[opcode\] << (\d+);", text
        )
        require(shift, "Missing opcode chunk shift")
        setup.append(f"Bits |= (uint64_t){array[2]}[opcode] << {int(shift[1])};")
        for index, row in enumerate(rows):
            values[index] |= int(row[2]) << int(shift[1])
    require(names, "Missing opcode table")
    start = text.find("  // Fragment 0")
    require(start >= 0, "Missing fragment boundary")
    setup.extend(
        ["#ifndef CAPSTONE_DIET", mnemonic.SIZED_APPEND.search(text)[0], "#endif"]
    )
    # Precomputed paths require the same unmodified table selector and bits.
    actual_setup = without_comments(text[arrays[-1].end() : start])
    require(
        re.sub(r"\s+", "", actual_setup) == re.sub(r"\s+", "", "\n".join(setup)),
        "Unsupported opcode or fragment-bit setup",
    )
    commands = fragments(text[start:])
    paths = []
    for value in values:
        path = []
        for shift, mask, cases in commands:
            selected = (value >> shift) & mask
            require(selected in cases, "Opcode selects an absent fragment")
            path.extend(cases[selected])
            if path[-1] == "return;":
                break
        else:
            raise ValueError("Opcode has no terminal return")
        paths.append(tuple(path))
    sized = mnemonic.SIZED_APPEND.search(text)
    maximum = max(
        path_extent(path, (value >> int(sized[2])) & int(sized[3]))
        for path, value in zip(paths, values)
    )
    frequency = Counter(paths)
    # Bound extra code to short paths shared by at least sixteen opcodes.
    quick = [
        path
        for path in dict.fromkeys(paths)
        if len(path) <= 6 and frequency[path] >= 16
    ]
    require(len(quick) < 256, "Quick-printer selector exceeds uint8_t")
    indices = {path: index + 1 for index, path in enumerate(quick)}
    table = "  static const uint8_t QuickRecipe[] = {\n"
    table += "".join(
        f"    {indices.get(path, 0)}, // {name}\n" for path, name in zip(paths, names)
    )
    table += "  };\n"
    dispatch = "  switch (QuickRecipe[opcode]) {\n  default: break;\n"
    for index, path in enumerate(quick, 1):
        dispatch += f"  case {index}:\n" + "".join(
            "    " + line + "\n" for line in path
        )
    dispatch += "  }\n"
    projection = (
        "/* Generated by suite/synctools/x86_printer_dispatch.py. */\n"
        "#if defined(CAPSTONE_X86_PRINTER_EXTENT)\n"
        + f"enum {{ X86_PRINTER_MAX_LENGTH = {maximum} }};\n"
        + "typedef char X86PrinterExtentFits[\n"
        + "    X86_PRINTER_MAX_LENGTH < SSTREAM_BUF_LEN ? 1 : -1];\n"
        + "#elif defined(CAPSTONE_X86_QUICK_PRINTER_TABLE)\n"
        + table
        + "#else\n"
        + dispatch
        + "#endif\n"
    )
    first = text.rfind("\n", 0, arrays[0].start()) + 1
    output = text[:first] + TABLE_INCLUDE + text[first:start] + INCLUDE + text[start:]
    return output, projection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = ROOT / "arch/X86"
    writer = directory / "X86GenAsmWriter1.inc"
    projection = directory / "X86GenPrinterQuick.inc"
    enum = (directory / "X86GenInstrInfo.inc").read_text()
    output, generated = generate(writer.read_text(), enum)
    require(
        generate(output, enum) == (output, generated),
        "Non-idempotent printer projection",
    )
    for path, expected in [(writer, output), (projection, generated)]:
        if args.check:
            require(
                path.exists() and path.read_text() == expected,
                f"Stale {path}; rerun {Path(__file__).name}",
            )
        elif not path.exists() or path.read_text() != expected:
            path.write_text(expected)


if __name__ == "__main__":
    main()

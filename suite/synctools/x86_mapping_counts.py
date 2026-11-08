#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Project implicit register and group counts from the x86 mapping tables."""

import argparse
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
ENTRY = re.compile(
    r"\{\s*(X86_\w+),\s*(X86_INS_\w+),\s*\d+,\s*"
    r"#ifndef CAPSTONE_DIET\s*"
    r"\{([^{}]*)\},\s*\{([^{}]*)\},\s*\{([^{}]*)\},\s*\d+,\s*\d+"
    r"\s*#endif\s*\},"
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def entries(text):
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    rows = list(ENTRY.finditer(text))
    require(rows and not ENTRY.sub("", text).strip(), "Unexpected x86 mapping syntax")
    return rows


def implicit_repair_ids(source):
    """Derive eligibility from the guarded public-ID switches themselves."""
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    guards = list(
        re.finditer(
            r"if\s*\(\s*!\(\s*x86_mapping_counts\[i\]\s*&\s*"
            r"X86_MAPPING_IMPLICIT_REPAIR\s*\)\s*\)\s*"
            r"goto\s+implicit_registers_done\s*;",
            source,
        )
    )
    labels = list(re.finditer(r"\bimplicit_registers_done\s*:", source))
    require(
        len(guards) == len(labels) == 1 and guards[0].end() < labels[0].start(),
        "Unexpected implicit-register repair guard",
    )
    remaining = source[guards[0].end() : labels[0].start()].strip()
    require(
        "#" not in remaining, "Conditional repair cases need an explicit projection"
    )
    require(
        not re.search(r'["\']', remaining),
        "Quoted repair literals need explicit parsing",
    )
    result = set()
    while remaining:
        switch = re.match(r"switch\s*\(\s*insn->id\s*\)\s*\{", remaining)
        require(switch is not None, "Only public-ID switches may be skipped")
        depth = 1
        end = switch.end()
        while end < len(remaining) and depth:
            depth += (remaining[end] == "{") - (remaining[end] == "}")
            end += 1
        require(depth == 0, "Unbalanced implicit-register repair switch")
        body = remaining[switch.end() : end - 1]
        levels = []
        depth = 0
        for character in body:
            levels.append(depth)
            depth += (character == "{") - (character == "}")
        cases = [
            match
            for match in re.finditer(r"\b(case\s+([^:]+)|default)\s*:", body)
            if levels[match.start()] == 0
        ]
        require(
            cases and not body[: cases[0].start()].strip(),
            "Unexpected statements before repair cases",
        )
        defaults = 0
        for index, case in enumerate(cases):
            if case[2] is not None:
                identifier = case[2].strip()
                require(
                    re.fullmatch(r"X86_INS_\w+", identifier),
                    "Repair cases must use public instruction IDs",
                )
                result.add(identifier)
            else:
                defaults += 1
                stop = cases[index + 1].start() if index + 1 < len(cases) else len(body)
                require(
                    re.fullmatch(r"\s*break\s*;\s*", body[case.end() : stop]),
                    "Implicit-register repair defaults must do no work",
                )
        require(defaults == 1, "Each repair switch must have an empty default")
        remaining = remaining[end:].strip()
    require(result, "Missing implicit-register repair cases")
    return result


def generate(directory, suffix):
    source = (directory / f"X86MappingInsn{suffix}.inc").read_text()
    repairs = implicit_repair_ids((directory / "X86Mapping.c").read_text())
    enum = dict(
        (name, int(value))
        for name, value in re.findall(
            r"\b(X86_\w+)\s*=\s*(\d+)",
            (directory / f"X86GenInstrInfo{suffix}.inc").read_text(),
        )
    )
    lines = ["static const uint16_t x86_mapping_counts[] = {"]
    header = re.sub(
        r"/\*.*?\*/|//[^\n]*", "", (directory / "X86Mapping.h").read_text(), flags=re.S
    )
    capacities = []
    for field in ("regs_use", "regs_mod", "groups"):
        match = re.search(field + r"\s*\[\s*(\d+)\s*\]", header)
        require(match is not None, "Mapping array layout changed")
        capacities.append(int(match[1]))
    require(
        capacities[0] <= 32 and capacities[1] <= 32 and capacities[2] <= 16,
        "Mapping counts exceed packed widths",
    )
    previous = -1
    for row in entries(source):
        name = row[1]
        require(
            name in enum and enum[name] > previous,
            "Mapping IDs must follow the instruction enum",
        )
        previous = enum[name]
        counts = []
        for body, capacity, prefix in zip(
            row.groups()[2:], capacities, ("X86_REG_", "X86_REG_", "X86_GRP_")
        ):
            tokens = [value.strip() for value in body.split(",") if value.strip()]
            require(len(tokens) <= capacity, "Mapping list exceeds its storage")
            require(
                all(
                    value == "0" or re.fullmatch(prefix + r"\w+", value)
                    for value in tokens
                ),
                "Unknown mapping list element",
            )
            require(
                "0" in tokens or len(tokens) < capacity, "Unterminated mapping list"
            )
            counts.append(tokens.index("0") if "0" in tokens else len(tokens))
        read, write, group = counts
        # Fixed fields are checked against the owning array capacities above.
        value = read | (write << 5) | (group << 10)
        if row[2] in repairs:
            value |= 1 << 14
        lines.append(f"\t{value}, // {name}")
    return "\n".join(lines + ["};", ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = ROOT / "arch/X86"
    text = (
        "/* SPDX-License-Identifier: BSD-3-Clause */\n"
        "/* Generated by suite/synctools/x86_mapping_counts.py; do not edit. */\n"
        "/* Fields: reads [0:4], writes [5:9], groups [10:13], implicit repair [14]. */\n"
        "#define X86_MAPPING_IMPLICIT_REPAIR (1U << 14)\n\n"
        "#ifdef CAPSTONE_X86_REDUCE\n"
        + generate(directory, "_reduce")
        + "#else\n"
        + generate(directory, "")
        + "#endif\n"
    )
    target = directory / "X86GenMappingCounts.inc"
    if args.check:
        require(
            target.exists() and target.read_text() == text,
            f"Stale {target}; rerun {Path(__file__).name}",
        )
    else:
        target.write_text(text)


if __name__ == "__main__":
    main()

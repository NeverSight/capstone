# Capstone Architecture overview

## Architecture of Capstone

TODO

## Architecture of a Module

An architecture module is split into two components.

1. The disassembler logic, which decodes bytes to instructions.
2. The mapping logic, which maps the result from component 1 to
a Capstone internal representation and adds additional detail.

### Component 1 - Disassembler logic

The disassembler logic consists exclusively of code from LLVM.
It uses:

- Generated state machines, enums and the like for instruction decoding.
- Handwritten disassembler logic for decoding instruction operands
and controlling the decoding procedure.

### Component 2 - Mapping logic

The mapping component has three different task:

1. Serving as programmable interface for the Capstone core to the LLVM code.
2. Mapping LLVM decoded instructions to a Capstone instruction.
3. Adding additional detail to the Capstone instructions
(e.g. operand `read/write` attributes etc.).

### Instruction representation

There exist two structs which represent an instruction:

- `MCInst`: The LLVM representation of an instruction.
- `cs_insn`: The Capstone representation of an instruction.

The `MCInst` is used by the disassembler component for storing the decoded instruction.
The mapping component on the other hand, uses the `MCInst` to populate the `cs_insn`.

Hot opcode accessors and checked operand append operations are defined in
`MCInst.h` for inlining. `MCInst.c` emits the same bodies as external functions,
preserving their symbols. The shared assertion policy lives in `cs_assert.h`;
operand capacity remains defined by `MAX_MC_OPS` in `MCInst.h`.

The `cs_insn` is meant to be used by the Capstone core.
It is distinct from the `MCInst`. It uses different instruction identifiers, other operand representation
and holds more details about an instruction.

For x86 with both text and detail disabled, the core initializes only the
`MCInst` opcode fields and operand count, then sets its handle, address and
public instruction pointer. Translation runs the same operand validation and
opcode corrections with operand stores disabled. No consumer reads those
intermediate operand slots in this mode. Text or detail output retains full
operand construction. Memory validation and construction share one implementation
specialized for the two constant store policies.

Without detail, the x86 mapping layer exposes its existing checked public-ID
lookup as a private inline helper shared by the mapper and both core decode
APIs. Cached holes preserve the current ID. Out-of-range IDs, unavailable
caches and detailed output retain the original mapping callback. The range
check precedes cache access, so source-owned extension IDs return promptly to
their existing mapper. Printer aliases and pseudo-opcode adjustments still
follow mapping at their original core locations.

The x86 extension selector is inlined at the decoder entry. It retains the
mode-dependent prefix and opcode filters in `X86FeatureExtension.h`, and only
calls the extension decoders for a possible match. EVEX normalization and its
scratch buffer live in a separate helper; ordinary instructions enter the
generated decoder directly. Both routes retain operand validation and
translation, including immediate-dependent opcode selection.

Extension dispatch groups handlers by the selected legacy/VEX escape and EVEX
map, retaining handler precedence within each map. A new source-owned encoding
must be routed to its handler here as well as validated by that handler. The
legacy pointer-load ambiguity, duplicate-prefix policy and reserved-map-4
rejection remain ahead of fallback to the generated decoder.

The prefix reader shares the selector's byte classification. A first ordinary
opcode, optionally after one REX in 64-bit mode, skips the legacy prefix loop;
vector escapes reuse the existing payload parser. Other prefix sequences keep
the full ordering and conflict checks. The reader reports when it has consumed
no legacy prefix and at most one REX. This path supplies the known absent size
overrides to the shared size policy and enters the existing legacy opcode
reader directly. ID selection and prefix validation keep their existing rules.
Both paths retain checked reads and full instruction-state initialization.

The x86 operand reader and translator specialize common scalar and vector
operand sets from the full and reduced `X86GenDisassemblerTables*.inc`
descriptors. Run `python3 suite/synctools/x86_operand_specializations.py` whenever
those descriptors, opcode tables or `X86Lookup16*.inc` change; `--check` verifies
`X86GenOperandRead.inc`, `X86GenOperandTranslate.inc`, `X86GenOperandScan.inc` and
`X86GenLegacyTerminal.inc` without writing, and runs in the unit suite when Python
is available.

The reader selects up to two scalar or four vector operands after ignoring
duplicates. It calls the same register, memory, immediate, VVVV, writemask and
VSIB helpers as the generic loop. Reserved VVVV checks, register restrictions
and compressed displacement scaling remain active. Translation selects up to
three scalar or five vector operands, resolving duplicates in original order,
including forward references. Scaled R/M and VSIB encodings share translation
sequences after the reader has applied their addressing rules. Register-encoded
immediates, opcode-changing comparison predicates, UD1's runtime override and
other operand shapes retain their generic paths.

With text and detail disabled, selected scalar and three-operand VEX shapes
combine operand reading and translation validation in one generated dispatch.
The latter have one REG, one VVVV and one RM or VSIB operand, with scalar,
XMM/YMM or matching memory types. This bounds generated code while covering
arithmetic and gather families. Cases derive from the intersection of reader
and translator descriptors, keyed by both sequences so duplicate translation
order is preserved. Operand setup runs only after a case matches. All reads
finish before the shared final decode checks, size assignment, opcode
initialization and operand validation. The shared private
`X86DisassemblerTranslator.h` owns the translation implementations for both
paths.

One shared parser reads prefixes and opcodes before selecting a terminal or
generic ID lookup. Ordinary legacy instructions with no prefix or one REX use
generated terminal plans for selected scalar operand shapes in the one-byte
and two-byte maps. Each terminal packs the instruction ID, operand-set index
and operand-handler index, avoiding ID-to-descriptor-to-shape lookups at runtime.
The plans derive from the same full/reduced opcode tables and operand helpers;
they do not define another instruction set. Direct decisions embed terminals;
indexed decisions retain their ModR/M read and branch selection, including
invalid IDs. Generation checks every selected ModR/M value and packed result.

The 16-bit row composes the existing primary and operand-size lookups only when
their decision kinds match. Both then require the same read, and the second
lookup either reads nothing or reuses an already successful ModR/M read.
Equivalence comes from the existing lookup ranges. Different read requirements,
address-size repairs, opcode 90 and UD1's runtime operand override retain generic
selection. No failed secondary read or cursor update is removed from that path.

The terminal admission rule excludes LOCK, REX2 and vector prefixes. Generation
also checks every selected ModR/M against both operand sequences: REG and
opcode-register operands must be GPRs, an RM operand must match its register or
memory form, and immediates must neither encode registers nor change the opcode.
Any incompatible descriptor keeps the generic path. Under this admission rule,
REX produces only valid GPR indices, and a successful legacy address read
produces valid base/index registers. These facts discharge the operand fixup
and translation checks for scan terminals before code generation.

The same ModR/M, SIB, displacement and immediate readers serve both outputs,
with a constant materialization policy. Raw decoding retains all fields and
failed-read state. Scan terminals consume and bounds-check the same bytes but
retain only control state before the shared final checks and opcode setup;
they do not build register/address values merely to discard them. Identical
scan read sequences share a handler. The completed scan result does not expose
a raw instruction. Its null-`MCInst` entry still returns the same raw state as
the generic reader. VVVV and EVEX/VSIB checks remain on the paths that need them.
Other encodings retain generic ID selection, prefix validation and final checks.
UD1 and unselected shapes use the original reader. After reading and final
checks succeed, the private
`X86_SCAN_RAW_READY` result returns them to the backend's size assignment,
displacement correction and translation. It does not mean translation has
succeeded. Selected cases complete translation before returning
`X86_SCAN_COMPLETE`; the raw entry with a null `MCInst` retains its existing
zero-on-success/nonzero-on-error contract.

Source-owned extension dispatch still precedes the generated parser. EVEX keeps
its raw path and existing normalization and restoration order: APX prefix bits
are restored after raw decoding and before backend translation, while
scalar-compare P2 restoration stays in the successful public-output path. The
GFNI displacement correction remains before backend translation. Public output
modes and instruction state remain caller-local.

Instruction ID selection specializes the existing rules for each bitness. In
32- and 64-bit legacy encodings without operand/address-size or repeat prefixes,
ordinary opcodes take the direct attribute lookup. Opcode 90 and other prefix
combinations retain the size, mandatory-prefix and XCHG repair rules.

The decoder's packed decision tables derive from the original full/reduced
`X86GenDisassemblerTables*.inc` inputs. Direct decisions embed one or two
instruction IDs in the existing four-byte entry; other decisions retain their
ModR/M-table offsets. The read-required flag is independent of those IDs, so
invalid split entries still consume ModR/M. The trailing 3DNow opcode keeps its
explicit ModR/M requirement. Identical complete opcode rows share storage.
Run `python3 suite/synctools/x86_disassembler_tables.py` after changing the
inputs or decoder context definitions. Its `--check` mode verifies generated
output and every context/opcode/ModR/M result against the original tables,
including read requirements, and rejects values outside the packed format.
This check runs in the unit suite when Python is available. Edit the original
tables, then regenerate; the packed tables are not a separate instruction
definition.

### Disassembling process

There are two steps in disassembling an instruction.

1. Decoding bytes to a `MCInst`.
2. Decoding the assembler string for the `MCInst` AND mapping it to a `cs_insn` in the same step.

Here is a boiled down explanation about these steps.

**Step 1**

```
                                                                 ARCH_LLVM_getInstr(
                                     ARCH_getInstr(bytes)   ┌───┐   bytes)           ┌─────────┐            ┌──────────┐
                                    ┌──────────────────────►│ A ├──────────────────► │         ├───────────►│          ├────┐
                                    │                       │ R │                    │ LLVM    │            │ LLVM     │    │ Decode
                                    │                       │ C │                    │         │            │          │    │ Instr.
                                    │                       │ H │                    │         │decode(Op0) │          │◄───┘
┌────────┐ disasm(bytes) ┌──────────┴──┐                    │   │                    │ Disass- │ ◄──────────┤ Decoder  │
│CS Core ├──────────────►│ ARCH Module │                    │   │                    │ embler  ├──────────► │ State    │
└────────┘               └─────────────┘                    │ M │                    │         │            │ Machine  │
                                    ▲                       │ A │                    │         │decode(Op1) │          │
                                    │                       │ P │                    │         │ ◄──────────┤          │
                                    │                       │ P │                    │         ├──────────► │          │
                                    │                       │ I │                    │         │            │          │
                                    │                       │ N │                    │         │            │          │
                                    └───────────────────────┤ G │◄───────────────────┤         │◄───────────┤          │
                                                            └───┘                    └─────────┘            └──────────┘
```

In the first decoding step the instruction bytes get forwarded to the
decoder state machine.
After the instruction was identified, the state machine calls decoder functions
for each operand to extract the operand values from the bytes.

The disassembler and the state machine are equivalent to what `llvm-objdump` uses
(in fact they use the same files, except we translated them from C++ to C).

**Step 2**

```
                                      ARCH_printInst(        ARCH_LLVM_printInst(
                                         MCInst,                MCInst,
                                         asm_buf)      ┌───┐    asm_buf)         ┌────────┐            ┌──────────┐
                                      ┌───────────────►│ A ├───────────────────► │        ├───────────►│          ├──────┐
                                      │                │ R │                     │ LLVM   │            │ LLVM     │      │ Decode
                                      │                │ C │                     │        │            │          │      │ Mnemonic
                                      │                │ H │ add_cs_detail(Op0)  │        │ print(Op0) │          │◄─────┘
                                      │                │   │ ◄───────────────────┤        │ ◄──────────┤          │
           printer(MCInst,            │                │   ├───────────────────► │        ├──────────► │ Asm-     │
┌────────┐         asm_buf)┌──────────┴──┐             │   │                     │ Inst   │            │ Writer   │
│CS Core ├────────────────►│ ARCH Module │             │   │                     │ Printer│            │ State    │
└────────┘                 └─────────────┘             │ M │                     │        │            │ Machine  │
                                      ▲                │ A │ add_cs_detail(Op1)  │        │ print(Op1) │          │
                                      │                │ P │ ◄───────────────────┤        │ ◄──────────┤          │
                                      │                │ P ├───────────────────► │        ├──────────► │          │
                                      │                │ I │                     │        │            │          │
                                      │                │ N │                     │        │            │          │
                                      └────────────────┤ G │◄────────────────────┤        │◄───────────┤          │
                                                       └───┘                     └────────┘            └──────────┘
```

The second decoding step passes the `MCInst` and a buffer to the printer.

After determining the mnemonic, each operand is printed by using
functions defined in the `InstPrinter`.

Each time an operand is printed, the mapping component is called
to populate the `cs_insn` with the operand information and details.

Again the `InstPrinter` and `AsmWriter` are translated code from LLVM,
so they mirror the behavior of `llvm-objdump`.

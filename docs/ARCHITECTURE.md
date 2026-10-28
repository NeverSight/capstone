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

### Direct decoder generation

ARM, AArch64, RISC-V, LoongArch, SPARC, PowerPC, MIPS, SystemZ and Xtensa lower their
generated decoder state machines to C branches with
`suite/synctools/fixed_len_decoder.py`.
The existing LLVM tables
remain the instruction authority. Lowering preserves field extraction,
predicate order, soft failures, operand decoder calls and incomplete-decode
rollback. A mismatch-only filter chain becomes a switch only when no other
control-flow edge enters its interior. Operand decoding and mapping are shared
with the original interpreter; text, detail and scan use the same decoder.

Run the generator after updating these architectures; `--check` verifies the
derived files and runs in the unit suite. Generation validates decoder input types, byte offsets,
ULEB128 widths and every branch target. It refuses a changed interpreter body
until its semantics have been reviewed. Auto-Sync adds the derived include after
the original table include. Unrecognized table pointers retain the interpreter.
This trades additional machine code for removal of repeated bytecode dispatch
and runtime decoding of table parameters, without changing the public API.
The generator records encoded table widths separately from helper suffixes
and C input widths. PowerPC's 32-bit and prefixed 64-bit tables both use the
64-bit `_4` helper input; MIPS halfwords use a 32-bit input, and NanoMIPS
48-bit words use the 64-bit `_8` input. SystemZ's 16-, 32- and 48-bit tables
all use the 64-bit `_8` input. Xtensa uses its generated 64-bit `_3` helper
for every table, regardless of encoded width; the translator selects that
same helper at its call sites. The wrappers retain those exact types
and the original reader, table-selection order and fallback interpreter.

ARM, AArch64 and RISC-V define their feature queries in the existing
disassembler extension headers. Constant feature numbers can then fold into
mode-bit checks at decoder and printer call sites. Each extension source emits
the external definition from that same body; the enabled-feature policy and
mode changes remain unchanged. The RISC-V extension header owns its generated
feature enum include, including after Auto-Sync regeneration.

### Operand postprocessing

AArch64 projects descriptor requirements with
`suite/synctools/aarch64_postprocess.py`. Per-opcode flags skip implicit operand
insertion and tied-operand traversals only when those traversals perform no
writes. Instructions requiring them keep the original helpers, including on
decode failure; decoding, legality checks and operand order are unchanged.

Run the generator after updating AArch64 descriptors or translating its decoder.
It regenerates `AArch64GenPostprocess.inc` and reapplies the two local guards.
`--check` verifies both outputs and rejects changes to the owning helper bodies
until their skip conditions are reviewed. The native unit check evaluates all
descriptors with the actual enum and constraint definitions.

ARM and RISC-V similarly project tied-operand requirements with
`suite/synctools/operand_writeback.py`. Opcodes without tied operands skip the
writeback descriptor traversal; flagged opcodes retain the owning helper,
including its existing invocation after failed decoding. Native tests compare
every projected flag with the actual descriptor objects. The AArch64 generator
shares the writeback helper audit, so a helper change has one review boundary.

### Component 2 - Mapping logic

The mapping component has three different task:

1. Serving as programmable interface for the Capstone core to the LLVM code.
2. Mapping LLVM decoded instructions to a Capstone instruction.
3. Adding additional detail to the Capstone instructions
(e.g. operand `read/write` attributes etc.).

For AArch64, ARM, Alpha, ARC, Mips, PPC, Sparc, LoongArch, and RISC-V, DIET retains
the operand type classifications used to construct architectural operands,
including memory components and AArch64 bound operands. Its compact
rows in `*GenCSMappingInsnOpDiet.inc` are projections of the checked-in full
`*GenCSMappingInsnOp.inc` tables, not independent ISA descriptions. Run
`python3 suite/synctools/mapping_diet_types.py` after changing those tables,
`*GenInstrInfo.inc` opcode enums, common operand type values, or the mapping
capacities in `Mapping.h`. `--check`
validates every opcode name/index, type expression, row extent and zero sentinel,
and rejects stale output. Equal padded type rows share a uint16-indexed entry.
Only DIET includes the projection; full builds keep the original mapping tables
and access path. Access metadata and data-type lists remain omitted in DIET.
The private x86 feature printers validate decoded register IDs independently of
the public register-name API, which intentionally returns no names in DIET.
Lack of a printable name must not reject a valid feature instruction or route its
private opcode into an unrelated generated instruction table.
These checks establish that the compact table preserves its source's numeric
operand classifications and opcode alignment. They do not validate ISA semantics
or replace decoder and architectural-detail regression tests.

AArch64 records post-index addressing while constructing its operands: a
separate immediate after a writeback base, or a post-increment register operand,
identifies the update. It does not recover this semantic flag by searching
printed assembly, which is absent in DIET and may use different register names.
The fixed-offset LRCPC3 pre/post-index forms encode their displacement in the
opcode rather than an immediate operand. Their detail completion supplies the
fixed displacement and post-index flag; tied-operand metadata still owns
writeback detection.

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

The private full x86 path initializes all instruction metadata and the default
first operand, leaving the other operand slots for the decoder's append helpers.
Those helpers set both operand tags and the complete value; translation and
feature decoders construct each operand before the printers read it. Readers
must honor the constructed operand count. The shared initializer owns all
metadata defaults, while `MCInst_Init` still clears the complete object for
other callers. Public instruction/detail arrays retain their existing clearing
and callback-visible state. This does not change decoding or legality checks.

The `cs_insn` is meant to be used by the Capstone core.
It is distinct from the `MCInst`. It uses different instruction identifiers, other operand representation
and holds more details about an instruction.

For x86 with both text and detail disabled, the core uses a compact result
containing the validated internal opcode, optional public opcode, length and
pseudo-opcode adjustment. Proven scalar terminals fill this result directly.
The generic and source-extension fallback owns its own `MCInst`, initializes
only opcode/count state and context, and validates operands without storing
them. Existing decoder entries retain their raw and `MCInst` contracts. Text
or detail output retains full operand construction. Memory validation and
construction share one implementation specialized for the two store policies.

The core selects the scan policy for each instruction before any detail
allocation. No allocation or callback intervenes after a scan selection; other
selections call the normal backend with its live options and initialized
`MCInst` metadata, even if an allocation callback changes those options. Full decoding
and printing own their temporary objects in a separate function. Public ID
mapping, byte copying, aliases, pseudo-opcode adjustments and cursor updates
remain owned by the shared core helpers in `cs_disasm_internal.h`. When x86 is
enabled, its decoder translation unit instantiates the iterator core from that header
beside the inline scan decoder. Otherwise `cs.c` instantiates it. Each public
entry delegates to that same inline core.
This allows the compiler to combine scan and output state without link-time
optimization, an extra dispatch boundary or duplicate iterator policies.
Input validation and option selection retain their original order.
On Clang targets supporting `preserve_most` (AArch64 and x86-64), private
scan, feature-check, mapping and full-output calls preserve additional registers.
This lets the iterator retain its context across those calls with fewer entry
and exit saves. The public API and callback calling conventions stay unchanged;
other compilers use the ordinary internal calling convention. The shared core
owns skip-data handling in an outlined helper, with detail hiding and restoration
remaining around the entire decode and callback operation.
For an unprefixed two-byte VEX header, public iteration inlines the existing
VEX reader with a constant C5 prefix after source-feature selection. Its shared
operand, reserved-field and truncation checks remain in that reader; admission
misses use the original fallback.
Ordinary generated C4 headers try that same reader before materializing an
`MCInst`. The adapter still runs first, and the existing feature-family check
excludes source-owned extensions before this shortcut. Admission misses enter
the generic helper with the same decoding and output rules.
Successful compact x86 results consume at most 15 bytes. The public iterator
uses that validated bound to omit generic truncation, large-copy dispatch and
a redundant size write. Allocated output retains the generic copy policy,
keeping the shared core code unchanged in the qualification build; full decoding
and other architectures also retain that policy. Copies still read only consumed
input bytes and preserve the unused output tail. On GNU-compatible compilers, scan entries and their
hot prefix, public-terminal and VEX tables have explicit 128-byte alignment so
nearby cold-code changes do not move them to different alignment offsets.
The private `X86_scanBatch` entry keeps the bounded classification loop in the
same translation unit. It uses the same decoder, checked ID mapping, aliases
and pseudo-opcode adjustment as `cs_disasm_iter`, returning owned ID/length
records without writing unused instruction bytes or text. It accepts only
x86 handles with text, detail and skip-data disabled, stops before an invalid
instruction, and retains no input or output pointer. Ordinary public decode
APIs retain their existing outputs. After source-owned VEX extensions decline
an encoding, the fallback tries the generated compact VEX reader before the
generic operand path. The source extension dispatcher selects disjoint VEX
map/opcode families before invoking their handlers, avoiding repeated scans
through unrelated families. This selection stays in the cold extension path;
each handler retains prefix, operand and truncation validation.
The private `X86_scanCallTarget` query uses the ordinary raw decoder and only
projects a direct near CALL's target. Immediate sign extension is shared with
operand translation, and absolute target calculation is shared with both
printers. It avoids constructing `MCInst`/`cs_insn` operands or changing handle
options when a batch consumer needs one call target. It does not change the
classification loop or the public text/detail contract.
Batch decoding retains its existing entry and allocation behavior. Skip-data
callbacks can change options for the next instruction; common iterator helpers
hide and restore the detail pointer around decoding and callback execution.

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

Legacy RAO-INT (`0F 38 FC` with its operation-selecting mandatory prefix) and
VEX CMPccXADD use the source-owned atomic handler in `X86Mapping.c`. They
reuse the existing atomic mapping and printers while retaining their own
raw prefix, opcode, REX and displacement metadata. RAO supports 16/32/64-bit
code modes; VEX CMPccXADD requires 64-bit mode. The memory reader owns SIB,
address-size overrides and 16-bit addressing. The handler rejects LOCK,
register-only operands, conflicting mandatory prefixes and reserved VEX
fields before returning a decoded instruction.

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
`X86GenOperandRead.inc`, `X86GenOperandTranslate.inc`, `X86GenOperandScan.inc`,
`X86GenLegacyTerminal.inc` and `X86GenVexScan.inc` without writing, and runs in the
unit suite when Python is available.

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
For compact scan results, the same plans have a public-ID projection derived
from `X86MappingInsn*.inc` and `x86.h`. It uses the same operand readers and
decision kinds, while avoiding a subsequent UID-to-public-ID lookup. Raw and
operand-producing decoding retain internal IDs and their original state writes.

Full decoding uses the same terminal groups to read, validate and construct
MCInst operands in one handler, removing a second operand-shape dispatch.
Generated handlers reuse the owning translation helpers and preserve duplicate
operand order. Size is assigned after final read validation and before
translation, including translation failure. The completed raw state still feeds
prefix and public-detail metadata. Nonterminal instructions retain generic
translation; EVEX keeps raw decoding so normalization, displacement repair and
prefix restoration retain their order. Raw and scan entry contracts are unchanged.

Public scans additionally admit three-operand scalar and ordinary XMM/MMX
descriptors when their exact ordered reads already occur in the compact scan
dispatch. Generation proves every descriptor's register/memory requirements
before merging handlers with identical reader calls. New reader sequences stay
generic, keeping the common iterator's dispatch bounded. Raw tables and handler
numbering remain unchanged: the raw entry can inherit size flags from its
caller, including on truncated input, while public scan state starts fresh.

The public iterator also uses the projection's unused operand-set bits to
separate the ModR/M requirement from the optional immediate-read sequence.
Generation reconstructs and checks the original ordered reader calls. The
handler index remains available to native batches and other scan callers,
which retain their existing dispatch. Both choices use the same readers,
legality decisions and finalization.

The 16-bit rows compose the existing primary and operand-size lookups only when
their decision kinds match. Both then require the same read, and the second
lookup either reads nothing or reuses an already successful ModR/M read.
Equivalence comes from the existing lookup ranges. Rows for operand/address-size
prefix combinations keep the primary ID with an operand-size override and use
the equivalent secondary ID without one; both still preserve the secondary
lookup's read requirement. Different read requirements,
address-size repairs and UD1's runtime operand override retain generic
selection. No failed secondary read or cursor update is removed from that path.

The terminal admission rule excludes LOCK, REX2 and vector prefixes. Generation
also checks every selected ModR/M against both operand sequences: REG operands
must be admitted GPR, XMM or MMX classes; opcode-register operands must be GPRs.
An RM operand must match its register or
memory form, and immediates must neither encode registers nor change the opcode.
Any incompatible descriptor keeps the generic path. Under this admission rule,
REX produces only valid GPR/XMM indices, MMX indices are masked to three bits,
and a successful legacy address read
produces valid base/index registers. These facts discharge the operand fixup
and translation checks for scan terminals before code generation. Segment,
control and debug registers are excluded, so these compact readers also omit
the MOV-to-CS rejection and MOV-control/debug ModR/M repair. Generic and raw
decoding retain those checks. Opcode 90 with REX.B keeps the XCHG repair path;
F3/PAUSE is outside the prefix admission.

The compact scan result also admits unprefixed 64-bit C4/C5 instructions with
ordinary GPR, XMM/YMM, memory and plain immediate operands. Generated UID flags
derive register/memory legality, VVVV use and immediate-read patterns from both
operand sequences. Prefix parsing, attribute selection and opcode decisions
reuse the generic decoder's policy; checked address and immediate readers
consume the same bytes. An unused VVVV field must still be zero after inversion.
Within these admitted forms, the VEX register indices and ordinary addresses
already satisfy the operand fixup and translation checks.
The VEX metadata word combines these flags with the public ID from the same
mapping source. Unmapped UIDs retain their existing mapping behavior. Neither
projection changes opcode admission, prefix checks or operand-read ordering.

For these C4/C5 forms, W/L/pp select generated pointers to the existing packed
opcode rows. The generator verifies those row numbers against the owning
packed-table generator before emitting them. Prefix parsing and map validation
still precede this lookup, and the same metadata and operand checks follow it.

Source-owned extensions retain precedence. The extension dispatcher and compact
C4 fallback share a map/opcode family classifier. An ordinary unprefixed C4
instruction bypasses the source handler in the outlined fallback, without
adding opcode-family tests to the ordinary scalar entry. Legacy prefixes, other bitness,
VSIB, masks, register-encoded immediates, opcode-changing predicates and special
size repairs keep generic decoding. An admission miss restarts that path from
the original bytes. The raw and operand-producing interfaces retain their
existing state and failure contracts. VEX admission runs after successful
legacy terminals, without retaining prefix-loop state across those readers.

The same ModR/M, SIB, displacement and immediate readers serve both outputs,
with a constant materialization policy. Raw decoding retains all fields and
failed-read state. Scan terminals consume and bounds-check the same bytes but
retain only control state before the shared final checks and opcode setup;
they do not build register/address values merely to discard them. Identical
scan read sequences share a generated switch case and one finalization. The
MOFFS absolute addresses use the same address-size read and retain displacement
and immediate metadata in raw output. Incoming raw size flags still use generic
MOFFS ID selection, including truncated reads. The completed scan result does
not expose a raw instruction. Its null-`MCInst` entry still returns the same raw state as
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

The dedicated scan entries share the parser with raw decoding. Their scalar
terminals return only the validated ID and length before constructing
the requested compact or `MCInst` result. They need no intermediate opcode
translation because terminal admission excludes acquire/release prefixes and
opcode-changing operands. Prefix, opcode, ID selection, prefix validation,
terminal, checked scalar reads and compact ModR/M helpers stay inline so the
compiler can remove unused local state.

Compact results first try unprefixed and single-REX legacy headers, plus
16-bit size-prefix headers, in the shared readers. These common instructions
finish without a separate extension-prefix walk. The existing feature-byte
flags and 0F refinement predicate defer possible source-owned extensions before
a generated invalid terminal can reject them. Mixed mode flags retain the
original extension-selector ordering because its CS_MODE_64 test differs from
the raw decoder's 16/32-bit priority.

The shared byte classifier includes the C5 and 8F headers in compact legacy
exclusions, so admission uses one mask. Their existing prefix and extension
routes retain the same precedence.

The public iterator selects a terminal from a bounded ModR/M peek before the
shared reader consumes SIB and displacement bytes. The complete reader still
runs before invalid-ID rejection. Native batches retain their original read
order, and both interfaces share the same generated decisions and operands.

The public iterator completes an admitted terminal through the shared output
helper before joining fallback result handling. This keeps its public ID,
length and zero alias adjustment separate from the result object passed by
address to cold decoders. Initial admission and fallback routing remain shared
with native batches; the fallback selector stays inline and does not repeat
initial parsing. Byte copying, detail-pointer lifetime, callbacks and cursor
updates retain their common core policy.

On an admission miss, the extension selector supplies the bounded first
non-prefix offset. Ordinary terminal admission and the outlined compact reader
retain operand/address-size prefixes, segment prefixes and ordered REX prefixes
in 32/64-bit mode, including repeats. The 16-bit reader retains its
size-prefix-only loop. Prefix field updates and size calculation use the full
parser's helpers, including clearing REX when a legacy prefix follows it.
Generated size-prefix rows select ordinary scalar instructions and multi-byte
NOPs. REX.B opcode 90, relative-size repairs, 64-bit prefixed MOFFS and other
unproven shapes restart generic decoding from the original bytes. These rows
apply only to fresh compact state; raw decoding retains its original selection
when incoming state already contains size flags. Each bitness enters the shared
reader with a constant mode so unused size and prefix branches can fold away.

Compact terminal state stays local to its shared readers. The opcode reader
returns to generic decoding before three-byte maps and operand-bearing 3DNow
headers, which are outside the terminal tables. The outlined generic fallback
owns a separate state. No terminal copies register/address values merely to
discard them; byte consumption, bounds and legality still come from the shared
readers.

After the initial admission miss, the scan entry runs the existing extension
selector once. Source-owned
extensions keep their handlers and precedence; EVEX enters the same backend
after extension dispatch, retaining normalization and restoration. Generic raw
results share backend size assignment, displacement correction and scan
translation. The normal backend inlines the same post-extension implementation
with its original option checks; the scan-only entry uses a constant policy so
it does not carry full-output construction. Public ID mapping, aliases, byte
copying and cursor advancement
remain in the common core for both decoding APIs.

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

The legacy x86 full Intel and AT&T printer tables store mnemonic lengths in
unused high bits of their existing opcode records. The string bytes and operand
fragment masks remain authoritative. After updating `X86GenAsmWriter*.inc`, run
`python3 suite/synctools/x86_mnemonic_sizes.py`; `--check` verifies every string
length, offset and operand fragment, and rejects layouts without enough spare
bits. Reduced writers retain their original append path. The known-length
`SStream_concat0_n` helper copies exactly the supplied string bytes, with bounded
fixed-size copies for short names; truncation, markup and index repair retain the
general writer. It requires a NUL-terminated source whose bytes do not overlap
the append range.

With the default userspace formatter, the Intel/MASM printer fills operand
access and flags once, after explicit and implicit operands are complete. A
custom formatter can observe partial detail or change options, so it retains
the earlier assignments as well; kernel and custom-runtime builds retain that
path too. AT&T keeps its separate ordering and mask handling.

The private x86 output stream initializes its empty string and scalar state
without clearing the unused character tail when the active userspace formatter
is the system `vsnprintf`. Its readers consume only the terminated text prefix.
Custom formatters retain the complete clear because they can inspect the whole
destination capacity. Other architectures, DIET and custom-runtime builds keep
`SStream_Init`; the shared stream API and public output-array clearing are
unchanged.

### Disassembling process

Printers append text through the shared `SStream` helpers. In non-DIET builds with
GCC or Clang, `SStream_concat0` exposes compile-time string lengths at the call site. A token
that fits in an open stream without a pending markup close uses a fixed-length
copy; other writes retain the external helper, including truncation and index
repair. Empty strings remain no-ops. For `SStream_concat0`, DIET and other
compilers retain the external helper. This constant-token specialization applies
to generated printers without changing their tables or the translator.

Generated alias printers append the mnemonic prefix through
`SStream_concat0_substr`. The prefix contains no NUL bytes and comes from a
static table separate from the stream. With the default system malloc/free
hooks, this copies the bounded prefix directly, including the usual truncation
and markup handling. Custom allocator hooks retain the temporary allocation,
copy, append and free in their original order, even for empty or closed streams.
The owning emitter is `PrinterCapstone::asmWriterEmitPrintAliasInstrBody` in
the source-built NeverSight LLVM generator branch described by Auto-Sync.

The final public-output copy combines mnemonic extraction and the internal
`|` prefix separator conversion. It retains the full output-buffer clearing,
postprinter ordering and custom mnemonic replacement; the general stream
extraction helper retains its original behavior.

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

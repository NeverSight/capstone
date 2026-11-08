# Unit tests

`unit_mips16_word_order` checks MIPS16 EXTEND-prefixed LI at two-byte alignment,
mixed 16/32-bit streams and truncated prefixes/suffixes. Both byte orders,
decode APIs and text/detail options run in normal and DIET builds. The initial
operand cases use unsigned immediates below 0x8000; JAL/JALX and other MIPS16
operand semantics are outside this byte-order regression.


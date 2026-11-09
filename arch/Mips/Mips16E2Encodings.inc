/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

/* MD01172 rev 1.00: EXTEND immediate and GP-relative selectors. */
#ifdef M16E2_IMMEDIATE
M16E2_IMMEDIATE(0x00, 1, ADDiu, 28)
M16E2_IMMEDIATE(0x0d, 1, LUi, 0)
M16E2_IMMEDIATE(0x0d, 2, ORi, rx)
M16E2_IMMEDIATE(0x0d, 3, ANDi, rx)
M16E2_IMMEDIATE(0x0d, 4, XORi, rx)
#endif
#ifdef M16E2_MEMORY
M16E2_MEMORY(0x12, 1, LW)
M16E2_MEMORY(0x12, 2, LH)
M16E2_MEMORY(0x12, 3, LB)
M16E2_MEMORY(0x12, 4, LHu)
M16E2_MEMORY(0x12, 5, LBu)
M16E2_MEMORY(0x1a, 1, SW)
M16E2_MEMORY(0x1a, 2, SH)
M16E2_MEMORY(0x1a, 3, SB)
#endif
#ifdef M16E2_TMOVE
M16E2_TMOVE(MOVZ_I_I, "movtz\t")
M16E2_TMOVE(MOVN_I_I, "movtn\t")
#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_ALIAS_PATTERN_LOOKUP_H
#define CS_ALIAS_PATTERN_LOOKUP_H

#include "cs_priv.h"
#include "MCInstPrinter.h"

CAPSTONE_INTERNAL const char *
matchAArch64AliasPatterns(MCInst *MI, const AliasMatchingData *data);
CAPSTONE_INTERNAL const char *
matchMipsAliasPatterns(MCInst *MI, const AliasMatchingData *data);
CAPSTONE_INTERNAL const char *
matchARMAliasPatterns(MCInst *MI, const AliasMatchingData *data);
CAPSTONE_INTERNAL const char *
matchPPCAliasPatterns(MCInst *MI, const AliasMatchingData *data);
CAPSTONE_INTERNAL const char *
matchRISCVAliasPatterns(MCInst *MI, const AliasMatchingData *data);
CAPSTONE_INTERNAL const char *
matchSparcAliasPatterns(MCInst *MI, const AliasMatchingData *data);
CAPSTONE_INTERNAL const char *
matchLoongArchAliasPatterns(MCInst *MI, const AliasMatchingData *data);

#endif

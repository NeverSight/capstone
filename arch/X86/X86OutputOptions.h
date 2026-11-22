/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_OUTPUT_OPTIONS_H
#define CS_X86_OUTPUT_OPTIONS_H

#include "../../cs_priv.h"
#include "../../utils.h"
#include "X86Disassembler.h"
#include "X86InstPrinter.h"
#include "X86InstPrinterCommon.h"
#include "X86Mapping.h"

/* Called by the static i386 iterator with at least one input byte. */
CAPSTONE_INTERNAL CS_PRESERVE_MOST bool
X86_decodeOutputMiss32(cs_struct *handle, const uint8_t *code, size_t size,
			cs_insn *insn, uint16_t *insn_size, bool batch);

/* Keep the mode, option and callback checks in a single short-circuit chain
 * in both instantiations of the scalar writer. */
#define X86_OUTPUT_UNSUPPORTED(handle, mode_mismatch) \
	((mode_mismatch) || (handle)->no_text || (handle)->imm_unsigned || \
	 (handle)->mnem_list || (handle)->doing_mem || \
	 ((handle)->syntax != CS_OPT_SYNTAX_INTEL && \
	  (handle)->syntax != CS_OPT_SYNTAX_DEFAULT) || \
	 (handle)->disasm != X86_getInstruction || \
	 (handle)->insn_id != X86_get_insn_id || \
	 (handle)->printer != X86_Intel_printInst || \
	 (handle)->post_printer != X86_postprinter || \
	 cs_vsnprintf != cs_default_vsnprintf)

#endif

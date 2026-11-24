/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_register_fallback32_text" rodata = \
	".cs_x86_register_fallback32_rodata"
#endif
#include "../../cs_priv.h"
#if !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_REDUCE) && \
	defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#include "X86OutputOptions.h"
#include "X86RegisterImmediateOutput.h"
#include "X86GenTest32Registers.inc"
/* The extra Group 3 forms improve the i386 reader on Linux x86-64 Clang. */
#if defined(__linux__) && defined(__clang__) && defined(__x86_64__)
#define X86_GROUP3_REGISTER_OUTPUT
#include "X86GenGroup3Registers32.inc"
#endif
#include "../../cs_disasm_internal.h"

CAPSTONE_INTERNAL CS_PRESERVE_MOST bool
X86_decodeRegisterFallback32(cs_struct *handle, const uint8_t *code,
			     size_t size, cs_insn *insn, uint16_t *insn_size,
			     bool batch)
{
	const unsigned opcode = code[0];
	if ((opcode & 0xfe) == 0xf6) {
		const unsigned form = opcode & 1;
		const unsigned width = form ? 4 : 1;
		if (size >= 2 + width && (code[1] & 0xf8) == 0xc0 &&
		    !X86_OUTPUT_UNSUPPORTED(handle, false)) {
			writeUnsignedRegisterImmediate(
				insn, &test32_rows[form],
				&test32_regs[form][code[1] & 7], code, 0,
				code[1], 2, width, insn_size);
			return true;
		}
#ifdef X86_GROUP3_REGISTER_OUTPUT
		/* Register forms /2 through /7 have no immediate. */
		if (size >= 2 && code[1] >= 0xd0 &&
		    !X86_OUTPUT_UNSUPPORTED(handle, false)) {
			const unsigned modrm = code[1];
			const struct X86SimpleOutput *row =
				&group3_registers[form][((modrm >> 3) & 7) - 2];
			const struct X86SimpleRegister *reg =
				&test32_regs[form][modrm & 7];
			insn->id = row->id;
			*insn_size = insn->size = 2;
			memcpy(insn->bytes, code, 2);
			memset(insn->mnemonic, 0, sizeof(insn->mnemonic));
			memcpy(insn->mnemonic, row->mnemonic, sizeof(row->mnemonic));
			memset(insn->op_str, 0, sizeof(insn->op_str));
			memcpy(insn->op_str, reg->name, sizeof(reg->name));
			if (insn->detail)
				X86_writeSimpleDetail(insn->detail, row, opcode, 0,
						      modrm, reg->reg, 0);
			return true;
		}
#endif
	}
	return cs_decode_full_insn(handle, code, size, insn, insn_size, batch);
}
#endif
#endif

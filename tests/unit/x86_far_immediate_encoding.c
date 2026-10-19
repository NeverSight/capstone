/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "../../arch/X86/X86Mapping.h"
#include <stdio.h>

static bool check(bool condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "far immediate encoding: %s\n", message);
	return condition;
}

int main(void)
{
	uint8_t unknown_size = 0xa5;
	bool success =
		check(X86_immediate_size(~0u, &unknown_size) == 0 &&
			      unknown_size == 0,
		      "missing table entry must initialize encoded size");
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32 };
	const cs_opt_value syntaxes[] = { CS_OPT_SYNTAX_INTEL,
					  CS_OPT_SYNTAX_ATT };
	size_t m, s, opcode, override;
	for (m = 0; m < 2; ++m) {
		for (s = 0; s < 2; ++s) {
			csh handle;
			if (cs_open(CS_ARCH_X86, modes[m], &handle) !=
			    CS_ERR_OK)
				return 1;
			cs_option(handle, CS_OPT_SYNTAX, syntaxes[s]);
			cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
			for (opcode = 0; opcode < 2; ++opcode) {
				for (override = 0; override < 2; ++override) {
					uint8_t code[8];
					const bool wide = (m != 0) !=
							  (override != 0);
					size_t n = 0;
					cs_insn *insn = NULL;
					if (override)
						code[n++] = 0x66;
					code[n++] = opcode ? 0xea : 0x9a;
					code[n++] = 0x34;
					code[n++] = 0x12;
					if (wide) {
						code[n++] = 0x78;
						code[n++] = 0x56;
					}
					code[n++] = 0xbc;
					code[n++] = 0x9a;
					const size_t count =
						cs_disasm(handle, code, n,
							  0x1000, 1, &insn);
					success &=
						check(count == 1,
						      "decode far call/jump");
					if (count) {
						const cs_x86 *detail =
							&insn->detail->x86;
						success &= check(
							insn->size == n &&
								insn->id ==
									(opcode ?
										 X86_INS_LJMP :
										 X86_INS_LCALL),
							"far instruction identity");
						// The single encoding record describes the final ptr16 selector.
						success &= check(
							detail->encoding.imm_offset ==
									n - 2 &&
								detail->encoding.imm_size ==
									2,
							"printer must retain decoded selector extent");
						cs_free(insn, count);
					}
				}
			}
			cs_close(&handle);
		}
	}
	return success ? 0 : 1;
}

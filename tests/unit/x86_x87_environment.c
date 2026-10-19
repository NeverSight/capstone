/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>

static bool check(const cs_insn *insn, unsigned id, unsigned size,
		  unsigned access, unsigned length, bool detail)
{
	if (!detail)
		return insn && insn->id == id && insn->size == length &&
		       !insn->detail;
	if (!insn || !insn->detail || insn->id != id || insn->size != length ||
	    insn->detail->x86.op_count != 1 ||
	    insn->detail->x86.operands[0].type != X86_OP_MEM ||
	    insn->detail->x86.operands[0].size != size ||
	    insn->detail->x86.operands[0].access != access) {
		fprintf(stderr,
			"x87 id=%u: expected %u bytes/access %u/length %u, got %u/%u/%u\n",
			id, size, access, length,
			insn && insn->detail ?
				insn->detail->x86.operands[0].size :
				0,
			insn && insn->detail ?
				insn->detail->x86.operands[0].access :
				0,
			insn ? insn->size : 0);
		return false;
	}
	return true;
}
int main(void)
{
	const cs_mode modes[] = { CS_MODE_16, CS_MODE_32, CS_MODE_64 };
	const cs_opt_value syntaxes[] = { CS_OPT_SYNTAX_INTEL,
					  CS_OPT_SYNTAX_ATT };
	const unsigned ids[] = { X86_INS_FNSTENV, X86_INS_FLDENV,
				 X86_INS_FNSAVE, X86_INS_FRSTOR };
	bool success = true;
	unsigned observations = 0;
	for (unsigned m = 0; m < 3; ++m)
		for (unsigned s = 0; s < 2; ++s)
			for (unsigned detail = 0; detail < 2; ++detail)
				for (unsigned prefix = 0; prefix < 2; ++prefix)
					for (unsigned address = 0; address < 2;
					     ++address)
						for (unsigned i = 0; i < 4;
						     ++i) {
							csh handle;
							if (cs_open(CS_ARCH_X86,
								    modes[m],
								    &handle) !=
							    CS_ERR_OK)
								return 1;
							cs_option(
								handle,
								CS_OPT_DETAIL,
								detail ?
									CS_OPT_ON :
									CS_OPT_OFF);
							cs_option(handle,
								  CS_OPT_SYNTAX,
								  syntaxes[s]);
							uint8_t bytes[6];
							unsigned length = 0;
							if (prefix)
								bytes[length++] =
									0x66;
							if (address)
								bytes[length++] =
									0x67;
							if (m == 2)
								bytes[length++] =
									0x48; /* REX.W does not widen legacy x87 state. */
							bytes[length++] =
								i < 2 ? 0xd9 :
									0xdd;
							bytes[length++] =
								i % 2 ? 0x20 :
									0x30;
							const bool
								short_environment =
									(m ==
									 0) !=
									!!prefix;
							const unsigned size =
								(short_environment ?
									 14 :
									 28) +
								(i >= 2 ? 80 :
									  0);
							const unsigned access =
								i % 2 ? CS_AC_READ :
									CS_AC_WRITE;
							cs_insn *insn = NULL;
							const size_t count =
								cs_disasm(
									handle,
									bytes,
									length,
									0x1000,
									1,
									&insn);
							success &=
								count == 1 &&
								check(insn,
								      ids[i],
								      size,
								      access,
								      length,
								      detail);
							cs_free(insn, count);
							insn = cs_malloc(
								handle);
							const uint8_t *cursor =
								bytes;
							size_t remaining =
								length;
							uint64_t pc = 0x1000;
							if (!insn ||
							    !cs_disasm_iter(
								    handle,
								    &cursor,
								    &remaining,
								    &pc, insn))
								success = false;
							else
								success &=
									!remaining &&
									cursor ==
										bytes + length &&
									pc == 0x1000 + length &&
									check(insn,
									      ids[i],
									      size,
									      access,
									      length,
									      detail);
							cs_free(insn, 1);
							cs_close(&handle);
							observations += 2;
						}
	printf("%u x87 environment detail observations\n", observations);
	return success ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

static bool check_implicit_copies(csh handle)
{
	for (unsigned reads = 0; reads <= MAX_IMPL_R_REGS; ++reads) {
		for (unsigned writes = 0; writes <= MAX_IMPL_W_REGS; ++writes) {
			for (unsigned overlap = 0; overlap < 3; ++overlap) {
				cs_detail detail = { 0 }, before;
				cs_insn insn = { 0 };
				insn.id = X86_INS_MOV;
				insn.detail = &detail;
				detail.regs_read_count = reads;
				detail.regs_write_count = writes;
				for (unsigned i = 0; i < reads; ++i)
					detail.regs_read[i] =
						(uint16_t)(i * 73 + 1);
				for (unsigned i = 0; i < writes; ++i)
					detail.regs_write[i] =
						(uint16_t)(65535 - i * 91);
				memcpy(&before, &detail, sizeof(detail));
				uint16_t actual[129], expected[129];
				memset(actual, 0xa5, sizeof(actual));
				memcpy(expected, actual, sizeof(actual));
				size_t write_offset =
					overlap == 0 ? 64 : overlap - 1;
				for (unsigned i = 0; i < reads; ++i)
					expected[i] = detail.regs_read[i];
				for (unsigned i = 0; i < writes; ++i)
					expected[write_offset + i] =
						detail.regs_write[i];
				uint8_t read_count = 0xa5, write_count = 0xa5;
				if (cs_regs_access(handle, &insn, actual,
						   &read_count,
						   actual + write_offset,
						   &write_count) != CS_ERR_OK ||
				    read_count != reads ||
				    write_count != writes ||
				    memcmp(actual, expected, sizeof(actual)) ||
				    memcmp(&detail, &before, sizeof(detail))) {
					fprintf(stderr,
						"implicit register copy: read=%u write=%u overlap=%u\n",
						reads, writes, overlap);
					return false;
				}
			}
		}
	}
	return true;
}

static bool check_test_operands(void)
{
	static const unsigned widths[] = { 1, 2, 4, 8 };
	static const unsigned modes[] = { 16, 32, 64 };
	static const x86_reg registers[] = { X86_REG_AL, X86_REG_AX,
					     X86_REG_EAX, X86_REG_RAX };
	static const uint32_t masks[] = { 0,	1,    9,	  10,
					  0x80, 0xff, 0x80000000, 0xffffffff };
	const uint64_t flags = X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_CF |
			       X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF |
			       X86_EFLAGS_MODIFY_PF | X86_EFLAGS_UNDEFINED_AF;
	for (unsigned m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
		csh h = 0;
		cs_mode mode = modes[m] == 16 ? CS_MODE_16 :
			       modes[m] == 32 ? CS_MODE_32 :
						CS_MODE_64;
		if (cs_open(CS_ARCH_X86, mode, &h) != CS_ERR_OK)
			return false;
		if (cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
			cs_close(&h);
			return false;
		}
		cs_insn *insn = cs_malloc(h);
		if (!insn) {
			cs_close(&h);
			return false;
		}
		bool ok = true;
		for (unsigned syntax = 0; syntax < 2 && ok; ++syntax) {
			cs_err err = cs_option(h, CS_OPT_SYNTAX,
					       syntax ? CS_OPT_SYNTAX_ATT :
							CS_OPT_SYNTAX_INTEL);
			if (syntax && err == CS_ERR_X86_ATT)
				continue;
			if (err != CS_ERR_OK) {
				ok = false;
				break;
			}
			for (unsigned text = 0; text < 2 && ok; ++text) {
				if (cs_option(h, CS_OPT_TEXT,
					      text ? CS_OPT_ON : CS_OPT_OFF)) {
					ok = false;
					break;
				}
				for (unsigned w = 0; w < 4 && ok; ++w) {
					unsigned width = widths[w];
					if (width == 8 && modes[m] != 64)
						continue;
					for (unsigned form = 0; form < 2 && ok;
					     ++form) {
						for (unsigned v = 0;
						     v <
						     sizeof(masks) /
							     sizeof(masks[0]);
						     ++v) {
							uint8_t bytes[8],
								*end = bytes;
							if ((width == 2 &&
							     modes[m] != 16) ||
							    (width == 4 &&
							     modes[m] == 16))
								*end++ = 0x66;
							if (width == 8)
								*end++ = 0x48;
							*end++ =
								(uint8_t)((form ? 0xf6 :
										  0xa8) +
									  (width !=
									   1));
							if (form)
								*end++ = 0xc0;
							unsigned immediate_size =
								width == 8 ?
									4 :
									width;
							for (unsigned b = 0;
							     b < immediate_size;
							     ++b)
								*end++ =
									(uint8_t)(masks[v] >>
										  (b *
										   8));
							const uint8_t *cursor =
								bytes;
							size_t left =
								(size_t)(end -
									 bytes);
							uint64_t pc = 0x1000;
							cs_regs reads, writes;
							uint8_t nr = 0, nw = 0;
							bool decoded =
								cs_disasm_iter(
									h,
									&cursor,
									&left,
									&pc,
									insn) &&
								left == 0 &&
								insn->id ==
									X86_INS_TEST;
							if (!text) {
								ok = decoded &&
								     !insn->mnemonic
									      [0] &&
								     !insn->op_str
									      [0];
								if (!ok)
									fprintf(stderr,
										"TEST textless decode failed\n");
								if (!ok)
									break;
								continue;
							}
							ok = decoded &&
							     insn->detail->x86
									     .op_count ==
								     2 &&
							     insn->detail->x86
									     .eflags ==
								     flags &&
							     cs_regs_access(
								     h, insn,
								     reads, &nr,
								     writes,
								     &nw) ==
								     CS_ERR_OK &&
							     nr == 1 &&
							     reads[0] ==
								     registers[w] &&
							     nw == 1 &&
							     writes[0] ==
								     X86_REG_EFLAGS;
							if (ok) {
								const cs_x86 *x =
									&insn->detail
										 ->x86;
								unsigned reg_slot =
									x->operands[0].type ==
											X86_OP_REG ?
										0 :
										1;
								ok = x->operands[reg_slot]
										     .type ==
									     X86_OP_REG &&
								     x->operands[reg_slot]
										     .reg ==
									     registers[w] &&
								     x->operands[reg_slot]
										     .size ==
									     width &&
								     x->operands[reg_slot]
										     .access ==
									     CS_AC_READ &&
								     x->operands[1 -
										 reg_slot]
										     .type ==
									     X86_OP_IMM &&
								     x->operands[1 -
										 reg_slot]
										     .access ==
									     0;
							}
							if (!ok) {
								fprintf(stderr,
									"TEST operand access: mode=%u width=%u form=%u syntax=%u text=%u value=%08x reads=%u writes=%u\n",
									modes[m],
									width,
									form,
									syntax,
									text,
									masks[v],
									nr, nw);
								break;
							}
						}
					}
				}
			}
		}
		cs_free(insn, 1);
		cs_close(&h);
		if (!ok)
			return false;
	}
	return true;
}

int main(void)
{
	if (cs_support(CS_SUPPORT_DIET))
		return 0;
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		cs_close(&handle);
		return 1;
	}
	bool success = check_implicit_copies(handle) && check_test_operands();
	cs_close(&handle);
	return success ? 0 : 1;
}

#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>

static bool check(csh handle, cs_insn *insn, uint32_t word, bool big_endian)
{
	uint8_t bytes[4];
	for (unsigned i = 0; i < 4; ++i)
		bytes[big_endian ? 3 - i : i] = (uint8_t)(word >> (8 * i));
	const uint8_t *code = bytes;
	size_t size = sizeof(bytes);
	uint64_t address = 0x1000;
	if (!cs_disasm_iter(handle, &code, &size, &address, insn) ||
	    size != 0 || address != 0x1004)
		return false;

	const cs_hppa *detail = &insn->detail->hppa;
	cs_regs read, written;
	uint8_t nr = 0, nw = 0;
	const bool diet = cs_support(CS_SUPPORT_DIET);
	const cs_err err =
		cs_regs_access(handle, insn, read, &nr, written, &nw);
	if (err != (diet ? CS_ERR_DIET : CS_ERR_OK))
		return false;
	if (word == 0x2b98c54f) {
		return insn->id == HPPA_INS_ADDIL && detail->op_count == 2 &&
		       detail->operands[0].type == HPPA_OP_IMM &&
		       detail->operands[0].access == CS_AC_INVALID &&
		       detail->operands[1].reg == HPPA_REG_GR28 &&
		       (diet || (insn->detail->regs_write_count == 1 &&
				 insn->detail->regs_write[0] == HPPA_REG_GR1 &&
				 nr == 1 && read[0] == HPPA_REG_GR28 &&
				 nw == 1 && written[0] == HPPA_REG_GR1));
	}

	/* Three sources refer to fr4 in fmpyadd,dbl fr4,fr4,fr6,fr4,fr5. */
	return insn->id == HPPA_INS_FMPYADD && detail->op_count == 5 &&
	       (diet ||
		(nr == 2 && read[0] == HPPA_REG_FPR4 &&
		 read[1] == HPPA_REG_FPR5 && nw == 2 &&
		 written[0] == HPPA_REG_FPR5 && written[1] == HPPA_REG_FPR6));
}

int main(void)
{
	const cs_mode versions[] = { CS_MODE_HPPA_11, CS_MODE_HPPA_20,
				     CS_MODE_HPPA_20W };
	for (unsigned v = 0; v < sizeof(versions) / sizeof(versions[0]); ++v) {
		for (unsigned big = 0; big < 2; ++big) {
			csh handle;
			cs_mode mode = (cs_mode)(versions[v] |
						 (big ? CS_MODE_BIG_ENDIAN :
							CS_MODE_LITTLE_ENDIAN));
			if (cs_open(CS_ARCH_HPPA, mode, &handle) != CS_ERR_OK)
				return 1;
			if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) !=
			    CS_ERR_OK) {
				cs_close(&handle);
				return 1;
			}
			cs_insn *insn = cs_malloc(handle);
			bool ok = insn &&
				  check(handle, insn, 0x2b98c54f, big) &&
				  check(handle, insn, 0x18842906, big);
			if (insn)
				cs_free(insn, 1);
			cs_close(&handle);
			if (!ok) {
				fprintf(stderr,
					"HPPA register detail differs in mode %u\n",
					(unsigned)mode);
				return 1;
			}
		}
	}
	return 0;
}

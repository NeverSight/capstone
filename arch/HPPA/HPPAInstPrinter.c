/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_HPPA

#include <capstone/platform.h>
#include "../../Mapping.h"
#include "../../utils.h"

#include "HPPAInstPrinter.h"
#include "HPPAMapping.h"

static void set_op_imm(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_IMM;
	op->imm = val;
}

static void set_op_reg(cs_hppa *hppa, uint64_t val, cs_ac_type access)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_REG;
	op->reg = val;
	op->access = access;
}

static void set_op_idx_reg(cs_hppa *hppa, uint64_t reg)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_IDX_REG;
	op->reg = reg;
	op->access = CS_AC_READ;
}

static void set_op_disp(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_DISP;
	op->imm = val;
}

static void set_op_target(cs_hppa *hppa, uint64_t val)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_TARGET;
	op->imm = val;
}

static void set_op_mem(cs_hppa *hppa, uint32_t base, uint32_t space,
		       cs_ac_type base_access)
{
	cs_hppa_op *op = &hppa->operands[hppa->op_count++];
	op->type = HPPA_OP_MEM;
	op->mem.base = base;
	op->mem.space = space;
	op->access = base_access;
}
/* HPPA instruction formats (access)
   i - imm arguments
   R - read access register
   W - write access register
   w - read + write access register
   r - index register (read only)
   T - offset (pc relative)
   o - displacement (imm)
   x - [r] or [o] defined by the operand kind
   b - base register (may be writable in some cases)
*/
struct hppa_print_info {
	hppa_insn_group group;
	const char *format;
	const char *alternative;
};

static const struct hppa_print_info print_info[HPPA_INS_ENDING] = {
	[HPPA_INS_LDI] = { HPPA_GRP_LONG_IMM, "iW" },
	[HPPA_INS_CMPIB] = { HPPA_GRP_BRANCH, "iRT" },
	[HPPA_INS_COMIB] = { HPPA_GRP_BRANCH, "iRT" },
	[HPPA_INS_CMPB] = { HPPA_GRP_BRANCH, "RRT" },
	[HPPA_INS_COMB] = { HPPA_GRP_BRANCH, "RRT" },
	[HPPA_INS_ADDB] = { HPPA_GRP_BRANCH, "RwT" },
	[HPPA_INS_ADDIB] = { HPPA_GRP_BRANCH, "iwT" },
	[HPPA_INS_NOP] = { HPPA_GRP_COMPUTATION, "" },
	[HPPA_INS_COPY] = { HPPA_GRP_COMPUTATION, "RW" },
	[HPPA_INS_MTSAR] = { HPPA_GRP_SYSCTRL, "R" },
	[HPPA_INS_LDD] = { HPPA_GRP_MEM_REF, "x(Rb)W" },
	[HPPA_INS_LDW] = { HPPA_GRP_MEM_REF, "x(Rb)W" },
	[HPPA_INS_LDH] = { HPPA_GRP_MEM_REF, "x(Rb)W" },
	[HPPA_INS_LDB] = { HPPA_GRP_MEM_REF, "x(Rb)W" },
	[HPPA_INS_STD] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_STW] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_STH] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_STB] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_LDWM] = { HPPA_GRP_MEM_REF, "o(Rw)W" },
	[HPPA_INS_STWM] = { HPPA_GRP_MEM_REF, "Ro(Rw)" },
	[HPPA_INS_LDWX] = { HPPA_GRP_MEM_REF, "r(Rb)W" },
	[HPPA_INS_LDHX] = { HPPA_GRP_MEM_REF, "r(Rb)W" },
	[HPPA_INS_LDBX] = { HPPA_GRP_MEM_REF, "r(Rb)W" },
	[HPPA_INS_LDWA] = { HPPA_GRP_MEM_REF, "x(R)W" },
	[HPPA_INS_LDCW] = { HPPA_GRP_MEM_REF, "x(Rb)W" },
	[HPPA_INS_STWA] = { HPPA_GRP_MEM_REF, "Ro(b)" },
	[HPPA_INS_STBY] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_LDDA] = { HPPA_GRP_MEM_REF, "x(b)W" },
	[HPPA_INS_LDCD] = { HPPA_GRP_MEM_REF, "x(Rb)W" },
	[HPPA_INS_STDA] = { HPPA_GRP_MEM_REF, "Ro(b)" },
	[HPPA_INS_LDWAX] = { HPPA_GRP_MEM_REF, "r(b)W" },
	[HPPA_INS_LDCWX] = { HPPA_GRP_MEM_REF, "r(Rb)W" },
	[HPPA_INS_LDWS] = { HPPA_GRP_MEM_REF, "o(Rb)W" },
	[HPPA_INS_LDHS] = { HPPA_GRP_MEM_REF, "o(Rb)W" },
	[HPPA_INS_LDBS] = { HPPA_GRP_MEM_REF, "o(Rb)W" },
	[HPPA_INS_LDWAS] = { HPPA_GRP_MEM_REF, "o(b)W" },
	[HPPA_INS_LDCWS] = { HPPA_GRP_MEM_REF, "o(Rb)W" },
	[HPPA_INS_STWS] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_STHS] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_STBS] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_STWAS] = { HPPA_GRP_MEM_REF, "Ro(b)" },
	[HPPA_INS_STDBY] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_STBYS] = { HPPA_GRP_MEM_REF, "Ro(Rb)" },
	[HPPA_INS_LDO] = { HPPA_GRP_LONG_IMM, "o(R)W" },
	[HPPA_INS_LDIL] = { HPPA_GRP_LONG_IMM, "iW" },
	[HPPA_INS_ADDIL] = { HPPA_GRP_LONG_IMM, "iR" },
	[HPPA_INS_B] = { HPPA_GRP_BRANCH, "TW" },
	[HPPA_INS_BL] = { HPPA_GRP_BRANCH, "TW" },
	[HPPA_INS_GATE] = { HPPA_GRP_BRANCH, "TW" },
	[HPPA_INS_BLR] = { HPPA_GRP_BRANCH, "RW" },
	[HPPA_INS_BV] = { HPPA_GRP_BRANCH, "x(R)" },
	[HPPA_INS_BVE] = { HPPA_GRP_BRANCH, "(b)", "(b)W" },
	[HPPA_INS_BE] = { HPPA_GRP_BRANCH, "o(RR)", "o(RR)WW" },
	[HPPA_INS_BLE] = { HPPA_GRP_BRANCH, "o(RR)" },
	[HPPA_INS_MOVB] = { HPPA_GRP_BRANCH, "RWT" },
	[HPPA_INS_MOVIB] = { HPPA_GRP_BRANCH, "iWT" },
	[HPPA_INS_COMBT] = { HPPA_GRP_BRANCH, "RRT" },
	[HPPA_INS_COMBF] = { HPPA_GRP_BRANCH, "RRT" },
	[HPPA_INS_COMIBT] = { HPPA_GRP_BRANCH, "iRT" },
	[HPPA_INS_COMIBF] = { HPPA_GRP_BRANCH, "iRT" },
	[HPPA_INS_ADDBT] = { HPPA_GRP_BRANCH, "RwT" },
	[HPPA_INS_ADDBF] = { HPPA_GRP_BRANCH, "RwT" },
	[HPPA_INS_ADDIBT] = { HPPA_GRP_BRANCH, "iwT" },
	[HPPA_INS_ADDIBF] = { HPPA_GRP_BRANCH, "iwT" },
	[HPPA_INS_BB] = { HPPA_GRP_BRANCH, "RiT" },
	[HPPA_INS_BVB] = { HPPA_GRP_BRANCH, "RT" },
	[HPPA_INS_CLRBTS] = { HPPA_GRP_BRANCH, "" },
	[HPPA_INS_POPBTS] = { HPPA_GRP_BRANCH, "i" },
	[HPPA_INS_PUSHNOM] = { HPPA_GRP_BRANCH, "" },
	[HPPA_INS_PUSHBTS] = { HPPA_GRP_BRANCH, "R" },
	[HPPA_INS_CMPCLR] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_COMCLR] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_OR] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_XOR] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_AND] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_ANDCM] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_UXOR] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_UADDCM] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_UADDCMT] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_DCOR] = { HPPA_GRP_COMPUTATION, "RW" },
	[HPPA_INS_IDCOR] = { HPPA_GRP_COMPUTATION, "RW" },
	[HPPA_INS_ADDI] = { HPPA_GRP_COMPUTATION, "iRW" },
	[HPPA_INS_ADDIO] = { HPPA_GRP_COMPUTATION, "iRW" },
	[HPPA_INS_ADDIT] = { HPPA_GRP_COMPUTATION, "iRW" },
	[HPPA_INS_ADDITO] = { HPPA_GRP_COMPUTATION, "iRW" },
	[HPPA_INS_ADD] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_ADDL] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_ADDO] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_ADDC] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_ADDCO] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SUB] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SUBO] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SUBB] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SUBBO] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SUBT] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SUBTO] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_DS] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SUBI] = { HPPA_GRP_COMPUTATION, "iRW" },
	[HPPA_INS_SUBIO] = { HPPA_GRP_COMPUTATION, "iRW" },
	[HPPA_INS_CMPICLR] = { HPPA_GRP_COMPUTATION, "iRW" },
	[HPPA_INS_COMICLR] = { HPPA_GRP_COMPUTATION, "iRW" },
	[HPPA_INS_SHLADD] = { HPPA_GRP_COMPUTATION, "RiRW" },
	[HPPA_INS_SH1ADD] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SH1ADDL] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SH1ADDO] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SH2ADD] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SH2ADDL] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SH2ADDO] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SH3ADD] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SH3ADDL] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SH3ADDO] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_HADD] = { HPPA_GRP_MULTIMEDIA, "RRW" },
	[HPPA_INS_HAVG] = { HPPA_GRP_MULTIMEDIA, "RRW" },
	[HPPA_INS_HSHL] = { HPPA_GRP_MULTIMEDIA, "RiW" },
	[HPPA_INS_HSHLADD] = { HPPA_GRP_MULTIMEDIA, "RiRW" },
	[HPPA_INS_HSHR] = { HPPA_GRP_MULTIMEDIA, "RiW" },
	[HPPA_INS_HSHRADD] = { HPPA_GRP_MULTIMEDIA, "RiRW" },
	[HPPA_INS_HSUB] = { HPPA_GRP_MULTIMEDIA, "RRW" },
	[HPPA_INS_MIXH] = { HPPA_GRP_MULTIMEDIA, "RRW" },
	[HPPA_INS_MIXW] = { HPPA_GRP_MULTIMEDIA, "RRW" },
	[HPPA_INS_PERMH] = { HPPA_GRP_MULTIMEDIA, "RW" },
	[HPPA_INS_SHRPD] = { HPPA_GRP_COMPUTATION, "RRiW", "RRRW" },
	[HPPA_INS_SHRPW] = { HPPA_GRP_COMPUTATION, "RRiW", "RRRW" },
	[HPPA_INS_VSHD] = { HPPA_GRP_COMPUTATION, "RRW" },
	[HPPA_INS_SHD] = { HPPA_GRP_COMPUTATION, "RRiW" },
	[HPPA_INS_EXTRD] = { HPPA_GRP_COMPUTATION, "RiiW", "RRiW" },
	[HPPA_INS_EXTRW] = { HPPA_GRP_COMPUTATION, "RiiW", "RRiW" },
	[HPPA_INS_VEXTRU] = { HPPA_GRP_COMPUTATION, "RiW" },
	[HPPA_INS_VEXTRS] = { HPPA_GRP_COMPUTATION, "RiW" },
	[HPPA_INS_EXTRU] = { HPPA_GRP_COMPUTATION, "RiiW" },
	[HPPA_INS_EXTRS] = { HPPA_GRP_COMPUTATION, "RiiW" },
	[HPPA_INS_DEPD] = { HPPA_GRP_COMPUTATION, "RiiW" },
	[HPPA_INS_DEPDI] = { HPPA_GRP_COMPUTATION, "iiiW" },
	[HPPA_INS_DEPW] = { HPPA_GRP_COMPUTATION, "RiiW", "RRiW" },
	[HPPA_INS_DEPWI] = { HPPA_GRP_COMPUTATION, "iiiW", "iRiW" },
	[HPPA_INS_ZVDEP] = { HPPA_GRP_COMPUTATION, "RiW" },
	[HPPA_INS_VDEP] = { HPPA_GRP_COMPUTATION, "RiW" },
	[HPPA_INS_ZDEP] = { HPPA_GRP_COMPUTATION, "RiiW" },
	[HPPA_INS_DEP] = { HPPA_GRP_COMPUTATION, "RiiW" },
	[HPPA_INS_ZVDEPI] = { HPPA_GRP_COMPUTATION, "iiW" },
	[HPPA_INS_VDEPI] = { HPPA_GRP_COMPUTATION, "iiW" },
	[HPPA_INS_ZDEPI] = { HPPA_GRP_COMPUTATION, "iiiW" },
	[HPPA_INS_DEPI] = { HPPA_GRP_COMPUTATION, "iiiW" },
	[HPPA_INS_BREAK] = { HPPA_GRP_SYSCTRL, "ii" },
	[HPPA_INS_RFI] = { HPPA_GRP_SYSCTRL, "" },
	[HPPA_INS_RFIR] = { HPPA_GRP_SYSCTRL, "" },
	[HPPA_INS_SSM] = { HPPA_GRP_SYSCTRL, "iW" },
	[HPPA_INS_RSM] = { HPPA_GRP_SYSCTRL, "iW" },
	[HPPA_INS_MTSM] = { HPPA_GRP_SYSCTRL, "R" },
	[HPPA_INS_LDSID] = { HPPA_GRP_SYSCTRL, "(RR)W" },
	[HPPA_INS_MTSP] = { HPPA_GRP_SYSCTRL, "RW" },
	[HPPA_INS_MTCTL] = { HPPA_GRP_SYSCTRL, "RW" },
	[HPPA_INS_MTSARCM] = { HPPA_GRP_SYSCTRL, "R" },
	[HPPA_INS_MFIA] = { HPPA_GRP_SYSCTRL, "W" },
	[HPPA_INS_MFSP] = { HPPA_GRP_SYSCTRL, "RW" },
	[HPPA_INS_MFCTL] = { HPPA_GRP_SYSCTRL, "RW" },
	[HPPA_INS_SYNC] = { HPPA_GRP_SYSCTRL, "" },
	[HPPA_INS_SYNCDMA] = { HPPA_GRP_SYSCTRL, "" },
	[HPPA_INS_PROBE] = { HPPA_GRP_SYSCTRL, "(RR)RW" },
	[HPPA_INS_PROBEI] = { HPPA_GRP_SYSCTRL, "(RR)iW" },
	[HPPA_INS_PROBER] = { HPPA_GRP_SYSCTRL, "(RR)RW" },
	[HPPA_INS_PROBERI] = { HPPA_GRP_SYSCTRL, "(RR)iW" },
	[HPPA_INS_PROBEW] = { HPPA_GRP_SYSCTRL, "(RR)RW" },
	[HPPA_INS_PROBEWI] = { HPPA_GRP_SYSCTRL, "(RR)iW" },
	[HPPA_INS_LPA] = { HPPA_GRP_SYSCTRL, "r(Rb)W" },
	[HPPA_INS_LCI] = { HPPA_GRP_SYSCTRL, "r(RR)W" },
	[HPPA_INS_PDTLB] = { HPPA_GRP_SYSCTRL, "r(Rb)" },
	[HPPA_INS_PITLB] = { HPPA_GRP_SYSCTRL, "r(Rb)" },
	[HPPA_INS_PDTLBE] = { HPPA_GRP_SYSCTRL, "r(Rb)" },
	[HPPA_INS_PITLBE] = { HPPA_GRP_SYSCTRL, "r(Rb)" },
	[HPPA_INS_IDTLBA] = { HPPA_GRP_SYSCTRL, "R(RR)" },
	[HPPA_INS_IITLBA] = { HPPA_GRP_SYSCTRL, "R(RR)" },
	[HPPA_INS_IDTLBP] = { HPPA_GRP_SYSCTRL, "R(RR)" },
	[HPPA_INS_IITLBP] = { HPPA_GRP_SYSCTRL, "R(RR)" },
	[HPPA_INS_PDC] = { HPPA_GRP_SYSCTRL, "r(Rb)" },
	[HPPA_INS_FDC] = { HPPA_GRP_SYSCTRL, "x(Rb)" },
	[HPPA_INS_FIC] = { HPPA_GRP_SYSCTRL, "r(Rb)" },
	[HPPA_INS_FDCE] = { HPPA_GRP_SYSCTRL, "r(Rb)" },
	[HPPA_INS_FICE] = { HPPA_GRP_SYSCTRL, "r(Rb)" },
	[HPPA_INS_DIAG] = { HPPA_GRP_SYSCTRL, "i" },
	[HPPA_INS_IDTLBT] = { HPPA_GRP_SYSCTRL, "RR" },
	[HPPA_INS_IITLBT] = { HPPA_GRP_SYSCTRL, "RR" },
	[HPPA_INS_MTCPU] = { HPPA_GRP_SYSCTRL, NULL },
	[HPPA_INS_MFCPU] = { HPPA_GRP_SYSCTRL, NULL },
	[HPPA_INS_TOCEN] = { HPPA_GRP_SYSCTRL, NULL },
	[HPPA_INS_TOCDIS] = { HPPA_GRP_SYSCTRL, NULL },
	[HPPA_INS_SHDWGR] = { HPPA_GRP_SYSCTRL, NULL },
	[HPPA_INS_GRSHDW] = { HPPA_GRP_SYSCTRL, NULL },
	[HPPA_INS_GFW] = { HPPA_GRP_SYSCTRL, NULL },
	[HPPA_INS_GFR] = { HPPA_GRP_SYSCTRL, NULL },
	[HPPA_INS_FLDW] = { HPPA_GRP_FLOAT, "x(Rb)W" },
	[HPPA_INS_FLDD] = { HPPA_GRP_FLOAT, "x(Rb)W" },
	[HPPA_INS_FSTW] = { HPPA_GRP_FLOAT, "Rx(Rb)" },
	[HPPA_INS_FSTD] = { HPPA_GRP_FLOAT, "Rx(Rb)" },
	[HPPA_INS_FLDWX] = { HPPA_GRP_FLOAT, "r(Rb)W" },
	[HPPA_INS_FLDDX] = { HPPA_GRP_FLOAT, "r(Rb)W" },
	[HPPA_INS_FSTWX] = { HPPA_GRP_FLOAT, "Rr(Rb)" },
	[HPPA_INS_FSTDX] = { HPPA_GRP_FLOAT, "Rr(Rb)" },
	[HPPA_INS_FSTQX] = { HPPA_GRP_FLOAT, "" },
	[HPPA_INS_FLDWS] = { HPPA_GRP_FLOAT, "o(Rb)W" },
	[HPPA_INS_FLDDS] = { HPPA_GRP_FLOAT, "o(Rb)W" },
	[HPPA_INS_FSTWS] = { HPPA_GRP_FLOAT, "Ro(Rb)" },
	[HPPA_INS_FSTDS] = { HPPA_GRP_FLOAT, "Ro(Rb)" },
	[HPPA_INS_FSTQS] = { HPPA_GRP_FLOAT, "Ro(Rb)" },
	[HPPA_INS_FADD] = { HPPA_GRP_FLOAT, "RRW" },
	[HPPA_INS_FSUB] = { HPPA_GRP_FLOAT, "RRW" },
	[HPPA_INS_FMPY] = { HPPA_GRP_FLOAT, "RRW" },
	[HPPA_INS_FDIV] = { HPPA_GRP_FLOAT, "RRW" },
	[HPPA_INS_FSQRT] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FABS] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FREM] = { HPPA_GRP_FLOAT, "" },
	[HPPA_INS_FRND] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FCPY] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FCNVFF] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FCNVXF] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FCNVFX] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FCNVFXT] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FMPYFADD] = { HPPA_GRP_FLOAT, "RRRW" },
	[HPPA_INS_FMPYNFADD] = { HPPA_GRP_FLOAT, "RRRW" },
	[HPPA_INS_FNEG] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FNEGABS] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FCNV] = { HPPA_GRP_FLOAT, "RW" },
	[HPPA_INS_FCMP] = { HPPA_GRP_FLOAT, "RR", "RRi" },
	[HPPA_INS_XMPYU] = { HPPA_GRP_FLOAT, "RRW" },
	[HPPA_INS_FMPYADD] = { HPPA_GRP_FLOAT, "RRWRw" },
	[HPPA_INS_FMPYSUB] = { HPPA_GRP_FLOAT, "RRWRw" },
	[HPPA_INS_FTEST] = { HPPA_GRP_FLOAT, "", "i" },
	[HPPA_INS_FID] = { HPPA_GRP_FLOAT, "" },
	[HPPA_INS_PMDIS] = { HPPA_GRP_PERFMON, "" },
	[HPPA_INS_PMENB] = { HPPA_GRP_PERFMON, "" },
	[HPPA_INS_SPOP0] = { HPPA_GRP_ASSIST, "" },
	[HPPA_INS_SPOP1] = { HPPA_GRP_ASSIST, "W" },
	[HPPA_INS_SPOP2] = { HPPA_GRP_ASSIST, "R" },
	[HPPA_INS_SPOP3] = { HPPA_GRP_ASSIST, "RR" },
	[HPPA_INS_COPR] = { HPPA_GRP_ASSIST, "" },
	[HPPA_INS_CLDW] = { HPPA_GRP_ASSIST, "x(Rb)W" },
	[HPPA_INS_CLDD] = { HPPA_GRP_ASSIST, "o(Rb)W" },
	[HPPA_INS_CSTW] = { HPPA_GRP_ASSIST, "Rx(Rb)" },
	[HPPA_INS_CSTD] = { HPPA_GRP_ASSIST, "Rx(Rb)" },
	[HPPA_INS_CLDWX] = { HPPA_GRP_ASSIST, "r(Rb)W" },
	[HPPA_INS_CLDDX] = { HPPA_GRP_ASSIST, "r(Rb)W" },
	[HPPA_INS_CSTWX] = { HPPA_GRP_ASSIST, "Rr(Rb)" },
	[HPPA_INS_CSTDX] = { HPPA_GRP_ASSIST, "Rr(Rb)" },
	[HPPA_INS_CLDWS] = { HPPA_GRP_ASSIST, "o(Rb)W" },
	[HPPA_INS_CLDDS] = { HPPA_GRP_ASSIST, "o(Rb)W" },
	[HPPA_INS_CSTWS] = { HPPA_GRP_ASSIST, "Ro(Rb)" },
	[HPPA_INS_CSTDS] = { HPPA_GRP_ASSIST, "Ro(Rb)" },
	[HPPA_INS_CALL] = { HPPA_GRP_INVALID, "" },
	[HPPA_INS_RET] = { HPPA_GRP_INVALID, "" },
};

static void print_operand(MCInst *MI, SStream *O, const cs_hppa_op *op)
{
	switch (op->type) {
	case HPPA_OP_INVALID:
		SStream_concat(O, "invalid");
		break;
	case HPPA_OP_REG:
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->reg));
		break;
	case HPPA_OP_IMM:
		printInt32(O, op->imm);
		break;
	case HPPA_OP_DISP:
		printInt32(O, op->imm);
		break;
	case HPPA_OP_IDX_REG:
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->reg));
		break;
	case HPPA_OP_MEM:
		SStream_concat(O, "(");
		if (op->mem.space != HPPA_REG_INVALID &&
		    op->mem.space != HPPA_REG_SR0) {
			SStream_concat(O, HPPA_reg_name((csh)MI->csh,
							op->mem.space));
			SStream_concat(O, ",");
		}
		SStream_concat(O, HPPA_reg_name((csh)MI->csh, op->mem.base));
		SStream_concat(O, ")");
		break;
	case HPPA_OP_TARGET:
		printUInt64(O, MI->address + op->imm);
		break;
	}
}

static void fill_operands(MCInst *MI, cs_hppa *hppa, const char *fmt)
{
	hppa->op_count = 0;
	if (!fmt || !MCInst_getNumOperands(MI))
		return;

	hppa_ext *hppa_ext = &MI->hppa_ext;
	uint8_t idx = 0;
	uint32_t space_regs[2] = { HPPA_REG_INVALID, HPPA_REG_INVALID };
	uint8_t space_reg_idx = 0;
	cs_ac_type base_access = CS_AC_INVALID;
	MCOperand *op = NULL;
	while (*fmt) {
		op = MCInst_getOperand(MI, idx++);
		switch (*fmt++) {
		case 'i':
			if (MCOperand_isReg(op)) {
				set_op_reg(hppa, MCOperand_getReg(op),
					   CS_AC_READ);
			} else {
				set_op_imm(hppa, MCOperand_getImm(op));
			}
			break;
		case 'o':
			set_op_disp(hppa, MCOperand_getImm(op));
			break;

		case 'R':
			set_op_reg(hppa, MCOperand_getReg(op),
				   CS_AC_READ);
			break;

		case 'W':
			set_op_reg(hppa, MCOperand_getReg(op),
				   CS_AC_WRITE);
			break;

		case 'w':
			set_op_reg(hppa, MCOperand_getReg(op),
				   CS_AC_READ_WRITE);
			break;

		case 'r':
			set_op_idx_reg(hppa, MCOperand_getReg(op));
			break;

		case 'T':
			set_op_target(hppa, MCOperand_getImm(op) + 8);
			break;

		case 'x':
			if (MCOperand_isReg(op)) {
				set_op_idx_reg(hppa,
					       MCOperand_getReg(op));
			} else {
				set_op_disp(hppa, MCOperand_getImm(op));
			}
			break;

		case '(':
			while (*fmt != ')') {
				if (space_reg_idx > 0) {
					op = MCInst_getOperand(MI,
							       idx++);
				}
				CS_ASSERT_RET(space_reg_idx <
					      ARR_SIZE(space_regs));
				space_regs[space_reg_idx] =
					MCOperand_getReg(op);
				if (*fmt == 'R') {
					base_access = CS_AC_READ;
				} else if (*fmt == 'W') {
					base_access = CS_AC_WRITE;
				} else if (*fmt == 'b') {
					base_access = CS_AC_READ;
					if (hppa_ext->b_writeble)
						base_access |=
							CS_AC_WRITE;
				}
				fmt++;
				space_reg_idx++;
			}

			if (space_regs[1] == HPPA_REG_INVALID)
				set_op_mem(hppa, space_regs[0],
					   space_regs[1], base_access);
			else
				set_op_mem(hppa, space_regs[1],
					   space_regs[0], base_access);
			fmt++;
			break;

		default:
			printf("Unknown: %c\n", *(fmt - 1));
			break;
		}
	}
}

static void print_modifiers(MCInst *MI, SStream *O)
{
	hppa_ext *hppa_ext = &MI->hppa_ext;
	for (uint8_t i = 0; i < hppa_ext->mod_num; ++i) {
		SStream_concat(O, ",");
		if (hppa_ext->modifiers[i].type == HPPA_MOD_STR)
			SStream_concat(O, hppa_ext->modifiers[i].str_mod);
		else
			SStream_concat(O, "%d", hppa_ext->modifiers[i].int_mod);
	}
}

#ifndef CAPSTONE_DIET
static void update_regs_access(MCInst *MI, unsigned int opcode)
{
	if (opcode == HPPA_INS_INVALID)
		return;

	hppa_ext *hppa_ext = &MI->hppa_ext;
	switch (opcode) {
	default:
		break;
	case HPPA_INS_BLE:
		map_add_implicit_write(MI, HPPA_REG_GR31);
		map_add_implicit_write(MI, HPPA_REG_SR0);
		break;
	case HPPA_INS_BVB:
		map_add_implicit_read(MI, HPPA_REG_CR11);
		break;
	case HPPA_INS_RFI:
		if (hppa_ext->mod_num == 0) {
			break;
		}
		// fallthrough
	case HPPA_INS_RFIR:
		map_add_implicit_write(MI, HPPA_REG_GR1);
		map_add_implicit_write(MI, HPPA_REG_GR8);
		map_add_implicit_write(MI, HPPA_REG_GR9);
		map_add_implicit_write(MI, HPPA_REG_GR16);
		map_add_implicit_write(MI, HPPA_REG_GR17);
		map_add_implicit_write(MI, HPPA_REG_GR24);
		map_add_implicit_write(MI, HPPA_REG_GR25);
		break;
	case HPPA_INS_VDEP:
	case HPPA_INS_VDEPI:
	case HPPA_INS_VEXTRS:
	case HPPA_INS_VEXTRU:
	case HPPA_INS_VSHD:
	case HPPA_INS_ZVDEPI:
		map_add_implicit_read(MI, HPPA_REG_CR11);
		break;
	case HPPA_INS_ADDIL:
		map_add_implicit_write(MI, HPPA_REG_GR1);
		break;
	}
}
#endif

void HPPA_printInst(MCInst *MI, SStream *O, void *Info)
{
	cs_hppa hppa = { 0 };
	unsigned int opcode = MCInst_getOpcode(MI);
	const struct hppa_print_info *info = &print_info[opcode];

	/* set pubOpcode as instruction id */
	MCInst_setOpcodePub(MI, opcode);

	SStream_concat(O, HPPA_insn_name((csh)MI->csh, opcode));
	print_modifiers(MI, O);
	SStream_concat(O, " ");
	fill_operands(MI, &hppa, MI->hppa_ext.is_alternative ? info->alternative :
								 info->format);
	for (int i = 0; i < hppa.op_count; i++) {
		cs_hppa_op *op = &hppa.operands[i];
		print_operand(MI, O, op);
		if (op->type != HPPA_OP_IDX_REG && op->type != HPPA_OP_DISP &&
		    i != hppa.op_count - 1) {
			SStream_concat(O, ", ");
		}
	}

	if (detail_is_set(MI)) {
		cs_hppa *hppa_detail = HPPA_get_detail(MI);
		*hppa_detail = hppa;
		if (opcode != HPPA_INS_INVALID)
			add_group(MI, info->group);
#ifndef CAPSTONE_DIET
		update_regs_access(MI, opcode);
#endif
	}
}

#endif

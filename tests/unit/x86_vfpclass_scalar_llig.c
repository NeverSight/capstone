#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool same_as_ll0(csh h, uint8_t *code, size_t size)
{
    cs_insn *base = NULL, *got = NULL;
    uint8_t saved = code[3];
    code[3] &= (uint8_t)~0x60;
    if (cs_disasm(h, code, size, 0, 1, &base) != 1) return false;
    code[3] = saved;
    if (cs_disasm(h, code, size, 0, 1, &got) != 1) { cs_free(base,1); return false; }
    bool ok = base->id == got->id && !strcmp(base->mnemonic,got->mnemonic) &&
              !strcmp(base->op_str,got->op_str) && base->detail && got->detail &&
              base->detail->x86.op_count == got->detail->x86.op_count;
    cs_free(base,1); cs_free(got,1); return ok;
}

int main(void)
{
    csh h; cs_insn *i = NULL; bool ok = true;
    uint8_t ss_reg[]={0x62,0xf3,0x7d,0x09,0x67,0xda,0xff};
    uint8_t ss_mem[]={0x62,0xf3,0x7d,0x09,0x67,0x1a,0xff};
    uint8_t sd_reg[]={0x62,0xf3,0xfd,0x08,0x67,0xda,0xff};
    uint8_t sd_mem[]={0x62,0xf3,0xfd,0x08,0x67,0x1a,0xff};
    uint8_t *forms[]={ss_reg,ss_mem,sd_reg,sd_mem};
    if (cs_open(CS_ARCH_X86,CS_MODE_64,&h)) return 1;
    cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
    for (unsigned f=0;f<4;f++) for (unsigned ll=0;ll<3;ll++) {
        forms[f][3]=(forms[f][3]&0x1f)|(uint8_t)(ll<<5);
        ok &= same_as_ll0(h,forms[f],7);
    }
    for (unsigned f=0;f<4;f++) {
        forms[f][3]=(forms[f][3]&0x1f)|0x60;
        if (cs_disasm(h,forms[f],7,0,1,&i)) { ok=false; cs_free(i,1); }
        forms[f][3]=(forms[f][3]&0x0f)|0x10;
        if (cs_disasm(h,forms[f],7,0,1,&i)) { ok=false; cs_free(i,1); }
    }
    cs_close(&h);
    if (!ok) fprintf(stderr,"scalar VFPCLASS LLIG mismatch\n");
    return ok?0:1;
}

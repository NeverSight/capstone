#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(csh h, const uint8_t *b, size_t n, unsigned id,
                  const char *mn, const char *ops)
{
    cs_insn *i = NULL;
    bool ok = cs_disasm(h, b, n, 0, 1, &i) == 1 && i->id == id &&
              !strcmp(i->mnemonic, mn) && !strcmp(i->op_str, ops) &&
              i->detail && i->detail->x86.op_count == 2 &&
              i->detail->x86.operands[0].access == CS_AC_READ &&
              i->detail->x86.operands[1].access == CS_AC_READ &&
              (i->detail->x86.eflags & X86_EFLAGS_MODIFY_CF);
    if (!ok && i) fprintf(stderr, "%s %s\n", i->mnemonic, i->op_str);
    cs_free(i, 1);
    return ok;
}

int main(void)
{
    static const char *const names[] = {"ccmpo","ccmpno","ccmpb","ccmpnb",
        "ccmpz","ccmpnz","ccmpbe","ccmpnbe","ccmps","ccmpns","ccmpt",
        "ccmpf","ccmpl","ccmpnl","ccmple","ccmpnle"};
    uint8_t b[] = {0x62,0x6c,0x2c,0x00,0x39,0xd1};
    csh h; cs_insn *i = NULL; bool ok = true;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h)) return 1;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    for (unsigned k=0;k<16;k++) { b[3]=(uint8_t)k; ok &= check(h,b,sizeof(b),
        X86_INS_CCMPO+k,names[k],"{dfv=sf,cf} r17d, r26d"); }
    b[2]=0xac; b[3]=2;
    ok &= check(h,b,sizeof(b),X86_INS_CCMPB,"ccmpb","{dfv=sf,cf} r17, r26");
    cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
    ok &= check(h,b,sizeof(b),X86_INS_CCMPB,"ccmpbq","{dfv=sf,cf} %r26, %r17");
    cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);
    { const uint8_t m[]={0x62,0x6c,0x2c,0x02,0x39,0x11};
      ok &= check(h,m,sizeof(m),X86_INS_CCMPB,"ccmpb",
                  "{dfv=sf,cf} dword ptr [r17], r26d"); }
    { const uint8_t m[]={0x64,0x62,0x0c,0x28,0x02,0x39,0x54,0xa5,0x20};
      ok &= check(h,m,sizeof(m),X86_INS_CCMPB,"ccmpb",
                  "{dfv=sf,cf} dword ptr fs:[r29 + r28*4 + 0x20], r26d"); }
    { const uint8_t m[]={0x67,0x64,0x62,0x0c,0x28,0x02,0x39,0x54,0xa5,0x20};
      ok &= check(h,m,sizeof(m),X86_INS_CCMPB,"ccmpb",
                  "{dfv=sf,cf} dword ptr fs:[r29d + r28d*4 + 0x20], r26d"); }
    { const uint8_t q[]={0x62,0x6c,0x2c,0x02,0x83,0xf9,0x07};
      ok &= check(h,q,sizeof(q),X86_INS_CCMPB,"ccmpb",
                  "{dfv=sf,cf} r17d, 7"); }
    /* As in the promoted ALU forms, W overrides 66 and byte forms ignore it. */
    b[3]=2; b[2]=0xad;
    ok &= check(h,b,sizeof(b),X86_INS_CCMPB,"ccmpb","{dfv=sf,cf} r17, r26");
    { const uint8_t w8[]={0x62,0x6c,0xac,0x02,0x38,0xd1};
      ok &= check(h,w8,sizeof(w8),X86_INS_CCMPB,"ccmpb",
                  "{dfv=sf,cf} r17b, r26b"); }
    /* Immediates follow CMP: byte and word values are zero-extended, and
     * the operand has the width of the comparison. */
    { const uint8_t q[]={0x62,0x6c,0x04,0x02,0x80,0xf9,0xa5};
      ok &= check(h,q,sizeof(q),X86_INS_CCMPB,"ccmpb","{dfv=} r17b, 0xa5");
      if (cs_disasm(h,q,sizeof(q),0,1,&i) == 1) {
        ok &= i->detail->x86.operands[1].type == X86_OP_IMM &&
              i->detail->x86.operands[1].imm == 0xa5 &&
              i->detail->x86.operands[1].size == 1;
        cs_free(i,1);
      } else ok = false; }
    { const uint8_t q[]={0x62,0x6c,0xac,0x02,0x83,0xf9,0x80};
      ok &= check(h,q,sizeof(q),X86_INS_CCMPB,"ccmpb",
                  "{dfv=sf,cf} r17, -0x80");
      if (cs_disasm(h,q,sizeof(q),0,1,&i) == 1) {
        ok &= i->detail->x86.operands[1].imm == -0x80 &&
              i->detail->x86.operands[1].size == 8;
        cs_free(i,1);
      } else ok = false; }
    { const uint8_t q[]={0x62,0x6c,0x2d,0x02,0x81,0xf9,0x00,0x80};
      ok &= check(h,q,sizeof(q),X86_INS_CCMPB,"ccmpb",
                  "{dfv=sf,cf} r17w, 0x8000"); }
    { const uint8_t q[]={0x62,0x6c,0x2c,0x02,0x81,0xf9,0x00,0x00,0x00,0x80};
      ok &= check(h,q,sizeof(q),X86_INS_CCMPB,"ccmpb",
                  "{dfv=sf,cf} r17d, 0x80000000"); }
    b[2]=0xac; b[3]=0x12; if (cs_disasm(h,b,sizeof(b),0,1,&i)) { ok=false; cs_free(i,1); }
    b[3]=2; b[2]=0xa8; if (cs_disasm(h,b,sizeof(b),0,1,&i)) { ok=false; cs_free(i,1); }
    b[2]=0xae; if (cs_disasm(h,b,sizeof(b),0,1,&i)) { ok=false; cs_free(i,1); }
    cs_close(&h); return ok ? 0 : 1;
}

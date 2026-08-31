#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(csh h,const uint8_t*b,size_t n,unsigned id,const char*mn,const char*ops)
{
    cs_insn*i=NULL;bool ok=cs_disasm(h,b,n,0,1,&i)==1&&i->id==id&&
        !strcmp(i->mnemonic,mn)&&!strcmp(i->op_str,ops)&&i->detail&&
        i->detail->x86.op_count==2&&
        i->detail->x86.operands[0].access==CS_AC_READ&&
        i->detail->x86.operands[1].access==CS_AC_READ&&
        (i->detail->x86.eflags&X86_EFLAGS_RESET_OF)&&
        (i->detail->x86.eflags&X86_EFLAGS_RESET_CF)&&
        (i->detail->x86.eflags&X86_EFLAGS_UNDEFINED_AF)&&
        (i->detail->x86.eflags&X86_EFLAGS_MODIFY_ZF);
    if(!ok&&i)fprintf(stderr,"%s %s\n",i->mnemonic,i->op_str);
    cs_free(i,1);return ok;
}

int main(void)
{
    static const char*const names[]={"ctesto","ctestno","ctestb","ctestnb",
      "ctestz","ctestnz","ctestbe","ctestnbe","ctests","ctestns","ctestt",
      "ctestf","ctestl","ctestnl","ctestle","ctestnle"};
    uint8_t b[]={0x62,0x6c,0x2c,0,0x85,0xd1};csh h;cs_insn*i=NULL;bool ok=true;
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 1;
    cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
    for(unsigned k=0;k<16;k++){b[3]=(uint8_t)k;ok&=check(h,b,6,X86_INS_CTESTO+k,
      names[k],"{dfv=sf,cf} r17d, r26d");}
    b[3]=2;b[2]=0x2d;ok&=check(h,b,6,X86_INS_CTESTB,"ctestb",
      "{dfv=sf,cf} r17w, r26w");
    b[2]=0x2c;b[4]=0x84;ok&=check(h,b,6,X86_INS_CTESTB,"ctestb",
      "{dfv=sf,cf} r17b, r26b");b[4]=0x85;
    b[2]=0xac;b[3]=2;ok&=check(h,b,6,X86_INS_CTESTB,"ctestb",
      "{dfv=sf,cf} r17, r26");
    {const uint8_t m[]={0x64,0x62,0x6c,0x2c,0x02,0x85,0x11};
      ok&=check(h,m,sizeof(m),X86_INS_CTESTB,"ctestb",
        "{dfv=sf,cf} dword ptr fs:[r17], r26d");}
    {const uint8_t m[]={0x64,0x62,0x0c,0x28,0x02,0x85,0x54,0xa5,0x20};
      ok&=check(h,m,sizeof(m),X86_INS_CTESTB,"ctestb",
        "{dfv=sf,cf} dword ptr fs:[r29 + r28*4 + 0x20], r26d");}
    {const uint8_t m[]={0x67,0x64,0x62,0x0c,0x28,0x02,0x85,0x54,0xa5,0x20};
      ok&=check(h,m,sizeof(m),X86_INS_CTESTB,"ctestb",
        "{dfv=sf,cf} dword ptr fs:[r29d + r28d*4 + 0x20], r26d");}
    {uint8_t q[]={0x62,0x6c,0x2c,0x02,0xf6,0xc1,7};
      ok&=check(h,q,7,X86_INS_CTESTB,"ctestb","{dfv=sf,cf} r17b, 7");
      q[5]=0xc9;ok&=check(h,q,7,X86_INS_CTESTB,"ctestb","{dfv=sf,cf} r17b, 7");
      q[5]=0xd1;if(cs_disasm(h,q,7,0,1,&i)){ok=false;cs_free(i,1);}}
    cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
    ok&=check(h,b,6,X86_INS_CTESTB,"ctestbq","{dfv=sf,cf} %r26, %r17");
    cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);
    b[3]=0x12;if(cs_disasm(h,b,6,0,1,&i)){ok=false;cs_free(i,1);}
    b[3]=2;b[2]=0xa8;if(cs_disasm(h,b,6,0,1,&i)){ok=false;cs_free(i,1);}
    cs_close(&h);return ok?0:1;
}

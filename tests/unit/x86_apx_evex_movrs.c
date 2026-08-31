#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool ck(csh h,const uint8_t*b,size_t n,const char*mn,const char*ops,
               x86_reg dst,uint8_t size)
{
    cs_insn*i=NULL;bool ok=cs_disasm(h,b,n,0,1,&i)==1&&i->id==X86_INS_MOVRS&&
      !strcmp(i->mnemonic,mn)&&!strcmp(i->op_str,ops)&&i->detail&&
      i->detail->x86.op_count==2;
    if(ok){cs_x86*x=&i->detail->x86;unsigned d=x->operands[0].type==X86_OP_REG?0:1;
      unsigned m=1-d;cs_regs r,w;uint8_t nr=0,nw=0;bool wr=false;
      ok=x->operands[d].reg==dst&&x->operands[d].size==size&&
        x->operands[d].access==CS_AC_WRITE&&x->operands[m].type==X86_OP_MEM&&
        x->operands[m].size==size&&x->operands[m].access==CS_AC_READ;
      cs_regs_access(h,i,r,&nr,w,&nw);for(unsigned k=0;k<nw;k++)wr|=w[k]==dst;
      ok&=wr&&nr!=0;}
    if(!ok&&i)fprintf(stderr,"%s %s\n",i->mnemonic,i->op_str);
    cs_free(i,1);return ok;
}

int main(void)
{
    csh h;cs_insn*i=NULL;bool ok=true;
    const uint8_t b8[]={0x64,0x62,0xec,0x7c,8,0x8a,0x11};
    const uint8_t b16[]={0x62,0xec,0x7d,8,0x8b,0x11};
    const uint8_t b32[]={0x67,0x62,0xec,0x7c,8,0x8b,0x11};
    const uint8_t b64[]={0x64,0x67,0x62,0xec,0xfc,8,0x8b,0x11};
    const uint8_t x4[]={0x64,0x62,0x0c,0x78,8,0x8b,0x54,0xa5,0x20};
    const uint8_t x4a32[]={0x67,0x64,0x62,0x0c,0x78,8,0x8b,0x54,0xa5,0x20};
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 1;cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
    ok&=ck(h,b8,sizeof(b8),"movrs","r18b, byte ptr fs:[r17]",X86_REG_R18B,1);
    ok&=ck(h,b16,sizeof(b16),"movrs","r18w, word ptr [r17]",X86_REG_R18W,2);
    ok&=ck(h,b32,sizeof(b32),"movrs","r18d, dword ptr [r17d]",X86_REG_R18D,4);
    ok&=ck(h,b64,sizeof(b64),"movrs","r18, qword ptr fs:[r17d]",X86_REG_R18,8);
    ok&=ck(h,x4,sizeof(x4),"movrs",
      "r26d, dword ptr fs:[r29 + r28*4 + 0x20]",X86_REG_R26D,4);
    ok&=ck(h,x4a32,sizeof(x4a32),"movrs",
      "r26d, dword ptr fs:[r29d + r28d*4 + 0x20]",X86_REG_R26D,4);
    cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
    ok&=ck(h,b64,sizeof(b64),"movrsq","%fs:(%r17d), %r18",X86_REG_R18,8);
    cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);
    {uint8_t x[]={0x62,0xec,0x7c,8,0x8b,0xd1};if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[2]=0x78;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[5]=0x11;x[3]=9;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[3]=8;x[2]=0x7e;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}}
    cs_close(&h);return ok?0:1;
}

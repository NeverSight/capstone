#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool ck(csh h,const uint8_t*b,size_t n,unsigned id,const char*mn,
               const char*ops,uint8_t dsz,uint8_t ssz)
{
    cs_insn*i=NULL;bool ok=cs_disasm(h,b,n,0,1,&i)==1&&i->id==id&&
      !strcmp(i->mnemonic,mn)&&!strcmp(i->op_str,ops)&&i->detail&&
      i->detail->x86.op_count==2&&i->detail->x86.operands[0].size==dsz&&
      i->detail->x86.operands[1].size==ssz&&
      ((i->detail->x86.operands[0].access==CS_AC_WRITE&&
        i->detail->x86.operands[1].access==CS_AC_READ)||
       (i->detail->x86.operands[0].access==CS_AC_READ&&
        i->detail->x86.operands[1].access==CS_AC_WRITE));
    if(ok){cs_regs r,w;uint8_t nr=0,nw=0;
      bool register_destination=false;cs_regs_access(h,i,r,&nr,w,&nw);
      for(unsigned k=0;k<2;k++)register_destination|=
        i->detail->x86.operands[k].type==X86_OP_REG&&
        i->detail->x86.operands[k].access==CS_AC_WRITE;
      ok&=nr!=0&&(!register_destination||nw!=0);}
    if(!ok&&i)fprintf(stderr,"%s %s\n",i->mnemonic,i->op_str);
    cs_free(i,1);return ok;
}

int main(void)
{
    csh h;cs_insn*i=NULL;bool ok=true;
    const uint8_t kk[][6]={{0x62,0xf1,0x7d,8,0x90,0xd9},{0x62,0xf1,0x7c,8,0x90,0xd9},
      {0x62,0xf1,0xfd,8,0x90,0xd9},{0x62,0xf1,0xfc,8,0x90,0xd9}};
    const unsigned ids[]={X86_INS_KMOVB,X86_INS_KMOVW,X86_INS_KMOVD,X86_INS_KMOVQ};
    const char*mn[]={"kmovb","kmovw","kmovd","kmovq"};uint8_t sz[]={1,2,4,8};
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 1;cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
    for(unsigned k=0;k<4;k++)ok&=ck(h,kk[k],6,ids[k],mn[k],"k3, k1",sz[k],sz[k]);
    {const uint8_t legacy[]={0xc5,0xf9,0x90,0xd9};
      ok&=ck(h,legacy,4,X86_INS_KMOVB,"kmovb","k3, k1",1,1);}
    {const uint8_t b[]={0x62,0xf9,0x7d,8,0x92,0xd9};ok&=ck(h,b,6,X86_INS_KMOVB,"kmovb","k3, r17d",1,4);}
    {const uint8_t b[]={0x62,0xe1,0x7d,8,0x93,0xcb};ok&=ck(h,b,6,X86_INS_KMOVB,"kmovb","r17d, k3",4,1);}
    {const uint8_t b[]={0x62,0xf9,0x7f,8,0x92,0xd9};ok&=ck(h,b,6,X86_INS_KMOVD,"kmovd","k3, r17d",4,4);}
    {const uint8_t b[]={0x62,0xf9,0x7c,8,0x92,0xd9};ok&=ck(h,b,6,X86_INS_KMOVW,"kmovw","k3, r17d",2,4);}
    {const uint8_t b[]={0x62,0xe1,0x7c,8,0x93,0xcb};ok&=ck(h,b,6,X86_INS_KMOVW,"kmovw","r17d, k3",4,2);}
    {const uint8_t b[]={0x62,0xf9,0xff,8,0x92,0xd9};ok&=ck(h,b,6,X86_INS_KMOVQ,"kmovq","k3, r17",8,8);}
    {uint8_t b[]={0x64,0x62,0xf9,0,8,0x90,0x11};
      const uint8_t p[]={0x7d,0x7c,0xfd,0xfc};
      const char*ld[]={"k2, byte ptr fs:[r17]","k2, word ptr fs:[r17]",
        "k2, dword ptr fs:[r17]","k2, qword ptr fs:[r17]"};
      const char*st[]={"byte ptr fs:[r17], k3","word ptr fs:[r17], k3",
        "dword ptr fs:[r17], k3","qword ptr fs:[r17], k3"};
      for(unsigned k=0;k<4;k++){b[3]=p[k];b[5]=0x90;b[6]=0x11;
        ok&=ck(h,b,7,ids[k],mn[k],ld[k],sz[k],sz[k]);
        b[5]=0x91;b[6]=0x19;ok&=ck(h,b,7,ids[k],mn[k],st[k],sz[k],sz[k]);}}
    {const uint8_t b[]={0x64,0x62,0x99,0xf9,8,0x90,0x54,0xa5,0x20};
      ok&=ck(h,b,sizeof(b),X86_INS_KMOVD,"kmovd",
        "k2, dword ptr fs:[r29 + r28*4 + 0x20]",4,4);}
    {const uint8_t b[]={0x64,0x62,0x99,0xf9,8,0x91,0x5c,0xa5,0x20};
      ok&=ck(h,b,sizeof(b),X86_INS_KMOVD,"kmovd",
        "dword ptr fs:[r29 + r28*4 + 0x20], k3",4,4);}
    {const uint8_t b[]={0x67,0x64,0x62,0x99,0xf9,8,0x90,0x54,0xa5,0x20};
      ok&=ck(h,b,sizeof(b),X86_INS_KMOVD,"kmovd",
        "k2, dword ptr fs:[r29d + r28d*4 + 0x20]",4,4);}
    {const uint8_t b[]={0x62,0xf9,0xff,8,0x92,0xd9};cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);ok&=ck(h,b,6,X86_INS_KMOVQ,"kmovq","%r17, %k3",8,8);cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);}
    {uint8_t x[]={0x62,0xf9,0x7d,8,0x92,0x19};if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[3]=9;x[5]=0xd9;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[3]=8;x[2]=0x79;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[2]=0x75;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}}
    cs_close(&h);return ok?0:1;
}

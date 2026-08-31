#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool ck(csh h,const uint8_t*b,size_t n,unsigned id,const char*mn,const char*ops)
{
    cs_insn*i=NULL;bool ok=cs_disasm(h,b,n,0,1,&i)==1&&i->id==id&&
      !strcmp(i->mnemonic,mn)&&!strcmp(i->op_str,ops)&&i->detail&&
      i->detail->x86.op_count==2;
    if(ok){cs_x86*x=&i->detail->x86;unsigned r=x->operands[0].type==X86_OP_REG?0:1,m=1-r;
      cs_regs reads,writes;uint8_t nr=0,nw=0;bool type_read=false;
      ok=x->operands[r].reg==X86_REG_R18&&x->operands[r].size==8&&
        x->operands[r].access==CS_AC_READ&&x->operands[m].type==X86_OP_MEM&&
        x->operands[m].size==16&&x->operands[m].access==CS_AC_READ;
      cs_regs_access(h,i,reads,&nr,writes,&nw);for(unsigned k=0;k<nr;k++)type_read|=reads[k]==X86_REG_R18;
      ok&=type_read&&nw==0&&i->detail->groups_count==1&&
        i->detail->groups[0]==X86_GRP_PRIVILEGE;}
    if(!ok&&i)fprintf(stderr,"%s %s\n",i->mnemonic,i->op_str);
    cs_free(i,1);return ok;
}

int main(void)
{
    csh h;cs_insn*i=NULL;bool ok=true;uint8_t b[]={0x62,0xec,0x7e,8,0xf0,0x11};
    const unsigned ids[]={X86_INS_INVEPT,X86_INS_INVVPID,X86_INS_INVPCID};
    const char*mn[]={"invept","invvpid","invpcid"};
    if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 1;cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
    for(unsigned k=0;k<3;k++){b[4]=(uint8_t)(0xf0+k);ok&=ck(h,b,6,ids[k],mn[k],
      k==0?"r18, xmmword ptr [r17]":k==1?"r18, xmmword ptr [r17]":"r18, xmmword ptr [r17]");}
    b[2]=0xfe;b[4]=0xf0;ok&=ck(h,b,6,X86_INS_INVEPT,"invept","r18, xmmword ptr [r17]");
    {const uint8_t a[]={0x64,0x67,0x62,0xec,0x7a,8,0xf2,0x11};
      ok&=ck(h,a,sizeof(a),X86_INS_INVPCID,"invpcid","r18, xmmword ptr fs:[r17d]");
      cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);ok&=ck(h,a,sizeof(a),X86_INS_INVPCID,
        "invpcid","%fs:(%r17d), %r18");cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);}
    {uint8_t x[]={0x62,0xec,0x7e,8,0xf0,0xd1};if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[5]=0x11;x[3]=9;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[3]=8;x[2]=0x7f;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}x[2]=0x76;if(cs_disasm(h,x,6,0,1,&i)){ok=false;cs_free(i,1);}}
    cs_close(&h);return ok?0:1;
}

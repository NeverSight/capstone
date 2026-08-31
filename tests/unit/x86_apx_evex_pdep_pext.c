#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool check(csh h,const uint8_t*b,size_t n,unsigned id,const char*m,const char*o)
{
	cs_insn*i=NULL;bool ok=cs_disasm(h,b,n,0,1,&i)==1;if(ok){const cs_x86*x=&i->detail->x86;bool access=(x->operands[0].access==CS_AC_WRITE&&x->operands[1].access==CS_AC_READ&&x->operands[2].access==CS_AC_READ)||(x->operands[2].access==CS_AC_WRITE&&x->operands[0].access==CS_AC_READ&&x->operands[1].access==CS_AC_READ);ok=i->id==id&&!strcmp(i->mnemonic,m)&&!strcmp(i->op_str,o)&&x->op_count==3&&access&&x->eflags==0;}if(i)cs_free(i,1);return ok;
}

int main(void)
{
	const uint8_t pd[]={0x62,0xea,0x77,0x00,0xf5,0xd3};
	const uint8_t px[]={0x62,0xea,0xf6,0x00,0xf5,0xd3};
	const uint8_t pm[]={0x64,0x62,0x0a,0xf7,0x00,0xf5,0x54,0xb5,0x20};
	uint8_t bad[]={0x62,0xea,0x77,0x00,0xf5,0xd3};csh h;cs_insn*i=NULL;bool ok=true;if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 1;cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
	ok&=check(h,pd,sizeof(pd),X86_INS_PDEP,"pdep","r18d, r17d, r19d");ok&=check(h,px,sizeof(px),X86_INS_PEXT,"pext","r18, r17, r19");ok&=check(h,pm,sizeof(pm),X86_INS_PDEP,"pdep","r26, r17, qword ptr fs:[r29 + r14*4 + 0x20]");
	cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);ok&=check(h,pm,sizeof(pm),X86_INS_PDEP,"pdepq","%fs:0x20(%r29,%r14,4), %r17, %r26");cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);
	for(unsigned k=0;k<4;k++){bad[3]=(uint8_t[]){4,0x10,0x20,0x80}[k];if(cs_disasm(h,bad,sizeof(bad),0,1,&i)){ok=false;cs_free(i,1);i=NULL;}}
	bad[2]=0x75;bad[3]=0;if(cs_disasm(h,bad,sizeof(bad),0,1,&i)){ok=false;cs_free(i,1);}cs_close(&h);if(!ok)fprintf(stderr,"APX PDEP/PEXT failure\n");return ok?0:1;
}

#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool ck(csh h,const uint8_t*b,size_t n,unsigned id,const char*m,const char*o,unsigned ops,bool nf)
{
	cs_insn*i=NULL;bool ok=cs_disasm(h,b,n,0,1,&i)==1;if(ok){const cs_x86*x=&i->detail->x86;ok=i->id==id&&!strcmp(i->mnemonic,m)&&!strcmp(i->op_str,o)&&x->op_count==ops&&(nf?x->eflags==0:x->eflags!=0);}if(i)cs_free(i,1);return ok;
}

int main(void)
{
	const uint8_t a[]={0x62,0xec,0xfc,0x08,0xa5,0xd3};
	const uint8_t b[]={0x62,0xec,0x7d,0x0c,0x24,0xd3,7};
	const uint8_t c[]={0x62,0xec,0xf4,0x10,0xa5,0xd3};
	const uint8_t d[]={0x62,0xec,0x74,0x14,0x2c,0xd3,9};
	const uint8_t e[]={0x64,0x62,0x0c,0xf4,0x14,0xad,0x54,0xb5,0x20};
	const uint8_t f[]={0x64,0x62,0x0c,0x7c,0x08,0x24,0x54,0xb5,0x20,3};
	uint8_t bad[]={0x62,0xec,0xfc,0x08,0xa5,0xd3};csh h;cs_insn*i=NULL;bool ok=true;if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 1;cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
	ok&=ck(h,a,sizeof(a),X86_INS_SHLD,"shld","r19, r18, cl",3,false);
	ok&=ck(h,b,sizeof(b),X86_INS_SHLD,"{nf} shld","r19w, r18w, 7",3,true);
	ok&=ck(h,c,sizeof(c),X86_INS_SHLD,"shld","r17, r19, r18, cl",4,false);
	ok&=ck(h,d,sizeof(d),X86_INS_SHRD,"{nf} shrd","r17d, r19d, r18d, 9",4,true);
	ok&=ck(h,e,sizeof(e),X86_INS_SHRD,"{nf} shrd","r17, qword ptr fs:[r29 + r14*4 + 0x20], r26, cl",4,true);
	ok&=ck(h,f,sizeof(f),X86_INS_SHLD,"shld","dword ptr fs:[r29 + r14*4 + 0x20], r26d, 3",3,false);
	cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);ok&=ck(h,e,sizeof(e),X86_INS_SHRD,"{nf} shrdq","%cl, %r26, %fs:0x20(%r29,%r14,4), %r17",4,true);cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);
	for(unsigned k=0;k<4;k++){bad[3]=(uint8_t[]){0x09,0x28,0x48,0x88}[k];if(cs_disasm(h,bad,sizeof(bad),0,1,&i)){ok=false;cs_free(i,1);i=NULL;}}
	bad[2]=0x7e;bad[3]=8;if(cs_disasm(h,bad,sizeof(bad),0,1,&i)){ok=false;cs_free(i,1);}cs_close(&h);if(!ok)fprintf(stderr,"APX double shift failure\n");return ok?0:1;
}

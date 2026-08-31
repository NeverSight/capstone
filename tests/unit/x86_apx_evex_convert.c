#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool one(csh h,const uint8_t*b,size_t n,unsigned id,const char*m,const char*o)
{
	cs_insn*i=NULL;bool ok=cs_disasm(h,b,n,0,1,&i)==1;
	if(ok)ok=i->id==id&&!strcmp(i->mnemonic,m)&&!strcmp(i->op_str,o)&&i->detail->x86.eflags==0;
	cs_free(i,ok||i?1:0);return ok;
}

int main(void)
{
	const uint8_t ml16[]={0x62,0xec,0x7d,0x08,0x60,0xd3};
	const uint8_t ms32[]={0x62,0xec,0x7c,0x08,0x61,0xda};
	const uint8_t mlm[]={0x64,0x62,0x0c,0x7c,0x08,0x60,0x54,0xb5,0x20};
	const uint8_t cb[]={0x62,0xec,0xfc,0x08,0xf0,0xd3};
	const uint8_t cw[]={0x62,0xec,0x7d,0x08,0xf1,0xd3};
	const uint8_t cq[]={0x64,0x62,0x0c,0xfc,0x08,0xf1,0x54,0xb5,0x20};
	uint8_t bad[]={0x62,0xec,0x7c,0x08,0x60,0xd3};csh h;cs_insn*i=NULL;bool ok=true;
	if(cs_open(CS_ARCH_X86,CS_MODE_64,&h))return 1;cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
	ok&=one(h,ml16,sizeof(ml16),X86_INS_MOVBE,"movbe","r18w, r19w");
	ok&=one(h,ms32,sizeof(ms32),X86_INS_MOVBE,"movbe","r18d, r19d");
	if(cs_disasm(h,ms32,sizeof(ms32),0,1,&i)!=1)ok=false;else{const cs_x86*x=&i->detail->x86;ok&=x->operands[0].reg==X86_REG_R18D&&x->operands[0].access==CS_AC_WRITE&&x->operands[1].reg==X86_REG_R19D&&x->operands[1].access==CS_AC_READ;cs_free(i,1);i=NULL;}
	ok&=one(h,mlm,sizeof(mlm),X86_INS_MOVBE,"movbe","r26d, dword ptr fs:[r29 + r14*4 + 0x20]");
	ok&=one(h,cb,sizeof(cb),X86_INS_CRC32,"crc32","r18, r19b");
	ok&=one(h,cw,sizeof(cw),X86_INS_CRC32,"crc32","r18d, r19w");
	ok&=one(h,cq,sizeof(cq),X86_INS_CRC32,"crc32","r26, qword ptr fs:[r29 + r14*4 + 0x20]");
	if(cs_disasm(h,cq,sizeof(cq),0,1,&i)!=1)ok=false;else{const cs_x86*x=&i->detail->x86;ok&=x->op_count==2&&x->operands[0].reg==X86_REG_R26&&x->operands[0].access==CS_AC_READ_WRITE&&x->operands[1].type==X86_OP_MEM&&x->operands[1].access==CS_AC_READ&&x->operands[1].mem.segment==X86_REG_FS&&x->operands[1].mem.base==X86_REG_R29&&x->operands[1].mem.index==X86_REG_R14;cs_free(i,1);i=NULL;}
	cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
	ok&=one(h,cq,sizeof(cq),X86_INS_CRC32,"crc32q","%fs:0x20(%r29,%r14,4), %r26");
	cs_option(h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);
	for(unsigned k=0;k<4;k++){bad[3]=(uint8_t[]){0x00,0x0c,0x18,0x28}[k];if(cs_disasm(h,bad,sizeof(bad),0,1,&i)){ok=false;cs_free(i,1);i=NULL;}}
	bad[2]=0x74;bad[3]=8;if(cs_disasm(h,bad,sizeof(bad),0,1,&i)){ok=false;cs_free(i,1);i=NULL;}
	bad[2]=0x7d;bad[3]=8;bad[4]=0xf0;if(cs_disasm(h,bad,sizeof(bad),0,1,&i)){ok=false;cs_free(i,1);}
	cs_close(&h);if(!ok)fprintf(stderr,"APX conversion failure\n");return ok?0:1;
}

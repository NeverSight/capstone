/* Capstone Disassembly Engine; SPDX-License-Identifier: BSD-3-Clause */
#include <capstone/capstone.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define CS_JUMP_VALUE(Name, Value) enum { Name = Value };
#define CS_JUMP_WIDE_VALUE(Name, Value) static const uint64_t Name = Value;
#define CS_JUMP_TEXT(Name, Value) static const char Name[] = Value;
#include "x86_relative_jump.def"
#undef CS_JUMP_TEXT
#undef CS_JUMP_WIDE_VALUE
#undef CS_JUMP_VALUE
struct Jump {
  const char *Name;
  cs_mode Mode;
  unsigned Size, ImmediateOffset, ImmediateSize;
  uint64_t Target;
  uint8_t Bytes[MaxBytes];
};
static bool check(const struct Jump *J, unsigned Syntax) {
  csh Handle;
  if (cs_open(CS_ARCH_X86, J->Mode, &Handle) != CS_ERR_OK)
    return false;
  bool OK = cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK &&
            cs_option(Handle, CS_OPT_SYNTAX, Syntax) == CS_ERR_OK;
  for (unsigned Size = J->Size - 1; Size <= J->Size; ++Size) {
    cs_insn *I = NULL;
    const size_t Count = cs_disasm(Handle, J->Bytes, Size, Address, 1, &I);
    if (Size < J->Size) {
      OK &= Count == 0;
    } else if (Count == 1 && I->detail) {
      const cs_x86 *X = &I->detail->x86;
      OK &= I->id == X86_INS_JMP && I->size == J->Size &&
            memcmp(I->bytes, J->Bytes, J->Size) == 0 && X->op_count == 1 &&
            X->operands[0].type == X86_OP_IMM &&
            (uint64_t)X->operands[0].imm == J->Target &&
            X->encoding.imm_offset == J->ImmediateOffset &&
            X->encoding.imm_size == J->ImmediateSize &&
            cs_insn_group(Handle, I, CS_GRP_JUMP) &&
            cs_insn_group(Handle, I, CS_GRP_BRANCH_RELATIVE) && !X->eflags;
    } else {
      OK = false;
    }
    cs_free(I, Count);
  }
  cs_close(&Handle);
  if (!OK)
    fprintf(stderr, Failure, J->Name, Syntax);
  return OK;
}
int main(void) {
  const struct Jump Cases[] = {
#define CS_JUMP_CASE(Name, Mode, Size, Offset, Width, Target, ...)             \
  {#Name, Mode, Size, Offset, Width, Target, {__VA_ARGS__}},
#include "x86_relative_jump.def"
#undef CS_JUMP_CASE
  };
  const unsigned Syntaxes[] = {CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT};
  bool OK = true;
  for (size_t I = 0; I < sizeof(Cases) / sizeof(Cases[0]); ++I)
    for (size_t S = 0; S < sizeof(Syntaxes) / sizeof(Syntaxes[0]); ++S)
      OK &= check(&Cases[I], Syntaxes[S]);
  return OK ? 0 : 1;
}

/* Capstone Disassembly Engine */
/* By Spike, xwings 2019 */

#include <capstone/capstone.h>

void WASM_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);
const char *WASM_insn_name(csh handle, unsigned int id);
const char *WASM_group_name(csh handle, unsigned int id);
const char *WASM_kind_name(unsigned int id);

#if defined(CAPSTONE_WASM_LITERAL_MNEMONICS) && \
	!defined(CAPSTONE_DIET) && defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
#define WASM_LITERAL_NAMES
struct SStream;
void WASM_printMnemonic(struct SStream *out, unsigned int id);
#endif

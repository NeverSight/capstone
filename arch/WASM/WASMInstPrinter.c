/* Capstone Disassembly Engine */
/* By Spike, xwings  2019 */

#include "WASMInstPrinter.h"
#include "WASMMapping.h"

void WASM_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
#if defined(CAPSTONE_WASM_LITERAL_MNEMONICS) && \
	!defined(CAPSTONE_DIET) && defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
	const char *name = WASM_insn_name((csh)MI->csh, MI->Opcode);
	/* Mnemonics contain no format conversions. A custom formatter still
	 * receives the original mnemonic as its format string. */
	if (cs_vsnprintf == cs_default_vsnprintf && O->index < SSTREAM_BUF_LEN - 1)
		SStream_concat0(O, name);
	else
		SStream_concat(O, name);
#else
	SStream_concat(O, WASM_insn_name((csh)MI->csh, MI->Opcode));
#endif

	switch (MI->wasm_data.type) {
	default:
		break;

	case WASM_OP_VARUINT32:
		SStream_concat(O, "\t0x%x", MI->wasm_data.varuint32);
		break;

	case WASM_OP_VARUINT64:
		/* Retain the callback's original format for values that fit. */
		if ((unsigned long)MI->wasm_data.varuint64 ==
		    MI->wasm_data.varuint64)
			SStream_concat(O, "\t0x%lx",
				       (unsigned long)MI->wasm_data.varuint64);
		else
			SStream_concat(O, "\t0x%" PRIx64, MI->wasm_data.varuint64);
		break;

	case WASM_OP_UINT32:
		SStream_concat(O, "\t0x%2" PRIx32, MI->wasm_data.uint32);
		break;

	case WASM_OP_UINT64:
		SStream_concat(O, "\t0x%2" PRIx64, MI->wasm_data.uint64);
		break;

	case WASM_OP_IMM:
		SStream_concat(O, "\t0x%x, 0x%x", MI->wasm_data.immediate[0],
			       MI->wasm_data.immediate[1]);
		break;

	case WASM_OP_INT7:
		SStream_concat(O, "\t%d", MI->wasm_data.int7);
		break;

	case WASM_OP_BRTABLE:
		SStream_concat(O, "\t0x%x, [", MI->wasm_data.brtable.length);
		SStream_concat(O, "0x%x", MI->wasm_data.brtable.address);
		SStream_concat(O, "], 0x%x",
			       MI->wasm_data.brtable.default_target);

		break;
	}
}

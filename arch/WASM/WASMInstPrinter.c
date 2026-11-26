/* Capstone Disassembly Engine */
/* By Spike, xwings  2019 */

#include "WASMInstPrinter.h"
#include "WASMMapping.h"

#ifdef WASM_LITERAL_NAMES
static char *prependHex32(char *end, uint32_t value)
{
	do {
		*--end = "0123456789abcdef"[value & 15];
		value >>= 4;
	} while (value);
	*--end = 'x';
	*--end = '0';
	return end;
}

static bool printHexOperands32(SStream *out, const uint32_t *values,
			      unsigned count)
{
	if (cs_vsnprintf != cs_default_vsnprintf ||
	    out->index >= SSTREAM_BUF_LEN - 1)
		return false;

	char text[sizeof("\t0xffffffff, 0xffffffff")];
	char *end = text + sizeof(text) - 1;
	char *p = end;
	*end = '\0';
	if (count == 2) {
		p = prependHex32(p, values[1]);
		*--p = ' ';
		*--p = ',';
	}
	p = prependHex32(p, values[0]);
	*--p = '\t';
	SStream_concat0_n(out, p, (size_t)(end - p));
	return true;
}
#endif

void WASM_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
#ifdef WASM_LITERAL_NAMES
	WASM_printMnemonic(O, MI->Opcode);
#else
	SStream_concat(O, WASM_insn_name((csh)MI->csh, MI->Opcode));
#endif

	switch (MI->wasm_data.type) {
	default:
		break;

	case WASM_OP_VARUINT32:
#ifdef WASM_LITERAL_NAMES
		if (printHexOperands32(O, &MI->wasm_data.varuint32, 1))
			break;
#endif
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
#ifdef WASM_LITERAL_NAMES
		if (printHexOperands32(O, MI->wasm_data.immediate, 2))
			break;
#endif
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

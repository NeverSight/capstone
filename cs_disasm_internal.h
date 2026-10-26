/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_DISASM_INTERNAL_H
#define CS_DISASM_INTERNAL_H

#include <string.h>
#include "cs_priv.h"
#include "utils.h"
#ifdef CAPSTONE_HAS_X86
#include "arch/X86/X86Mapping.h"
#include "arch/X86/X86Disassembler.h"
#endif

/* The core owns output and iterator policy in one implementation. With x86
 * enabled, the decoder translation unit instantiates the iterator core so
 * the compiler can combine scan and output state without an extra boundary.
 * Otherwise cs.c instantiates the same iterator. Input validation, option
 * selection and callbacks keep their original order. */
CAPSTONE_INTERNAL bool cs_decode_full_insn(cs_struct *handle,
					   const uint8_t *code, size_t size,
					   cs_insn *insn, uint16_t *insn_size,
					   bool batch);
#ifndef CAPSTONE_DIET
CAPSTONE_INTERNAL void cs_skipdata_opstr(char *opstr, const uint8_t *buffer,
					 size_t size);
#endif

/* Keep successful compact decoding contiguous with cached mapping and
 * short copies; cold fallback blocks otherwise split the inline path. */
#if defined(__GNUC__)
#define CS_DECODE_LIKELY(x) __builtin_expect(!!(x), 1)
#define CS_DECODE_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define CS_DECODE_LIKELY(x) (x)
#define CS_DECODE_UNLIKELY(x) (x)
#endif

static inline void map_insn_id(cs_struct *handle, cs_insn *insn,
			       unsigned int id)
{
#ifdef CAPSTONE_HAS_X86
	/* The LUT contains only generated 16-bit opcodes; source-owned
	 * feature opcodes exceed its bound and keep the normal mapper. */
	if (CS_DECODE_LIKELY(handle->arch == CS_ARCH_X86 &&
			     X86_get_insn_id_no_detail(handle, insn, id)))
		return;
#endif
	handle->insn_id(handle, insn, id);
}

static inline bool use_x86_scan(const cs_struct *handle)
{
	return handle->arch == CS_ARCH_X86 && handle->no_text &&
	       !handle->detail_opt;
}

/* Keep the compact decode and bounded copy in the caller. Outlining either
 * wrapper gives short instructions an extra call and saved-register frame. */
#if defined(_MSC_VER)
#define CS_DECODE_INLINE static __forceinline
#elif defined(__GNUC__)
#define CS_DECODE_INLINE static inline __attribute__((always_inline))
#else
#define CS_DECODE_INLINE static inline
#endif

// fill the parts of insn that do not come from printing it, for a handle
// with CS_OPT_TEXT off
CS_DECODE_INLINE void fill_insn_without_text(cs_insn *insn, unsigned opcode_pub,
					     const uint8_t *code,
					     bool short_insn)
{
	/* Successful compact x86 decoding guarantees at most 15 bytes. */
	uint16_t copy_size = short_insn ? insn->size :
					  MIN(sizeof(insn->bytes), insn->size);

	code += insn->size - copy_size;
	/* Constant-size chunks let short copies inline. The head and tail may
	 * overlap, but both stay within the instruction. */
	if (CS_DECODE_UNLIKELY(copy_size >= 8)) {
		if (!short_insn && CS_DECODE_UNLIKELY(copy_size > 16)) {
			memcpy(insn->bytes, code, copy_size);
		} else {
			memcpy(insn->bytes, code, 8);
			memcpy(insn->bytes + copy_size - 8,
			       code + copy_size - 8, 8);
		}
	} else if (copy_size >= 4) {
		memcpy(insn->bytes, code, 4);
		memcpy(insn->bytes + copy_size - 4, code + copy_size - 4, 4);
	} else if (copy_size >= 2) {
		memcpy(insn->bytes, code, 2);
		memcpy(insn->bytes + copy_size - 2, code + copy_size - 2, 2);
	} else if (copy_size) {
		insn->bytes[0] = code[0];
	}
	if (!short_insn)
		insn->size = copy_size;
	insn->mnemonic[0] = '\0';
	insn->op_str[0] = '\0';

	// alias instruction might have ID saved in OpcodePub
	if (CS_DECODE_UNLIKELY(opcode_pub))
		insn->id = opcode_pub;
}

/* A decoder translation unit may bind its own inline scan implementation.
 * Other users retain the normal private decoder entry. */
#ifndef CS_DECODE_SCAN
#define CS_DECODE_SCAN X86_getInstructionScanResult
#endif
#ifdef CAPSTONE_HAS_X86
CS_DECODE_INLINE void finish_x86_scan(cs_struct *handle, cs_insn *insn,
				      const X86ScanResult *result,
				      const uint8_t *code, bool batch,
				      bool store_bytes)
{
	insn->size = result->length;
	if (CS_DECODE_LIKELY(result->opcode_pub))
		insn->id = result->opcode_pub;
	else
		map_insn_id(handle, insn, result->opcode);
	if (store_bytes)
		fill_insn_without_text(insn, 0, code, !batch);
	if (!batch || insn->id != X86_INS_VCMP)
		insn->id += result->popcode_adjust;
}
#endif

CS_DECODE_INLINE bool decode_insn(cs_struct *handle, const uint8_t *code,
				  size_t size, cs_insn *insn,
				  uint16_t *insn_size, bool scan, bool batch)
{
#ifdef CAPSTONE_HAS_X86
	if (CS_DECODE_LIKELY(scan)) {
		X86ScanResult result;
		if (CS_DECODE_UNLIKELY(!CS_DECODE_SCAN(
			    (csh)(uintptr_t)handle, code, size, insn, &result)))
			return false;
		*insn_size = result.length;
		finish_x86_scan(handle, insn, &result, code, batch, true);
		return true;
	}
#endif
	return cs_decode_full_insn(handle, code, size, insn, insn_size, batch);
}
#undef CS_DECODE_SCAN

CS_DECODE_INLINE bool cs_disasm_iter_body(struct cs_struct *handle,
					  const uint8_t **code, size_t *size,
					  uint64_t *address, cs_insn *insn)
{
	uint16_t insn_size;
	bool r;

	handle->errnum = CS_ERR_OK;

	const bool scan = use_x86_scan(handle);
	insn->address = *address;
#ifdef CAPSTONE_DIET
	// zero out mnemonic & op_str
	insn->mnemonic[0] = '\0';
	insn->op_str[0] = '\0';
#endif

	r = decode_insn(handle, *code, *size, insn, &insn_size, scan, false);
	if (CS_DECODE_LIKELY(r)) {
		*code += insn_size;
		*size -= insn_size;
		*address += insn_size;
	} else { // encounter a broken instruction
		size_t skipdata_bytes;

		// if there is no request to skip data, or remaining data is too small,
		// then bail out
		if (!handle->skipdata || handle->skipdata_size > *size)
			return false;

		if (handle->skipdata_setup.callback) {
			skipdata_bytes = handle->skipdata_setup.callback(
				*code, *size, 0,
				handle->skipdata_setup.user_data);
			if (skipdata_bytes > *size)
				// remaining data is not enough
				return false;

			if (!skipdata_bytes)
				// user requested not to skip data, so bail out
				return false;
		} else
			skipdata_bytes = handle->skipdata_size;

		// we have to skip some amount of data, depending on arch & mode
		insn->id = 0; // invalid ID for this "data" instruction
		insn->address = *address;
		insn->size = (uint16_t)MIN(skipdata_bytes, sizeof(insn->bytes));
		memcpy(insn->bytes, *code,
		       MIN(skipdata_bytes, sizeof(insn->bytes)));
#ifdef CAPSTONE_DIET
		insn->mnemonic[0] = '\0';
		insn->op_str[0] = '\0';
#else
		strncpy(insn->mnemonic, handle->skipdata_setup.mnemonic,
			sizeof(insn->mnemonic) - 1);
		cs_skipdata_opstr(insn->op_str, *code, skipdata_bytes);
#endif

		*code += skipdata_bytes;
		*size -= skipdata_bytes;
		*address += skipdata_bytes;
	}

	return true;
}

CS_DECODE_INLINE bool cs_disasm_iter_core(csh ud, const uint8_t **code,
					  size_t *size, uint64_t *address,
					  cs_insn *insn)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;
	cs_detail *detail;
	bool r;

	if (*size == 0 || !handle)
		return false;

	// An instruction cs_malloc() allocated while detail was on keeps its
	// detail after detail is turned off.  Much of the decoder tests only
	// whether that pointer is set, so a decode without detail hides it, as
	// cs_disasm() never allocates it then; the detail is left as it was.
	detail = insn->detail;
	if (CS_DECODE_LIKELY(!handle->detail_opt))
		insn->detail = NULL;
	r = cs_disasm_iter_body(handle, code, size, address, insn);
	insn->detail = detail;
	return r;
}

#endif

/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifdef CAPSTONE_HAS_X86
/* Keep the optional static iterator and its tables in their own ELF sections. */
#if defined(__ELF__) && defined(__clang__)
#pragma clang section text = ".cs_x86_native_batch_text" rodata = \
	".cs_x86_native_batch_rodata"
#endif
#include "X86ScanAdapter.h"
#include "../../cs_priv.h"

#if !defined(CAPSTONE_X86_REDUCE) && !defined(CAPSTONE_X86_SCAN_ADAPTER)
#include "../../cs_disasm_internal.h"
#define X86_DEFINE_VEX2_PUBLIC_PLANS
#include "X86GenVexPublicPlans.inc"
#undef X86_DEFINE_VEX2_PUBLIC_PLANS
#include "X86GenBatchPrimary.inc"

/* Number of bytes following the ModR/M byte in 32- and 64-bit addressing. */
static bool addressBytes(const uint8_t *code, size_t size, unsigned offset,
			 unsigned *tail)
{
	if (size <= offset)
		return false;
	const uint8_t modrm = code[offset];
	if (modrm >= 0xc0) {
		*tail = 0;
		return true;
	}
	static const uint8_t lengths[3][8] = { { 0, 0, 0, 0, 1, 4, 0, 0 },
					       { 1, 1, 1, 1, 2, 1, 1, 1 },
					       { 4, 4, 4, 4, 5, 4, 4, 4 } };
	unsigned length = lengths[modrm >> 6][modrm & 7];
	if ((modrm & 0xc7) == 4) {
		if (size <= offset + 1)
			return false;
		if ((code[offset + 1] & 7) == 5)
			length += 4;
	}
	*tail = length;
	return true;
}

static uint32_t readPrimary(const uint8_t *code, size_t size, unsigned plan)
{
	if (plan & X86_BATCH_REG_GROUP) {
		if (size < 2)
			return 0;
		const uint8_t mr = code[1];
		plan = x86BatchRegGroups[plan & ~X86_BATCH_REG_GROUP]
					[((mr >> 3) & 7) + (mr >= 0xc0 ? 8 : 0)];
		if (!plan)
			return 0;
	}
	unsigned length = plan & 15;
	if (plan & 0x10) {
		unsigned tail;
		if (!addressBytes(code, size, 1, &tail))
			return 0;
		length += tail;
	}
	return length <= size ? (plan & ~0xffu) | length : 0;
}

/* Every admitted plan has the same public ID, reserved-vvvv rule and
 * immediate extent as all of its canonical ModR/M outcomes. */
static uint32_t readVex2Plan(const uint8_t *code, size_t size)
{
	if (size < 3)
		return 0;
	const unsigned payload = code[1];
	unsigned plan = x86Vex2PublicPlans[payload & 3][code[2]];
	if (plan & (X86_VEX2_PUBLIC_LENGTH | X86_VEX2_PUBLIC_GROUP)) {
#if X86_HAS_VEX2_LENGTH_PLANS
		if (plan & X86_VEX2_PUBLIC_LENGTH)
			plan = x86Vex2LengthPlans[plan &
						  (X86_VEX2_PUBLIC_LENGTH - 1)]
						 [(payload >> 2) & 1];
#endif
#if X86_HAS_VEX2_PUBLIC_GROUPS
		if (plan & X86_VEX2_PUBLIC_GROUP) {
			if (size < 4)
				return 0;
			const unsigned modrm = code[3];
			plan = x86Vex2PublicGroups[plan &
						   (X86_VEX2_PUBLIC_GROUP - 1)]
						  [((modrm >> 3) & 7) +
						   (modrm >= 0xc0 ? 8 : 0)];
		}
#endif
	}
	if (!plan)
		return 0;
	if ((plan & 2) && (payload & 0x78) != 0x78)
		return 0;
	unsigned end = 3;
	if (plan & 4) {
		unsigned tail;
		if (!addressBytes(code, size, 3, &tail))
			return 0;
		end = 4 + tail;
	}
	end += plan & 1;
	if (end > size)
		return 0;
	return ((plan >> 3) << 8) | end;
}

static uint32_t readFirst32(const uint8_t *code, size_t size)
{
	const unsigned plan = x86Batch32Primary[code[0]];
	if (plan)
		return readPrimary(code, size, plan);
	if (code[0] == 0xc5 && size >= 3 && (code[1] & 0xc0) == 0xc0)
		return readVex2Plan(code, size);
	return 0;
}

static uint32_t readFirst64(const uint8_t *code, size_t size)
{
	const unsigned byte = code[0];
	if ((byte & 0xf0) == 0x40) {
		if (size < 2)
			return 0;
		const unsigned opcode = code[1];
		/* getIDForMode repairs 90 with REX.B to XCHG. */
		if (opcode == 0x90 && (byte & 1))
			return 0;
		const unsigned plan = (byte & 8 ? x86Batch64RexWPrimary :
						  x86Batch64Primary)[opcode];
		const uint32_t word =
			plan ? readPrimary(code + 1, size - 1, plan) : 0;
		return word ? word + 1 : 0;
	}
	const unsigned plan = x86Batch64Primary[byte];
	if (plan)
		return readPrimary(code, size, plan);
	if (byte == 0xc5)
		return readVex2Plan(code, size);
	return 0;
}

static inline X86ScanBatchResult scanBatch(csh ud, const uint8_t *code,
					   size_t size, uint64_t address,
					   uint32_t *output, size_t capacity,
					   bool wide)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	X86ScanBatchResult batch = { 0, 0 };
	cs_insn insn = { 0 };
	handle->errnum = CS_ERR_OK;
	while (batch.count < capacity && size) {
		uint32_t packed = wide ? readFirst64(code, size) :
					 readFirst32(code, size);
		if (!packed) {
			insn.address = address;
			X86ScanResult result;
			if (!X86_getInstructionScanResult(ud, code, size, &insn,
							  &result))
				break;
			finish_x86_scan(handle, &insn, &result, code, false,
					false);
			packed = (insn.id << 8) | result.length;
		}
		output[batch.count++] = packed;
		const unsigned length = packed & 0xff;
		batch.bytes += length;
		code += length;
		size -= length;
		address += length;
	}
	return batch;
}
#endif

CAPSTONE_INTERNAL
X86ScanBatchResult X86_scanNativeBatch(csh ud, const uint8_t *code, size_t size,
				       uint64_t address, uint32_t *output,
				       size_t capacity)
{
#if !defined(CAPSTONE_X86_REDUCE) && !defined(CAPSTONE_X86_SCAN_ADAPTER)
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	if (handle && use_x86_scan(handle) && !handle->skipdata && code &&
	    output && capacity && size && handle->insn_id == X86_get_insn_id &&
	    handle->disasm == X86_getInstruction) {
		if (handle->mode == CS_MODE_32)
			return scanBatch(ud, code, size, address, output,
					 capacity, false);
		if (handle->mode == CS_MODE_64)
			return scanBatch(ud, code, size, address, output,
					 capacity, true);
	}
#endif
	return X86_scanBatch(ud, code, size, address, output, capacity);
}
#endif

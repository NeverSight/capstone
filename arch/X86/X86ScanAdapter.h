/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef CS_X86_SCAN_ADAPTER_H
#define CS_X86_SCAN_ADAPTER_H

#include <capstone/capstone.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Requires CAPSTONE_X86_SCAN_ADAPTER. Private static-link integration, not
 * an installed cs_* API. The callback
 * must use the handle's exact 32/64-bit profile and return (public_id << 8) |
 * length only for validated encodings, or zero to retain ordinary decoding.
 * It borrows the input for this call and must not retain it or reenter the
 * handle. Capstone owns output, options, errors and cursor advancement.
 * Only vector slow paths with text and detail disabled consult the adapter.
 * The owner must clear it before releasing user_data or pooling the handle. */
typedef uint32_t (*X86ScanAdapter)(void *user_data, const uint8_t *code,
				   size_t code_len);

bool X86_setScanAdapter(csh handle, cs_mode mode, X86ScanAdapter adapter,
			void *user_data);

#ifdef __cplusplus
}
#endif
#endif

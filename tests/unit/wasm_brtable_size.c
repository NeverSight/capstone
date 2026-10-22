#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>

static size_t uleb32(uint32_t v, uint8_t *out)
{
	size_t n = 0;
	for (;;) {
		uint8_t b = (uint8_t)(v & 0x7f);
		v >>= 7;
		if (v)
			b |= 0x80;
		out[n++] = b;
		if (!v)
			return n;
	}
}

static int run_count_case(csh h, uint32_t labels, size_t count_limit)
{
	uint8_t enc[5];
	size_t enc_len = uleb32(labels, enc);
	size_t len = 1 + enc_len + labels + 1;
	uint8_t *buf = calloc(1, len);
	if (!buf)
		return 1;

	buf[0] = 0x0e;
	memcpy(buf + 1, enc, enc_len);

	cs_insn *insn = NULL;
	size_t count = cs_disasm(h, buf, len, 0, count_limit, &insn);
	printf("labels=%u input_len=%zu requested=%zu returned=%zu\n", labels,
	       len, count_limit, count);
	if (count > 1) {
		cs_free(insn, count);
		free(buf);
		return 1;
	}
	for (size_t i = 0; i < count; i++) {
		printf("  insn[%zu]: address=%" PRIu64 " size=%u id=%u\n", i,
		       insn[i].address, insn[i].size, insn[i].id);
	}

	cs_free(insn, count);
	free(buf);
	return 0;
}

static int check_copy_sizes(csh handle)
{
	uint8_t bytes[32] = { 0x0e };
	for (unsigned text = 0; text != 2; ++text) {
		cs_option(handle, CS_OPT_TEXT, text ? CS_OPT_ON : CS_OPT_OFF);
		for (size_t length = 3; length <= sizeof(bytes); ++length) {
			bytes[1] = (uint8_t)(length - 3);
			cs_insn *batch = NULL, *iter = cs_malloc(handle);
			const uint8_t *cursor = bytes;
			size_t remaining = length;
			uint64_t address = 0x1000;
			if (!iter)
				return 1;
			memset(iter->bytes, 0xa5, sizeof(iter->bytes));
			size_t count = cs_disasm(handle, bytes, length, address,
						 1, &batch);
			bool decoded = cs_disasm_iter(
				handle, &cursor, &remaining, &address, iter);
			size_t copied = length < sizeof(iter->bytes) ?
						length :
						sizeof(iter->bytes);
			bool ok = decoded && count == 1 &&
				  cursor == bytes + length && remaining == 0 &&
				  address == 0x1000 + length;
			if (ok) {
				ok = iter->size == copied &&
				     batch->size == copied &&
				     iter->id == batch->id &&
				     memcmp(iter->bytes,
					    bytes + length - copied,
					    copied) == 0 &&
				     memcmp(batch->bytes,
					    bytes + length - copied,
					    copied) == 0;
				for (size_t i = copied; i < sizeof(iter->bytes);
				     ++i)
					ok &= iter->bytes[i] == 0xa5;
			}
			cs_free(iter, 1);
			cs_free(batch, count);
			if (!ok) {
				fprintf(stderr,
					"WASM copy: text=%u length=%zu\n", text,
					length);
				return 1;
			}
		}
	}
	return 0;
}

int main(void)
{
	csh h;
	if (cs_open(CS_ARCH_WASM, 0, &h) != CS_ERR_OK)
		return 1;

	if (check_copy_sizes(h) || run_count_case(h, 10, 5) ||
	    run_count_case(h, 65531, 5)) {
		cs_close(&h);
		return 1;
	}

	cs_close(&h);
	return 0;
}

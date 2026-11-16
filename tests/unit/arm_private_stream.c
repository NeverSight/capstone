/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned calls;
static bool zero_tail;
static bool inside_decode;
static unsigned allocation_hooks;
static cs_opt_mem current_memory;

static int inspect_tail(char *out, size_t size, const char *fmt, va_list ap)
{
	++calls;
	/* Every append destination retains the full initialization on the
	 * custom-formatter route, including bytes beyond the visible string. */
	for (size_t i = 0; i < size; ++i)
		zero_tail &= out[i] == '\0';
	return vsnprintf(out, size, fmt, ap);
}

static void install_observer(void)
{
	if (inside_decode) {
		++allocation_hooks;
		current_memory.vsnprintf = inspect_tail;
		if (cs_option(0, CS_OPT_MEM, (size_t)&current_memory) !=
		    CS_ERR_OK)
			zero_tail = false;
	}
}

static void *switching_malloc(size_t size)
{
	install_observer();
	return malloc(size);
}

static void switching_free(void *ptr)
{
	install_observer();
	free(ptr);
}

static bool check_allocator_alias(cs_mode mode, const uint8_t *bytes,
				  bool on_free, bool detail)
{
	csh handle;
	if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK)
		return false;
	bool ok = cs_option(handle, CS_OPT_DETAIL,
			    detail ? CS_OPT_ON : CS_OPT_OFF) == CS_ERR_OK;
	cs_insn records[2];
	cs_detail details[2];
	calls = allocation_hooks = 0;
	zero_tail = true;
	for (unsigned side = 0; side < 2 && ok; ++side) {
		memset(&records[side], 0x5a, sizeof(records[side]));
		memset(&details[side], 0x5a, sizeof(details[side]));
		records[side].illegal = records[side].is_alias =
			records[side].usesAliasDetails = false;
		records[side].detail = detail ? &details[side] : NULL;
		current_memory = (cs_opt_mem){
			side && !on_free ? switching_malloc : malloc, calloc,
			realloc, side && on_free ? switching_free : free,
			vsnprintf
		};
		ok = cs_option(0, CS_OPT_MEM, (size_t)&current_memory) ==
		     CS_ERR_OK;
		const uint8_t *cursor = bytes;
		size_t remaining = 4;
		uint64_t address = 0x1000;
		/* The alias substring is allocated after the private stream has
		 * been initialized. Its allocation/free hook installs a formatter
		 * before the alias operands are printed. */
		inside_decode = side != 0;
		ok = ok &&
		     cs_disasm_iter(handle, &cursor, &remaining, &address,
				    &records[side]) &&
		     cursor == bytes + 4 && remaining == 0 && address == 0x1004;
		inside_decode = false;
		records[side].detail = NULL;
	}
	current_memory =
		(cs_opt_mem){ malloc, calloc, realloc, free, vsnprintf };
	ok &= cs_option(0, CS_OPT_MEM, (size_t)&current_memory) == CS_ERR_OK;
	ok = ok && allocation_hooks && calls && zero_tail &&
	     records[0].alias_id &&
	     !memcmp(records, records + 1, sizeof(cs_insn)) &&
	     (!detail || !memcmp(details, details + 1, sizeof(cs_detail)));
	cs_close(&handle);
	return ok;
}

static bool check(cs_mode mode, unsigned syntax, bool detail, bool unsigned_imm)
{
	csh handle;
	if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK)
		return false;
	bool ok = cs_option(handle, CS_OPT_SYNTAX, syntax) == CS_ERR_OK &&
		  cs_option(handle, CS_OPT_DETAIL,
			    detail ? CS_OPT_ON : CS_OPT_OFF) == CS_ERR_OK &&
		  cs_option(handle, CS_OPT_UNSIGNED,
			    unsigned_imm ? CS_OPT_ON : CS_OPT_OFF) == CS_ERR_OK;
	const uint8_t arm[] = { 0x04, 0x90, 0x9a, 0xe5 };
	const uint8_t thumb[] = { 0x01, 0x30 };
	const size_t length = mode & CS_MODE_THUMB ? sizeof(thumb) :
						     sizeof(arm);
	const uint8_t *original = mode & CS_MODE_THUMB ? thumb : arm;
	uint8_t bytes[4];
	for (size_t i = 0; i < length; ++i)
		bytes[i] =
			original[mode & CS_MODE_BIG_ENDIAN ? length - i - 1 : i];
	cs_insn records[2];
	cs_detail details[2];
	cs_opt_mem memory = { malloc, calloc, realloc, free, vsnprintf };
	calls = 0;
	zero_tail = true;
	for (unsigned side = 0; side < 2 && ok; ++side) {
		memset(&records[side], 0x5a, sizeof(records[side]));
		memset(&details[side], 0x5a, sizeof(details[side]));
		records[side].illegal = records[side].is_alias =
			records[side].usesAliasDetails = false;
		records[side].detail = detail ? &details[side] : NULL;
		memory.vsnprintf = side ? inspect_tail : vsnprintf;
		ok = cs_option(0, CS_OPT_MEM, (size_t)&memory) == CS_ERR_OK;
		const uint8_t *cursor = bytes;
		size_t remaining = length;
		uint64_t address = 0x1000;
		ok = ok &&
		     cs_disasm_iter(handle, &cursor, &remaining, &address,
				    &records[side]) &&
		     cursor == bytes + length && remaining == 0 &&
		     address == 0x1000 + length;
		records[side].detail = NULL;
	}
	memory.vsnprintf = vsnprintf;
	ok &= cs_option(0, CS_OPT_MEM, (size_t)&memory) == CS_ERR_OK;
	ok = ok && calls && zero_tail &&
	     !memcmp(records, records + 1, sizeof(cs_insn)) &&
	     (!detail || !memcmp(details, details + 1, sizeof(cs_detail)));
	cs_close(&handle);
	return ok;
}

int main(void)
{
	if (cs_support(CS_SUPPORT_DIET))
		return 0;
	const uint8_t cinc[] = { 0x52, 0xea, 0x22, 0x9e };
	const uint8_t vmlav[] = { 0xf0, 0xee, 0x0e, 0xee };
	for (unsigned flags = 0; flags < 4; ++flags) {
		if (!check_allocator_alias(
			    (cs_mode)(CS_MODE_THUMB | CS_MODE_V8), cinc,
			    (flags & 1) != 0, (flags & 2) != 0) ||
		    !check_allocator_alias(
			    (cs_mode)(CS_MODE_THUMB | CS_MODE_V8 |
				      CS_MODE_MCLASS),
			    vmlav, (flags & 1) != 0, (flags & 2) != 0)) {
			fprintf(stderr,
				"ARM allocator-to-formatter contract mismatch: flags=%u hooks=%u calls=%u zero=%u\n",
				flags, allocation_hooks, calls,
				(unsigned)zero_tail);
			return 1;
		}
	}
	const cs_mode modes[] = { CS_MODE_ARM, CS_MODE_THUMB,
				  (cs_mode)(CS_MODE_ARM | CS_MODE_BIG_ENDIAN),
				  (cs_mode)(CS_MODE_THUMB |
					    CS_MODE_BIG_ENDIAN) };
	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i)
		for (unsigned flags = 0; flags < 8; ++flags)
			if (!check(modes[i],
				   flags & 1 ? CS_OPT_SYNTAX_CS_REG_ALIAS :
					       CS_OPT_SYNTAX_DEFAULT,
				   (flags & 2) != 0, (flags & 4) != 0)) {
				fprintf(stderr,
					"ARM stream contract mismatch: mode=%u flags=%u\n",
					(unsigned)modes[i], flags);
				return 1;
			}
	return 0;
}

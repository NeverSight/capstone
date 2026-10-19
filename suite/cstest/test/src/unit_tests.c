// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "../../../utils.h"
#include "../../../Mapping.h"
#include "test_mapping.h"
#include "helper.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool test_add_str_long_and_aliased(void)
{
	char payload[2049];
	memset(payload, 'x', sizeof(payload) - 1);
	payload[sizeof(payload) - 1] = '\0';
	char *text = malloc(1);
	if (!text)
		return false;
	text[0] = '\0';
	add_str(&text, "%s:%d", payload, 42);
	bool success = strlen(text) == 2051 &&
		       memcmp(text, payload, 2048) == 0 &&
		       strcmp(text + 2048, ":42") == 0;
	add_str(&text, "%s", text);
	success &= strlen(text) == 4102 && memcmp(text, text + 2051, 2051) == 0;
	free(text);
	return success;
}

bool test_cs_enum_get_val()
{
	bool found = false;
	// Get first value
	uint32_t val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
					   "AAAAAAAAAAAAAAAAAAAAAAAAAA",
					   &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), AAAAAAAAAAAAAAAAAAAAAAAAAA) failed is %d.\n",
			val);
		return false;
	}
	// Get second value
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "AAAAAAAAAAAAAAAAAAAAAAAAAB", &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), AAAAAAAAAAAAAAAAAAAAAAAAAB) failed is %d.\n",
			val);
		return false;
	}

	// Get second to last value
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzx", &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzx) failed is %d.\n",
			val);
		return false;
	}

	// Get last value
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz) failed is %d.\n",
			val);
		return false;
	}

	// Some values
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "AArch64CC_EQ", &found);
	if (!found || val != AArch64CC_EQ) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), AArch64CC_EQ) failed is %d.\n",
			val);
		return false;
	}
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "AArch64CC_Invalid", &found);
	if (!found || val != AArch64CC_Invalid) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), AArch64CC_In) failed is %d.\n",
			val);
		return false;
	}

	enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), "\0", &found);
	if (found) {
		fprintf(stderr, "Out of bounds failed.\n");
		return false;
	}

	enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
			    "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
			    &found);
	if (found) {
		fprintf(stderr, "Out of bounds failed.\n");
		return false;
	}

	return true;
}

int main()
{
	bool success = true;
	success &= test_cs_enum_get_val();
	printf("test_cs_enum_get_val: %s\n", success ? "ok" : "fail");
	const bool append_success = test_add_str_long_and_aliased();
	printf("test_add_str_long_and_aliased: %s\n",
	       append_success ? "ok" : "fail");
	success &= append_success;
	return success ? 0 : 1;
}

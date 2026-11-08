// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "unit_test.h"
#include "../utils.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

static bool test_register_membership(void)
{
	printf("Test test_register_membership\n");
	uint16_t values[] = { 0, 1, UINT16_MAX, 17, 17 };
	bool (*external)(uint16_t *, unsigned char, unsigned int) = arr_exist;
	static const struct {
		unsigned char count;
		unsigned int query;
		bool found;
	} cases[] = {
		{ 0, 0, false },	 { 0, UINT_MAX, false },
		{ 1, 0, true },		 { 1, 1, false },
		{ 2, 1, true },		 { 2, UINT16_MAX, false },
		{ 3, UINT16_MAX, true }, { 3, 65536u, false },
		{ 3, 65537u, false },	 { 3, UINT_MAX, false },
		{ 3, 17, false },	 { 4, 17, true },
		{ 5, 17, true },
	};
	for (size_t i = 0; i < ARR_SIZE(cases); ++i) {
		if (arr_exist_inline(values, cases[i].count, cases[i].query) !=
			    cases[i].found ||
		    external(values, cases[i].count, cases[i].query) !=
			    cases[i].found)
			return false;
	}
	if (arr_exist_inline(NULL, 0, UINT_MAX) || external(NULL, 0, UINT_MAX))
		return false;
	uint16_t full[UCHAR_MAX] = { 0 };
	full[UCHAR_MAX - 1] = 4242;
	if (arr_exist_inline(full, UCHAR_MAX - 1, 4242) ||
	    !arr_exist_inline(full, UCHAR_MAX, 4242) ||
	    external(full, UCHAR_MAX - 1, 4242) ||
	    !external(full, UCHAR_MAX, 4242))
		return false;
	uint16_t *cursor = values;
	unsigned char count = 1;
	unsigned int query = 0;
	return arr_exist_inline(cursor++, count++, query++) &&
	       cursor == values + 1 && count == 2 && query == 1;
}

static bool test_str_append_no_realloc()
{
	printf("Test test_str_append_no_realloc\n");

	char str_a[] = "AAAA\0\0\0\0\0";
	char str_b[] = "BBBB";
	char str_c[] = "\0\0\0\0\0";

	CHECK_NULL_RET_FALSE(str_append(NULL, NULL));
	CHECK_NULL_RET_FALSE(str_append(str_a, NULL));
	CHECK_NULL_RET_FALSE(str_append(NULL, str_b));

	str_append_no_realloc(str_a, sizeof(str_a), str_c);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "AAAA");

	str_append_no_realloc(str_a, sizeof(str_a), str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "AAAABBBB");

	str_append_no_realloc(str_c, sizeof(str_c), str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_c, "BBBB");

	str_append_no_realloc(str_b, sizeof(str_b), str_c);
	CHECK_STR_EQUAL_RET_FALSE(str_b, "BBBB");

	return true;
}

static bool test_str_append()
{
	printf("Test test_str_append\n");
	char *str_a = NULL;
	char *str_b = NULL;
	CHECK_NULL_RET_FALSE(str_append(str_a, str_b));

	str_a = cs_mem_calloc(5, sizeof(char));
	memcpy(str_a, "AAAA", 5);
	CHECK_NULL_RET_FALSE(str_append(str_a, str_b));

	str_b = cs_mem_calloc(5, sizeof(char));
	str_a = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "AAAA");

	memcpy(str_b, "BBBB", 5);
	str_a = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "AAAABBBB");

	memset(str_a, 0, strlen(str_a) + 1);
	str_a = str_append(str_a, str_b);
	CHECK_STR_EQUAL_RET_FALSE(str_a, "BBBB");
	free(str_a);
	free(str_b);

	return true;
}

int main()
{
	bool result = true;
	result &= test_register_membership();
	result &= test_str_append();
	result &= test_str_append_no_realloc();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}

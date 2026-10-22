/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifndef CS_ASSERT_H
#define CS_ASSERT_H

#include "include/capstone/platform.h"
#ifdef CAPSTONE_DEBUG
#include <assert.h>
#endif
#ifdef CAPSTONE_ASSERTION_WARNINGS
#include <stdio.h>
#endif

/// Capstone assert macros. They can be configured to print warnings
/// when the `expr` is false.
/// This can be enabled by defining CAPSTONE_ASSERTION_WARNINGS.
/// Debug builds will always include an `assert(expr)` and hard fail
/// if `!expr`.
/// Release builds will not have `assert(expr)` code.

/// An simple assert.
#if defined(CAPSTONE_DEBUG) && !defined(CAPSTONE_ASSERTION_WARNINGS)
#define CS_ASSERT(expr) assert(expr)
#elif defined(CAPSTONE_DEBUG) && defined(CAPSTONE_ASSERTION_WARNINGS)
#define CS_ASSERT(expr) \
	do { \
		if (!(expr)) { \
			fprintf(stderr, \
				"Capstone hit the assert: \"" #expr \
				"\": %s:%" PRIu32 "\n", \
				__FILE__, __LINE__); \
			assert(expr); \
		} \
	} while (0)
#elif defined(CAPSTONE_ASSERTION_WARNINGS)
#define CS_ASSERT(expr) \
	do { \
		if (!(expr)) { \
			fprintf(stderr, \
				"Capstone hit the assert: \"" #expr \
				"\": %s:%" PRIu32 "\n", \
				__FILE__, __LINE__); \
		} \
	} while (0)
#else
#define CS_ASSERT(expr)
#endif

/// An assert which returns the value in release builds if `!expr`.
#if defined(CAPSTONE_DEBUG) && !defined(CAPSTONE_ASSERTION_WARNINGS)
#define CS_ASSERT_RET_VAL(expr, val) assert(expr)
#elif defined(CAPSTONE_ASSERTION_WARNINGS)
#define CS_ASSERT_RET_VAL(expr, val) \
	do { \
		if (!(expr)) { \
			CS_ASSERT(expr); \
			return val; \
		} \
	} while (0)
#else
#define CS_ASSERT_RET_VAL(expr, val) \
	do { \
		if (!(expr)) { \
			return val; \
		} \
	} while (0)
#endif

/// An assert which returns in release builds if `!expr`.
#if defined(CAPSTONE_DEBUG) && !defined(CAPSTONE_ASSERTION_WARNINGS)
#define CS_ASSERT_RET(expr) assert(expr)
#elif defined(CAPSTONE_ASSERTION_WARNINGS)
#define CS_ASSERT_RET(expr) \
	do { \
		if (!(expr)) { \
			CS_ASSERT(expr); \
			return; \
		} \
	} while (0)
#else
#define CS_ASSERT_RET(expr) \
	do { \
		if (!(expr)) { \
			return; \
		} \
	} while (0)
#endif

#endif

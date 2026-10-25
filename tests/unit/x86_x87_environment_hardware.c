/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

#if defined(__x86_64__) && (defined(__linux__) || defined(__APPLE__))
#include <cpuid.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

/* Execute the exact decoded bytes in a child. The next data page is inaccessible,
 * so the CPU independently distinguishes the short and full memory images. */
static int execute(const uint8_t *bytes, size_t length, unsigned available,
		   bool writable)
{
	const pid_t child = fork();
	if (child == -1)
		return -1;
	if (child == 0) {
		const struct rlimit no_core = { 0, 0 };
		setrlimit(RLIMIT_CORE, &no_core);
		signal(SIGSEGV, SIG_DFL);
		signal(SIGBUS, SIG_DFL);
		signal(SIGILL, SIG_DFL);
		signal(SIGFPE, SIG_DFL);
		const long page = sysconf(_SC_PAGESIZE);
		if (page <= 0 || (unsigned long)page < available)
			_exit(2);
		uint8_t *data = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANON, -1, 0);
		uint8_t *code = mmap(NULL, page, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANON, -1, 0);
		if (data == MAP_FAILED || code == MAP_FAILED)
			_exit(2);
		uint8_t *operand = data + page - available;
		/* Mask all exceptions for loads; the remaining initial state is zero. */
		operand[0] = 0x7f;
		operand[1] = 0x03;
		if (mprotect(data + page, page, PROT_NONE) ||
		    mprotect(data, page,
			     writable ? PROT_READ | PROT_WRITE : PROT_READ))
			_exit(2);
		/* FNINIT; MOV RAX,RDI; MOV R8,RDI (the base with REX.B). */
		const uint8_t setup[] = { 0xdb, 0xe3, 0x48, 0x89,
					  0xf8, 0x49, 0x89, 0xf8 };
		const uint8_t finish[] = { 0xdb, 0xe3, 0xc3 };
		memcpy(code, setup, sizeof(setup));
		memcpy(code + sizeof(setup), bytes, length);
		memcpy(code + sizeof(setup) + length, finish, sizeof(finish));
		if (mprotect(code, page, PROT_READ | PROT_EXEC))
			_exit(2);
		void (*run)(void *);
		memcpy(&run, &code, sizeof(run));
		run(operand);
		_exit(0);
	}
	int status;
	if (waitpid(child, &status, 0) != child)
		return -1;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	if (WIFSIGNALED(status) &&
	    (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS))
		return 1;
	return -1;
}

static bool check_case(csh handle, const uint8_t *prefix, size_t prefix_length,
		       unsigned family, unsigned *observations)
{
	uint8_t bytes[8];
	memcpy(bytes, prefix, prefix_length);
	bytes[prefix_length] = family < 2 ? 0xd9 : 0xdd;
	bytes[prefix_length + 1] = family % 2 ? 0x20 : 0x30;
	const size_t length = prefix_length + 2;
	cs_insn *insn = NULL;
	const size_t count = cs_disasm(handle, bytes, length, 0x1000, 1, &insn);
	if (count != 1 || insn->size != length || !insn->detail ||
	    insn->detail->x86.op_count != 1 ||
	    insn->detail->x86.operands[0].type != X86_OP_MEM) {
		cs_free(insn, count);
		return false;
	}
	const cs_x86_op *operand = &insn->detail->x86.operands[0];
	const unsigned spans[2] = { family < 2 ? 14 : 94,
				    family < 2 ? 28 : 108 };
	bool success = operand->size == spans[0] || operand->size == spans[1];
	for (unsigned i = 0; i < 2; ++i)
		for (unsigned writable = 0; writable < 2; ++writable) {
			const bool expect_fault =
				spans[i] < operand->size ||
				(!writable && (operand->access & CS_AC_WRITE));
			const int actual =
				execute(bytes, length, spans[i], writable);
			++*observations;
			if (actual != (int)expect_fault) {
				fprintf(stderr, "x87 hardware mismatch:");
				for (size_t b = 0; b < length; ++b)
					fprintf(stderr, " %02x", bytes[b]);
				fprintf(stderr,
					" decoded=%u access=%u available=%u writable=%u expected_fault=%u actual=%d\n",
					operand->size, operand->access,
					spans[i], writable, expect_fault,
					actual);
				success = false;
			}
		}
	cs_free(insn, count);
	return success;
}

int main(void)
{
	unsigned a, b, c, d;
	char vendor[13] = { 0 };
	__cpuid(0, a, b, c, d);
	memcpy(vendor, &b, 4);
	memcpy(vendor + 4, &d, 4);
	memcpy(vendor + 8, &c, 4);
	__cpuid(1, a, b, c, d);
	int translated = 0;
#ifdef __APPLE__
	size_t translated_size = sizeof(translated);
	if (sysctlbyname("sysctl.proc_translated", &translated,
			 &translated_size, NULL, 0) != 0)
		translated = 0;
#endif
	printf("x87 execution CPU=%s signature=%08x translated=%d\n", vendor, a,
	       translated);
	fflush(stdout);
	if (translated) {
		puts("SKIP: translated x87 faults do not qualify native memory access");
		return 77;
	}
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 1;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	bool success = true;
	unsigned observations = 0;
	const uint8_t prefixes[][4] = { { 0 },
					{ 0x66 },
					{ 0x48, 0x66 },
					{ 0x66, 0x48, 0x40 },
					{ 0x66, 0x40, 0x48 },
					{ 0x48, 0x66, 0x48 } };
	const unsigned lengths[] = { 0, 1, 2, 3, 3, 3 };
	for (unsigned family = 0; family < 4; ++family) {
		for (unsigned p = 0; p < sizeof(lengths) / sizeof(lengths[0]);
		     ++p)
			success &= check_case(handle, prefixes[p], lengths[p],
					      family, &observations);
		for (unsigned rex = 0x40; rex <= 0x4f; ++rex) {
			const uint8_t prefix[] = { 0x66, rex };
			success &= check_case(handle, prefix, sizeof(prefix),
					      family, &observations);
			success &= check_case(handle, prefix + 1, 1, family,
					      &observations);
		}
	}
	cs_close(&handle);
	printf("%u x87 CPU memory-boundary/access observations\n",
	       observations);
	return success ? 0 : 1;
}
#else
int main(void)
{
	puts("SKIP: x87 execution requires an x86-64 POSIX host");
	return 77;
}
#endif

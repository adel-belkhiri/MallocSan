#define _GNU_SOURCE

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Variant A microbench for the loop-exit post-handler deferral (#5).
 *
 * The faulting access lives INSIDE the loop (header <= fault < latch) on a
 * loop-invariant tainted base.  There is no prologue strip, so MallocSan's
 * SIGSEGV handler must strip the invariant base once per loop ENTRY
 * (dw_loop_exit_activate_context), run the body clean, and retaint once at the
 * loop's fall-through exit (latch_addr + latch_size).
 *
 *   exit_engage_a(p, n):
 *       push  %rbx
 *       mov   %rdi, %rbx            ; rbx = tainted heap pointer (invariant)
 *       mov   %rsi, %rcx            ; rcx = iteration count
 *   1:                             ; header = (D)
 *       imul  $0x100, %edx, %edx    ; (D) 6B clean prefix [header, fault)
 *       mov   0x40(%rbx), %eax      ; (A) FAULT inside loop (3B: 8b 43 40)
 *       dec   %ecx                  ; (E) 2B clean
 *       jne   1b                    ; (F) backward Jcc, target = (D) < (A)
 *       pop   %rbx
 *       mov   %esi, %eax
 *       ret
 *
 * Expected (DW_LOG_LEVEL=3): one "Loop-exit deferral (Variant A)" line staging
 * the post at the fall-through (pop %rbx, just past the latch), and the fault
 * firing once per loop entry (here: once total for a single call), NOT once per
 * iteration.
 *
 * OOB variant ("oob"): call the SAME function (same fault RIP) first with a
 * LARGE object (discovery, in-bounds at [rbx+0x40]) and then with a SMALLER
 * object on a LATER entry.  The per-entry dw_check_access(base+0x40, 4) on the
 * smaller object must report the invalid access -- this is the exact scenario
 * the exact-EA cut + per-entry re-check defends (coverage on every entry, not
 * just at discovery time).  The check emits "Out-of-bounds access detected"
 * (WARNING, recoverable) -- that detection firing on the smaller object is the
 * pass signal; the deferral must not suppress it.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -rdynamic tests/loop-exit-variant-a.c -o /tmp/loop-exit-variant-a
 *
 * Run:
 *   env LD_LIBRARY_PATH=external/libolx/lib:external/libpatch/src/lib \
 *       LD_PRELOAD=$PWD/build/src/.libs/libmallocsan.so \
 *       DW_MIN_SIZE=1 DW_LOG_LEVEL=3 \
 *       /tmp/loop-exit-variant-a 1000000
 */

struct rec_large {
	uint32_t head;		/* offset 0x00 */
	uint8_t pad[0x3c];	/* 0x04 .. 0x3f */
	uint32_t field40;	/* offset 0x40, read by (A) */
	uint32_t tail[4];	/* keep [rbx+0x40] strictly in bounds */
};

struct rec_small {
	uint32_t head;		/* offset 0x00 only -- [rbx+0x40] is OOB */
};

__asm__(
	".text\n"
	".globl exit_engage_a\n"
	".type exit_engage_a,@function\n"
	"exit_engage_a:\n"
	"  .cfi_startproc\n"
	"  push %rbx\n"
	"  .cfi_def_cfa_offset 16\n"
	"  mov %rdi, %rbx\n"			/* rbx = tainted heap pointer (invariant) */
	"  mov %rsi, %rcx\n"			/* rcx = iteration count */
	"1:\n"					/* header = (D) */
	"  .byte 0x69, 0xd2, 0x00, 0x01, 0x00, 0x00\n"	/* (D) imul $0x100, %edx, %edx -- clean prefix */
	"  .byte 0x8b, 0x43, 0x40\n"		/* (A) mov 0x40(%rbx), %eax -- FAULT inside loop */
	"  .byte 0xff, 0xc9\n"			/* (E) dec %ecx */
	"  jne 1b\n"				/* (F) conditional back-edge to (D) */
	"  pop %rbx\n"
	"  .cfi_def_cfa_offset 8\n"
	"  mov %esi, %eax\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".size exit_engage_a, .-exit_engage_a\n"
);

extern uint32_t exit_engage_a(void *p, uintptr_t n);

static volatile uint32_t sink;

int main(int argc, char **argv)
{
	uintptr_t n = (argc >= 2) ? strtoull(argv[1], NULL, 10) : 1000000;
	bool oob = (argc >= 3) && (strcmp(argv[2], "oob") == 0);

	if (n == 0) {
		fprintf(stderr, "iteration count must be > 0\n");
		return 2;
	}

	struct rec_large *big = malloc(sizeof(*big));	/* discovery object */
	if (!big) {
		perror("malloc");
		return 2;
	}
	memset(big, 0, sizeof(*big));
	big->field40 = 0xabcd;

	/* Discovery entry: in-bounds at [rbx+0x40]. */
	uint32_t r = exit_engage_a(big, n);
	sink = r;
	printf("variant-a discovery: iterations=%" PRIuPTR " sink=0x%" PRIx32 "\n", n, sink);

	if (oob) {
		/*
		 * Later entry, SAME fault RIP, SMALLER object: [rbx+0x40] now reads
		 * past the allocation.  The per-entry activation check must catch it.
		 */
		struct rec_small *small = malloc(sizeof(*small));
		if (!small) {
			perror("malloc");
			return 2;
		}
		small->head = 1;
		uint32_t r2 = exit_engage_a(small, n);	/* expect "Out-of-bounds access detected" */
		sink = r2;
		printf("variant-a oob: sink=0x%" PRIx32 " (OOB should have been reported above)\n", sink);
		free(small);
	}

	free(big);
	return 0;
}

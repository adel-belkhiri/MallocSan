#define _GNU_SOURCE

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Variant B microbench for the loop-exit post-handler deferral (#5).
 *
 * The faulting access lives BEFORE the loop (fault < header < latch) and a
 * SIMILAR access re-dereferences the same loop-invariant object INSIDE the loop
 * body.  The normal pre-probe strips the invariant base once in the prologue;
 * the deferral relocates the retaint to the loop's fall-through exit
 * (latch_addr + latch_size) instead of paying a per-iteration in-loop post.
 * No signal-handler change: loop_exit_activate stays false, the pre-probe is
 * unchanged, only the post moves past the latch.
 *
 *   exit_engage_b(p, n):
 *       push  %rbx
 *       mov   %rdi, %rbx           ; rbx = tainted heap pointer (invariant)
 *       mov   %rsi, %rcx           ; rcx = iteration count
 *       mov   (%rbx), %eax         ; (A) FAULT, BEFORE loop  (2B: 8b 03)
 *   1:                             ; header = (B)
 *       add   (%rbx), %eax         ; (B) similar access INSIDE loop (2B: 03 03)
 *       dec   %ecx                 ; (C) 2B clean
 *       jne   1b                   ; (D) backward Jcc, target = (B) > (A)
 *       pop   %rbx
 *       mov   %esi, %eax
 *       ret
 *
 * Expected (DW_LOG_LEVEL=3): one "Loop-exit deferral (Variant B)" line staging
 * the post at the fall-through (pop %rbx, just past the latch) and one retaint
 * per loop entry rather than per iteration.
 *
 * OOB variant ("oob"): advance the base by one element so (A)'s `mov (%rbx)`
 * reads past the allocation.  The normal pre-probe at the fault must still
 * report the invalid access -- the loop-exit deferral only relocates the
 * retaint, it must not suppress the bounds check.  The pre-probe emits
 * "Out-of-bounds access detected" (WARNING, recoverable) -- that detection
 * firing is the pass signal.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -rdynamic tests/loop-exit-variant-b.c -o /tmp/loop-exit-variant-b
 *
 * Run:
 *   env LD_LIBRARY_PATH=external/libolx/lib:external/libpatch/src/lib \
 *       LD_PRELOAD=$PWD/build/src/.libs/libmallocsan.so \
 *       DW_MIN_SIZE=1 DW_LOG_LEVEL=3 \
 *       /tmp/loop-exit-variant-b 1000000
 */

struct rec {
	uint32_t field0;	/* read by (A) and (B): [rbx+0] */
	uint32_t tail[15];	/* padding so a single allocation is a full element */
};

__asm__(
	".text\n"
	".globl exit_engage_b\n"
	".type exit_engage_b,@function\n"
	"exit_engage_b:\n"
	"  .cfi_startproc\n"
	"  push %rbx\n"
	"  .cfi_def_cfa_offset 16\n"
	"  mov %rdi, %rbx\n"			/* rbx = tainted heap pointer (invariant) */
	"  mov %rsi, %rcx\n"			/* rcx = iteration count */
	"  .byte 0x8b, 0x03\n"			/* (A) mov (%rbx), %eax -- FAULT before loop */
	"1:\n"					/* header = (B) */
	"  .byte 0x03, 0x03\n"			/* (B) add (%rbx), %eax -- similar access in loop */
	"  .byte 0xff, 0xc9\n"			/* (C) dec %ecx */
	"  jne 1b\n"				/* (D) conditional back-edge to (B) */
	"  pop %rbx\n"
	"  .cfi_def_cfa_offset 8\n"
	"  mov %esi, %eax\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".size exit_engage_b, .-exit_engage_b\n"
);

extern uint32_t exit_engage_b(struct rec *p, uintptr_t n);

static volatile uint32_t sink;

int main(int argc, char **argv)
{
	uintptr_t n = (argc >= 2) ? strtoull(argv[1], NULL, 10) : 1000000;
	bool oob = (argc >= 3) && (strcmp(argv[2], "oob") == 0);

	if (n == 0) {
		fprintf(stderr, "iteration count must be > 0\n");
		return 2;
	}

	struct rec *p = malloc(sizeof(*p));	/* tainted under MallocSan */
	if (!p) {
		perror("malloc");
		return 2;
	}
	memset(p, 0, sizeof(*p));
	p->field0 = 1;

	/* OOB variant: advance the base so (A) reads one element past the object. */
	struct rec *arg = oob ? p + 1 : p;

	uint32_t r = exit_engage_b(arg, n);
	sink = r;

	printf("variant-b: iterations=%" PRIuPTR " oob=%d sink=0x%" PRIx32 "\n", n, (int)oob, sink);

	free(p);
	return 0;
}

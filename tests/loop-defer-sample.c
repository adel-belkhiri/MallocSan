#define _GNU_SOURCE

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Minimal sample program for measuring the loop-exit post-handler deferral.
 *
 * The hot loop (mallocsan_hot_loop) contains exactly the instruction pattern the
 * optimization targets: a tainted heap pointer accessed every iteration through a
 * loop-INVARIANT effective address (fixed displacement, no index), inside a
 * conditional back-edge whose target is the access itself.
 *
 *   mallocsan_hot_loop(p, n):
 *       mov   %rsi, %rcx            ; rcx = n
 *       xor   %rax, %rax            ; acc = 0
 *   1:  add   %rax, 0x30(%rdi)      ; [rdi+0x30] += rax   <- fault/patch site
 *                                   ;   base=rdi (tainted), disp 0x30, no index,
 *                                   ;   RMW (not a plain mov, so it is NOT eaten
 *                                   ;   by the fixed-field-mov SIGSEGV fast path)
 *       inc   %rax                  ; mutate the VALUE reg, not the pointer
 *       dec   %rcx
 *       jne   1b                    ; conditional back-edge to the access
 *       movabs $0x9e3779b97f4a7c15, %rdx   ; 10-byte fall-through == the loop
 *       xor   %rdx, %rax            ;   exit; wide enough to host a JUMP probe,
 *       ret                         ;   so the deferred post is a JUMP, not a TRAP
 *
 * The deferral moves the reprotect (post-handler) from the back-edge (once per
 * iteration) to this single loop exit (once per call). Time the whole program
 * under MallocSan with the optimization OFF and ON to see the difference.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -rdynamic tests/loop-defer-sample.c -o /tmp/loop-defer-sample
 *
 * Run under MallocSan:
 *   env LD_LIBRARY_PATH=external/libolx/lib:external/libpatch/src/lib \
 *       LD_PRELOAD=$PWD/build/src/.libs/libmallocsan.so \
 *       DW_MIN_SIZE=1 DW_LOG_LEVEL=0 \
 *       /tmp/loop-defer-sample 50000000
 */

struct rec {
	uintptr_t pad[6];	/* 6 * 8 = 0x30 bytes */
	uintptr_t field;	/* lives at [base + 0x30] */
};

__asm__(
	".text\n"
	".globl mallocsan_hot_loop\n"
	".type mallocsan_hot_loop,@function\n"
	"mallocsan_hot_loop:\n"
	"  .cfi_startproc\n"			/* .eh_frame: lets libunwind resolve
						 * function bounds (required by the
						 * deferral scan) */
	"  mov %rsi, %rcx\n"			/* rcx = iteration count */
	"  xor %rax, %rax\n"			/* rax = accumulator */
	"1:\n"
	"  .byte 0x48, 0x01, 0x47, 0x30\n"	/* add %rax, 0x30(%rdi)  (RMW, invariant EA) */
	"  inc %rax\n"				/* mutate value reg (not the pointer) */
	"  dec %rcx\n"
	"  jne 1b\n"				/* conditional back-edge */
	"  movabs $0x9e3779b97f4a7c15, %rdx\n"	/* 10-byte loop-exit fall-through:
						 * JUMP-patchable deferred post site */
	"  xor %rdx, %rax\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".size mallocsan_hot_loop, .-mallocsan_hot_loop\n"
);

extern uintptr_t mallocsan_hot_loop(struct rec *p, uintptr_t n);

static volatile uintptr_t sink;

static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		perror("clock_gettime");
		exit(2);
	}
	return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
	uintptr_t n = (argc >= 2) ? strtoull(argv[1], NULL, 10) : 50000000;
	if (n == 0) {
		fprintf(stderr, "iteration count must be > 0\n");
		return 2;
	}

	struct rec *p = malloc(sizeof(*p));	/* tainted under MallocSan */
	if (!p) {
		perror("malloc");
		return 2;
	}
	p->field = 0;

	uint64_t t0 = now_ns();
	uintptr_t r = mallocsan_hot_loop(p, n);
	uint64_t t1 = now_ns();

	sink = r ^ p->field;

	double elapsed_s = (double)(t1 - t0) / 1e9;
	printf("iterations=%" PRIuPTR " elapsed_s=%.6f ns_per_iter=%.2f sink=0x%" PRIxPTR "\n",
	       n, elapsed_s, elapsed_s * 1e9 / (double)n, sink);

	free(p);
	return 0;
}

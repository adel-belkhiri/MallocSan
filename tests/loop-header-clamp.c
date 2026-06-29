#define _GNU_SOURCE

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Synthetic harness for the loop-header clamp on the linear forward-scan
 * deferral path (dw_defer_post_handler in src/dw-disassembly.c).
 *
 * It reproduces Example A from the design: the faulting access is OUTSIDE the
 * loop, the loop body never re-dereferences the faulting object, and there is a
 * >=4-byte pre-header safe site. Without the clamp, make_deferred_post prefers
 * the newest (in-loop) candidate and the post fires once per iteration; with the
 * clamp, the in-loop candidates are pruned and the post anchors at the
 * pre-header `mov esi, 0x10`, firing once.
 *
 *   clamp_engage(p, n):
 *       push  %rbx
 *       mov   %rdi, %rbx           ; rbx = tainted heap pointer
 *       mov   %rsi, %rcx           ; rcx = iteration count
 *       mov   (%rbx), %eax         ; (A) FAULT  (2B: 8b 03)
 *       add   0x4(%rbx), %eax      ; (B) similar access, OUTSIDE loop (3B)
 *       mov   $0x10, %esi          ; (C) 5B safe anchor, addr < header
 *   1:                             ; header = (D)
 *       imul  $0x100, %edx, %edx   ; (D) 6B safe, addr >= header (in-loop tail)
 *       dec   %ecx                 ; (E) 2B, never recorded
 *       jne   1b                   ; (F) latch, target = (D)  => backward Jcc
 *       pop   %rbx
 *       ret
 *
 * Expected (clamp ON): the deferral log shows
 *     "Staged deferred post-probe at 0x<C>"
 * with <C> < <D> (the header / first in-loop instruction).  Clamp OFF would
 * stage at 0x<D> (inside the loop).  Either way md5/result parity holds; the
 * clamp only relocates the retaint, never the bounds check.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -rdynamic tests/loop-header-clamp.c -o /tmp/loop-header-clamp
 *
 * Run under MallocSan (observe the staged-post address vs the header):
 *   env LD_LIBRARY_PATH=external/libolx/lib:external/libpatch/src/lib \
 *       LD_PRELOAD=$PWD/build/src/.libs/libmallocsan.so \
 *       DW_MIN_SIZE=1 DW_LOG_LEVEL=0 \
 *       /tmp/loop-header-clamp 1000000
 *
 * OOB variant: pass a second arg ("oob") to make the in-bounds fault site read
 * one element past the allocation.  The pre-probe at the fault still guards the
 * first access, so MallocSan must report the invalid access regardless of where
 * the (relocated) post lands -- the clamp must not suppress the bounds check.
 */

struct rec {
	uint32_t field0;	/* read by (A): mov (%rbx), %eax            */
	uint32_t field4;	/* read by (B): add 0x4(%rbx), %eax        */
	uint32_t tail[14];	/* padding so [rbx+4] stays in bounds      */
};

__asm__(
	".text\n"
	".globl clamp_engage\n"
	".type clamp_engage,@function\n"
	"clamp_engage:\n"
	"  .cfi_startproc\n"			/* let libunwind resolve function bounds */
	"  push %rbx\n"
	"  .cfi_def_cfa_offset 16\n"
	"  mov %rdi, %rbx\n"			/* rbx = tainted heap pointer */
	"  mov %rsi, %rcx\n"			/* rcx = iteration count */
	"  .byte 0x8b, 0x03\n"			/* (A) mov (%rbx), %eax  -- FAULT */
	"  .byte 0x03, 0x43, 0x04\n"		/* (B) add 0x4(%rbx), %eax -- similar, OUTSIDE loop */
	"  .byte 0xbe, 0x10, 0x00, 0x00, 0x00\n"/* (C) mov $0x10, %esi  -- 5B pre-header anchor */
	"1:\n"					/* header = (D) */
	"  .byte 0x69, 0xd2, 0x00, 0x01, 0x00, 0x00\n"	/* (D) imul $0x100, %edx, %edx -- 6B in-loop */
	"  .byte 0xff, 0xc9\n"			/* (E) dec %ecx -- 2B, never recorded */
	"  jne 1b\n"				/* (F) conditional back-edge to (D) */
	"  pop %rbx\n"
	"  .cfi_def_cfa_offset 8\n"
	"  mov %esi, %eax\n"			/* return something derived from the loop */
	"  ret\n"
	"  .cfi_endproc\n"
	".size clamp_engage, .-clamp_engage\n"
);

extern uint32_t clamp_engage(struct rec *p, uintptr_t n);

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
	p->field4 = 2;

	/*
	 * OOB variant: advance the base so (A)'s `mov (%rbx), %eax` reads one
	 * element past the allocation.  The pre-probe at the fault must still
	 * catch this; the loop-header clamp only relocates the retaint.
	 */
	struct rec *arg = oob ? p + 1 : p;

	uint32_t r = clamp_engage(arg, n);
	sink = r;

	printf("iterations=%" PRIuPTR " oob=%d sink=0x%" PRIx32 "\n", n, (int)oob, sink);

	free(p);
	return 0;
}

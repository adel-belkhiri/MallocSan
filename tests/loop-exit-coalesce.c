#define _GNU_SOURCE

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Reproducer for the #5 loop-exit "coalescable sibling" property.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -rdynamic tests/loop-exit-coalesce.c -o /tmp/loop-exit-coalesce
 *
 * First rebuild MallocSan with the diagnostic enabled:
 *   make -C build/src clean
 *   make -C build -j4 CPPFLAGS=-DDW_LEBUSY_DEBUG
 *
 * Run:
 *   env LD_LIBRARY_PATH=external/libolx/lib:external/libpatch/src/lib \
 *       LD_PRELOAD=$PWD/build/src/.libs/libmallocsan.so \
 *       DW_MIN_SIZE=1 DW_LOG_LEVEL=3 DW_STATS_ENABLED=1 \
 *       DW_STATS_FILE=/tmp/loop-exit-coalesce.stats \
 *       /tmp/loop-exit-coalesce 100000
 *
 * Expected with the current diagnostic-only implementation:
 *   - one "Loop-exit deferral (Variant A)" owner for [rbx+0x40]
 *   - one later otherwise-eligible sibling [r12+0x40] blocked because the same
 *     fall-through exit is already owned by the first #5 post
 *   - stats footer:
 *       committed #5 exit owners: 1
 *       coalescable exits (>=1 busy sibling): 1
 *       exit-busy siblings total hits: non-zero
 *
 * Shape:
 *
 *   coalescable_loop(a, b, n):
 *       rbx = a                 ; first tainted invariant base
 *       r12 = b                 ; second tainted invariant base
 *   loop_header:
 *       mov 0x40(%rbx), %eax    ; owner candidate: installs post at loop_exit
 *       add %eax, %r8d
 *       mov 0x40(%r12), %edx    ; sibling candidate: same latch/exit as owner
 *       add %edx, %r9d
 *       dec %ecx
 *       jne loop_header
 *   loop_exit:
 *       movabs ..., %r10        ; single shared fall-through post location
 *       ...
 *
 * The first fault at [rbx+0x40] commits a #5 post at loop_exit.  The loop then
 * continues with rbx clean but r12 still tainted, so [r12+0x40] faults before
 * loop_exit executes.  Its scan reaches the same latch and the same fall-through
 * exit, which is now occupied by the committed owner.  DW_LEBUSY_DEBUG should
 * classify that second site as exit-busy/coalescable, not exit-unpatchable.
 */

struct rec {
	uint8_t pad[0x40];
	uint32_t field40;
	uint32_t tail[15];
};

__asm__(
	".text\n"
	".globl coalescable_loop\n"
	".type coalescable_loop,@function\n"
	"coalescable_loop:\n"
	"  .cfi_startproc\n"
	"  push %rbx\n"
	"  .cfi_def_cfa_offset 16\n"
	"  .cfi_offset %rbx, -16\n"
	"  push %r12\n"
	"  .cfi_def_cfa_offset 24\n"
	"  .cfi_offset %r12, -24\n"
	"  mov %rdi, %rbx\n"			/* rbx = object A */
	"  mov %rsi, %r12\n"			/* r12 = object B */
	"  mov %rdx, %rcx\n"			/* rcx = iteration count */
	"  xor %r8d, %r8d\n"
	"  xor %r9d, %r9d\n"
	"1:\n"
	"  mov 0x40(%rbx), %eax\n"		/* owner candidate */
	"  add %eax, %r8d\n"
	"  mov 0x40(%r12), %edx\n"		/* coalescable sibling candidate */
	"  add %edx, %r9d\n"
	"  dec %ecx\n"
	"  jne 1b\n"
	"  movabs $0x9e3779b97f4a7c15, %r10\n"	/* shared loop-exit post site */
	"  xor %r10d, %r8d\n"
	"  lea (%r8,%r9), %eax\n"
	"  pop %r12\n"
	"  .cfi_def_cfa_offset 16\n"
	"  pop %rbx\n"
	"  .cfi_def_cfa_offset 8\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".size coalescable_loop, .-coalescable_loop\n"
);

extern uint32_t coalescable_loop(struct rec *a, struct rec *b, uintptr_t n);

static volatile uint32_t sink;

int main(int argc, char **argv)
{
	uintptr_t n = (argc >= 2) ? strtoull(argv[1], NULL, 10) : 100000;
	if (n == 0) {
		fprintf(stderr, "iteration count must be > 0\n");
		return 2;
	}

	struct rec *a = malloc(sizeof(*a));
	struct rec *b = malloc(sizeof(*b));
	if (!a || !b) {
		perror("malloc");
		free(a);
		free(b);
		return 2;
	}

	memset(a, 0, sizeof(*a));
	memset(b, 0, sizeof(*b));
	a->field40 = 3;
	b->field40 = 5;

	uint32_t result = coalescable_loop(a, b, n);
	sink = result;

	printf("loop-exit-coalesce: iterations=%" PRIuPTR
	       " a=%u b=%u sink=0x%" PRIx32 "\n",
	       n, a->field40, b->field40, sink);

	free(a);
	free(b);
	return 0;
}

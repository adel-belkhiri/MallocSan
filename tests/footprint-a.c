#define _GNU_SOURCE

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Variant A microbench for the invariant-base footprint extension of #5.
 *
 * The faulting access lives INSIDE the loop on a loop-invariant tainted base.
 * The loop body reads TWO fixed fields from the same base: [rbx+0x40] (the
 * fault instruction) and [rbx+0x50] (a second, different displacement).
 * Under the footprint extension the forward scan should widen the footprint to
 * [0x40, 0x54) and set loop_exit_footprint=true on the entry; activation then
 * bounds-checks the full range rather than only the fault EA.
 *
 *   exit_footprint_a(p, n):
 *       push  %rbx
 *       mov   %rdi, %rbx            ; rbx = tainted heap pointer (invariant)
 *       mov   %rsi, %rcx            ; rcx = iteration count
 *   1:                              ; header
 *       .byte 0x69,0xd2,0x00,0x01,0x00,0x00   ; imul $0x100,%edx,%edx (clean prefix)
 *       mov   0x40(%rbx), %eax      ; (A) FAULT inside loop  [rbx+0x40]
 *       add   0x50(%rbx), %eax      ; (B) second field       [rbx+0x50]
 *       dec   %ecx
 *       jne   1b
 *       pop   %rbx
 *       mov   %esi, %eax
 *       ret
 *
 * Normal run: both fields in-bounds; expect one "Loop-exit deferral (Variant A)"
 * log line, loop_exit_footprint=true (visible at DW_LOG_LEVEL=3), no crash.
 *
 * OOB run ("oob"): allocate an object large enough for [rbx+0x40] but NOT for
 * [rbx+0x50].  The footprint check in dw_loop_exit_activate_context must catch
 * the OOB before stripping the base.  Look for "Out-of-bounds access detected".
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -rdynamic tests/footprint-a.c -o /tmp/footprint-a
 *
 * Run:
 *   env LD_LIBRARY_PATH=external/libolx/lib:external/libpatch/src/lib \
 *       LD_PRELOAD=$PWD/build/src/.libs/libmallocsan.so \
 *       DW_MIN_SIZE=1 DW_LOG_LEVEL=3 \
 *       /tmp/footprint-a 1000000
 *
 *   /tmp/footprint-a 1000000 oob
 */

/* Large object: both fields [+0x40] and [+0x50] are in-bounds. */
struct rec_large {
	uint8_t  pad[0x40];
	uint32_t field40;	/* offset 0x40 */
	uint8_t  gap[0x0c];
	uint32_t field50;	/* offset 0x50 */
	uint32_t tail[4];	/* ensure field50 is strictly in-bounds */
};

/* Small object: [+0x40] in-bounds, [+0x50] OOB. */
struct rec_small {
	uint8_t  pad[0x40];
	uint32_t field40;	/* offset 0x40 */
	/* ends here; [+0x50] is past the allocation */
};

__asm__(
	".text\n"
	".globl exit_footprint_a\n"
	".type exit_footprint_a,@function\n"
	"exit_footprint_a:\n"
	"  .cfi_startproc\n"
	"  push %rbx\n"
	"  .cfi_def_cfa_offset 16\n"
	"  mov %rdi, %rbx\n"				/* rbx = invariant tainted base */
	"  mov %rsi, %rcx\n"				/* rcx = iteration count */
	"1:\n"						/* header */
	"  .byte 0x69,0xd2,0x00,0x01,0x00,0x00\n"	/* imul $0x100,%edx,%edx (clean prefix) */
	"  .byte 0x8b,0x43,0x40\n"			/* (A) mov 0x40(%rbx),%eax  FAULT */
	"  .byte 0x03,0x43,0x50\n"			/* (B) add 0x50(%rbx),%eax  second field */
	"  .byte 0xff,0xc9\n"				/* dec %ecx */
	"  jne 1b\n"
	"  pop %rbx\n"
	"  .cfi_def_cfa_offset 8\n"
	"  mov %esi, %eax\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".size exit_footprint_a, .-exit_footprint_a\n"
);

extern uint32_t exit_footprint_a(void *p, uintptr_t n);

static volatile uint32_t sink;

int main(int argc, char **argv)
{
	uintptr_t n   = (argc >= 2) ? strtoull(argv[1], NULL, 10) : 1000000;
	bool      oob = (argc >= 3) && (strcmp(argv[2], "oob") == 0);

	if (n == 0) {
		fprintf(stderr, "iteration count must be > 0\n");
		return 2;
	}

	if (!oob) {
		struct rec_large *big = malloc(sizeof(*big));
		if (!big) { perror("malloc"); return 2; }
		memset(big, 0, sizeof(*big));
		big->field40 = 0xabcd;
		big->field50 = 0x1234;

		uint32_t r = exit_footprint_a(big, n);
		sink = r;
		printf("footprint-a normal: iterations=%" PRIuPTR " sink=0x%" PRIx32 "\n", n, sink);
		free(big);
	} else {
		/*
		 * OOB: object has field40 in-bounds but field50 is past the end.
		 * The footprint check [base+0x40, base+0x54) must catch it.
		 */
		struct rec_small *small = malloc(sizeof(*small));
		if (!small) { perror("malloc"); return 2; }
		memset(small, 0, sizeof(*small));
		small->field40 = 0xdead;

		uint32_t r = exit_footprint_a(small, n);
		sink = r;
		printf("footprint-a oob: sink=0x%" PRIx32 " (OOB should have been reported above)\n", sink);
		free(small);
	}

	return 0;
}

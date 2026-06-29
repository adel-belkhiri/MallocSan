#define _GNU_SOURCE

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Variant B microbench for the invariant-base footprint extension of #5.
 *
 * The faulting access lives BEFORE the loop; a similar access plus one
 * additional fixed-field access on the same invariant base live INSIDE the
 * loop.  Under the footprint extension the forward scan widens the footprint
 * to cover both in-loop displacements and sets loop_exit_footprint=true.
 * The Variant B pre-probe (dw_unprotect_context) must then bounds-check the
 * full footprint range using the TAINTED base before stripping.
 *
 *   exit_footprint_b(p, n):
 *       push  %rbx
 *       mov   %rdi, %rbx            ; rbx = tainted heap pointer (invariant)
 *       mov   %rsi, %rcx            ; rcx = iteration count
 *       mov   0x0(%rbx), %eax       ; (A) FAULT before loop  [rbx+0]
 *   1:                              ; header
 *       add   0x0(%rbx), %eax       ; (B) same field         [rbx+0]
 *       add   0x10(%rbx), %eax      ; (C) second field       [rbx+0x10]
 *       dec   %ecx
 *       jne   1b
 *       pop   %rbx
 *       mov   %esi, %eax
 *       ret
 *
 * Normal run: both fields in-bounds; expect one "Loop-exit deferral (Variant B)"
 * log line, loop_exit_footprint=true (DW_LOG_LEVEL=3), no crash.
 *
 * OOB run ("oob"): allocate an object large enough for [rbx+0] but NOT for
 * [rbx+0x10].  The footprint check in dw_unprotect_context must catch the OOB
 * using the tainted base (a clean base would make oid==0 and silently skip).
 * Look for "Out-of-bounds access detected".
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -rdynamic tests/footprint-b.c -o /tmp/footprint-b
 *
 * Run:
 *   env LD_LIBRARY_PATH=external/libolx/lib:external/libpatch/src/lib \
 *       LD_PRELOAD=$PWD/build/src/.libs/libmallocsan.so \
 *       DW_MIN_SIZE=1 DW_LOG_LEVEL=3 \
 *       /tmp/footprint-b 1000000
 *
 *   /tmp/footprint-b 1000000 oob
 */

/* Large object: both fields [+0] and [+0x10] in-bounds. */
struct rec_large {
	uint32_t field0;	/* offset 0x00 */
	uint8_t  gap[0x0c];
	uint32_t field10;	/* offset 0x10 */
	uint32_t tail[4];
};

/* Small object: [+0] in-bounds, [+0x10] OOB. */
struct rec_small {
	uint32_t field0;	/* offset 0x00 only */
	/* ends here; [+0x10] is past the allocation */
};

__asm__(
	".text\n"
	".globl exit_footprint_b\n"
	".type exit_footprint_b,@function\n"
	"exit_footprint_b:\n"
	"  .cfi_startproc\n"
	"  push %rbx\n"
	"  .cfi_def_cfa_offset 16\n"
	"  mov %rdi, %rbx\n"			/* rbx = invariant tainted base */
	"  mov %rsi, %rcx\n"			/* rcx = iteration count */
	"  .byte 0x8b,0x03\n"			/* (A) mov (%rbx),%eax  FAULT before loop */
	"1:\n"					/* header */
	"  .byte 0x03,0x03\n"			/* (B) add (%rbx),%eax  same field in loop */
	"  .byte 0x03,0x43,0x10\n"		/* (C) add 0x10(%rbx),%eax  second field */
	"  .byte 0xff,0xc9\n"			/* dec %ecx */
	"  jne 1b\n"
	"  pop %rbx\n"
	"  .cfi_def_cfa_offset 8\n"
	"  mov %esi, %eax\n"
	"  ret\n"
	"  .cfi_endproc\n"
	".size exit_footprint_b, .-exit_footprint_b\n"
);

extern uint32_t exit_footprint_b(void *p, uintptr_t n);

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
		big->field0  = 1;
		big->field10 = 2;

		uint32_t r = exit_footprint_b(big, n);
		sink = r;
		printf("footprint-b normal: iterations=%" PRIuPTR " sink=0x%" PRIx32 "\n", n, sink);
		free(big);
	} else {
		/*
		 * OOB: object has field0 in-bounds but field10 is past the end.
		 * Footprint check [base+0, base+0x14) in dw_unprotect_context must
		 * catch it using the tainted base (not base_clean).
		 */
		struct rec_small *small = malloc(sizeof(*small));
		if (!small) { perror("malloc"); return 2; }
		small->field0 = 1;

		uint32_t r = exit_footprint_b(small, n);
		sink = r;
		printf("footprint-b oob: sink=0x%" PRIx32 " (OOB should have been reported above)\n", sink);
		free(small);
	}

	return 0;
}

#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * Estimator for the loop-exit post-handler deferral (improvement #5).
 *
 * What the optimization does
 * --------------------------
 * For a loop that accesses a tainted pointer through an INVARIANT effective
 * address (fixed displacement off an unchanging base, no walking index), the
 * pre-handler (unprotect) still fires every iteration, but the post-handler
 * (reprotect) is deferred from the loop back-edge to the single loop exit. So
 * the reprotect runs once per loop ENTRY instead of once per ITERATION.
 *
 * How this benchmark estimates the win
 * ------------------------------------
 * We keep the total number of tainted stores constant (R * L) and sweep the
 * inner-loop trip count L. The store kernel below is a hand-encoded fixed-field
 * store inside a conditional back-edge, so the disassembler classifies it as a
 * loop-exit-deferral site:
 *
 *      mallocsan_loop_store(p, seed, L):
 *   1:   add  [rdi + 0x30], rsi      ; fault/patch site, base=rdi (tainted),
 *                                    ; fixed disp 0x30, no index -> invariant EA.
 *                                    ; A read-modify-write, NOT a plain mov, so it
 *                                    ; bypasses the fixed-field-mov SIGSEGV fast
 *                                    ; path and is routed through the deferrable
 *                                    ; pre/post handlers instead.
 *        add  rcx, rsi              ; mutate the VALUE reg (not the pointer)
 *        dec  rcx
 *        jne  1b                    ; conditional back-edge, target == fault
 *        ret                        ; fall-through = the deferred post site
 *
 * With deferral: post fires ~R times (once per call). ns/access therefore drops
 * as L grows, approaching the floor of (pre-handler + native) cost. Without
 * deferral the post would fire R*L times and the curve would be flat at the L=1
 * level. The difference  (ns/access @ L=1) - (ns/access @ large L)  approximates
 * the per-iteration post-handler cost that the optimization eliminates.
 *
 * Build & run
 * -----------
 *   gcc -O2 -Wall -Wextra -rdynamic tests/loop-defer-bench.c -o /tmp/loop-defer-bench
 *
 *   # native baseline (no instrumentation):
 *   /tmp/loop-defer-bench
 *
 *   # under MallocSan (the numbers that matter):
 *   env LD_PRELOAD=/home/adel/git/MallocSan2/build/src/.libs/libmallocsan.so \
 *       DW_MIN_SIZE=1 DW_LOG_LEVEL=0 \
 *       DW_STATS_ENABLED=1 DW_STATS_FILE=/tmp/loop-defer.taintstats \
 *       /tmp/loop-defer-bench
 *
 * Read the printed table: under MallocSan the ns/access column should decay as L
 * grows. (ns/access @ L=1) - (ns/access @ L=max) is the estimated win per
 * tainted access for a long deferrable loop.
 */

struct test_record {
	uintptr_t pad[6];	/* 6 * 8 = 0x30 bytes of padding */
	uintptr_t field;	/* stored at [base + 0x30] */
};

/*
 * count (rdx) must be >= 1. rdi = tainted record, rsi = seed value.
 * The memory op is emitted as raw bytes so the encoding is exactly
 *   48 01 77 30   add qword ptr [rdi + 0x30], rsi
 * A read-modify-write through a fixed field off a tainted base: invariant
 * effective address (deferral-eligible) but not a plain mov (so it skips the
 * fixed-field-mov SIGSEGV fast path and exercises the post-handler deferral).
 */
__asm__(
	".text\n"
	".globl mallocsan_loop_store\n"
	".type mallocsan_loop_store,@function\n"
	"mallocsan_loop_store:\n"
	"  .cfi_startproc\n"			/* emit .eh_frame so libunwind can
						 * resolve function bounds; without
						 * this the deferral path bails out */
	"  mov %rdx, %rcx\n"			/* rcx = trip count */
	"1:\n"
	"  .byte 0x48, 0x01, 0x77, 0x30\n"	/* add [rdi + 0x30], rsi */
	"  add %rcx, %rsi\n"			/* mutate VALUE reg (not the pointer) */
	"  dec %rcx\n"
	"  jne 1b\n"				/* conditional back-edge to the store */
	"  ret\n"
	"  .cfi_endproc\n"
	".size mallocsan_loop_store, .-mallocsan_loop_store\n"
);

extern void mallocsan_loop_store(struct test_record *p, uintptr_t seed, uintptr_t count);

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

static size_t parse_size(const char *s, const char *what)
{
	if (!s || !*s) {
		fprintf(stderr, "Invalid %s\n", what);
		exit(2);
	}

	errno = 0;
	char *end = NULL;
	unsigned long long v = strtoull(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0') {
		fprintf(stderr, "Invalid %s: '%s'\n", what, s);
		exit(2);
	}
	return (size_t)v;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [total_accesses]\n"
		"\n"
		"  total_accesses  Tainted stores per sweep row, default 200000000.\n"
		"                  Each row uses inner-loop length L and R = total/L\n"
		"                  outer calls, so every row does ~the same work.\n"
		"\n"
		"Run once natively and once under MallocSan; compare the ns/access\n"
		"column. The drop from L=1 to large L is the deferral win per access.\n",
		argv0);
}

int main(int argc, char **argv)
{
	if (argc > 2) {
		usage(argv[0]);
		return 2;
	}

	size_t total = (argc >= 2) ? parse_size(argv[1], "total_accesses") : 200000000;
	if (total == 0) {
		fprintf(stderr, "total_accesses must be > 0\n");
		return 2;
	}

	struct test_record *tainted_record = malloc(sizeof(*tainted_record));
	if (!tainted_record) {
		perror("malloc");
		return 2;
	}
	tainted_record->field = UINT64_C(0xaabbccddeeff0011);

	static const size_t inner_lengths[] = {
		1, 2, 4, 8, 16, 32, 64, 256, 1024, 4096, 16384, 65536,
	};
	const size_t nrows = sizeof(inner_lengths) / sizeof(inner_lengths[0]);

	printf("total_accesses=%zu  store site=mallocsan_loop_store [rdi+0x30]\n", total);
	printf("%-10s %-14s %-16s %-12s %-12s\n",
	       "L(inner)", "R(outer)", "accesses", "elapsed_s", "ns/access");

	uintptr_t acc = 0;
	double ns_at_l1 = 0.0, ns_at_lmax = 0.0;

	for (size_t r = 0; r < nrows; r++) {
		size_t L = inner_lengths[r];
		size_t R = total / L;
		if (R == 0)
			R = 1;
		size_t accesses = R * L;

		uintptr_t seed = UINT64_C(0x9e3779b97f4a7c15) ^ (uintptr_t)L;

		uint64_t start = now_ns();
		for (size_t i = 0; i < R; i++) {
			mallocsan_loop_store(tainted_record, seed, L);
			seed ^= tainted_record->field;
		}
		uint64_t end = now_ns();

		double elapsed_s = (double)(end - start) / 1e9;
		double ns_per_access = elapsed_s * 1e9 / (double)accesses;

		printf("%-10zu %-14zu %-16zu %-12.6f %-12.3f\n",
		       L, R, accesses, elapsed_s, ns_per_access);

		if (r == 0)
			ns_at_l1 = ns_per_access;
		ns_at_lmax = ns_per_access;
		acc += seed;
	}

	sink = acc;

	printf("\n");
	printf("ns/access @ L=%zu      : %.3f\n", inner_lengths[0], ns_at_l1);
	printf("ns/access @ L=%zu  : %.3f\n", inner_lengths[nrows - 1], ns_at_lmax);
	printf("estimated deferral win : %.3f ns per tainted access (L=1 minus L=max)\n",
	       ns_at_l1 - ns_at_lmax);
	printf("sink=0x%" PRIxPTR "\n", sink);

	free(tainted_record);
	return 0;
}

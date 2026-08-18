
#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>

#include <capstone/capstone.h>

#include "dw-backtrace.h"
#include "dw-disassembly.h"
#include "dw-exec-policy.h"
#include "dw-patch.h"
#include "dw-log.h"
#include "dw-protect.h"
#include "dw-registers.h"
#include "dw-wrap-glibc.h"

/*
 * When an instruction accesses a protected object, we need to create an entry
 * to tell us the affected registers, a buffer to emulate the instruction, and
 * an epilogue to reprotect the registers if needed.
 */
struct insn_table {
	size_t size;
	struct insn_entry *entries;
};

__thread struct insn_entry_runtime insn_rt_slots[MAX_SCAN_INST_COUNT]
	__attribute__((tls_model("initial-exec")));

__thread struct insn_entry *slot_owner[MAX_SCAN_INST_COUNT]
	__attribute__((tls_model("initial-exec")));

#define DW_RT_SLOT_BUCKETS (MAX_SCAN_INST_COUNT * 2)

/*
 * Per-thread entry -> slot index side map for the runtime slots above.
 *
 * The hot pre-handler path must answer two questions:
 *   1. does this entry already own a slot on this thread?
 *   2. if not, allocate one free slot.
 *
 * A full 256-entry scan answers both but is far too expensive on hot faults.
 * Instead we keep a tiny fixed-size hash chain keyed by insn_entry*. Each live
 * slot index is the node in one bucket chain, so lookup is O(1) expected and
 * release can unlink via the slot index it already has. No malloc, no locks,
 * and all state stays thread-local and signal-safe.
 */
static __thread int16_t rt_slot_bucket_head[DW_RT_SLOT_BUCKETS]
	__attribute__((tls_model("initial-exec")));
static __thread int16_t rt_slot_next[MAX_SCAN_INST_COUNT]
	__attribute__((tls_model("initial-exec")));
static __thread uint16_t rt_slot_free_stack[MAX_SCAN_INST_COUNT]
	__attribute__((tls_model("initial-exec")));
static __thread uint16_t rt_slot_free_top
	__attribute__((tls_model("initial-exec")));
static __thread bool rt_slot_state_ready
	__attribute__((tls_model("initial-exec")));

/*
 * One-entry memo for the hot pre/post pair. A hit is valid only while
 * slot_owner[idx] still matches, so stale or signal-interrupted updates fall
 * back to the hash chain. Publish the key last so it identifies the stored idx.
 */
static __thread struct insn_entry *rt_slot_memo_entry
	__attribute__((tls_model("initial-exec")));
static __thread int rt_slot_memo_idx
	__attribute__((tls_model("initial-exec")));

static inline void dw_rt_slot_memo_set(struct insn_entry *entry, int idx)
{
	rt_slot_memo_idx = idx;
	atomic_signal_fence(memory_order_release);
	rt_slot_memo_entry = entry;
}

/*
 * Shared loop-exit plan registry (#5 coalescing). A fixed-size linear,
 * append-only table of committed #5 exit posts, keyed on the fall-through exit
 * address. members[0] of each plan is the OWNER (it installed the physical
 * post); siblings appended later share that one post.
 *
 * WRITERS (lookup-for-election, create_owner, attach) run from patch_entry_sync.
 * That is USUALLY the single patch worker thread, but it also runs synchronously
 * on arbitrary faulting threads (worker not started, queue stopped, or a request
 * issued from the worker itself), so the table is NOT implicitly single-writer.
 * All writers therefore hold dw_le_plan_mu, and the owner/sibling election
 * (lookup -> emptiness re-check -> install -> create_owner/attach) runs as one
 * critical section under that lock, so two entries can never both own one exit.
 *
 * The READER is the owner's exit post (dw_reprotect_plan_context), which fires
 * from async-signal/trap context on arbitrary threads and MUST stay lock-free:
 * it never takes dw_le_plan_mu. It reads owner->loop_exit_plan plus nb_members
 * with acquire, paired with the writers' release stores on nb_members and
 * dw_le_plan_count, so it always observes a coherent {plan, members[]} snapshot.
 */
#define DW_LE_PLAN_MAX 512
static struct le_plan dw_le_plans[DW_LE_PLAN_MAX];
static atomic_uint dw_le_plan_count;

/*
 * Serializes the registry WRITERS only (the commit/election path). It is never
 * taken from the async-signal post-handler reader, so it cannot deadlock or
 * stall signal context. Held across a whole lookup->create/attach sequence so
 * the read-modify-write is atomic with respect to other writers.
 */
static pthread_mutex_t dw_le_plan_mu = PTHREAD_MUTEX_INITIALIZER;

DW_INTERNAL void dw_le_plan_lock(void)
{
	(void) pthread_mutex_lock(&dw_le_plan_mu);
}

DW_INTERNAL void dw_le_plan_unlock(void)
{
	(void) pthread_mutex_unlock(&dw_le_plan_mu);
}

DW_INTERNAL struct le_plan *dw_le_plan_lookup(uintptr_t exit_target)
{
	if (!exit_target)
		return NULL;

	unsigned n = atomic_load_explicit(&dw_le_plan_count, memory_order_acquire);
	for (unsigned i = 0; i < n; i++)
		if (dw_le_plans[i].exit_target == exit_target)
			return &dw_le_plans[i];
	return NULL;
}

/* Caller must hold dw_le_plan_mu (the lookup-then-append must be atomic). */
DW_INTERNAL struct le_plan *dw_le_plan_create_owner(struct insn_entry *owner,
		uintptr_t exit_target)
{
	if (!exit_target || !owner)
		return NULL;

	struct le_plan *existing = dw_le_plan_lookup(exit_target);
	if (existing)
		return existing; /* idempotent: owner already registered */

	unsigned n = atomic_load_explicit(&dw_le_plan_count, memory_order_acquire);
	if (n >= DW_LE_PLAN_MAX)
		return NULL; /* registry full: caller keeps its own per-iteration post */

	struct le_plan *plan = &dw_le_plans[n];
	plan->exit_target = exit_target;
	plan->members[0] = owner;
	/* Publish the owner (members[0]) before the post becomes reachable. */
	atomic_store_explicit(&plan->nb_members, 1, memory_order_release);
	owner->loop_exit_plan = plan;
	/* Publish the plan slot last so a reader that sees the new count also sees
	 * a fully-initialized exit_target/members[0]. */
	atomic_store_explicit(&dw_le_plan_count, n + 1, memory_order_release);
	return plan;
}

/* Caller must hold dw_le_plan_mu. */
DW_INTERNAL bool dw_le_plan_attach(struct le_plan *plan, struct insn_entry *sibling)
{
	if (!plan || !sibling)
		return false;

	unsigned m = atomic_load_explicit(&plan->nb_members, memory_order_acquire);
	if (m >= DW_LE_PLAN_MAX_MEMBERS)
		return false; /* plan full: caller falls back to its own post */

	plan->members[m] = sibling;
	/* Publish the new member after its slot is written so the owner's post,
	 * reading nb_members with acquire, never sees a half-written members[]. */
	atomic_store_explicit(&plan->nb_members, m + 1, memory_order_release);
	return true;
}

struct capstone_context {
	csh handle;
	cs_insn *insn;
	bool ready;
};

__thread struct capstone_context cs_ctx
	__attribute__((tls_model("initial-exec")));
static pthread_key_t cs_key;
static pthread_once_t cs_key_once = PTHREAD_ONCE_INIT;

static void capstone_context_cleanup(void *arg)
{
	(void) arg;
	if (!cs_ctx.ready)
		return;
	cs_free(cs_ctx.insn, 1);
	cs_close(&cs_ctx.handle);
	cs_ctx.ready = false;
}

static void dw_capstone_make_key(void)
{
	pthread_key_create(&cs_key, capstone_context_cleanup);
}

static inline struct capstone_context *capstone_get_context(void)
{
	pthread_once(&cs_key_once, dw_capstone_make_key);

	if (!cs_ctx.ready) {
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_ctx.handle) != CS_ERR_OK)
			DW_LOG(ERROR, DISASSEMBLY, "cs_open failed!\n");

		cs_option(cs_ctx.handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_ctx.insn = cs_malloc(cs_ctx.handle);
		if (!cs_ctx.insn) {
			cs_close(&cs_ctx.handle);
			DW_LOG(ERROR, DISASSEMBLY, "cs_malloc failed!\n");
		}
		cs_ctx.ready = true;
		pthread_setspecific(cs_key, (void *)1);
	}
	return &cs_ctx;
}

/*
 * True if the instruction at `addr` is already an INT3/JMP fill (a live patch
 * post) or is undecodable -- i.e. the exit is NOT a safe, empty owner-install
 * site. Decodes a single instruction with the thread's capstone context. Called
 * by the commit-time election (under dw_le_plan_mu) to refuse installing an
 * owner post on top of an occupied exit, which removes all dependence on
 * libpatch's same-address patch_make semantics.
 */
DW_INTERNAL bool dw_exit_is_filled(uintptr_t addr)
{
	if (!addr)
		return true;

	struct capstone_context *cs = capstone_get_context();
	const uint8_t *code = (const uint8_t *) addr;
	uint64_t iaddr = addr;
	size_t buf = 15; /* max x86 instruction length */

	if (!cs_disasm_iter(cs->handle, &code, &buf, &iaddr, cs->insn))
		return true;

	return cs->insn->id == X86_INS_INT3 || cs->insn->id == X86_INS_JMP;
}

static inline void add_post_safe_site(struct post_safe_site_rb *rb, uintptr_t addr, uint16_t size, unsigned skipped_same_access, bool trap_ok)
{
	/*
	 * A trap_ok site is patched with a 1-byte int3 (TRAP) post and therefore
	 * does not need the jump-class minimum size; bypass the size filter for it.
	 */
	if (!rb || (!trap_ok && size < DW_MIN_SAFE_CANDIDATE_SIZE))
		return;

	unsigned idx;
	if (rb->count < MAX_SAFE_SITE_COUNT) {
		idx = (rb->head + rb->count) % MAX_SAFE_SITE_COUNT;
		rb->count++;
	} else {
		idx = rb->head;
		rb->head = (rb->head + 1) % MAX_SAFE_SITE_COUNT;
	}

	rb->entries[idx].addr = addr;
	rb->entries[idx].skipped_same_access = skipped_same_access;
	rb->entries[idx].trap_ok = trap_ok;
}

/*
 * Drop every recorded safe site whose address is at or beyond `header`.
 *
 * The forward scan records candidate addresses monotonically, so in-loop sites
 * (addr >= header) are exactly the most-recently-added entries and form a
 * contiguous run at the tail of the ring buffer. Trimming the tail (decrement
 * `count` while the newest entry is in-loop) is therefore sufficient and also
 * removes the loop latch itself if Section 1 happened to record it. Used by the
 * loop-header clamp so make_deferred_post falls back to the newest pre-header
 * site (or the caller's no-site AROUND fallback) instead of a per-iteration
 * in-loop post.
 */
static inline void prune_post_safe_sites_from(struct post_safe_site_rb *rb, uintptr_t header)
{
	if (!rb)
		return;

	while (rb->count > 0) {
		unsigned idx = (rb->head + rb->count - 1) % MAX_SAFE_SITE_COUNT;
		if (rb->entries[idx].addr < header)
			break;
		rb->count--;
	}
}

static inline size_t hash_addr(uintptr_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	return (size_t)x;
}

static inline size_t get_pow2(size_t x)
{
	return 1ULL << (64 - __builtin_clzl(x - 1));
}

static inline void dw_init_runtime_slot_state(void)
{
	if (rt_slot_state_ready)
		return;

	for (int i = 0; i < DW_RT_SLOT_BUCKETS; ++i)
		rt_slot_bucket_head[i] = -1;

	for (int i = 0; i < MAX_SCAN_INST_COUNT; ++i) {
		rt_slot_next[i] = -1;
		rt_slot_free_stack[i] = (uint16_t)(MAX_SCAN_INST_COUNT - 1 - i);
	}

	rt_slot_free_top = MAX_SCAN_INST_COUNT;
	rt_slot_state_ready = true;
}

static inline size_t dw_runtime_slot_bucket(const struct insn_entry *entry)
{
	return hash_addr((uintptr_t)entry) % DW_RT_SLOT_BUCKETS;
}

static inline bool dw_find_runtime_slot(struct insn_entry *entry, int *idx_out);

/*
 * Allocate the instruction hash table and initialize libcapstone.
 */
instruction_table *dw_init_instruction_table(size_t size)
{
	instruction_table *table = malloc(sizeof(instruction_table));
	// have a hash table about twice as large, and a power of two
	table->size = get_pow2(2 * size);
	table->entries = calloc(table->size, sizeof(struct insn_entry));

	return table;
}

/*
 * Deallocate the instruction hash table and close libcapstone.
 */
void dw_fini_instruction_table(instruction_table *table)
{
	free(table->entries);
	free(table);
}

/*
 * Wait for the thread that owns an ENTRY_INITIALIZING slot to publish it.
 *
 * The creator holds ENTRY_INITIALIZING across the whole of handle_seg_fault(),
 * which includes the blocking round-trip to the patch worker in
 * dw_patch_entry(). A plain `while (state == ENTRY_INITIALIZING);` therefore
 * burns a full core per waiting thread for the entire duration of a patch --
 * and on an oversubscribed machine those spinners actively starve the worker
 * they are waiting for, turning a slow patch into a livelock.
 *
 * Spin briefly (the common case: the creator is running on another core and
 * publishes within a few hundred cycles), then yield. We do not bound the wait
 * and give up: returning NULL means "no entry for this instruction", which
 * forwards the fault to the saved handler and usually kills the process. Making
 * the wait cooperative is what keeps a stalled creator survivable; making it
 * *terminate* is dw-patch.c's job (see the fork handlers there).
 *
 * Both callers run in signal context. __builtin_ia32_pause() is a bare PAUSE
 * instruction and sched_yield() is async-signal-safe, so this is too.
 */
#define DW_ENTRY_SPIN_BEFORE_YIELD 256

static int dw_await_entry_ready(struct insn_entry *e)
{
	unsigned spins = 0;
	int state;

	for (;;) {
		state = atomic_load_explicit(&e->state, memory_order_acquire);
		if (state != ENTRY_INITIALIZING)
			return state;

		if (spins < DW_ENTRY_SPIN_BEFORE_YIELD) {
			spins++;
			__builtin_ia32_pause();
		} else {
			(void) sched_yield();
		}
	}
}

/*
 * Get the entry for this instruction address.
 */
struct insn_entry *dw_get_instruction_entry(instruction_table *table, uintptr_t fault)
{
	size_t mask   = table->size - 1;
	size_t start  = hash_addr(fault) & mask;
	size_t cursor = start;

	while (1) {
		struct insn_entry *e = &table->entries[cursor];
		int state = atomic_load_explicit(&e->state, memory_order_acquire);

		if (state == ENTRY_EMPTY)
			return NULL;

		if (state == ENTRY_INITIALIZING) {
			state = dw_await_entry_ready(e);

			if (state == ENTRY_EMPTY)
				return NULL;
		}

		if (e->insn == fault)
			return (state == ENTRY_READY) ? e : NULL;

		cursor = (cursor + 1) & mask;
		if (cursor == start)
			break;
	}
	return NULL;
}

static inline bool dw_acquire_runtime_slot(struct insn_entry *entry, int *idx_out)
{
	dw_init_runtime_slot_state();

	if (dw_find_runtime_slot(entry, idx_out))
		return true;

	if (rt_slot_free_top > 0) {
		int idx = rt_slot_free_stack[--rt_slot_free_top];
		size_t bucket = dw_runtime_slot_bucket(entry);

		slot_owner[idx] = entry;
		rt_slot_next[idx] = rt_slot_bucket_head[bucket];
		rt_slot_bucket_head[bucket] = (int16_t)idx;
		dw_rt_slot_memo_set(entry, idx);
		*idx_out = idx;
		return true;
	}

	// Out of slots
	DW_LOG(ERROR, DISASSEMBLY, "Runtime slots shouldn't be exhausted!\n");
	return false;
}

static inline bool dw_find_runtime_slot(struct insn_entry *entry, int *idx_out)
{
	if (!rt_slot_state_ready || !entry)
		return false;

	/* Read the published key first, then validate its index against the owner. */
	struct insn_entry *memo = rt_slot_memo_entry;
	atomic_signal_fence(memory_order_acquire);
	if (memo == entry) {
		int idx = rt_slot_memo_idx;
		if (idx >= 0 && idx < MAX_SCAN_INST_COUNT && slot_owner[idx] == entry) {
			if (idx_out)
				*idx_out = idx;
			return true;
		}
	}

	size_t bucket = dw_runtime_slot_bucket(entry);
	for (int idx = rt_slot_bucket_head[bucket]; idx >= 0; idx = rt_slot_next[idx]) {
		if (slot_owner[idx] == entry) {
			if (idx_out)
				*idx_out = idx;
			dw_rt_slot_memo_set(entry, idx);
			return true;
		}
	}

	return false;
}

static inline void dw_release_rt_slot(int idx)
{
	if (idx < 0 || idx >= MAX_SCAN_INST_COUNT)
		return;

	dw_init_runtime_slot_state();

	struct insn_entry *entry = slot_owner[idx];
	if (!entry)
		return;

	/* Drop the memo if it named this slot, so no later hit trusts a freed idx. */
	if (rt_slot_memo_idx == idx)
		rt_slot_memo_entry = NULL;

	size_t bucket = dw_runtime_slot_bucket(entry);
	int16_t *link = &rt_slot_bucket_head[bucket];

	while (*link >= 0) {
		if (*link == idx) {
			*link = rt_slot_next[idx];
			rt_slot_next[idx] = -1;
			slot_owner[idx] = NULL;
			rt_slot_free_stack[rt_slot_free_top++] = (uint16_t)idx;
			return;
		}
		link = &rt_slot_next[*link];
	}

	DW_LOG(ERROR, DISASSEMBLY, "Runtime slot %d missing from side map\n", idx);
	rt_slot_next[idx] = -1;
	slot_owner[idx] = NULL;
	rt_slot_free_stack[rt_slot_free_top++] = (uint16_t)idx;
}

/*
 * Is that register in the list or registers modified by the instruction?
 * There is a lot of aliasing between registers, e.g. al, ax, eax, rax,
 * all refer to the same register or portion thereof.
 */
static bool dw_reg_written(struct insn_entry *entry, unsigned reg)
{
	const struct reg_entry *re = dw_get_reg_entry(reg);
	if (!re)
		return false;

	int canon_index = re->canonical_index;
	for (int i = 0; i < entry->gregs_write_count; i++) {
		if (dw_get_reg_entry(entry->gregs_written[i])->canonical_index == canon_index)
			return true;
	}

	return false;
}

static bool dw_reg_si_di(struct insn_entry *entry, unsigned reg)
{
	if ((reg == X86_REG_RSI || reg == X86_REG_RDI) && entry->repeat)
		return true;
	else
		return false;
}

/*
 * Check if the instruction, indirectly, overwrites a register.
 */
static inline bool is_reg_zeroing(const cs_insn *insn)
{
	if (insn->id != X86_INS_XOR && insn->id != X86_INS_PXOR && insn->id != X86_INS_SUB)
		return false;

	const cs_x86 *x = &insn->detail->x86;
	return x->op_count == 2 && x->operands[0].type == X86_OP_REG &&
		   x->operands[1].type == X86_OP_REG &&
		   x->operands[0].reg == x->operands[1].reg;
}

static inline bool reg_check_access(uint32_t reg, const uint16_t *regs, uint8_t count)
{
	const struct reg_entry *re = dw_get_reg_entry(reg);
	if (!re)
		return false;

	int reg_canon_idx = re->canonical_index;

	for (uint8_t i = 0; i < count; i++)
		if (dw_get_reg_entry(regs[i])->canonical_index == reg_canon_idx)
			return true;

	return false;
}

static inline void reg_set_add(uint16_t *list, uint8_t *count, size_t cap, uint16_t reg)
{
	const struct reg_entry *re = dw_get_reg_entry(reg);
	if (!re || *count >= cap)
		return;

	int reg_canon_idx = re->canonical_index;
	if (reg_canon_idx == X86_REG_INVALID)
		return;

	for (uint8_t i = 0; i < *count; i++) {
		re = dw_get_reg_entry(list[i]);
		if (re && re->canonical_index == reg_canon_idx)
			return;
	}

	list[*count] = reg;
	(*count)++;
}

static inline bool reg_is_overwritten(uint32_t reg, uint8_t op_access, const uint16_t *regs_written,
								   uint8_t write_count)
{
	if (reg == X86_REG_INVALID)
		return false;

	bool written = (op_access & CS_AC_WRITE) || reg_check_access(reg, regs_written, write_count);
	if (!written)
		return false;

	bool data_read = (op_access & CS_AC_READ) != 0;
	return !data_read;
}

static inline bool base_index_overwritten(const cs_insn *insn,
										  const struct insn_entry *entry,
										  const struct insn_entry_runtime *entry_rt,
										  unsigned idx)
{
	const struct memory_arg *m = &entry->arg_m[idx];
	const struct memory_arg_runtime *m_rt = &entry_rt->arg_m[idx];
	bool is_vsib = reg_is_avx(m->index);

	bool base_overwritten = true;
	bool index_overwritten = true;

	bool is_xadd_xchg = insn && (insn->id == X86_INS_XCHG || insn->id == X86_INS_XADD);

	// Base
	if (m_rt->base_taint && m->base != X86_REG_INVALID) {
		base_overwritten = false;
		if (is_xadd_xchg && (m->base_access & CS_AC_WRITE))
			base_overwritten = true; // override (xadd/xchg overwrite reg operand)
		else
			base_overwritten = reg_is_overwritten(m->base, m->base_access, entry->gregs_written,
											   entry->gregs_write_count);
	}

	// Index
	if (m->index != X86_REG_INVALID) {
		bool idx_tainted = (!is_vsib && m_rt->index_taint) ||
						   (is_vsib && m_rt->index_is_tainted);

		if (idx_tainted) {
			index_overwritten = false;
			if (is_xadd_xchg && (m->index_access & CS_AC_WRITE))
				index_overwritten = true;
			else
				index_overwritten = reg_is_overwritten(m->index, m->index_access, entry->gregs_written,
												   entry->gregs_write_count);
		}
	}

	return base_overwritten && index_overwritten;
}

static inline uint8_t vsib_index_width(x86_insn id)
{
	switch (id)
	{
	/* Gather/Scatter: 32-bit indices */
	case X86_INS_VGATHERDPS:
	case X86_INS_VGATHERDPD:
	case X86_INS_VPGATHERDD:
	case X86_INS_VPGATHERDQ:
	case X86_INS_VSCATTERDPS:
	case X86_INS_VSCATTERDPD:
		return 4;

	/* Gather/Scatter: 64-bit indices */
	case X86_INS_VGATHERQPS:
	case X86_INS_VGATHERQPD:
	case X86_INS_VPGATHERQD:
	case X86_INS_VPGATHERQQ:
	case X86_INS_VSCATTERQPS:
	case X86_INS_VSCATTERQPD:
		return 8;

	/* Not a VSIB instruction, but we must not forget prefetch instructions */
	default:
		DW_LOG(ERROR, DISASSEMBLY, "Instruction %u is not a Gather/Scatter VSIB instruction\n", id);
		return 0;
	}
}

/*
 * REPE/REPNE CMPS/SCAS stop on a data condition, so the RCX prefix count is
 * only an upper bound on the number of iterations (unlike REP MOVS/STOS, which
 * always run exactly RCX times). Bounds checks must not assume the full count.
 */
static inline bool instruction_is_rep_conditional(unsigned id)
{
	switch (id) {
	case X86_INS_CMPSB: case X86_INS_CMPSW: case X86_INS_CMPSD: case X86_INS_CMPSQ:
	case X86_INS_SCASB: case X86_INS_SCASW: case X86_INS_SCASD: case X86_INS_SCASQ:
		return true;
	default:
		return false;
	}
}

/*
 * This function is used for deferring the post-handler. It checks if the memory
 * access is similar to the one in the entry. The base and index registers must
 * match, but the displacement, scale, and length can be different. In the latter
 * case, we check that the resulting address is within bounds.
 *
 * base_delta / index_delta carry the net constant adjustment applied to the
 * base/index register since the fault, accumulated by the forward scan when it
 * steps over `add/sub/inc/dec reg, imm` (improvement: constant pointer walk).
 * The register's live value at this access is therefore m_rt->base_addr +
 * base_delta (resp. index), so the deltas are folded into the effective-address
 * computation below. A non-zero delta also disqualifies the fast path: even an
 * identical addressing form now resolves to a different (shifted) address than
 * the one validated at fault time, so it must take the bounds-checked slow path.
 */
static bool similar_memory_access(unsigned int ins_id, const cs_x86_op *arg,
		const struct memory_arg *m, const struct memory_arg_runtime *m_rt, ucontext_t *uctx, bool repeat,
		int64_t base_delta, int64_t index_delta)
{
	uintptr_t addr;

	/*
	 * Never defer across a REP-prefixed conditional scan (REPE/REPNE
	 * CMPS/SCAS). Its extent is data-dependent (RCX is only an upper bound),
	 * so it can only be validated by a post-execution extent check on its
	 * own entry. If it were stepped over here, it would run with an
	 * already-unprotected pointer and no post hook, reading past the object
	 * undetected. Returning false stops the scan: the pointer is retainted
	 * before this instruction, which then faults and is handled as its own
	 * entry. (Checked before the addressing-mode test below, which would
	 * otherwise wave it through via the fast path.)
	 */
	if (repeat && instruction_is_rep_conditional(ins_id))
		return false;

	/* Fast path: same addressing mode (base/index/scale/disp) and size. */
	if (arg->mem.base != m->base || arg->mem.index != m->index)
		return false;

	/*
	 * LEA instructions compute a new pointer from a (possibly tainted) base/index register
	 * without performing a memory access. When the pre-handler has already unprotected the
	 * base/index register, an instruction like `lea rX, [rY + z]` produces a new, untagged
	 * alias in rX. This alias can then escape the post-handler’s taint-tracking logic.
	 */
	if (ins_id == X86_INS_LEA)
		return false;

	if (base_delta == 0 && index_delta == 0 &&
	    arg->mem.scale == m->scale &&
	    arg->mem.disp  == m->displacement &&
	    arg->size      == m->length)
		return true;

	/*
	 * Slow path: recompute the effective addresses for the new memory
	 * access and check that they stay within the bounds of the original
	 * protected object.
	 *
	 * TODO: For now, we do not check similar accesses for VSIB instructions.
	 */
	if (reg_is_avx(m->index))
		return false;

	/*
	 * SIB case: base + index * scale + disp.
	 */
	uintptr_t index_addr = (m->index != X86_REG_INVALID)
				       ? m_rt->index_addr + (uintptr_t)index_delta : 0;

	addr = m_rt->base_addr + (uintptr_t)base_delta +
	       index_addr * arg->mem.scale + arg->mem.disp;

	uint64_t count = 0;
	bool df = false;
	if (repeat) {
		count = dw_get_register(uctx, dw_get_reg_entry(X86_REG_RCX)->ucontext_index);
		df = (uctx->uc_mcontext.gregs[REG_EFL] & DW_EFLAGS_DF) != 0;
	}

	uintptr_t check_addr;
	size_t check_size;
	/* Conditional REP scans were already rejected above, so any repeat that
	 * reaches here is unconditional (an exact RCX-count access). */
	string_access_range(addr, arg->size, count, repeat, false, df,
			       &check_addr, &check_size);

	/* Size 0 (REP with RCX==0) means no access: trivially within bounds. */
	if (check_size == 0)
		return true;

	return dw_check_access((void *) check_addr, check_size);
}

#define UNW_LOCAL_ONLY
#include <libunwind.h>

static bool get_function_bounds(uintptr_t ip, uintptr_t *start, uintptr_t *end)
{
	if (!start || !end)
		return false;

	unw_proc_info_t pi;
	int ret = unw_get_proc_info_by_ip(unw_local_addr_space, (unw_word_t)ip, &pi, NULL);
	if (ret != 0)
		return false;

	*start = (uintptr_t)pi.start_ip;
	*end = (uintptr_t)pi.end_ip;

	if (*start == 0 || *end == 0 || *end <= *start)
		return false;

	return true;
}

/*
 * Upper bound on the magnitude of an accumulated constant pointer-walk delta the
 * forward scan will track. Real constant adjustments (`add p, 8`, page strides)
 * are tiny; this cap exists only to keep base_addr + delta far from wrapping the
 * object-id field in bits 48-63 of a tainted pointer. Well beyond any plausible
 * in-window walk, nowhere near the 48-bit boundary. Exceeding it stops tracking
 * (the instruction then takes the normal reg-modified stop), which is safe.
 */
#define DW_MAX_PTR_WALK_DELTA (1LL << 30)

/*
 * Return the accumulated constant delta tracked for `reg` (matched by canonical
 * register index against the tainted-register set), or 0 when `reg` is not a
 * tracked tainted register. `deltas` is parallel to `regs`.
 */
static inline int64_t reg_tracked_delta(uint32_t reg, const uint16_t *regs,
					const int64_t *deltas, uint8_t count)
{
	const struct reg_entry *re = dw_get_reg_entry(reg);
	if (!re)
		return 0;

	int canon = re->canonical_index;
	for (uint8_t i = 0; i < count; i++)
		if (dw_get_reg_entry(regs[i])->canonical_index == canon)
			return deltas[i];

	return 0;
}

/*
 * Recognize a width-64 constant adjustment of a single tracked tainted register:
 * `add reg, imm`, `sub reg, imm`, `inc reg`, `dec reg`. On a match, *reg_out is
 * the adjusted register and *adj_out the signed constant added to it. Such an
 * instruction creates no new alias and performs no memory access; the scan can
 * step over it by folding `adj_out` into that register's running delta and
 * validating subsequent same-object accesses against the shifted address.
 *
 * Strict gating keeps it sound:
 *   - exactly the listed opcodes;
 *   - destination operand is a 64-bit register (a 32-bit form would zero-extend
 *     and truncate the high object-id bits, destroying the tag);
 *   - that register is in the tainted set;
 *   - for add/sub the source is an immediate (no register/memory term, so the
 *     adjustment is a compile-time constant known here at scan time).
 */
static bool const_adjust_of_tainted_reg(const cs_insn *insn,
					const uint16_t *tainted_regs,
					uint8_t tainted_regs_count,
					uint32_t *reg_out, int64_t *adj_out)
{
	const cs_x86 *x = &insn->detail->x86;
	const cs_x86_op *dst = &x->operands[0];
	int64_t adj;

	switch (insn->id) {
	case X86_INS_ADD:
	case X86_INS_SUB:
		if (x->op_count != 2 || x->operands[1].type != X86_OP_IMM)
			return false;
		adj = (insn->id == X86_INS_SUB) ? -x->operands[1].imm
						: x->operands[1].imm;
		break;
	case X86_INS_INC:
		if (x->op_count != 1)
			return false;
		adj = 1;
		break;
	case X86_INS_DEC:
		if (x->op_count != 1)
			return false;
		adj = -1;
		break;
	default:
		return false;
	}

	/* Destination must be a full 64-bit register, else the tag is truncated. */
	if (dst->type != X86_OP_REG || dst->size != 8)
		return false;

	if (!reg_check_access(dst->reg, tainted_regs, tainted_regs_count))
		return false;

	*reg_out = dst->reg;
	*adj_out = adj;
	return true;
}

/*
 * A memory operand is provably non-heap when its effective address cannot carry
 * a tainted (OID-tagged) heap pointer. MallocSan taints only heap pointers, so
 * such an access can never raise a guard fault:
 *   - FS/GS segment override: thread-local / segment storage.
 *   - RIP-relative: a fixed link-time global/static address.
 *   - RSP-relative with no index: the stack.
 * %rbp is deliberately NOT accepted as a stack base: under -fomit-frame-pointer
 * it is a general-purpose register that may hold a tainted pointer. Any operand
 * carrying an index register is rejected conservatively (the index itself could
 * hold a tainted pointer).
 */
static bool mem_operand_is_non_heap(const cs_x86_op *op)
{
	if (op->mem.segment == X86_REG_FS || op->mem.segment == X86_REG_GS)
		return true;
	if (op->mem.base == X86_REG_RIP)
		return true;
	if (op->mem.base == X86_REG_RSP && op->mem.index == X86_REG_INVALID)
		return true;
	return false;
}

/*
 * True if executing this instruction could raise a heap guard fault, i.e. it
 * dereferences memory through an address that may hold a tainted heap pointer.
 * Used to decide whether the instruction is a valid post-handler (retaint)
 * site: a fault-free instruction can host a probe even though it touches memory.
 * LEA and the multi-byte NOP decode with a memory operand but never dereference
 * it; an instruction whose every memory operand is provably non-heap (see
 * mem_operand_is_non_heap) is likewise fault-free.
 */
static bool insn_can_heap_fault(const cs_insn *insn, const cs_x86 *x86)
{
	if (insn->id == X86_INS_LEA || insn->id == X86_INS_NOP)
		return false;

	for (int i = 0; i < x86->op_count; i++) {
		const cs_x86_op *op = &x86->operands[i];
		if (op->type == X86_OP_MEM && !mem_operand_is_non_heap(op))
			return true;
	}
	return false;
}

/*
 * Variant A loop-exit defer site (#5). The caller has established gates (1)-(3):
 * `latch` is a conditional Jcc (not JMP/CALL/RET/INT3) with an immediate target,
 * and the backward target `header` lies inside the function with
 * header <= fault < latch (the header ENCLOSES the fault).
 *
 * Applies the remaining gates and, on success, returns the loop's fall-through
 * exit address (latch + latch_size) with its instruction size in *exit_size_out.
 * Returns 0 on any gate failure (the caller then leaves today's per-iteration
 * behavior in place).
 *
 * cs->insn is clobbered (prefix and exit re-decode); the caller goes to
 * stop_return and never reads the latch insn again.
 */
static uintptr_t loop_exit_defer_site(struct insn_entry *entry,
				      struct capstone_context *cs,
				      cs_insn *latch,
				      cs_regs latch_read, uint8_t latch_read_count,
				      cs_regs latch_write, uint8_t latch_write_count,
				      uint16_t *tainted_regs, int64_t *tainted_delta,
				      uint8_t tainted_regs_count,
				      uintptr_t func_end,
				      uintptr_t fault, uintptr_t header,
				      bool loop_exit_eligible, bool ea_has_index,
				      uint16_t *exit_size_out, bool *exit_filled_out)
{
	uintptr_t latch_end = latch->address + latch->size;

	*exit_filled_out = false;

	/*
	 * (4) Exact-EA footprint: a single non-indexed memory operand that is not a
	 * base-as-value case and not REP/string, and every accepted body access an
	 * exact replay of the fault EA. This reduces activation to a plain base
	 * strip + dw_check_access, matching the normal pre-handler's side effects,
	 * and guarantees the one per-entry bounds check covers the whole body.
	 *
	 * NOTE(indexed-EA, MEASURED 2026-06-26 on x264 625.x264_s @128x72/100f):
	 * ea_has_index rejects ALL indexed EAs. A read-only classifier (DW_LXIDX_DEBUG,
	 * since removed) bucketed every loop-exit candidate that passes the other gate-4
	 * subconditions and is blocked ONLY by ea_has_index, weighting each bucket by
	 * dynamic hit_count (108.1M total faults; indexed EAs = 73.7M = 68%):
	 *   - tagged pointer in the INDEX slot (the shape worth a base-style strip):
	 *     0 sites / 0 hits. It simply does not occur here.
	 *   - tagged INVARIANT base + a CLEAN index that is loop-invariant (fixed EA,
	 *     genuinely recoverable by the single per-entry check): 9 sites / 14,181
	 *     hits = 0.013% of faults -- three orders below the noise floor.
	 *   - tagged INVARIANT base + a CLEAN index that is an induction variable
	 *     (walking EA): 103 sites / 18.07M hits = 16.7% of faults. This is the bulk,
	 *     and it is RANGE-HOIST territory (a per-element range), NOT loop-exit
	 *     single-check territory -- it must stay rejected here.
	 * VERDICT: do NOT extend loop-exit deferral to indexed EAs. The recoverable
	 * subset is ~0.013%; the only sizeable indexed population is walking-index pixel
	 * gathers already owned by the range-hoist substrate. If ever revisited, the
	 * admissible predicate must be EXACT (lax => false-negative OOB): tag in
	 * tainted_regs, delta==0, scale==1 (scale!=1 corrupts the high-bit OID tag), and
	 * EVERY other addressing reg (incl. a CLEAN base/index, which is NOT delta-
	 * tracked today) proven loop-invariant. Touch points: this gate, the exact-EA
	 * test (relax index==INVALID), the activation strip + full-EA dw_check_access,
	 * and the deferred post's retaint (index_taint).
	 */
	if (entry->nb_arg_m != 1 || ea_has_index || entry->repeat ||
	    entry->arg_m[0].base_access || !loop_exit_eligible)
		return 0;

	/* (5) The latch must not itself read or write the tainted base. */
	for (unsigned i = 0; i < tainted_regs_count; i++)
		if (reg_check_access(tainted_regs[i], latch_read, latch_read_count) ||
		    reg_check_access(tainted_regs[i], latch_write, latch_write_count))
			return 0;

	/* (6) Base must be loop-invariant (no tracked constant pointer walk). */
	for (unsigned i = 0; i < tainted_regs_count; i++)
		if (tainted_delta[i] != 0)
			return 0;

	/*
	 * (6b) No in-body call can precede the latch: the forward scan's Section 1
	 * stop fires on any call/branch/ret, so reaching the latch already proves
	 * the scanned body [fault, latch) is single-exit straight-line code. No
	 * explicit call gate is needed (review 4).
	 */

	/* (7) The fall-through exit must lie inside the function. */
	if (latch_end >= func_end)
		return 0;

	/*
	 * (8) The prefix [header, fault) is never covered by the forward scan.
	 * Re-decode it and reject anything that could transfer control, read or
	 * write a tainted register, or dereference memory through a tainted
	 * base/index. cs_regs_access' regs_read/write include addressing base+index
	 * registers, so a tainted reg used as a prefix index is covered by the
	 * tainted-reg check; the explicit mem-operand scan is belt-and-braces.
	 */
	if (header < fault) {
		const uint8_t *pcode = (const uint8_t *) header;
		uint64_t paddr = header;
		size_t pbuf = (size_t)(fault - header);

		while (paddr < fault && pbuf > 0) {
			if (!cs_disasm_iter(cs->handle, &pcode, &pbuf, &paddr, cs->insn))
				return 0;

			cs_insn *pin = cs->insn;
			cs_detail *pdet = pin->detail;
			cs_x86 *px86 = &pdet->x86;

			for (int g = 0; g < pdet->groups_count; g++)
				if (pdet->groups[g] < X86_GRP_VM)
					return 0;

			cs_regs pr, pw;
			uint8_t prc = 0, pwc = 0;
			if (cs_regs_access(cs->handle, pin, pr, &prc, pw, &pwc) != CS_ERR_OK)
				return 0;
			for (unsigned i = 0; i < tainted_regs_count; i++)
				if (reg_check_access(tainted_regs[i], pr, prc) ||
				    reg_check_access(tainted_regs[i], pw, pwc))
					return 0;

			for (int i = 0; i < px86->op_count; i++) {
				const cs_x86_op *op = &px86->operands[i];
				if (op->type != X86_OP_MEM)
					continue;
				if (reg_check_access(op->mem.base, tainted_regs, tainted_regs_count) ||
				    reg_check_access(op->mem.index, tainted_regs, tainted_regs_count))
					return 0;
			}
		}
	}

	/*
	 * (9) Locate the retaint site on the fall-through path. It must NOT itself
	 * dereference a heap pointer: a post-only probe relocates its host into the
	 * OLX buffer, and if that host later faults on any tainted pointer we cannot
	 * add the pre-strip as an overlap child -- libpatch rejects a child on the
	 * patch head (region_idx == 0), forcing a per-iteration single-step. So we
	 * apply the SAME safe-site predicate as the regular forward scan
	 * (insn_can_heap_fault): only an instruction whose every memory operand is
	 * provably non-heap (stack/global/segment, or LEA/NOP) can host the post.
	 *
	 * Mirroring the regular scan, a heap-faulting instruction that does not
	 * touch this deferral's tainted base is SKIPPED (it faults and is patched on
	 * its own) and we keep scanning to the first provably-non-heap instruction.
	 * The scan stops at:
	 *   - a control transfer (no safe site reachable on the fall-through);
	 *   - a patch fill (INT3/JMP) -- reported as a filled site so the commit
	 *     path can coalesce onto an existing post or decline under the lock;
	 *   - a read or write of the tainted base (the strip must outlive the loop,
	 *     so the retaint cannot be deferred past a use of the base).
	 *
	 * The chosen site is the first non-heap instruction reachable by skipping
	 * heap-faulting ones; both conditions are base-independent, so every member
	 * of one loop converges on the same address and the shared-exit coalescing
	 * key (loop_exit_target) is preserved. The base-use check only decides
	 * whether THIS member may join -- it never shifts the site.
	 *
	 * We do NOT decide owner-vs-sibling here: that election is made at commit
	 * time under dw_le_plan_mu on a serialized writer (deciding it on a faulting
	 * thread was the old double-owner soundness hole). *exit_filled_out is
	 * advisory; commit re-checks exit emptiness under the lock.
	 */
	const uint8_t *ecode = (const uint8_t *) latch_end;
	uint64_t eaddr = latch_end;
	size_t ebuf = (size_t)(func_end - latch_end);

	for (unsigned escan = 0; escan < DW_LE_EXIT_SCAN_MAX && ebuf > 0; escan++) {
		if (!cs_disasm_iter(cs->handle, &ecode, &ebuf, &eaddr, cs->insn))
			return 0; /* undecodable on the fall-through path */

		cs_insn *ein = cs->insn;
		cs_detail *edet = ein->detail;
		cs_x86 *ex86 = &edet->x86;

		/*
		 * A patch fill (INT3/JMP, or a zero-size decode) is a live post. Report
		 * it as a filled site at its address: if a loop-exit plan already owns
		 * this exit the commit path attaches this base as a sibling; otherwise
		 * dw_exit_is_filled refuses the owner install and the caller falls back.
		 */
		if (ein->id == X86_INS_INT3 || ein->id == X86_INS_JMP || ein->size == 0) {
			*exit_size_out = ein->size;
			*exit_filled_out = true;
			return ein->address;
		}

		/* A real control transfer: no safe site on the fall-through. */
		for (int g = 0; g < edet->groups_count; g++)
			if (edet->groups[g] < X86_GRP_VM)
				return 0;

		/*
		 * The tainted base must stay stripped and unused until the retaint. A
		 * read or write of it before we have found a site means the post cannot
		 * be deferred this far; decline (member-specific, never shifts the site).
		 */
		cs_regs er, ew;
		uint8_t erc = 0, ewc = 0;
		if (cs_regs_access(cs->handle, ein, er, &erc, ew, &ewc) != CS_ERR_OK)
			return 0;
		for (unsigned i = 0; i < tainted_regs_count; i++)
			if (reg_check_access(tainted_regs[i], er, erc) ||
			    reg_check_access(tainted_regs[i], ew, ewc))
				return 0;

		/* Heap-faulting but base-independent: skip, it patches on its own. */
		if (insn_can_heap_fault(ein, ex86))
			continue;

		/* First provably-non-heap instruction: this is the retaint site. */
		*exit_size_out = ein->size;
		*exit_filled_out = false;
		return ein->address;
	}

	/* Scan budget exhausted without a clean site: decline deferral. */
	return 0;
}

/*
 * Defer post-handler installation by scanning forward for safe instruction sites.
 *
 * This function scans instructions starting from the next instruction after a fault,
 * looking for locations where a post-handler can be safely installed.
 *
 * The scan stops when:
 * - A control-flow instruction is encountered (branch, call, return, etc.)
 * - A tainted register is read or modified
 * - All tainted registers are overwritten
 * - Memory access patterns diverge from the original fault
 * - The maximum instruction count is reached
 */
static uintptr_t dw_defer_post_handler(struct insn_entry *entry,
				   struct insn_entry_runtime *entry_rt,
				   uintptr_t start_addr,
				   ucontext_t *uctx,
				   struct capstone_context *cs,
				   unsigned *scanned_count,
				   unsigned *similar_access_count,
				   int64_t *footprint_lo_out,
				   int64_t *footprint_hi_out,
				   bool *footprint_exact_out,
				   struct post_safe_site_rb *rb)
{
	const uint8_t *code            = (const uint8_t *) start_addr;
	uint64_t instr_addr            = (uint64_t) start_addr;
	uint64_t last_safe_addr        = instr_addr;
	uint64_t last_same_access_addr = 0; /* address of last identical memory access   */
	unsigned count_same_access = 0, pending_same_access = 0;
	size_t buff_size;
	unsigned n = 0;
	int error_code;
	uint16_t tainted_regs[MAX_MEM_ARG * 2] = {0};
	/* Parallel to tainted_regs: net constant adjustment applied to each tainted
	 * register since the fault, accumulated when the scan steps over a constant
	 * pointer walk (add/sub/inc/dec reg, imm). */
	int64_t tainted_delta[MAX_MEM_ARG * 2] = {0};
	uint8_t tainted_regs_count = 0;
	struct memory_arg *mem;
	struct memory_arg_runtime *mem_rt;
	unsigned tail_budget = 0;

	/*
	 * Loop-exit deferral (#5) bookkeeping. loop_exit_eligible stays true only
	 * while every accepted same-object body access is an EXACT replay of the
	 * fault EA (same disp/size/scale, no index, zero tracked delta). The slow
	 * path of similar_memory_access() bounds a *differing* access against the
	 * discovery object only, and that verdict is cached in the reused entry, so
	 * a smaller object on a later loop entry could run such an access unchecked.
	 * ea_has_index records whether the fault EA itself uses an index register
	 * (an induction-index walk is likewise never re-bounded per entry).
	 */
	bool loop_exit_eligible = true;
	bool ea_has_index = false;

	uintptr_t func_start = 0, func_end = 0;
	size_t max_bytes = (size_t)MAX_SCAN_INST_COUNT * 15;

	if (get_function_bounds(start_addr, &func_start, &func_end) && func_end > start_addr) {
		size_t func_bytes_left = (size_t)(func_end - start_addr);
		buff_size = func_bytes_left < max_bytes ? func_bytes_left : max_bytes;
	} else {
		// Return if libunwind can't provide bounds
		DW_LOG(
			WARNING, DISASSEMBLY,
			"Cannot get function bounds for address 0x%llx, so we cancel post-handler deferring\n",
			start_addr);
		if (scanned_count)
			*scanned_count = 0;
		if (similar_access_count)
			*similar_access_count = 0;
		return 0;
	}

	/* Identify which registers from the original instructions are tainted */
	for (int i = 0; i < entry->nb_arg_m; i++) {
		mem = &entry->arg_m[i];
		mem_rt = &entry_rt->arg_m[i];
		int taint_reg = X86_REG_INVALID;

		if (mem_rt->base_taint)
			taint_reg = mem->base;

		if (mem->index != X86_REG_INVALID)
			ea_has_index = true;

		if ((reg_is_gpr(mem->index) && mem_rt->index_taint) ||
			(reg_is_avx(mem->index) && mem_rt->index_is_tainted))
			taint_reg = mem->index;

		if (taint_reg != X86_REG_INVALID)
			reg_set_add(tainted_regs, &tainted_regs_count, sizeof(tainted_regs)/sizeof(tainted_regs[0]), taint_reg);
	}

	/* Footprint accumulators for #5. Seeded from the fault arg only when
	 * nb_arg_m == 1 (the gate in loop_exit_defer_site rejects anything else). */
	int64_t fp_disp_lo = 0, fp_disp_hi = 0;
	if (entry->nb_arg_m == 1) {
		fp_disp_lo = entry->arg_m[0].displacement;
		fp_disp_hi = entry->arg_m[0].displacement + (int64_t)entry->arg_m[0].length;
	}

	while (n < MAX_SCAN_INST_COUNT && buff_size > 0) {
		bool success = cs_disasm_iter(cs->handle, &code, &buff_size, &instr_addr, cs->insn);
		if (!success) {
			error_code = cs_errno(cs->handle);
			if (error_code != CS_ERR_OK)
				DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n",
					    instr_addr, error_code);

			goto stop_return;   // End of buffer
		}

		cs_insn *insn = cs->insn;
		cs_detail *detail = insn->detail;
		cs_x86 *x86 = &detail->x86;
		cs_regs regs_read, regs_write;
		uint8_t read_count = 0, write_count = 0;
		uint16_t reg_ops[16], mem_ops[16];
		uint8_t reg_ops_count = 0, mem_ops_count = 0;

		error_code = cs_regs_access(cs->handle, insn, regs_read, &read_count,
								   regs_write, &write_count);
		if (error_code != CS_ERR_OK)
			DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot give register accesses\n");

		for (int i = 0; i < x86->op_count; ++i) {
			const cs_x86_op *op = &x86->operands[i];

			if (op->type == X86_OP_REG) {
				reg_set_add(reg_ops, &reg_ops_count, sizeof(reg_ops) / sizeof(reg_ops[0]), op->reg);
			} else if (op->type == X86_OP_MEM) {
				reg_set_add(mem_ops, &mem_ops_count, sizeof(mem_ops) / sizeof(mem_ops[0]), op->mem.base);
				reg_set_add(mem_ops, &mem_ops_count, sizeof(mem_ops) / sizeof(mem_ops[0]), op->mem.index);
			}
		}

		/*
		 * Whether a post-handler may be installed on this instruction. A
		 * fault-free instruction is a valid retaint site even if it touches
		 * memory, as long as the access cannot reach a tainted heap pointer
		 * (stack/global/segment addressing, or LEA/NOP that never dereference).
		 */
		bool can_heap_fault = insn_can_heap_fault(insn, x86);

		// 1) Stop scanning on control-flow change
		for (int i = 0; i < detail->groups_count; i++) {
			if (detail->groups[i] < X86_GRP_VM) {
				/*
				 * We avoid selecting INT3 and JMP instructions, as they may have been
				 * inserted by libpatch. This prevents the need to track and distinguish
				 * already patched instructions, ensuring we don’t attempt to patch them again.
				 */
				if ((last_safe_addr <= last_same_access_addr) &&
					(insn->id != X86_INS_INT3) && (insn->id != X86_INS_JMP)) {
					last_safe_addr = insn->address;
					count_same_access += pending_same_access;
					pending_same_access = 0;
					add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access, false);
				}

				/*
				 * Loop-header clamp. If the first control-flow instruction the
				 * scan meets is a backward conditional branch, this insn is a
				 * single-latch loop's latch and `target` is its header. Deferring
				 * a retaint into the loop body would fire the post once per
				 * iteration; clamp it to the pre-header (or the fault) instead.
				 *
				 * Fires only for a genuine single-latch loop: a conditional Jcc
				 * (jump group, immediate target, not an unconditional JMP) whose
				 * target lies inside the function and strictly between the scan
				 * start and this latch (a backward edge). Loops with an internal
				 * branch before the latch stop on that branch and fall through to
				 * today's behavior, so they are left untouched.
				 */
				if (insn->id != X86_INS_JMP && insn->id != X86_INS_INT3 &&
					cs_insn_group(cs->handle, insn, X86_GRP_JUMP) &&
					x86->op_count >= 1 && x86->operands[0].type == X86_OP_IMM) {
					uintptr_t target = (uintptr_t) x86->operands[0].imm;

					/* Backward edge inside this function => `insn` is a loop latch. */
					if (target >= func_start && target < func_end &&
						target >= start_addr && target < insn->address) {
						uintptr_t header = target;

						/*
						 * Similar-access addresses are recorded monotonically, so
						 * the most recent one is the maximum: if it lies at or past
						 * the header, the faulting object is re-dereferenced inside
						 * the loop body.
						 */
						bool in_loop_access = (last_same_access_addr >= header);

						if (!in_loop_access) {
							/*
							 * The loop body never re-touches the object, so deferring
							 * into it buys nothing and costs one probe-fire per
							 * iteration. Drop every in-loop candidate; the newest
							 * pre-header site (or the caller's no-site AROUND
							 * fallback at the fault) is then selected.
							 */
							prune_post_safe_sites_from(rb, header);
						} else {
							/*
							 * Variant B loop-exit deferral (#5). The fault is BEFORE
							 * the loop (header > start_addr) and a similar access
							 * lives inside the loop body. The normal pre-probe already
							 * strips the invariant base once in the prologue; relocate
							 * the retaint to the loop's fall-through exit instead of
							 * paying a per-iteration in-loop post. This is standard
							 * deferral with the post moved past the latch -- the
							 * pre-probe is unchanged, so loop_exit_activate stays false
							 * (Variant B keeps its pre-probe).
							 *
							 * Identical gate set to Variant A, so route through the
							 * same loop_exit_defer_site helper. Because the header
							 * (target) lies past the fault here, the helper's prefix
							 * re-scan (gate 8) is a no-op and soundness rests on the
							 * unchanged pre-probe plus the exact-EA footprint invariant.
							 */
							uint16_t exit_size = 0;
							bool exit_filled = false;
							uintptr_t exit_addr = loop_exit_defer_site(
								entry, cs, insn,
								regs_read, read_count, regs_write, write_count,
								tainted_regs, tainted_delta, tainted_regs_count,
								func_end, entry->insn, target,
								loop_exit_eligible, ea_has_index, &exit_size, &exit_filled);
							/*
							 * Variant B does not coalesce: it keeps its pre-probe and
							 * installs a plain (single-entry) post at the exit, so it
							 * never joins the shared-exit plan. Stage that post only when
							 * the exit is still empty; if it is already filled (a Variant A
							 * owner's post or any other patch holds it), fall back to
							 * per-iteration deferral rather than colliding on the exit.
							 */
							if (exit_addr && !exit_filled) {
								count_same_access += pending_same_access;
								pending_same_access = 0;
								last_safe_addr = exit_addr;
								add_post_safe_site(rb, exit_addr, exit_size,
										   count_same_access, /*trap_ok=*/true);
								entry->loop_exit_defer = true;
								entry->footprint_check = (fp_disp_lo != entry->arg_m[0].displacement ||
								                              fp_disp_hi != entry->arg_m[0].displacement + (int64_t)entry->arg_m[0].length);
								entry->footprint_disp_lo = fp_disp_lo;
								entry->footprint_disp_hi = fp_disp_hi;
								entry->loop_exit_target = exit_addr;
								DW_LOG(DEBUG, DISASSEMBLY,
									   "Loop-exit deferral (Variant B): post staged at fall-through 0x%llx (latch 0x%llx, origin 0x%llx).\n",
									   (unsigned long long)exit_addr,
									   (unsigned long long)insn->address,
									   (unsigned long long)start_addr);
							}
						}
					}

					/*
					 * Variant A loop-exit deferral (#5): backward edge whose header
					 * ENCLOSES the fault (target < start_addr). The faulting insn
					 * re-executes every iteration, so there is no prologue strip;
					 * the SIGSEGV handler strips the invariant base once per loop
					 * entry (loop_exit_activate) and only the loop-exit post is
					 * installed. loop_exit_defer_site applies the full gate set and
					 * returns the fall-through exit address (0 on failure).
					 */
					else if (target >= func_start && target <= entry->insn) {
						uint16_t exit_size = 0;
						bool exit_filled = false;
						uintptr_t exit_addr = loop_exit_defer_site(
							entry, cs, insn,
							regs_read, read_count, regs_write, write_count,
							tainted_regs, tainted_delta, tainted_regs_count,
							func_end, entry->insn, target,
							loop_exit_eligible, ea_has_index, &exit_size, &exit_filled);
						(void) exit_size;
						if (exit_addr) {
							count_same_access += pending_same_access;
							pending_same_access = 0;
							last_safe_addr = exit_addr;
							/*
							 * Record the candidate only. The owner/sibling election
							 * and the physical post install both happen at commit
							 * time (patch_entry_sync), serialized under dw_le_plan_mu,
							 * so we stage NO post here and pre-decide nothing -- the
							 * commit path installs an owner post directly at
							 * loop_exit_target (a single fall-through exit post) or
							 * attaches this base to a committed owner's plan.
							 * (exit_filled is advisory only; commit re-checks the
							 * exit emptiness under the lock.)
							 */
							entry->loop_exit_defer = true;
							entry->footprint_check = (fp_disp_lo != entry->arg_m[0].displacement ||
							                              fp_disp_hi != entry->arg_m[0].displacement + (int64_t)entry->arg_m[0].length);
							entry->footprint_disp_lo = fp_disp_lo;
							entry->footprint_disp_hi = fp_disp_hi;
							entry->loop_exit_target = exit_addr;
							entry->loop_exit_activate = true;
							DW_LOG(DEBUG, DISASSEMBLY,
								   "Loop-exit deferral (Variant A): candidate at fall-through 0x%llx (latch 0x%llx, header 0x%llx, origin 0x%llx).\n",
								   (unsigned long long)exit_addr,
								   (unsigned long long)insn->address,
								   (unsigned long long)target,
								   (unsigned long long)start_addr);
						}
					}
				}

				goto stop_return;
			}
		}

		// 2) Skip the current instruction if it does not involve any tainted register
		bool taint_involved = false;
		for (unsigned i = 0; i < tainted_regs_count; i++) {
			int tainted_reg = tainted_regs[i];
			if (reg_check_access(tainted_reg, regs_read, read_count) ||
				reg_check_access(tainted_reg, regs_write, write_count) ||
				reg_check_access(tainted_reg, mem_ops, mem_ops_count)) {
				taint_involved = true;
				break;
			}
		}

		if (!taint_involved) {
			/*
			 * When a safe site is found, we record a few "tail" safe sites as fallback
			 * in case the preferred site is not patchable with a JUMP.
			 */
			if (!can_heap_fault) {
				if (last_safe_addr <= last_same_access_addr) {
					last_safe_addr = insn->address;
					count_same_access += pending_same_access;
					pending_same_access = 0;
					tail_budget = DW_TAIL_CANDIDATE_BUDGET;
					add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access, false);
				} else if (count_same_access > 0 && tail_budget > 0) {
					add_post_safe_site(rb, insn->address, insn->size, count_same_access, false);
					tail_budget--;
				}
			}

			DW_LOG(DEBUG, DISASSEMBLY, "Skipping instruction at 0x%llx -> %s %s, (%u)\n",
				   insn->address, insn->mnemonic, insn->op_str, insn->size);
			++n;
			continue;
		}

		/*
		 * A constant adjustment changes the live effective address. The forward
		 * scan can validate accesses after it against the object present while the
		 * entry is discovered, but that result is not valid when the same site is
		 * later reached with a smaller allocation. Reprotect at the adjustment so
		 * every shifted access faults (and is checked) on every execution.
		 */
		uint32_t adj_reg;
		int64_t adj;
		if (const_adjust_of_tainted_reg(insn, tainted_regs, tainted_regs_count,
						&adj_reg, &adj)) {
			(void)adj_reg;
			DW_LOG(DEBUG, DISASSEMBLY,
				   "Stopping deferral at constant pointer adjustment 0x%llx -> %s %s (delta %+lld)\n",
				   insn->address, insn->mnemonic, insn->op_str, (long long)adj);

			/* The adjustment has no memory operand, so it is a safe place to run
			 * the deferred post before the modified pointer is dereferenced. */
			if (last_safe_addr <= last_same_access_addr) {
				last_safe_addr = insn->address;
				count_same_access += pending_same_access;
				pending_same_access = 0;
				add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access, false);
			}
			goto stop_return;
		}

		// 3) Check memory addresses divergence
		bool repeat = (x86->prefix[0] == X86_PREFIX_REP ||
					   x86->prefix[0] == X86_PREFIX_REPE ||
					   x86->prefix[0] == X86_PREFIX_REPNE);

		for (int i = 0; i < x86->op_count; i++) {
			const cs_x86_op *op = &x86->operands[i];

			if (op->type != X86_OP_MEM)
				continue;

			bool uses_taint =
			    reg_check_access(op->mem.base, tainted_regs, tainted_regs_count) ||
			    reg_check_access(op->mem.index, tainted_regs, tainted_regs_count);

			if (uses_taint) {
				for (int j = 0; j < entry->nb_arg_m; j++) {
					mem = &entry->arg_m[j];
					mem_rt = &entry_rt->arg_m[j];

					/* Fold each register's tracked constant walk into the
					 * effective-address check. The deltas key on the entry's
					 * base/index registers (which match this access's, since
					 * uses_taint required a tainted base/index here). */
					int64_t bdelta = reg_tracked_delta(mem->base, tainted_regs,
									   tainted_delta, tainted_regs_count);
					int64_t idelta = reg_tracked_delta(mem->index, tainted_regs,
									   tainted_delta, tainted_regs_count);

					if (!similar_memory_access(insn->id, op, mem, mem_rt, uctx, repeat,
								   bdelta, idelta))
						goto stop_return;

					/*
					 * Loop-exit eligibility: the surviving signal (Variant B's
					 * pre-probe / Variant A's activation) bounds-checks only the
					 * fault EA. It covers this body access on EVERY loop entry
					 * only if the access is an exact replay of the fault EA.
					 * Anything admitted via the slow path (differing
					 * disp/size/scale, an index, or a nonzero tracked delta) was
					 * bounds-checked against the discovery object alone -> clear
					 * eligibility (safe direction; never under-rejects).
					 */
					if (bdelta == 0 && idelta == 0 &&
					    op->mem.index == X86_REG_INVALID &&
					    op->mem.scale == mem->scale) {
						/* Fixed-field access on the same invariant base: widen footprint.
						 * Overflow-safe: op->size <= 64 (max AVX-512) and op->mem.disp
						 * is a signed 32-bit Capstone value, so the sum fits in int64_t. */
						int64_t lo = (int64_t)op->mem.disp;
						int64_t hi = (int64_t)op->mem.disp + (int64_t)op->size;
						if (lo < fp_disp_lo) fp_disp_lo = lo;
						if (hi > fp_disp_hi) fp_disp_hi = hi;
					} else {
						loop_exit_eligible = false;
					}
					}
					last_same_access_addr = insn->address;
					pending_same_access++;
					tail_budget = 0;
				}
			}

		// 4) We need to stop if one of the memory registers is tainted and updated or read
		bool every_tainted_reg_written = true;
		for (unsigned i = 0; i < tainted_regs_count; i++) {
			int reg = tainted_regs[i];
			bool is_operand = reg_check_access(reg, reg_ops, reg_ops_count);
			bool read = is_operand && reg_check_access(reg, regs_read, read_count);
			bool write = reg_check_access(reg, regs_write, write_count);

			// The base or index register is modified, so we need to stop scanning further
			if (read && write) {
				/* If the instruction overwrites the register (e.g., xor eax, eax),
				then we need to disable the post-handler. */
				if (is_reg_zeroing(insn)) {
					DW_LOG(DEBUG, DISASSEMBLY, "Post-handler has been DISABLED because of register-zeroing instruction.\n");
					entry->post_handler = false;
				}

				if (!can_heap_fault && (last_safe_addr <= last_same_access_addr)) {
					last_safe_addr = insn->address;
					count_same_access += pending_same_access;
					add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access, false);
				}
				goto stop_return;
			}

			// The tainted base or index register is read
			if (read) {
				if (!can_heap_fault && (last_safe_addr <= last_same_access_addr)) {
					last_safe_addr = insn->address;
					count_same_access += pending_same_access;
					add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access, false);
				}
				goto stop_return;
			}

			if (!write)
				every_tainted_reg_written = false;
		}

		// All tainted registers are overwritten, so we can skip the post-handler
		if (every_tainted_reg_written) {
			if (!can_heap_fault && (last_safe_addr <= last_same_access_addr)) {
				last_safe_addr = insn->address;
				count_same_access += pending_same_access;
				add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access, false);
			}

			DW_LOG(DEBUG, DISASSEMBLY, "Post-handler has been DISABLED because all tainted registers are overwritten!\n");
			entry->post_handler = false;
			goto stop_return;
		}

		// Otherwise, we can safely skip the instruction
		DW_LOG(DEBUG, DISASSEMBLY, "Skipping instruction at 0x%llx -> %s %s, (%u)\n",
			    insn->address, insn->mnemonic, insn->op_str, insn->size);

		n++;
		continue;
	}

stop_return:
	if (n == MAX_SCAN_INST_COUNT)
		DW_LOG(DEBUG, DISASSEMBLY,
			    "Max instruction scan count reached while deferring post-handler for 0x%llx\n",
			    start_addr);

	if (scanned_count)
		*scanned_count = n + 1;

	if (similar_access_count)
		*similar_access_count = count_same_access;

	/*
	 * Footprint of the fixed-field accesses admitted into the window. Reported
	 * so a PLAIN forward deferral can also install the widened bounds check (the
	 * loop-exit variants set the entry fields themselves above). footprint_exact
	 * mirrors loop_exit_eligible: true only while every admitted same-object
	 * access was an exact fixed-field access (no index, no tracked delta, same
	 * scale) and so is fully covered by [fp_disp_lo, fp_disp_hi). When it is
	 * false some access took the discovery-only slow path and the footprint does
	 * NOT cover it, so the caller must not claim footprint coverage.
	 */
	if (footprint_lo_out)
		*footprint_lo_out = fp_disp_lo;
	if (footprint_hi_out)
		*footprint_hi_out = fp_disp_hi;
	if (footprint_exact_out)
		*footprint_exact_out = loop_exit_eligible;

	return last_safe_addr;
}

static bool
fill_memory_operand(struct memory_arg* m, struct memory_arg_runtime* m_rt, const cs_x86_op *op, const csh handle,
				    const cs_insn *insn, const cs_x86 *x86, const ucontext_t *uctx)
{
	const struct reg_entry *re;
	unsigned base, index;
	uintptr_t addr, index_addr, base_addr = 0;
	int scale;
	int64_t displacement;
	bool register_is_protected = false;

	m->scale = scale = op->mem.scale;
	m->displacement = displacement = op->mem.disp;
	m->length = op->size;
	m->access = op->access;

	m->base = base = op->mem.base;
	m->index = index = op->mem.index;
	m->base_re = (base != X86_REG_INVALID) ? dw_get_reg_entry(base) : NULL;
	m->index_re = (index != X86_REG_INVALID) ? dw_get_reg_entry(index) : NULL;

	// Handle the base register
	re = m->base_re;
	if (re) {
		if (!reg_is_gpr(base))
			DW_LOG(ERROR, DISASSEMBLY, "Base register %s not a General-Purpose Register\n", re->name);

		m_rt->base_addr = base_addr = dw_get_register(uctx, re->ucontext_index);
		if (dw_is_protected((void *) base_addr)) {
			register_is_protected = true;
			m_rt->base_taint = base_addr;
		}
	}

	if (index == X86_REG_INVALID) {
		addr = base_addr + (0 * scale) + displacement;
		DW_LOG(DEBUG, DISASSEMBLY,
			"Memory operand (segment %d): base %s (0x%llx) + (index %s (0x0) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n",
			op->mem.segment, cs_reg_name(handle, base), base_addr, cs_reg_name(handle, index),
			scale, displacement, addr, op->access);
		return register_is_protected;
	}

	// Handle the index register according to SIB/VSIB access modes
	re = m->index_re;
	if (reg_is_gpr(index)) {
		m_rt->index_addr = index_addr = re ? dw_get_register(uctx, re->ucontext_index) : 0;
		if (dw_is_protected((void *) index_addr)) {
			m_rt->index_taint = index_addr;
			register_is_protected = true;
		}

		// The memory address is given by base + (index * scale) + displacement
		addr = base_addr + (index_addr * scale) + displacement;

		DW_LOG(DEBUG, DISASSEMBLY,
			"Memory operand (segment %d): base %s (0x%llx) + (index %s (0x%llx) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n",
			op->mem.segment, cs_reg_name(handle, base), base_addr, cs_reg_name(handle, index),
			index_addr, scale, displacement, addr, op->access);
	} else {
		// VSIB access
		if (!reg_is_avx(index))
			DW_LOG(ERROR, DISASSEMBLY, "Index register %s not AVX or GP register\n", re->name);

		/* Calculate the width of each of the indices and their count */
		uint8_t index_width = m->index_width = vsib_index_width(insn->id);
		if (index_width != MIN_VSIB_INDEX_WIDTH && index_width != MAX_VSIB_INDEX_WIDTH)
			DW_LOG(ERROR, DISASSEMBLY, "Invalid width (%d) for the indices within the %s register\n",
				   m->index_width, re->name);

		m->indices_count = (re && index_width) ? (re->size / index_width) : 0;

		// This is just a heuristic: we consider the index tainted if its width is equal to 8 bytes
		if (index_width == MAX_VSIB_INDEX_WIDTH) {
			m_rt->index_is_tainted = true;
			register_is_protected = true;
		}
	}

	return register_is_protected;
}

/*
 * This function assigns access type (READ, WRITE, or both) to base and index registers when they
 * also appear as register operands. It matches the base and index from each memory argument with
 * the register arguments to propagate access types.
 */
static void assign_base_index_access(struct insn_entry *entry)
{
	for (unsigned i = 0; i < entry->nb_arg_m; i++) {
		struct memory_arg *arg_m = &entry->arg_m[i];
		const struct reg_entry *base_re  = arg_m->base_re;
		const struct reg_entry *index_re = arg_m->index_re;

		for (unsigned j = 0; j < entry->nb_arg_r; j++) {
			const struct reg_entry *re_arg_r = dw_get_reg_entry(entry->arg_r[j].reg);

			if (base_re && re_arg_r && (base_re->canonical_index == re_arg_r->canonical_index)) {
				arg_m->base_access = entry->arg_r[j].access;

				if (arg_m->access == (CS_AC_READ | CS_AC_WRITE))
					DW_LOG(WARNING, DISASSEMBLY, "Memory argument is unexpectedly read and written\n");

				if (entry->nb_arg_r != 1)
					DW_LOG(WARNING, DISASSEMBLY, "More than one register argument, may be ambiguous\n");
			}

			if (index_re && re_arg_r && (index_re->canonical_index == re_arg_r->canonical_index)) {
				arg_m->index_access = entry->arg_r[j].access;

				if (arg_m->access == (CS_AC_READ | CS_AC_WRITE))
					DW_LOG(WARNING, DISASSEMBLY, "Memory argument is unexpectedly read and written\n");

				if (entry->nb_arg_r != 1)
					DW_LOG(WARNING, DISASSEMBLY, "More than one register argument, may be ambiguous\n");
			}
		}
	}
}

static inline unsigned int get_avx512_mask_register(uint16_t gregs_reads[],
												   uint8_t gregs_read_count) {
	for (int i = 0; i < gregs_read_count; i++) {
			if (gregs_reads[i] >= X86_REG_K0 && gregs_reads[i] <= X86_REG_K7)
				return (gregs_reads[i]);
	}
	return X86_REG_INVALID;
}

/*
 * Stage 1 of the SIGSEGV emulate-and-skip plan: tag a site as
 * DW_FAST_MOV_FIXED_FIELD when it is a simple fixed-field `mov` that the signal
 * handler can later emulate and skip in a single signal. All of the following
 * must hold:
 *   - mnemonic is `mov` (plain mov; movzx/movsx have distinct ids);
 *   - exactly one memory operand and exactly one register operand;
 *   - base is a GPR (this also rejects RIP-relative and absolute addressing);
 *   - no index register / VSIB;
 *   - no segment override beyond normal flat addressing;
 *   - not REP/string;
 *   - scalar access width in {1,2,4,8};
 *   - register operand is not a high-byte sub-register (AH/BH/CH/DH), whose
 *     offset/semantics are deferred to a later stage.
 * The flat metadata (base/dst ucontext offsets, width, disp, load/store) is
 * precomputed so the hot signal path needs no register-table lookup. This stage
 * only records the metadata; no handler or routing yet consumes it.
 */
static void
classify_fast_kind(struct insn_entry *entry, const cs_insn *insn, const cs_x86 *x86)
{
	entry->fast_kind = DW_FAST_NONE;

	if (insn->id != X86_INS_MOV)
		return;
	if (entry->repeat)
		return;
	if (entry->nb_arg_m != 1 || entry->nb_arg_r != 1)
		return;

	const struct memory_arg *m = &entry->arg_m[0];

	/* base must be a GPR: rejects RIP-relative and absolute addressing */
	if (!reg_is_gpr(m->base))
		return;
	/* no index register / VSIB */
	if (m->index != X86_REG_INVALID)
		return;
	/* scalar width must be one of the supported sizes */
	if (m->length != 1 && m->length != 2 && m->length != 4 && m->length != 8)
		return;

	/* no segment override beyond normal flat addressing */
	for (int i = 0; i < x86->op_count; i++) {
		if (x86->operands[i].type == X86_OP_MEM &&
		    x86->operands[i].mem.segment != X86_REG_INVALID)
			return;
	}

	/* the single register operand: load => destination, store => source */
	unsigned reg = entry->arg_r[0].reg;
	if (reg == X86_REG_AH || reg == X86_REG_BH ||
	    reg == X86_REG_CH || reg == X86_REG_DH)
		return;

	const struct reg_entry *base_re = m->base_re;
	const struct reg_entry *dst_re = dw_get_reg_entry(reg);
	if (!base_re || !dst_re)
		return;

	/* the ucontext offsets must fit the uint8_t hot-path fields */
	if (base_re->ucontext_index < 0 || base_re->ucontext_index > UINT8_MAX ||
	    dst_re->ucontext_index < 0 || dst_re->ucontext_index > UINT8_MAX)
		return;

	entry->fast_kind = DW_FAST_MOV_FIXED_FIELD;
	entry->fast_base_uctx = (uint8_t)base_re->ucontext_index;
	entry->fast_dst_uctx = (uint8_t)dst_re->ucontext_index;
	entry->fast_width = (uint8_t)m->length;
	entry->fast_is_load = (m->access & CS_AC_WRITE) == 0;
	entry->fast_disp = m->displacement;
}

/*
 * Select the specialized handler for one base+displacement memory operand.
 * Exclude shapes that need index, value-operand, REP/VSIB, loop-exit, or OLX
 * handling. This runs at patch time, keeping dispatch off the probe hot path.
 */
DW_INTERNAL bool dw_entry_base_only_fast(const struct insn_entry *entry)
{
	if (!entry)
		return false;

	/* Overlap children use patch_insn and require the generic handler. */
	if (entry->patch_insn)
		return false;

	if (entry->nb_arg_m != 1)
		return false;
	if (entry->has_vsib || entry->repeat || entry->repeat_conditional)
		return false;

	/*
	 * Loop-exit variants need the generic activation / shared-plan handling.
	 * A plain deferred footprint entry does NOT: dw_unprotect_base_only performs
	 * the widened footprint check itself (gated on deferred_post_handler), so it
	 * stays on the fast path whether deferral committed or fell back to AROUND --
	 * footprint_check alone must not disqualify it.
	 */
	if (entry->loop_exit_defer || entry->loop_exit_activate || entry->loop_exit_plan)
		return false;

	const struct memory_arg *m = &entry->arg_m[0];

	if (m->base == X86_REG_INVALID || m->base_re == NULL ||
	    !reg_is_gpr(m->base) || m->base_re->libpatch_index < 0)
		return false;
	if (m->index != X86_REG_INVALID)
		return false;
	/* A base used as a value operand requires the generic special cases. */
	if (m->base_access != 0)
		return false;

	return true;
}

static unsigned
fill_instruction_operands(struct insn_entry *entry, struct insn_entry_runtime* entry_rt, const csh handle, const cs_insn *insn,
						  const cs_x86 *x86, const ucontext_t *uctx)
{
	const struct reg_entry *re;
	unsigned arg_m = 0, arg_r = 0, nb_protected = 0;

	// Loop over all the instruction arguments
	for (int i = 0; i < x86->op_count; i++)
	{
		const cs_x86_op *op = &x86->operands[i];
		switch (op->type)
		{
		case X86_OP_REG:
			re = dw_get_reg_entry(op->reg);
			if (re && re->canonical_index != X86_REG_INVALID) {
				if (arg_r >= MAX_REG_ARG)
					DW_LOG(ERROR, DISASSEMBLY, "Too many destination register arguments\n");

				entry->arg_r[arg_r].reg = op->reg;
				entry->arg_r[arg_r].length = re->size;
				entry->arg_r[arg_r].access = op->access;
				arg_r++;
			}

			DW_LOG(DEBUG, DISASSEMBLY, "Register operand %lu, reg %s, access %hhu\n",
				   i, cs_reg_name(handle, op->reg), op->access);
			break;

		case X86_OP_MEM:
			if (arg_m >= MAX_MEM_ARG)
				DW_LOG(ERROR, DISASSEMBLY, "Too many memory arguments\n");

			if (fill_memory_operand(&entry->arg_m[arg_m], &entry_rt->arg_m[arg_m], op, handle, insn, x86, uctx)) {
				nb_protected++;

				// We need a VSIB flag per entry to know if we will need XSAVE/XRSTOR when patching the instruction
				int index = entry->arg_m[arg_m].index;
				entry->has_vsib |= reg_is_avx(index);

				// For AVX-512 scatter/gather operations, the mask register (k0..k1) is optional
				if (reg_is_avx512(index)) {
					entry->arg_m[arg_m].mask =
						get_avx512_mask_register(entry->gregs_read, entry->gregs_read_count);
				}
				else if (reg_is_sse(index) || reg_is_avx2(index)) {
					// For AVX-2 gather operations, the mask register (XMM0..YMM31) is mandatory
					if (x86->op_count < 3)
						DW_LOG(ERROR, DISASSEMBLY, "Too few operands for an AVX-2 gather operation\n");

					entry->arg_m[arg_m].mask = x86->operands[i + 1].reg;
				}
			}

			arg_m++;
			break;

		case X86_OP_IMM:
			DW_LOG(DEBUG, DISASSEMBLY, "Immediate operand %lu, value %lu\n", i,
				   op->imm);
			break;

		default:
			DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx: Invalid operand %lu (type %d)\n",
				    entry->insn, i, op->type);
			break;
		}
	}

	entry->nb_arg_m = arg_m;
	entry->nb_arg_r = arg_r;

	assign_base_index_access(entry);
	classify_fast_kind(entry, insn, x86);
	return nb_protected;
}

/*
 * Disassembles a faulted instruction, and populates the entry with register and memory operand
 * information.
 */
static bool dw_populate_instruction_entry(instruction_table *table, struct insn_entry *entry,
					   uintptr_t fault, uintptr_t patch_insn,
					   ucontext_t *uctx,
					   struct post_safe_site_rb *safe_sites)
{
	size_t sizeds = 15; /* x86 max insn length */
	bool success;
	int error_code;
	const uint8_t *code = (uint8_t *)fault;
	uint64_t insn_addr = (uint64_t) fault;

	// Disassemble the instruction with Capstone
	struct capstone_context * cs = capstone_get_context();
	success = cs_disasm_iter(cs->handle, &code, &sizeds, &insn_addr, cs->insn);
	error_code = cs_errno(cs->handle);
	if (!success)
		DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n",
			   fault, error_code);

	entry->insn = fault;
	entry->patch_insn = patch_insn;
	entry->insn_length = cs->insn->size;
	entry->next_insn = insn_addr;
	entry->post_handler = true;
	entry->deferred_post_handler = false;
	snprintf(entry->disasm_insn, sizeof(entry->disasm_insn), "%.11s %.51s", cs->insn->mnemonic, cs->insn->op_str);

	if (dw_log_enabled(INFO, DISASSEMBLY)) {
		code = (uint8_t *) fault;
		char insn_code[256], *c = insn_code;
		int ret, length = 256;
		for (int i = 0; i < entry->insn_length; i++) {
			ret = snprintf(c, length, "%02x ", *code);
			c += ret;
			length -= ret;
			code++;
		}

		// Get the symbol of the containing function, to help in debugging
		char proc_name[256];
		char* proc_name_p = proc_name;
		uint64_t offset = 0;

		struct func_cache_entry *e = func_cache_lookup(fault);
		if (!e) {
			uintptr_t start = 0, end = 0;
			dw_lookup_symbol(fault, proc_name, sizeof(proc_name), &start, &end);
			if (start != 0 && end > start)
				e = func_cache_insert(start, end, proc_name);
		}

		if (e) {
			proc_name_p = e->func_name;
			offset = (uint64_t) fault - e->start_ip;
		}

		// This is info, not a warning, but we need it for debug purposes for now
		DW_LOG(INFO, DISASSEMBLY,
			"[%u] ==> Instruction 0x%llx (%s+0x%lx), entry %lu, disasm -> %s %s, (%hu), %s\n",
			gettid(), fault, proc_name_p, offset, (entry - table->entries), cs->insn->mnemonic,
			cs->insn->op_str, cs->insn->size, insn_code);
	}

	cs_detail *detail = cs->insn->detail;
	cs_x86 *x86 = &(detail->x86);
	bool need_immediate_reprotection = false;
	bool overlap_child = patch_insn != 0;

	/*
	 * For control flow instructions, we need to reapply the taint immediatly.
	 */
	for (int i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] < X86_GRP_VM) {
			need_immediate_reprotection = true;
			DW_LOG(DEBUG, DISASSEMBLY, "Jump or Call instruction %llx (%s %s) has protected memory operands",
				    fault, cs->insn->mnemonic, cs->insn->op_str);
			break;
		}
	}

	entry->repeat =
				(x86->prefix[0] == X86_PREFIX_REP ||
				 x86->prefix[0] == X86_PREFIX_REPE ||
				 x86->prefix[0] == X86_PREFIX_REPNE);
	entry->repeat_conditional = entry->repeat && instruction_is_rep_conditional(cs->insn->id);

	unsigned reg;
	cs_regs regs_read, regs_write;
	uint8_t read_count = 0, write_count = 0;
	error_code = cs_regs_access(cs->handle, cs->insn,
							   regs_read, &read_count, regs_write, &write_count);

	if (error_code != CS_ERR_OK)
		DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot give register accesses\n");

	if (read_count > MAX_MOD_REG)
		DW_LOG(ERROR, DISASSEMBLY, "More registers read %d than expected %d\n",
			   read_count, MAX_MOD_REG);

	if (write_count > MAX_MOD_REG)
		DW_LOG(ERROR, DISASSEMBLY, "More registers written %d than expected %d\n",
			   write_count, MAX_MOD_REG);

	entry->gregs_read_count = min(read_count, MAX_MOD_REG);
	entry->gregs_write_count = min(write_count, MAX_MOD_REG);

	for (int i = 0; i < entry->gregs_read_count; i++) {
		reg = entry->gregs_read[i] = regs_read[i];
		DW_LOG(DEBUG, DISASSEMBLY, "read: %s; (%d)\n", cs_reg_name(cs->handle, reg), reg);
	}

	for (int i = 0; i < entry->gregs_write_count; i++) {
		reg = entry->gregs_written[i] = regs_write[i];
		DW_LOG(DEBUG, DISASSEMBLY, "write: %s; (%d)\n", cs_reg_name(cs->handle, reg), reg);
	}

	struct insn_entry_runtime entry_rt = {0};
	unsigned nb_protected = fill_instruction_operands(entry, &entry_rt, cs->handle, cs->insn, x86, uctx);
	if (nb_protected == 0) {
		DW_LOG(WARNING, DISASSEMBLY,
			   "Instruction 0x%llx generated a fault but no protected memory argument\n", entry->insn);
		return false;
	}

	if (nb_protected > 1)
		DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx accesses more than one protected object\n",
			   entry->insn);

	bool all_tainted_overwritten = true;
	bool has_compound = false;
	for (int i = 0; i < entry->nb_arg_m; i++) {
		/*
		 * Detect compound (strength-reduced) SIB taint, where the protected
		 * object-id is carried by the aggregate base+index*scale+disp rather
		 * than a single register. Such instructions need their base restored in
		 * the post handler, so the post handler must stay enabled and the
		 * reprotection must not be deferred.
		 */
		if (dw_sib_base_carries_compound_taint(
			    entry_rt.arg_m[i].base_addr, entry_rt.arg_m[i].index_addr,
			    entry->arg_m[i].scale, entry->arg_m[i].displacement,
			    entry_rt.arg_m[i].base_taint != 0,
			    entry_rt.arg_m[i].index_taint != 0)) {
			need_immediate_reprotection = true;
			has_compound = true;
		}

		if (!base_index_overwritten(cs->insn, entry, &entry_rt, i)) {
			// If the base or index register is not fully overwritten and corresponds to
			// a register argument, it must be immediately re-tainted.
			bool is_vsib = reg_is_avx(entry->arg_m[i].index);
			if ((entry->arg_m[i].base_access && entry_rt.arg_m[i].base_taint) ||
				(!is_vsib && entry->arg_m[i].index_access && entry_rt.arg_m[i].index_taint) ||
				(is_vsib && entry->arg_m[i].index_access && entry_rt.arg_m[i].index_is_tainted)) {
				need_immediate_reprotection = true;
			}

			all_tainted_overwritten = false;
		}

		/*
		 * Registers rsi and rdi are auto-incremented for some instructions with the rep prefix.
		 * This is accounted for by reapplying the taint, not restoring the saved register value.
		 * Here we check if there exists other cases apart from rsi and rdi with rep instructions.
		 */
		if (dw_reg_written(entry, entry->arg_m[i].base) && !(entry->arg_m[i].base_access & CS_AC_WRITE) &&
			!dw_reg_si_di(entry, entry->arg_m[i].base))
			DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx, base register %s implicitly modified\n",
				   entry->insn, (entry->arg_m[i].base_re)->name);

		if (dw_reg_written(entry, entry->arg_m[i].index) && !(entry->arg_m[i].index_access & CS_AC_WRITE) &&
			!dw_reg_si_di(entry, entry->arg_m[i].index))
			DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx, index register %s implicitly modified\n",
				   entry->insn, (entry->arg_m[i].index_re)->name);
	}

	// If all tainted registers are overwritten by the instruction, there is no point in installing a post handler
	// (unless the base carries compound taint and must be restored afterwards).
	//
	// REP string instructions are excluded: Capstone reports RSI/RDI as written,
	// but that is only the auto-advance - the pointers still reference the
	// protected object and must be retainted by the post handler (see
	// dw_reg_si_di), and conditional scans (REPE/REPNE CMPS/SCAS) additionally
	// need the post handler for the exact post-execution extent check.
	if (all_tainted_overwritten && !has_compound && !entry->repeat) {
		entry->post_handler = false;

		DW_LOG(DEBUG, DISASSEMBLY,
			   "Disabling post-handler at 0x%llx (%s %s) because all tainted registers were overwritten.\n",
			   entry->insn, cs->insn->mnemonic, cs->insn->op_str);
	}

	// Instructions with repeat prefix need immediate reprotection
	if (entry->repeat)
		need_immediate_reprotection = true;

	if (overlap_child)
		need_immediate_reprotection = true;

	/*
	 * Scan forward from the faulting instruction to determine whether the post-handler can be
	 * safely skipped or installed at a later instruction.
	 */
	if (entry->post_handler && !need_immediate_reprotection && !entry->patch_disabled) {
		unsigned int insn_scan_count, similar_access_count;
		uintptr_t last_safe_addr;
		int64_t footprint_lo = 0, footprint_hi = 0;
		bool footprint_exact = false;

		last_safe_addr = dw_defer_post_handler(entry, &entry_rt, insn_addr, uctx, cs,
							   &insn_scan_count, &similar_access_count,
							   &footprint_lo, &footprint_hi, &footprint_exact,
							   safe_sites);

		DW_LOG(DEBUG, DISASSEMBLY,
			   "Forward scan has stopped at 0x%llx (%s %s), after (%u) instructions.\n",
			   cs->insn->address, cs->insn->mnemonic, cs->insn->op_str, insn_scan_count);

		if (entry->post_handler && (similar_access_count > 0 || entry->loop_exit_defer)) {
			entry->deferred_post_handler = true;
			entry->next_insn = last_safe_addr;

			/*
			 * 2a: widen the pre-handler bounds check to the full window footprint
			 * for a PLAIN forward deferral (the loop-exit variants set their own
			 * footprint inside dw_defer_post_handler). Without this, a same-base
			 * access at a DIFFERENT displacement admitted into the window is
			 * validated only once, at discovery, against the discovery object;
			 * once the base is stripped it runs unchecked on every later
			 * execution, so a later, smaller object would miss the violation.
			 *
			 * Only sound for a base-only fixed-field shape whose window is fully
			 * covered by [footprint_lo, footprint_hi): single mem arg, no index,
			 * base not a value operand, and footprint_exact (every admitted
			 * access was an exact fixed-field access). Set only when the window
			 * actually widened beyond the fault EA; otherwise the plain fault-EA
			 * check already suffices.
			 */
			if (!entry->loop_exit_defer && footprint_exact &&
			    entry->nb_arg_m == 1 &&
			    entry->arg_m[0].index == X86_REG_INVALID &&
			    entry->arg_m[0].base_access == 0) {
				int64_t flt_lo = entry->arg_m[0].displacement;
				int64_t flt_hi = flt_lo + (int64_t)entry->arg_m[0].length;

				if (footprint_lo != flt_lo || footprint_hi != flt_hi) {
					entry->footprint_check = true;
					entry->footprint_disp_lo = footprint_lo;
					entry->footprint_disp_hi = footprint_hi;
					DW_LOG(DEBUG, DISASSEMBLY,
						   "Deferred footprint widened to [base%+lld, base%+lld) for 0x%llx\n",
						   (long long)footprint_lo, (long long)footprint_hi, entry->insn);
				}
			}

			DW_LOG(DEBUG, DISASSEMBLY,
				   "Post-handler DEFERRED to 0x%llx - skipped (%u) similar memory accesses%s!\n",
				   last_safe_addr, similar_access_count,
				   entry->loop_exit_activate ? " (loop-exit Variant A)" : "");
		}
	}
	return true;
}

/*
 * Create a new entry for this instruction address
 */
struct insn_entry *dw_create_instruction_entry(instruction_table *table, uintptr_t fault,
											   ucontext_t *uctx, bool *created_out,
											   struct post_safe_site_rb *safe_sites_out)
{
	uintptr_t overlap_patch_insn = 0;
	const bool patch_disabled = dw_patch_disabled_for_addr(fault, &overlap_patch_insn);
	const bool overlap_child = overlap_patch_insn != 0;

	if (overlap_child) {
		DW_LOG(DEBUG, DISASSEMBLY,
		       "Instruction 0x%llx is relocated in OLX from original 0x%llx; "
		       "attempting overlapping patch\n",
		       (unsigned long long)fault, (unsigned long long)overlap_patch_insn);
	}

	if (!patch_disabled && safe_sites_out == NULL) {
		DW_LOG(WARNING, MAIN,
			   "Cannot create patch request for instruction 0x%llx: safe_sites_out is NULL\n",
			   (unsigned long long)fault);
		return NULL;
	}

	size_t mask = table->size - 1;
	size_t start = hash_addr(fault) & mask;
	size_t cursor = start;

	*created_out = false;
	if (safe_sites_out) {
		safe_sites_out->head = 0;
		safe_sites_out->count = 0;
	}

	while (1) {
		struct insn_entry *e = &table->entries[cursor];
		int entry_state = atomic_load_explicit(&e->state, memory_order_acquire);

		if (entry_state == ENTRY_EMPTY) {
			int expected = ENTRY_EMPTY;
			/* Try to become the creator for this entry slot */
			if (atomic_compare_exchange_strong_explicit(&e->state, &expected, ENTRY_INITIALIZING,
														memory_order_acq_rel,
														memory_order_relaxed)) {
				struct post_safe_site_rb safe_sites = {.head = 0, .count = 0};

				e->patch_disabled = patch_disabled;
				e->strategy = DW_PATCH_UNKNOWN;

				bool ok = dw_populate_instruction_entry(table, e, fault,
									overlap_child ? overlap_patch_insn : 0,
									uctx, &safe_sites);
				if (!ok) {
					atomic_store_explicit(&e->state, ENTRY_FAILED, memory_order_release);
					DW_LOG(WARNING, MAIN, "Problem creating entry for instruction 0x%llx\n", fault);
					return NULL;
				}

				if (e->patch_disabled) {
					DW_LOG(WARNING, DISASSEMBLY,
						   "Instruction 0x%llx is within a libpatch-generated or unsupported "
						   "executable mapping, patching is disabled\n",
						   (unsigned long long)fault);
					atomic_store_explicit(&e->state, ENTRY_READY, memory_order_release);
				} else {
					*safe_sites_out = safe_sites;
				}

				*created_out = true;
				return e;
			}
			/* lost the race, go around and re-read the entry's state */
			continue;
		}

		if (entry_state == ENTRY_INITIALIZING) {
			/* Another thread is creating this slot; wait until it finishes. */
			entry_state = dw_await_entry_ready(e);

			if (e->insn == fault)
				return (entry_state == ENTRY_READY) ? e : NULL;
		} else if (entry_state == ENTRY_READY) {
			if (e->insn == fault)
				return e;
		} else if (entry_state == ENTRY_FAILED) {
			if (e->insn == fault)
				return NULL;
		}

		cursor = (cursor + 1) & mask;
		if (cursor == start) {
			DW_LOG(ERROR, DISASSEMBLY, "Instruction hash table full\n");
			break;
		}
	}

	return NULL;
}

void dw_print_regs(struct patch_exec_context *ctx)
{
	for (int i = 0; i < dw_nb_saved_registers; i++)
		DW_LOG(DEBUG, DISASSEMBLY, "%s, %llx\n",
			   dw_get_reg_entry(dw_saved_registers[i])->name, ctx->general_purpose_registers[i]);
}

static bool dw_check_handling = false;

void dw_set_check_handling(bool f) { dw_check_handling = f; }

static inline void decode_avx_mask(const uint8_t *mask_buffer, int num_lanes, int lane_width,
						    uint64_t *out_bits)
{
	uint64_t bits = 0;

	if (!mask_buffer || !out_bits || num_lanes <= 0 || num_lanes > 64)
		goto done;

	for (int i = 0; i < num_lanes; ++i) {
		// Sign-bit position for lane i
		int bit_offset = (i + 1) * lane_width - 1;
		int byte_index = bit_offset >> 3;
		int bit_index  = bit_offset & 7;

		uint8_t byte_val = mask_buffer[byte_index];
		uint8_t sign_bit = (byte_val >> bit_index) & 1u;

		if (sign_bit) bits |= (1ull << i);
	}

done:
	*out_bits = bits;
}

static void check_vsib_access(struct memory_arg *mem,
							  struct memory_arg_runtime *mem_rt,
							  uintptr_t valueb, unsigned idx, void *xsave_ptr,
							  struct patch_exec_context *ctx)
{
	uint8_t width, count;
	uint8_t index_buffer[64] = {0}; /* ZMM registers are 64 bytes */
	size_t bytes_count, index_size;
	unsigned index = mem->index;
	const int mask_reg = mem->mask;
	const struct reg_entry *index_re = mem->index_re;
	const struct reg_entry *mask_re = dw_get_reg_entry(mask_reg);

	width = mem->index_width;
	count = mem->indices_count;

	if (!width || (width != MIN_VSIB_INDEX_WIDTH && width != MAX_VSIB_INDEX_WIDTH)) {
		DW_LOG(ERROR, DISASSEMBLY, "Invalid VSIB index width %u for mem arg %u\n", width, idx);
		return;
	}

	if (!count) {
		DW_LOG(ERROR, DISASSEMBLY, "Zero VSIB lanes for mem arg %u\n", idx);
		return;
	}

	index_size = index_re ? index_re->size : 0;

	if (index_size > sizeof(index_buffer) || index_size != count * width)
		DW_LOG(WARNING, DISASSEMBLY, "Unexpected index register size %zu (width %u, lanes %u) for mem arg %u\n",
			index_size, width, count, idx);

	mem_rt->index_is_tainted = false;
	mem_rt->mask_bv = ~0ULL;

	/* Decode the indices from the XSAVE area. */
	bytes_count = decode_extended_states(index, xsave_ptr, index_buffer);
	if (bytes_count != index_size)
		DW_LOG(ERROR, DISASSEMBLY,
			   "Failed to decode index register %s (decoded %zu / expected %zu)\n",
			   index_re->name, bytes_count, index_size);

	/* Save the original indices as they might be tainted. */
	__builtin_memcpy(mem_rt->indices, index_buffer, bytes_count);

	/*
	 * Decode the mask register:
	 * - X86_REG_INVALID or K0: all lanes enabled
	 * - AVX-512 k1..k7: direct bit mask
	 * - AVX2/XMM|YMM: derive a bit mask from MSB of each lane.
	 */
	if (mask_reg == X86_REG_INVALID || mask_reg == X86_REG_K0) {
		mem_rt->mask_bv = ~0ULL; /* all lanes enabled */
	} else if (reg_is_avx512_opmask(mask_reg)) {
		bytes_count = decode_extended_states(mask_reg, xsave_ptr,
						     (uint8_t *)&mem_rt->mask_bv);

		if (bytes_count != mask_re->size)
			DW_LOG(ERROR, DISASSEMBLY, "Failed to decode mask register %s (decoded %zu / expected %zu)\n",
				mask_re->name, bytes_count, mask_re->size);
	} else if (reg_is_sse(mask_reg) || reg_is_avx2(mask_reg)) {
		uint8_t mask_buffer[32] = {0};

		bytes_count = decode_extended_states(mask_reg, xsave_ptr, mask_buffer);
		if (bytes_count != mask_re->size)
			DW_LOG(ERROR, DISASSEMBLY,
				"Failed to decode mask register %s (decoded %zu / expected %zu)\n",
				mask_re->name, bytes_count, mask_re->size);

		decode_avx_mask(mask_buffer, count, width * 8, &mem_rt->mask_bv);
	} else {
		DW_LOG(ERROR, DISASSEMBLY, "Invalid mask register %s for mem arg %u\n",
			mask_re ? mask_re->name : "<unknown>", idx);
	}

	for (int i = 0; i < count; i++) {
		uintptr_t valuei;

		if (width == MIN_VSIB_INDEX_WIDTH)
			valuei = *((uint32_t *)(index_buffer + i * width));
		else
			valuei = *((uint64_t *)(index_buffer + i * width));

		/* Check whether the access is valid for each enabled lane. */
		if (mem_rt->mask_bv & (1ull << i)) {
			uintptr_t addr = valueb + valuei * mem->scale + mem->displacement;
			dw_check_access_ctx((void *) addr, mem->length, ctx);
		}

		/* If the index width is 8 bytes, it might be a protected absolute address. */
		if (width != MAX_VSIB_INDEX_WIDTH ||
		    !(mem_rt->mask_bv & (1ull << i)) ||
		    !dw_is_protected((void *) valuei))
			continue;

		mem_rt->index_is_tainted = true;
		*((uint64_t *)(index_buffer + i * width)) = (uint64_t) dw_unprotect((void *) valuei);

		if (dw_is_protected((void *) valueb))
			DW_LOG(WARNING, DISASSEMBLY, "Both index and base tainted for mem arg %u\n", idx);
	}

	if (mem_rt->index_is_tainted) {
		bytes_count = save_extended_states(index, xsave_ptr, index_buffer);
		if (bytes_count != index_size)
			DW_LOG(ERROR, DISASSEMBLY,
				   "Failed to save indices to register %s (encoded %zu / expected %zu)\n",
				   index_re->name, bytes_count, index_size);
	}
}

static void check_sib_access(struct memory_arg *mem, struct memory_arg_runtime* mem_rt,
					uintptr_t valueb, unsigned idx, bool repeat,
					bool repeat_conditional,
					struct patch_exec_context *ctx, bool can_restore_base)
{
	bool index_is_protected, base_is_protected;
	uintptr_t valuei = 0, valuei_clean = 0, addr;
	unsigned regi = mem->index;

	mem_rt->index_taint = 0;
	mem_rt->index_addr = 0;
	mem_rt->saved_address = 0;
	mem_rt->saved_value = 0;
	mem_rt->saved_base_value = 0;
	mem_rt->restore_base = false;

	index_is_protected = false;
	base_is_protected = dw_is_protected((void *) valueb);

	const struct reg_entry *re = mem->index_re;
	if (re != NULL && regi != X86_REG_INVALID) {
		valuei = dw_get_register(ctx, re->libpatch_index);
		mem_rt->index_addr = valuei_clean = valuei;
		index_is_protected = dw_is_protected((void *) valuei);

		if (index_is_protected) {
			if (base_is_protected)
				DW_LOG(WARNING, DISASSEMBLY, "Both index and base tainted for mem arg %u\n", idx);

			mem_rt->index_taint = valuei;
			valuei_clean = (uintptr_t) dw_unprotect((void *) valuei);
			dw_set_register(ctx, re->libpatch_index, valuei_clean);

		} else {
			mem_rt->index_taint = 0;
		}
	}

	/*
	 * Compound taint: the protected object-id is carried by the aggregate
	 * base + index*scale + disp, not by a single register. The base holds a
	 * scaled taint residue whose MSB is set, so dw_is_protected() rejects it
	 * and only the index gets untainted above. Left alone, the out-of-line
	 * instruction copy would refault on a noncanonical effective address.
	 *
	 * Rewrite the base to an execution value so the executed EA equals the
	 * clean target, and remember to restore the original (tainted) base in
	 * the post handler. Detection is self-certifying: an unrelated base will
	 * not make the aggregate resolve to a live object-id.
	 */
	if (unlikely(dw_sib_base_carries_compound_taint(valueb, valuei, mem->scale,
						   mem->displacement, base_is_protected,
						   index_is_protected))) {
		const struct reg_entry *reb = mem->base_re;
		if (reb != NULL && mem->base != X86_REG_INVALID) {
			uintptr_t valueb_exec = dw_sib_compound_base_exec(
				valueb, valuei, valuei_clean, mem->scale, mem->displacement);
			dw_set_register(ctx, reb->libpatch_index, valueb_exec);

			/*
			 * Restore the original (tainted) base after the access, unless the
			 * instruction overwrites the base register itself - in that case the
			 * instruction's result is the live value and must be kept.
			 */
			if ((mem->base_access & CS_AC_WRITE) == 0) {
				if (can_restore_base) {
					mem_rt->saved_base_value = valueb;
					mem_rt->restore_base = true;
				} else {
					DW_LOG(WARNING, DISASSEMBLY,
					       "Compound SIB taint at mem arg %u but base cannot be "
					       "restored (no post handler); register stays clean\n", idx);
				}
			}
		}
	}

	if (unlikely(!base_is_protected && !index_is_protected))
		return;

	// The effective address computed from tainted base and/or tainted index
	addr = valueb + valuei * mem->scale + mem->displacement;

	// Check if the access is valid, honoring REP semantics (count, direction).
	uint64_t count = 0;
	bool df = false;
	if (unlikely(repeat)) {
		count = dw_get_register(ctx, dw_get_reg_entry(X86_REG_RCX)->libpatch_index);
		/* libpatch stores the application RFLAGS in status_register. */
		df = (ctx->status_register & DW_EFLAGS_DF) != 0;
	}

	uintptr_t check_addr;
	size_t check_size;
	string_access_range(addr, mem->length, count, repeat, repeat_conditional, df,
			       &check_addr, &check_size);

	/* Size 0 (REP with RCX==0) means no access: nothing to check. */
	if (likely(check_size != 0))
		dw_check_access_ctx((void *) check_addr, check_size, ctx);

	/*
	* We have a special case, the same register is used to access the memory and as argument.
	*
	* - For a memory read, register write, do not retaint the ovewritten register in post handler.
	*
	* - For a memory read, register read, it is presumably a comparison. We must untaint the
	* register and the memory for a proper comparison, and retaint both the register and memory
	* in the post handler. We save the memory address and value, and untaint the value. In the post
	* handler we retaint the register, and restore the saved value at the saved address
	*
	* - For a memory write, register read, the untainted register is stored in memory, we should
	* retaint both the register and memory in the post handler.
	*
	* - For a memory write, register write, not sure what to do. Not retaint the register but
	* retaint memory?
	*/
	if (unlikely((mem->length == sizeof(uintptr_t)) &&
				 ((mem->base_access && mem_rt->base_taint != 0) ||
				  (mem->index_access && mem_rt->index_taint != 0)))) {

		/* Saving memory address must be done in the pre-handler. e.g., mov rdi, qword ptr [rdi+0x10] */
		uintptr_t valueb_clean = (uintptr_t) dw_unprotect((void *) valueb);
		mem_rt->saved_address = valueb_clean + valuei_clean * mem->scale + mem->displacement;

		if ((mem->access & CS_AC_READ) &&
			    (((mem->base_access & CS_AC_READ) && mem_rt->base_taint) ||
			    ((mem->index_access & CS_AC_READ) && mem_rt->index_taint))) {

			mem_rt->saved_value = (uintptr_t) *((void **)mem_rt->saved_address);
			*((void **)mem_rt->saved_address) = dw_unprotect((void *)(mem_rt->saved_value));
		}
	}
}

DW_INTERNAL void dw_unprotect_context(struct patch_exec_context *ctx)
{
	struct insn_entry *entry = ctx->user_data;
	struct memory_arg *mem;
	struct memory_arg_runtime *mem_rt;
	unsigned regb;
	uintptr_t valueb;
	struct insn_entry_runtime rt_slot, *rt_slot_p;

	if (unlikely(dw_check_handling)) {
		DW_LOG(DEBUG, DISASSEMBLY, "(-) Before unprotecting instruction 0x%llx: %s\n",
			    entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
	}

	if (entry->post_handler) {
		int rt_idx = 0;
		if (unlikely(!dw_acquire_runtime_slot(entry, &rt_idx)))
			DW_LOG(ERROR, DISASSEMBLY, "Problem getting a runtime slot for instruction 0x%llx\n", entry->insn);

		rt_slot_p = &insn_rt_slots[rt_idx];
	} else {
		rt_slot_p = &rt_slot;
	}

	for (int i = 0; i < entry->nb_arg_m; i++) {
		mem_rt = &(rt_slot_p->arg_m[i]);
		mem_rt->base_taint = 0;
		mem_rt->base_addr = 0;

		// Handle the base register
		mem = &(entry->arg_m[i]);
		regb = mem->base;
		valueb = 0;
		if (regb != X86_REG_INVALID) {
			const struct reg_entry *reb = mem->base_re;
			valueb = dw_get_register(ctx, reb->libpatch_index);
			mem_rt->base_addr = valueb;

			if (dw_is_protected((void *) valueb)) {
				mem_rt->base_taint = valueb;
				/* Footprint entries bounds-check the full fixed-field range before
				 * stripping.  Use the tainted valueb: dw_check_access_ctx extracts
				 * the OID from bits 48-63 and skips the check when oid==0 (a clean
				 * pointer would silently pass). Gated on deferred_post_handler: the
				 * widened footprint is only reachable straight-line when the base is
				 * actually stripped for the window; if the patch path abandoned
				 * deferral (AROUND), each in-window access faults and is checked at
				 * its own site, so here only the fault EA (check_sib_access) applies. */
				if (entry->footprint_check && entry->deferred_post_handler) {
					size_t footprint_size = (size_t)(entry->footprint_disp_hi - entry->footprint_disp_lo);
					dw_check_access_ctx((void *)(valueb + entry->footprint_disp_lo),
					                    footprint_size, ctx);
				}
				dw_set_register(ctx, reb->libpatch_index, (uintptr_t) dw_unprotect((void *) valueb));
			} else {
				mem_rt->base_taint = 0;
			}
		}

		// Handle the index register
		if (mem->index == X86_REG_INVALID || reg_is_gpr(mem->index))
			check_sib_access(mem, mem_rt, valueb, i, entry->repeat,
					 entry->repeat_conditional, ctx,
					 entry->post_handler);
		else if (reg_is_avx(mem->index))
			check_vsib_access(mem, mem_rt, valueb, i, ctx->extended_states, ctx);
		else
			DW_LOG(ERROR, DISASSEMBLY, "Invalid index register %u for mem arg %u\n", mem->index, i);
	}

	if (unlikely(dw_stats_enabled))
		atomic_fetch_add_explicit(&entry->hit_count, 1, memory_order_relaxed);

	if (unlikely(dw_check_handling)) {
			DW_LOG(DEBUG, DISASSEMBLY, "-- After unprotecting instruction 0x%llx\n", entry->insn);
			for (int i = 0; i < dw_nb_saved_registers; i++) {
				struct reg_entry *re = dw_get_reg_entry(dw_saved_registers[i]);
				dw_save_regs[i] = dw_get_register(ctx, re->libpatch_index);
				DW_LOG(DEBUG, DISASSEMBLY, "%s, %llx\n", re->name, ctx->general_purpose_registers[i]);
			}
	}
}

/*
 * Variant A loop-exit activation (fault-driven, no pre-probe). Invoked once per
 * loop entry directly from the SIGSEGV handler on a ucontext_t. It strips the
 * invariant tainted base in-place, bounds-checks the fault EA against the live
 * object, and stashes the taint into the entry's runtime slot so the loop-exit
 * post probe (dw_reprotect_context) re-applies it after the loop falls through.
 *
 * Gates in loop_exit_defer_site guarantee a single non-indexed mem arg with no
 * base_access and no REP, so this reduces to the plain base strip + check that
 * the normal pre-handler performs - it must never touch SIB/VSIB/compound state.
 *
 * Returns true iff a protected base was found and stripped (a slot is then held
 * for the post handler); false leaves the context untouched and releases nothing.
 */
DW_INTERNAL bool dw_loop_exit_activate_context(struct insn_entry *entry, ucontext_t *uctx)
{
	int rt_idx = 0;
	bool stripped = false;

	if (unlikely(!dw_acquire_runtime_slot(entry, &rt_idx))) {
		DW_LOG(ERROR, DISASSEMBLY, "Problem getting a runtime slot for loop-exit instruction 0x%llx\n",
			entry->insn);
		return false;
	}

	struct insn_entry_runtime *rt_slot_p = &insn_rt_slots[rt_idx];

	for (int i = 0; i < entry->nb_arg_m; i++) {
		struct memory_arg *mem = &entry->arg_m[i];
		struct memory_arg_runtime *mem_rt = &rt_slot_p->arg_m[i];

		mem_rt->base_taint = 0;
		mem_rt->base_addr = 0;

		/* Base-as-value args are rejected by the gates; never strip one. */
		if (mem->base_access)
			continue;

		const struct reg_entry *reb = mem->base_re;
		if (mem->base == X86_REG_INVALID || reb == NULL || reb->ucontext_index < 0)
			continue;

		uintptr_t valueb = dw_get_register(uctx, reb->ucontext_index);
		mem_rt->base_addr = valueb;

		if (!dw_is_protected((void *) valueb))
			continue;

		/* Bounds-check the fault EA (or the full footprint when wider) against
		 * the live object.  Use the tainted valueb: dw_check_access extracts the
		 * OID from bits 48-63 and returns early with oid==0 for a clean pointer. */
		if (entry->footprint_check) {
			size_t footprint_size = (size_t)(entry->footprint_disp_hi - entry->footprint_disp_lo);
			dw_check_access((void *)(valueb + entry->footprint_disp_lo), footprint_size);
		} else {
			dw_check_access((void *)(valueb + mem->displacement), mem->length);
		}

		mem_rt->base_taint = valueb;
		dw_set_register(uctx, reb->ucontext_index, (uintptr_t) dw_unprotect((void *) valueb));
		stripped = true;
	}

	if (!stripped) {
		dw_release_rt_slot(rt_idx);
		return false;
	}

	if (unlikely(dw_stats_enabled))
		atomic_fetch_add_explicit(&entry->hit_count, 1, memory_order_relaxed);

	return true;
}

static void check_updated_regs (struct insn_entry *entry, struct insn_entry_runtime *entry_rt, struct patch_exec_context *ctx) {
	struct memory_arg *mem;
	struct memory_arg_runtime *mem_rt;
	bool should_check[dw_nb_saved_registers];
	__builtin_memset(should_check, 0, sizeof(should_check));

	if (!entry->deferred_post_handler) {
		for (int i = 0; i < dw_nb_saved_registers; i++)
			should_check[i] = true;
	} else {
		for (int i = 0; i < entry->nb_arg_m; i++) {
			mem = &(entry->arg_m[i]);
			mem_rt = &(entry_rt->arg_m[i]);

			if (mem_rt->base_taint) {
				const struct reg_entry *reb = mem->base_re;
				if (reb) {
					for (size_t j = 0; j < dw_nb_saved_registers; j++) {
						const struct reg_entry *saved_re = dw_get_reg_entry(dw_saved_registers[j]);
						if (saved_re->canonical_index == reb->canonical_index) {
							should_check[j] = true;
							break;
						}
					}
				}
			}

			const struct reg_entry *rei = mem->index_re;
			if (rei && rei->canonical_index != X86_REG_INVALID && mem_rt->index_taint) {
				for (size_t j = 0; j < dw_nb_saved_registers; j++) {
					const struct reg_entry *saved_re = dw_get_reg_entry(dw_saved_registers[j]);
					if (saved_re->canonical_index == rei->canonical_index) {
						should_check[j] = true;
						break;
					}
				}
			}
		}
	}

	for (int i = 0; i < dw_nb_saved_registers; i++) {
		if (!should_check[i])
			continue;

		unsigned reg = dw_saved_registers[i];
		const struct reg_entry *re = dw_get_reg_entry(reg);
		if (!re || re->libpatch_index < 0)
			continue;

		uintptr_t value = dw_get_register(ctx, re->libpatch_index);
		if (dw_save_regs[i] != value && !dw_reg_written(entry, reg)) {
			DW_LOG(ERROR, DISASSEMBLY,
				"Instruction 0x%llx, register %s modified but should not, now 0x%llx vs 0x%llx\n",
				entry->insn, re->name, value, dw_save_regs[i]);
		}
	}
}

/*
 * Retaint one entry's tainted registers using an already-resolved runtime slot.
 * In the post handler, we normally retaint all registers which were untainted
 * in the pre handler. There are a few special cases when the same register is
 * used as a base or index to access the memory and as argument. The slot is
 * released before returning. Shared by the single-entry and plan-owner posts.
 */
static void dw_reprotect_one_entry(struct insn_entry *entry, int slot_idx,
				   struct patch_exec_context *ctx)
{
	struct memory_arg *mem;
	struct memory_arg_runtime *mem_rt;
	const struct reg_entry *re;
	unsigned reg;

	struct insn_entry_runtime *runtime_slot = &insn_rt_slots[slot_idx];

	if (unlikely(dw_check_handling)) {
		DW_LOG(DEBUG, DISASSEMBLY, "(+) Before reprotecting instruction 0x%llx: %s\n",
				    entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
		check_updated_regs(entry, runtime_slot, ctx);
	}

	for (int i = 0; i < entry->nb_arg_m; i++) {
		mem = &(entry->arg_m[i]);
		mem_rt = &runtime_slot->arg_m[i];

		/*
		 * Conditional REP scan (REPE/REPNE CMPS/SCAS): the pre handler could
		 * vouch for the first element only, because RCX is just an upper
		 * bound on the iteration count. Now that the scan has executed, the
		 * advanced pointer register exposes its exact extent; validate it
		 * while the register still holds the clean (not yet retainted) value.
		 */
		if (unlikely(entry->repeat_conditional) && mem_rt->base_taint &&
		    mem->base_re != NULL) {
			uintptr_t initial = (uintptr_t)dw_unprotect((void *)mem_rt->base_taint);
			uintptr_t final = (uintptr_t)dw_unprotect(
				(void *)dw_get_register(ctx, mem->base_re->libpatch_index));
			uintptr_t scan_addr;
			size_t scan_size;

			if (string_scan_extent(initial, final, mem->length,
						  &scan_addr, &scan_size))
				dw_check_access_ctx(
					dw_reprotect((void *)scan_addr, (void *)mem_rt->base_taint),
					scan_size, ctx);
		}

		/*
		 * The tainted register, base or index, is retainted unless the same register was also
		 * an overwritten register argument.
		 */
		if (mem_rt->base_taint && ((mem->base_access & CS_AC_WRITE) == 0)) {
			reg = mem->base;
			re = mem->base_re;
			const void* valueb_new = (const void*) dw_get_register(ctx, re->libpatch_index);
			dw_set_register(ctx, re->libpatch_index, (uint64_t) dw_reprotect(valueb_new, (void *) mem_rt->base_taint));
		}

		// Handle the VSIB case
		if (mem->index != X86_REG_INVALID && reg_is_avx(mem->index)) {
			re = mem->index_re;
			if (mem_rt->index_is_tainted) {
				reg = mem->index;
				size_t saved_bytes = save_extended_states(reg, ctx->extended_states, mem_rt->indices);
				if (saved_bytes != (mem->indices_count * mem->index_width))
					DW_LOG(ERROR, DISASSEMBLY,
						   "Failed to save the indices from register %s into the XSAVE area!\n",
						   re->name);
				// Reset this flag as it will be set again in the pre-handler
				mem_rt->index_is_tainted = false;
			}
			continue;
		}

		// Handle the SIB case
		if (mem_rt->index_taint && ((mem->index_access & CS_AC_WRITE) == 0)) {
			reg = mem->index;
			re = mem->index_re;

			const void* valuei_new = (const void*) dw_get_register(ctx, re->libpatch_index);
			dw_set_register(ctx, re->libpatch_index,
					(uint64_t) dw_reprotect((void *) valuei_new, (void *) mem_rt->index_taint));
		}

		/*
		 * Compound taint: the base was rewritten to an execution value in the
		 * pre handler so the access would land on the clean target. Restore the
		 * original (tainted) base value here. We restore the exact saved value
		 * rather than re-deriving a taint, because the residue carried by the
		 * base is not a simple object-id taint.
		 */
		if (unlikely(mem_rt->restore_base)) {
			re = mem->base_re;
			if (re != NULL && mem->base != X86_REG_INVALID)
				dw_set_register(ctx, re->libpatch_index, mem_rt->saved_base_value);
			mem_rt->restore_base = false;
		}

		/*
		* If the tainted register, base or index, was also a register argument, we have special
		* cases to consider.
		*/
		if (unlikely((mem->length == sizeof(uintptr_t)) &&
					 ((mem->base_access && mem_rt->base_taint) ||
					  (mem->index_access && mem_rt->index_taint)))) {
			/*
			* If the memory was read and the tainted register, base or index, was a read register
			* argument, we presumably have a comparison. The memory value was untainted in
			* the pre handler and should be restored here.
			*/

			if (mem->access & CS_AC_READ) {
				if (((mem->base_access & CS_AC_READ) && mem_rt->base_taint) ||
					((mem->index_access & CS_AC_READ) && mem_rt->index_taint))
					*((void **) mem_rt->saved_address) = (void *) (mem_rt->saved_value);

			}
			/*
			* If the memory was written and the tainted register, base or index, was also a
			* register argument we suppose that the untainted register was stored in memory and we
			* need to retaint the memory with the saved register taint.
			*/
			else if (mem->access & CS_AC_WRITE) {
				uintptr_t saved_taint;
				if(mem_rt->base_taint) saved_taint = mem_rt->base_taint;
				else saved_taint = mem_rt->index_taint;

				*((void **) mem_rt->saved_address) =
						dw_reprotect(*((void **) mem_rt->saved_address), (void *) saved_taint);
			}
		}
	}

	if (unlikely(dw_check_handling)) {
		DW_LOG(DEBUG, DISASSEMBLY, "-- After reprotecting instruction 0x%llx: %s\n",
			entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
	}

	dw_release_rt_slot(slot_idx);
}

/*
 * In the post handler, we normally retaint all registers which were untainted
 * in the pre handler. There are a few special cases when the same register is
 * used as a base or index to access the memory and as argument.
 */
DW_INTERNAL void dw_reprotect_context(struct patch_exec_context *ctx)
{
	struct insn_entry *entry = ctx->user_data;
	int slot_idx;

	/* If the runtime slot was not found, it means we jumped into an address
	   between the pre- and post-handler. Therefore, we simply ignore the
	   post-handler invocation */
	if (unlikely(!dw_find_runtime_slot(entry, &slot_idx)))
		return;

	dw_reprotect_one_entry(entry, slot_idx, ctx);
}

/*
 * Specialized pre-probe for base-only entries. Check base+disp, strip a
 * protected base, and save its taint when a post will restore it. Coherency
 * checking uses the generic handler.
 */
DW_INTERNAL void dw_unprotect_base_only(struct patch_exec_context *ctx)
{
	struct insn_entry *entry = ctx->user_data;

	if (unlikely(dw_check_handling)) {
		dw_unprotect_context(ctx);
		return;
	}

	struct memory_arg *mem = &entry->arg_m[0];
	const struct reg_entry *reb = mem->base_re;
	uintptr_t valueb = dw_get_register(ctx, reb->libpatch_index);

	/*
	 * Only a post needs saved state. On slot exhaustion, proceed untracked so
	 * the post skips retainting instead of corrupting another entry's slot.
	 */
	struct memory_arg_runtime *mem_rt = NULL;
	if (entry->post_handler) {
		int rt_idx;
		if (likely(dw_acquire_runtime_slot(entry, &rt_idx))) {
			mem_rt = &insn_rt_slots[rt_idx].arg_m[0];
			/* Fields the post reads unconditionally for this shape. */
			mem_rt->base_taint = 0;
			mem_rt->index_taint = 0;
			mem_rt->restore_base = false;
			mem_rt->base_addr = valueb;
		} else {
			DW_LOG(ERROR, DISASSEMBLY,
			       "Problem getting a runtime slot for instruction 0x%llx\n", entry->insn);
		}
	}

	if (dw_is_protected((void *) valueb)) {
		if (mem_rt)
			mem_rt->base_taint = valueb;
		/*
		 * A deferred entry that widened its footprint checks the whole
		 * [base+lo, base+hi) window here -- the in-window accesses run unchecked
		 * once the base is stripped, so this is their only validation against the
		 * object present at THIS execution. The footprint always covers the fault
		 * EA, so it replaces (not adds to) the single-EA check. Gated on
		 * deferred_post_handler: if the patch path fell back to an immediate
		 * AROUND probe, each in-window access faults and is checked at its own
		 * site, so only the fault EA applies here. */
		if (unlikely(entry->footprint_check && entry->deferred_post_handler))
			dw_check_access_ctx((void *) (valueb + entry->footprint_disp_lo),
					    (size_t) (entry->footprint_disp_hi - entry->footprint_disp_lo), ctx);
		else
			dw_check_access_ctx((void *) (valueb + mem->displacement), mem->length, ctx);
		dw_set_register(ctx, reb->libpatch_index, (uintptr_t) dw_unprotect((void *) valueb));
	}

	if (unlikely(dw_stats_enabled))
		atomic_fetch_add_explicit(&entry->hit_count, 1, memory_order_relaxed);
}

/*
 * Specialized post-probe for base-only entries. Restore the saved taint to the
 * current base value and release the slot. As in the generic path, no slot
 * means execution entered after the pre-probe, so there is nothing to restore.
 */
DW_INTERNAL void dw_reprotect_base_only(struct patch_exec_context *ctx)
{
	struct insn_entry *entry = ctx->user_data;

	if (unlikely(dw_check_handling)) {
		dw_reprotect_context(ctx);
		return;
	}

	int slot_idx;
	if (unlikely(!dw_find_runtime_slot(entry, &slot_idx)))
		return;

	struct memory_arg *mem = &entry->arg_m[0];
	struct memory_arg_runtime *mem_rt = &insn_rt_slots[slot_idx].arg_m[0];

	if (mem_rt->base_taint) {
		const struct reg_entry *re = mem->base_re;
		const void *valueb_new = (const void *) dw_get_register(ctx, re->libpatch_index);
		dw_set_register(ctx, re->libpatch_index,
				(uint64_t) dw_reprotect(valueb_new, (void *) mem_rt->base_taint));
	}

	dw_release_rt_slot(slot_idx);
}

/*
 * Shared loop-exit post (#5 coalescing): the firing entry is the OWNER of a
 * shared-exit plan, so one physical post at the loop's fall-through exit must
 * retaint every coalesced member (the owner plus all siblings). Each member's
 * invariant base was stripped independently at its own activation, so each
 * holds its own runtime slot in the CURRENT thread. Resolve and retaint the
 * members that hold a slot; skip the ones that do not (a member may not have
 * faulted/activated this loop entry on this thread). Crucially, unlike
 * dw_reprotect_context this must NOT bail on the first missing slot -- the
 * owner itself may hold no slot this entry while a sibling does.
 */
DW_INTERNAL void dw_reprotect_plan_context(struct patch_exec_context *ctx)
{
	struct insn_entry *owner = ctx->user_data;
	struct le_plan *plan = owner->loop_exit_plan;

	if (unlikely(!plan)) {
		/* Not actually a plan owner: fall back to the single-entry path. */
		dw_reprotect_context(ctx);
		return;
	}

	unsigned n = atomic_load_explicit(&plan->nb_members, memory_order_acquire);
	for (unsigned i = 0; i < n; i++) {
		struct insn_entry *member = plan->members[i];
		int slot_idx;

		if (!dw_find_runtime_slot(member, &slot_idx))
			continue; /* member didn't activate this entry on this thread */

		dw_reprotect_one_entry(member, slot_idx, ctx);
	}
}

/*
 * Print the content of the instruction table. Dump one row per instruction entry,
 * including symbol information, hit count, and other patching metadata.
 */
void dw_print_instruction_entries(instruction_table *table, int fd)
{
	struct insn_entry *entry;
	char proc_name[MAX_FUNC_NAME_LEN];
	char *proc_name_p;
	const int func_col_width = 40;
	unsigned count = 0;
	uintptr_t start, end, fault, offset;
	bool has_index;

	/* Header */
	dw_fprintf(fd, "%-5s %-18s %-*s %-10s %-10s %-8s %-9s %-6s %-6s %-10s %-6s %-6s %s\n",
				   "#", "ip", func_col_width, "func", "off", "hits", "len", "m_args",
				   "index", "post", "defer", "fast", "strat", "disasm");

	for (int i = 0; i < table->size; i++) {

		entry = &(table->entries[i]);
		if (atomic_load_explicit(&entry->state, memory_order_acquire) != ENTRY_READY)
			continue;

		fault = entry->patch_insn ? entry->patch_insn : entry->insn;
		start = 0;
		end = 0;
		proc_name_p = proc_name;

		struct func_cache_entry *e = func_cache_lookup(fault);
		if (!e) {
			dw_lookup_symbol(fault, proc_name, sizeof(proc_name), &start, &end);
			if (start != 0 && end > start)
				e = func_cache_insert(start, end, proc_name);
		}

		if (e) {
			proc_name_p = e->func_name;
			start = e->start_ip;
		}

		offset = 0;
		has_index = false;
		if (start)
			offset = fault - start;

		for (unsigned j = 0; j < entry->nb_arg_m; j++) {
			if (entry->arg_m[j].index != X86_REG_INVALID) {
				has_index = true;
				break;
			}
		}

		dw_fprintf(fd, "%-5u 0x%-16lx %-*s 0x%-8lx %-10lu %-8u %-9u %-6u %-6u %-10u %-6u %-6u %s\n",
				   count,
				   (unsigned long)fault,
				   func_col_width,
				   proc_name_p,
				   (unsigned long)offset,
				   atomic_load(&entry->hit_count),
				   entry->insn_length,
				   entry->nb_arg_m,
				   (unsigned)has_index,
				   (unsigned)entry->post_handler,
				   (unsigned)entry->deferred_post_handler,
				   (unsigned)(entry->fast_kind == DW_FAST_MOV_FIXED_FIELD),
				   entry->strategy,
				   entry->disasm_insn);

		count++;
	}

#ifdef DW_LEBUSY_DEBUG
	/*
	 * Shared loop-exit coalescing (#5) summary. Walk the committed plan registry
	 * and report, per shared exit, the owner plus the number of attached sibling
	 * bases and their summed hit_count -- the dynamic faults that now collapse
	 * onto the owner's single exit post instead of paying their own per-iteration
	 * retaint. A plan with nb_members == 1 is a lone owner (no coalescing yet).
	 */
	unsigned nb_plans = atomic_load_explicit(&dw_le_plan_count, memory_order_acquire);
	unsigned nb_shared = 0, nb_siblings_total = 0;

	dw_fprintf(fd, "\n#5 shared loop-exit coalescing (committed plans: %u):\n", nb_plans);
	dw_fprintf(fd, "  %-18s %-8s %-12s\n", "exit_target", "members", "sibling_hits");
	for (unsigned p = 0; p < nb_plans; p++) {
		struct le_plan *plan = &dw_le_plans[p];
		unsigned m = atomic_load_explicit(&plan->nb_members, memory_order_acquire);
		unsigned long sib_hits = 0;

		/* members[0] is the owner; the rest are coalesced siblings. */
		for (unsigned k = 1; k < m; k++)
			sib_hits += atomic_load(&plan->members[k]->hit_count);

		if (m > 1) {
			nb_shared++;
			nb_siblings_total += (m - 1);
		}
		dw_fprintf(fd, "  0x%-16lx %-8u %-12lu\n",
			   (unsigned long)plan->exit_target, m, sib_hits);
	}
	dw_fprintf(fd,
		   "  shared exits (>=1 sibling): %u | coalesced siblings total: %u\n",
		   nb_shared, nb_siblings_total);
#endif /* DW_LEBUSY_DEBUG */
}

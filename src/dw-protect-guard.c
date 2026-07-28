#define _GNU_SOURCE

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/mman.h>

#include "attributes.h"
#include "dw-backtrace.h"
#include "dw-log.h"
#include "dw-protect-guard.h"

/*
 * Guard-page allocation backend. See dw-protect-guard.h for the model.
 *
 * Layout (right guard, end-aligned):
 *
 *   [ accessible slack ][ object bytes ][ PROT_NONE guard page ]
 *   ^ mapping                           ^ guard_page (page aligned)
 *           ^ user = (guard_page - size) rounded DOWN to 16 bytes
 *
 * The user pointer is aligned down to DW_GUARD_ALIGN (16, the max_align_t
 * guarantee) so the ABI alignment callers rely on is preserved. This can leave
 * a 0..15 byte gap before the guard page in which the very last overflow bytes
 * are not trapped; page-crossing and larger overflows are still caught.
 *
 * To catch those sub-guard-page overflows, the gap [user+size, guard_page) is
 * stamped with a fixed redzone byte (DW_GUARD_REDZONE_BYTE) at allocation and
 * re-checked at free(): any byte that no longer matches indicates a small
 * overflow write that never reached the trapping page. The gap is re-stamped on
 * in-place realloc, since the object end (and thus the redzone) moves with the
 * requested size.
 */

#define DW_GUARD_ALIGN        16u
#define DW_GUARD_TABLE_CAP    65536u   /* hard upper bound on table size */
#define DW_GUARD_STEP_PAGES   2u
#define DW_GUARD_EFLAGS_TF    (1ULL << 8)
#define GUARD_SNAPSHOT_RETRIES 4u

/*
 * Byte written across the trailing redzone gap. A repeated constant cannot
 * detect an overflow that happens to write this same value, but catches the
 * overwhelming majority of stray writes (pointers, lengths, ASCII, zero-fill).
 */
#define DW_GUARD_REDZONE_BYTE 0xCBu

/*
 * Sentinel stored in a slot's `user` field while the allocator is writing the
 * slot's metadata. Readers (free/get_size/fault) treat it as "not ready" and
 * skip it. A real user pointer is a 16-byte-aligned mmap address, never 1.
 */
#define GUARD_SLOT_CLAIMING   ((uintptr_t)1)

struct guard_alloc {
	_Atomic(uint64_t) sequence; /* even = stable; odd = metadata update */
	_Atomic(uintptr_t) user;   /* 0 = free; 1 = claiming; else live user pointer */
	_Atomic(uintptr_t) mapping;        /* mmap base, for munmap */
	_Atomic(size_t) mapping_len;       /* total bytes mapped */
	_Atomic(size_t) requested_size;    /* user-visible size */
	_Atomic(uintptr_t) guard_page;     /* PROT_NONE page base */
	_Atomic(uintptr_t) alloc_ip;       /* caller IP, for diagnostics */
};

struct guard_snapshot {
	uint64_t sequence;
	uintptr_t user;
	uintptr_t mapping;
	size_t mapping_len;
	size_t requested_size;
	uintptr_t guard_page;
	uintptr_t alloc_ip;
};

struct guard_step_page {
	unsigned slot;
	uint64_t sequence;
	uintptr_t user;
	uintptr_t guard_page;
};

struct guard_step_state {
	bool active;
	uintptr_t fault_rip;
	unsigned count;
	struct guard_step_page pages[DW_GUARD_STEP_PAGES];
};

static __thread struct guard_step_state guard_step
	__attribute__((tls_model("initial-exec")));

/* Configuration, set once in dw_guard_configure() before any allocation. */
static bool   guard_enabled    = false;
static size_t guard_min_size   = 0;
static bool   guard_abort      = true;
static long   guard_page_size  = 4096;

static struct guard_alloc guard_table[DW_GUARD_TABLE_CAP];
static unsigned guard_table_cap = 0;   /* active size <= DW_GUARD_TABLE_CAP */

/*
 * Address range covering all live guarded user pointers, for an O(1) reject on
 * the free/get_size/fault paths before scanning the table. Updated (widening
 * only) on allocation; never shrunk, which only ever costs an extra rejected
 * scan, never correctness.
 */
static _Atomic(uintptr_t) guard_lo = UINTPTR_MAX;
static _Atomic(uintptr_t) guard_hi = 0;

static inline size_t round_up(size_t v, size_t a)
{
	return (v + a - 1) & ~(a - 1);
}

/*
 * Fill the trailing redzone [user+size, guard_page) with the canary byte. The
 * region is part of the RW mapping (it precedes the PROT_NONE page), so this is
 * a plain store. A zero-length gap (object end already abuts the guard page) is
 * a no-op.
 */
static inline void guard_stamp_redzone(uintptr_t user, size_t size, uintptr_t guard_page)
{
	uintptr_t rz = user + size;
	if (rz < guard_page)
		memset((void *)rz, DW_GUARD_REDZONE_BYTE, (size_t)(guard_page - rz));
}

void dw_guard_configure(size_t min_size, size_t max_objects, bool abort_on_fault)
{
	guard_min_size = min_size;
	guard_abort    = abort_on_fault;
	guard_enabled  = (min_size > 0);

	long ps = sysconf(_SC_PAGESIZE);
	if (ps > 0)
		guard_page_size = ps;

	if (max_objects == 0)
		max_objects = 1;
	if (max_objects > DW_GUARD_TABLE_CAP)
		max_objects = DW_GUARD_TABLE_CAP;
	guard_table_cap = (unsigned)max_objects;
}

bool dw_guard_enabled_for_size(size_t size)
{
	return guard_enabled && size >= guard_min_size;
}

/* Widen the live-pointer address range to include [user, user+size). */
static void guard_range_extend(uintptr_t user, size_t size)
{
	uintptr_t lo = atomic_load_explicit(&guard_lo, memory_order_relaxed);
	while (user < lo &&
		   !atomic_compare_exchange_weak_explicit(&guard_lo, &lo, user,
						   memory_order_relaxed, memory_order_relaxed))
		; /* lo reloaded on failure */

	uintptr_t end = user + size;
	uintptr_t hi = atomic_load_explicit(&guard_hi, memory_order_relaxed);
	while (end > hi &&
		   !atomic_compare_exchange_weak_explicit(&guard_hi, &hi, end,
						   memory_order_relaxed, memory_order_relaxed))
		; /* hi reloaded on failure */
}

static inline bool guard_in_range(uintptr_t addr)
{
	return addr >= atomic_load_explicit(&guard_lo, memory_order_relaxed) &&
		   addr <  atomic_load_explicit(&guard_hi, memory_order_relaxed);
}

/*
 * Slot writers first claim user, then bracket all metadata changes with an odd
 * sequence value. Readers copy only an even, unchanged generation and recheck
 * user, so they cannot combine fields from a freed and reused slot.
 */
static inline void guard_slot_write_begin(struct guard_alloc *slot)
{
	atomic_fetch_add_explicit(&slot->sequence, 1, memory_order_acq_rel);
}

static inline void guard_slot_write_end(struct guard_alloc *slot)
{
	atomic_fetch_add_explicit(&slot->sequence, 1, memory_order_release);
}

static bool guard_slot_snapshot(unsigned index, struct guard_snapshot *out)
{
	struct guard_alloc *slot = &guard_table[index];

	for (unsigned attempt = 0; attempt < GUARD_SNAPSHOT_RETRIES; attempt++) {
		uint64_t sequence = atomic_load_explicit(&slot->sequence,
							memory_order_acquire);
		if (sequence & 1)
			continue;

		uintptr_t user = atomic_load_explicit(&slot->user,
						     memory_order_acquire);
		if (user <= GUARD_SLOT_CLAIMING)
			return false;

		uintptr_t mapping = atomic_load_explicit(&slot->mapping,
							memory_order_acquire);
		size_t mapping_len = atomic_load_explicit(&slot->mapping_len,
							 memory_order_acquire);
		size_t requested_size = atomic_load_explicit(&slot->requested_size,
							    memory_order_acquire);
		uintptr_t guard_page = atomic_load_explicit(&slot->guard_page,
							   memory_order_acquire);
		uintptr_t alloc_ip = atomic_load_explicit(&slot->alloc_ip,
							 memory_order_acquire);
		uintptr_t user_check = atomic_load_explicit(&slot->user,
							   memory_order_acquire);
		uint64_t sequence_check = atomic_load_explicit(&slot->sequence,
							      memory_order_acquire);

		if (sequence != sequence_check || (sequence_check & 1) ||
		    user != user_check)
			continue;

		*out = (struct guard_snapshot) {
			.sequence = sequence,
			.user = user,
			.mapping = mapping,
			.mapping_len = mapping_len,
			.requested_size = requested_size,
			.guard_page = guard_page,
			.alloc_ip = alloc_ip,
		};
		return true;
	}

	return false;
}

static bool guard_snapshot_is_current(unsigned index,
				      const struct guard_snapshot *snapshot)
{
	struct guard_snapshot current;

	return guard_slot_snapshot(index, &current) &&
	       current.sequence == snapshot->sequence &&
	       current.user == snapshot->user &&
	       current.mapping == snapshot->mapping &&
	       current.guard_page == snapshot->guard_page;
}

static int guard_claim_slot(uintptr_t ptr)
{
	if (!guard_in_range(ptr))
		return -1;

	for (unsigned i = 0; i < guard_table_cap; i++) {
		uintptr_t expected = ptr;
		if (atomic_compare_exchange_strong_explicit(&guard_table[i].user,
				&expected, GUARD_SLOT_CLAIMING,
				memory_order_acq_rel, memory_order_relaxed))
			return (int)i;
	}

	return -1;
}

static int guard_find_snapshot(uintptr_t ptr, struct guard_snapshot *snapshot)
{
	if (!guard_in_range(ptr))
		return -1;

	for (unsigned i = 0; i < guard_table_cap; i++) {
		if (guard_slot_snapshot(i, snapshot) && snapshot->user == ptr)
			return (int)i;
	}

	return -1;
}

void *dw_guard_malloc(size_t size, void *caller)
{
	if (!guard_enabled || size == 0)
		return NULL;

	size_t page = (size_t)guard_page_size;

	/*
	 * Reject sizes whose guard-page rounding would overflow. Without these
	 * checks round_up() and the trailing guard page wrap to a small
	 * mapping_len, mmap() a too-small region, and make
	 * `user = guard_page - size` underflow into a wild pointer. Such an
	 * allocation cannot succeed anyway, so fall back to the OID backend.
	 */
	if (size > SIZE_MAX - page)
		return NULL;
	size_t usable = round_up(size, page);
	if (usable > SIZE_MAX - page)
		return NULL;
	size_t mapping_len = usable + page;

	void *mapping = mmap(NULL, mapping_len, PROT_READ | PROT_WRITE,
						 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		return NULL;

	void *guard_page = (char *)mapping + usable;
	if (mprotect(guard_page, page, PROT_NONE) != 0) {
		munmap(mapping, mapping_len);
		return NULL;
	}

	uintptr_t user = ((uintptr_t)guard_page - size) & ~(uintptr_t)(DW_GUARD_ALIGN - 1);

	/* Stamp the trailing redzone so free() can detect a sub-page overflow. */
	guard_stamp_redzone(user, size, (uintptr_t)guard_page);

	/*
	 * Claim a free slot (user 0 -> CLAIMING), fill the metadata, then publish
	 * the real user pointer with release ordering. A concurrent reader that
	 * sees the slot still CLAIMING skips it; one that sees the published user
	 * is guaranteed (acquire) to see the metadata.
	 */
	for (unsigned i = 0; i < guard_table_cap; i++) {
		uintptr_t expected = 0;
		if (atomic_compare_exchange_strong_explicit(&guard_table[i].user, &expected,
				GUARD_SLOT_CLAIMING, memory_order_acq_rel, memory_order_relaxed)) {
			struct guard_alloc *slot = &guard_table[i];
			guard_slot_write_begin(slot);
			atomic_store_explicit(&slot->mapping, (uintptr_t)mapping, memory_order_relaxed);
			atomic_store_explicit(&slot->mapping_len, mapping_len, memory_order_relaxed);
			atomic_store_explicit(&slot->requested_size, size, memory_order_relaxed);
			atomic_store_explicit(&slot->guard_page, (uintptr_t)guard_page, memory_order_relaxed);
			atomic_store_explicit(&slot->alloc_ip, (uintptr_t)caller, memory_order_relaxed);
			guard_slot_write_end(slot);
			atomic_store_explicit(&slot->user, user, memory_order_release);
			guard_range_extend(user, size);
			return (void *)user;
		}
	}

	/* Table full: fall back to OID. */
	munmap(mapping, mapping_len);
	return NULL;
}

bool dw_guard_realloc_inplace(void *ptr, size_t new_size)
{
	if (!guard_enabled || ptr == NULL)
		return false;

	uintptr_t user = (uintptr_t)ptr;
	int i = guard_claim_slot(user);
	if (i < 0)
		return false;

	struct guard_alloc *slot = &guard_table[i];
	guard_slot_write_begin(slot);

	uintptr_t guard_end = atomic_load_explicit(&slot->guard_page,
						  memory_order_relaxed);
	size_t capacity = (size_t)(guard_end - user);
	if (new_size > capacity) {
		guard_slot_write_end(slot);
		atomic_store_explicit(&slot->user, user, memory_order_release);
		return false;
	}

	/* The object end moved, so re-stamp the redzone over the new gap. */
	guard_stamp_redzone(user, new_size, guard_end);
	atomic_store_explicit(&slot->requested_size, new_size, memory_order_relaxed);
	guard_slot_write_end(slot);
	atomic_store_explicit(&slot->user, user, memory_order_release);
	return true;
}

static DW_NOINLINE
void dw_guard_report_redzone(const struct guard_snapshot *snapshot,
				uintptr_t rz_start, size_t rz_len,
				size_t first_bad)
{
	uintptr_t user = snapshot->user;
	size_t size = snapshot->requested_size;
	uintptr_t guard_page = snapshot->guard_page;
	uintptr_t alloc_ip = snapshot->alloc_ip;

	char proc_name[256];
	char *proc_name_p = proc_name;
	uint64_t offset = 0;
	uintptr_t start = 0, end = 0;
	dw_lookup_symbol((uintptr_t)alloc_ip, proc_name, sizeof(proc_name), &start, &end);
	if (start != 0 && end > start)
		offset = (uintptr_t)alloc_ip - start;
	else
		proc_name_p = "??";

	uintptr_t bad_addr = rz_start + first_bad;
	unsigned char bad_val = *(volatile unsigned char *)bad_addr;

	DW_LOG_APP(WARNING, PROTECT,
			"Guard redzone corruption detected at free()\n"
			"  Allocation:\n"
			"    user   = 0x%llx\n"
			"    size   = %zu bytes\n"
			"    range  = [0x%llx..0x%llx)\n"
			"    guard  = 0x%llx\n"
			"    site   = (%s+0x%lx)\n"
			"  Redzone:\n"
			"    range  = [0x%llx..0x%llx) (%zu bytes, canary 0x%02x)\n"
			"  Violation:\n"
			"    byte 0x%llx = 0x%02x (expected 0x%02x), %zu byte(s) past the %zu-byte object\n"
			"  Backtrace:\n",
			(unsigned long long)user, size,
			(unsigned long long)user, (unsigned long long)(user + size),
			(unsigned long long)(uintptr_t)guard_page,
			proc_name_p, offset,
			(unsigned long long)rz_start,
			(unsigned long long)(rz_start + rz_len), rz_len,
			DW_GUARD_REDZONE_BYTE,
			(unsigned long long)bad_addr, bad_val,
			DW_GUARD_REDZONE_BYTE, first_bad, size);
}

/*
 * Verify the trailing redzone of a guarded object before it is unmapped. A byte
 * that no longer matches the canary means a small overflow wrote past the object
 * without reaching the trapping guard page. Reports (and, if configured, aborts).
 */
static void guard_check_redzone(const struct guard_snapshot *snapshot)
{
	uintptr_t user = snapshot->user;
	size_t size = snapshot->requested_size;
	uintptr_t guard_page = snapshot->guard_page;
	uintptr_t rz = user + size;
	if (rz >= guard_page)
		return; /* object end abuts the guard page: no redzone to check */

	const unsigned char *p = (const unsigned char *)rz;
	size_t n = (size_t)(guard_page - rz);
	for (size_t k = 0; k < n; k++) {
		if (p[k] != (unsigned char)DW_GUARD_REDZONE_BYTE) {
			dw_guard_report_redzone(snapshot, rz, n, k);
			if (guard_abort)
				abort();
			return;
		}
	}
}

bool dw_guard_free(void *ptr)
{
	if (!guard_enabled || ptr == NULL)
		return false;

	uintptr_t user = (uintptr_t)ptr;
	int i = guard_claim_slot(user);
	if (i < 0)
		return false;

	struct guard_alloc *slot = &guard_table[i];
	guard_slot_write_begin(slot);
	struct guard_snapshot snapshot = {
		.user = user,
		.mapping = atomic_load_explicit(&slot->mapping, memory_order_relaxed),
		.mapping_len = atomic_load_explicit(&slot->mapping_len, memory_order_relaxed),
		.requested_size = atomic_load_explicit(&slot->requested_size,
						      memory_order_relaxed),
		.guard_page = atomic_load_explicit(&slot->guard_page, memory_order_relaxed),
		.alloc_ip = atomic_load_explicit(&slot->alloc_ip, memory_order_relaxed),
	};

	/* Detect a sub-guard-page overflow before tearing the mapping down. */
	guard_check_redzone(&snapshot);
	munmap((void *)snapshot.mapping, snapshot.mapping_len);

	atomic_store_explicit(&slot->mapping, 0, memory_order_relaxed);
	atomic_store_explicit(&slot->mapping_len, 0, memory_order_relaxed);
	atomic_store_explicit(&slot->requested_size, 0, memory_order_relaxed);
	atomic_store_explicit(&slot->guard_page, 0, memory_order_relaxed);
	atomic_store_explicit(&slot->alloc_ip, 0, memory_order_relaxed);
	guard_slot_write_end(slot);
	atomic_store_explicit(&slot->user, 0, memory_order_release);
	return true;
}

bool dw_guard_get_size(void *ptr, size_t *size_out)
{
	if (!guard_enabled || ptr == NULL)
		return false;

	struct guard_snapshot snapshot;
	if (guard_find_snapshot((uintptr_t)ptr, &snapshot) < 0)
		return false;

	if (size_out)
		*size_out = snapshot.requested_size;
	return true;
}

static DW_NOINLINE
void dw_guard_report(const struct guard_snapshot *snapshot, uintptr_t fault_addr)
{
	uintptr_t user = snapshot->user;
	size_t size = snapshot->requested_size;
	uintptr_t guard_page = snapshot->guard_page;
	uintptr_t mapping = snapshot->mapping;
	uintptr_t alloc_ip = snapshot->alloc_ip;

	char proc_name[256];
	char *proc_name_p = proc_name;
	uint64_t offset = 0;
	uintptr_t start = 0, end = 0;
	dw_lookup_symbol((uintptr_t)alloc_ip, proc_name, sizeof(proc_name), &start, &end);
	if (start != 0 && end > start)
		offset = (uintptr_t)alloc_ip - start;
	else
		proc_name_p = "??";

	uintptr_t obj_end = user + size;
	size_t overflow = (fault_addr >= obj_end) ? (size_t)(fault_addr - obj_end) : 0;

	DW_LOG_APP(WARNING, PROTECT,
			"Guard-page out-of-bounds access detected\n"
			"  Allocation:\n"
			"    user   = 0x%llx\n"
			"    size   = %zu bytes\n"
			"    range  = [0x%llx..0x%llx)\n"
			"    mapping= 0x%llx\n"
			"    guard  = 0x%llx\n"
			"    site   = (%s+0x%lx)\n"
			"  Access:\n"
			"    addr   = 0x%llx\n"
			"  Violation:\n"
			"    overflows allocation by %zu bytes (into guard page)\n"
			"  Backtrace:\n",
			(unsigned long long)user, size,
			(unsigned long long)user, (unsigned long long)obj_end,
			(unsigned long long)(uintptr_t)mapping,
			(unsigned long long)(uintptr_t)guard_page,
			proc_name_p, offset,
			(unsigned long long)fault_addr, overflow);
}

static void guard_step_clear(void)
{
	guard_step.active = false;
	guard_step.fault_rip = 0;
	guard_step.count = 0;
}

static void guard_step_restore_pages(void)
{
	size_t page_size = (size_t)guard_page_size;

	for (unsigned i = 0; i < guard_step.count; i++) {
		const struct guard_step_page *step_page = &guard_step.pages[i];
		struct guard_snapshot current;

		/*
		 * Do not change an unrelated mapping that reused this virtual address.
		 * An in-place realloc changes the sequence but keeps user/guard_page, so
		 * the identity fallback still restores that allocation's guard.
		 */
		if (!guard_slot_snapshot(step_page->slot, &current) ||
		    current.guard_page != step_page->guard_page ||
		    (current.sequence != step_page->sequence &&
		     current.user != step_page->user))
			continue;

		if (mprotect((void *)step_page->guard_page, page_size, PROT_NONE) != 0)
			DW_LOG(ERROR, PROTECT,
			       "Failed to restore guard page at 0x%llx after single-step\n",
			       (unsigned long long)step_page->guard_page);
	}

	guard_step_clear();
}

static bool guard_step_allow_access(unsigned slot,
				    const struct guard_snapshot *snapshot,
				    ucontext_t *uctx)
{
	uintptr_t fault_rip = (uintptr_t)uctx->uc_mcontext.gregs[REG_RIP];

	if (guard_step.active && guard_step.fault_rip != fault_rip)
		guard_step_restore_pages();

	if (guard_step.active) {
		for (unsigned i = 0; i < guard_step.count; i++) {
			if (guard_step.pages[i].guard_page == snapshot->guard_page) {
				guard_step_restore_pages();
				uctx->uc_mcontext.gregs[REG_EFL] &=
					~(greg_t)DW_GUARD_EFLAGS_TF;
				return false;
			}
		}
	} else {
		guard_step.fault_rip = fault_rip;
	}

	if (guard_step.count == DW_GUARD_STEP_PAGES) {
		guard_step_restore_pages();
		uctx->uc_mcontext.gregs[REG_EFL] &= ~(greg_t)DW_GUARD_EFLAGS_TF;
		return false;
	}

	if (mprotect((void *)snapshot->guard_page, (size_t)guard_page_size,
		     PROT_READ | PROT_WRITE) != 0) {
		guard_step_restore_pages();
		uctx->uc_mcontext.gregs[REG_EFL] &= ~(greg_t)DW_GUARD_EFLAGS_TF;
		return false;
	}

	guard_step.pages[guard_step.count++] = (struct guard_step_page) {
		.slot = slot,
		.sequence = snapshot->sequence,
		.user = snapshot->user,
		.guard_page = snapshot->guard_page,
	};
	guard_step.active = true;
	uctx->uc_mcontext.gregs[REG_EFL] |= (greg_t)DW_GUARD_EFLAGS_TF;
	return true;
}

bool dw_guard_handle_trap(void *context)
{
	if (!guard_step.active || context == NULL)
		return false;

	ucontext_t *uctx = (ucontext_t *)context;
	uintptr_t trap_rip = (uintptr_t)uctx->uc_mcontext.gregs[REG_RIP];

	/*
	 * REP string instructions may generate one trace trap per iteration while
	 * RIP still names the same instruction. Keep the page open and TF armed
	 * until the instruction actually advances.
	 */
	if (trap_rip == guard_step.fault_rip) {
		uctx->uc_mcontext.gregs[REG_EFL] |= (greg_t)DW_GUARD_EFLAGS_TF;
		return true;
	}

	uctx->uc_mcontext.gregs[REG_EFL] &= ~(greg_t)DW_GUARD_EFLAGS_TF;
	guard_step_restore_pages();
	return true;
}

bool dw_guard_handle_fault(void *fault_addr, void *context)
{
	if (!guard_enabled || fault_addr == NULL)
		return false;

	uintptr_t addr = (uintptr_t)fault_addr;
	size_t page = (size_t)guard_page_size;
	unsigned matched_slot = 0;
	struct guard_snapshot matched = {0};
	bool found = false;

	for (unsigned i = 0; i < guard_table_cap; i++) {
		struct guard_snapshot candidate;
		if (!guard_slot_snapshot(i, &candidate))
			continue;

		uintptr_t gp = candidate.guard_page;
		if (addr < gp || addr - gp >= page)
			continue;

		/* Re-read the generation immediately before using the copied fields. */
		if (!guard_snapshot_is_current(i, &candidate))
			continue;

		matched_slot = i;
		matched = candidate;
		found = true;
		break;
	}

	if (!found)
		return false;

	dw_guard_report(&matched, addr);

	if (guard_abort)
		abort();

	/*
	 * Reporting is deliberately outside the slot, so another thread may have
	 * freed or reused it meanwhile. Revalidate once more before changing page
	 * permissions for non-abort continuation.
	 */
	if (!guard_snapshot_is_current(matched_slot, &matched))
		return false;

	if (context == NULL)
		return false;

	return guard_step_allow_access(matched_slot, &matched,
				       (ucontext_t *)context);
}

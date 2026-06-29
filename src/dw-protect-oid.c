#include <malloc.h>
#include <stdatomic.h>
#include <stdint.h>

#include "dw-protect.h"
#include "dw-log.h"


const uintptr_t taint_mask =    (uintptr_t)0xffff000000000000;
const uintptr_t untaint_mask =  (uintptr_t)0x0000ffffffffffff;

/*
 * Table of malloc objects tracked by tainted pointers.
 * The taint is the index + 1 since a taint of 0 would not
 * trigger a SIGSEGV. With the base_addr and the size, we can check
 * if the bytes accessed are within the allocated bounds for the object.

 * The base_addr field is NULL when the entry is not in use.
 * In that case, the size field contains the index of the next
 * entry in the free list, or 0 if this is the free list end.
 * The array entry at index zero is not used since this would
 * correspond to a null taint, no taint. Moreover, index 0 is
 * reserved for the free list end.
 */

struct object_id {
	_Atomic(void *) base_addr;
	_Atomic size_t size;

	void *alloc_ip;
};

/*
 * We use the upper 2 bytes of the pointer to store an object ID (taint tag),
 * so the ID is limited to a 16-bit value (< 2^16).
 *
 * The top bit of the tag (bit 15) must be 0 so that the resulting 64-bit
 * value is not interpreted as a negative signed integer. This restricts
 * valid tags to the range 0x0000–0x7FFF (2^15 possible values).
 *
 * We reserve tag 0 (0x0000) to mean "no taint", so we can use tags
 * 0x0001–0x7FFF, i.e., up to 2^15 - 1 = 32767 distinct tainted IDs.
 */
static const unsigned oids_size = 32767;
/* Packed free-list head: lower 16 bits = head index, upper bits = ABA counter. */
static _Atomic uint64_t oids_head = 0;
static struct object_id oids[32767];

/*
 *
 * A hot loop that repeatedly dereferences pointers into the same object hits
 * the same OID millions of times; each hit otherwise reloads base_addr/size
 * from the shared ~768 KB oids[] array -- a likely cache miss on a random slot.
 * This thread-local entry memoises {base,size} for the last validated OID so a
 * repeat hit collapses to two integer compares against a thread-private line.
 *
 * Soundness rests on one fact about the table: a *live* slot's {base,size} is
 * immutable. dw_protect() sets them once at allocation; realloc() is a fresh
 * dw_protect() plus a free() of the old slot (see realloc() in dw-preload.c);
 * the only mutation of a live slot is base_addr -> NULL at free(). So a cached
 * entry can be invalidated by exactly one kind of event: a free. dw_free_protect()
 * bumps the global epoch below, and an entry is trusted only while its recorded
 * epoch still equals the current one -- i.e. no free of any object has happened
 * since it was filled, which guarantees this OID's slot still holds the same
 * live object. Conservative (an unrelated free invalidates every thread's
 * cache) but always correct, and alloc-only / free-free hot loops (e.g. mcf)
 * keep the epoch stable.
 */
static _Atomic uint64_t dw_oid_epoch = 0;

struct dw_oid_cache {
	unsigned  oid;    /* 0 means empty; OID 0 is "no taint" and is never cached. */
	uint64_t  epoch;
	uintptr_t base;
	size_t    size;
};

static __thread struct dw_oid_cache dw_tls_oid_cache
	__attribute__((tls_model("initial-exec")));

#define OIDS_HEAD_IDX_MASK UINT64_C(0xFFFF)

static inline unsigned oids_head_get_idx(uint64_t head)
{
	return (unsigned)(head & OIDS_HEAD_IDX_MASK);
}

static inline uint64_t oids_head_get_counter(uint64_t head)
{
	return head >> 16;
}

static inline uint64_t oids_head_pack(unsigned idx, uint64_t counter)
{
	return (counter << 16) | ((uint64_t)idx & OIDS_HEAD_IDX_MASK);
}

static inline unsigned dw_oid_alloc(void)
{
	uint64_t head = atomic_load_explicit(&oids_head, memory_order_acquire);

	while (1) {
		unsigned idx = oids_head_get_idx(head);
		if (idx == 0)
			return 0;
		if (idx >= oids_size) {
			DW_LOG(ERROR, PROTECT, "OID free list corrupted (head=%u)\n", idx);
			return 0;
		}

		unsigned next = (unsigned)atomic_load_explicit(&oids[idx].size, memory_order_relaxed);
		if (next >= oids_size) {
			DW_LOG(ERROR, PROTECT, "OID free list corrupted (next=%u)\n", next);
			return 0;
		}

		uint64_t desired = oids_head_pack(next, oids_head_get_counter(head) + 1);
		if (atomic_compare_exchange_weak_explicit(&oids_head,
				&head, desired,
				memory_order_acq_rel, memory_order_acquire))
			return idx;
	}
}

static inline void dw_oid_free(unsigned oid)
{
	uint64_t head = atomic_load_explicit(&oids_head, memory_order_acquire);

	while (1) {
		atomic_store_explicit(&oids[oid].size, (size_t)oids_head_get_idx(head), memory_order_relaxed);
		uint64_t desired = oids_head_pack(oid, oids_head_get_counter(head) + 1);
		if (atomic_compare_exchange_weak_explicit(&oids_head,
				&head, desired,
				memory_order_release, memory_order_acquire))
			return;
	}
}

/* Start without protecting objects, wait until libdw is fully initialized. */
__thread bool dw_protect_active __attribute__((tls_model("initial-exec"))) = false;

void dw_protect_init()
{
	for (int i = 0; i < oids_size; i++) {
		atomic_store_explicit(&oids[i].base_addr, NULL, memory_order_relaxed);
		atomic_store_explicit(&oids[i].size, (size_t)i + 1, memory_order_relaxed);
		oids[i].alloc_ip = NULL;
	}
	atomic_store_explicit(&oids[oids_size - 1].size, 0, memory_order_relaxed);
	atomic_store_explicit(&oids_head, oids_head_pack(1, 0), memory_order_release);
}

static DW_NOINLINE
void dw_report_oob(unsigned oid, uintptr_t base, size_t sz,
				   uintptr_t real_addr, size_t size, void *alloc_ip,
				   const struct patch_exec_context *seed_ctx)
{
	/* Get the symbol of the function where the object was allocated */
	char proc_name[256];
	char *proc_name_p = proc_name;
	uint64_t offset = 0;
	struct func_cache_entry *e = func_cache_lookup((uintptr_t)alloc_ip);
	if (!e) {
		uintptr_t start, end;
		dw_lookup_symbol((uintptr_t)alloc_ip, proc_name, sizeof(proc_name), &start, &end);
		if (start != 0 && end > start)
			e = func_cache_insert(start, end, proc_name);
	}

	if (e) {
		proc_name_p = e->func_name;
		offset = (uintptr_t)alloc_ip - e->start_ip;
	}

	uintptr_t alloc_end  = base + sz;
	uintptr_t access_end = real_addr + size;
	size_t diff_bytes = 0;
	const char *viol_kind = (real_addr < base) ? "underflows allocation" : "overflows allocation";

	if (real_addr < base) {
		diff_bytes = (size_t)(base - real_addr);
	} else if (access_end > alloc_end) {
		diff_bytes = (size_t)(access_end - alloc_end);
	}

	/*
	 * Make the probe context available to the APP backtrace only here,
	 * on the cold violation path. The steady-state in-bounds path never
	 * touches this thread-local. A NULL seed_ctx (wrapper/signal callers)
	 * leaves the existing backtrace behavior untouched.
	 */
	if (seed_ctx)
		dw_bt_seed_patch_set(seed_ctx);

	DW_LOG_APP(WARNING, PROTECT,
			"Out-of-bounds access detected (oid=%u)\n"
			"  Allocation:\n"
			"    base   = 0x%llx\n"
			"    size   = %zu bytes\n"
			"    range  = [0x%llx..0x%llx)\n"
			"    site   = (%s+0x%lx)\n"
			"  Access:\n"
			"    addr   = 0x%llx\n"
			"    size   = %zu bytes\n"
			"    range  = [0x%llx..0x%llx)\n"
			"  Violation:\n"
			"    %s by %zu bytes\n"
			"  Backtrace:\n",
			oid, (unsigned long long)base, (size_t)sz, (unsigned long long)base,
			(unsigned long long)alloc_end, proc_name_p, offset,
			(unsigned long long)real_addr, (size_t)size, (unsigned long long)real_addr,
			(unsigned long long)access_end, viol_kind, diff_bytes);

	if (seed_ctx)
		dw_bt_seed_patch_clear();
}

DW_INTERNAL bool dw_check_access_ctx(const void *ptr, size_t size,
				     const struct patch_exec_context *seed_ctx)
{
	uintptr_t raw_addr = (uintptr_t)ptr;

	/* Skip checking for pointers with MSB set */
	if (unlikely(raw_addr & (1ULL << 63)))
		return true;

	unsigned oid = raw_addr >> 48;
	uintptr_t real_addr = raw_addr & untaint_mask;

	/* Skip checking when the pointer does not hold a taint */
	if (oid == 0)
		return true;

	uintptr_t base;
	size_t sz;

	/*
	 * Fast path: one-entry per-thread cache (see dw_tls_oid_cache). Trust it
	 * only while no free has happened since it was filled (epoch unchanged),
	 * which guarantees this OID's slot still holds the same live object with
	 * the same {base,size}. A hit avoids touching the shared oids[] line.
	 */
	struct dw_oid_cache *cache = &dw_tls_oid_cache;
	uint64_t epoch = atomic_load_explicit(&dw_oid_epoch, memory_order_acquire);

	if (likely(cache->oid == oid && cache->epoch == epoch)) {
		base = cache->base;
		sz   = cache->size;
	} else {
		if (unlikely(oid >= oids_size))
			goto invalid;

		void *base_addr = atomic_load_explicit(&oids[oid].base_addr, memory_order_acquire);
		if (unlikely(base_addr == NULL)) {
invalid:
			DW_LOG(WARNING, PROTECT,
				   "Invalid taint value %u for %p\n", oid, ptr);
			return false;
		}

		base = (uintptr_t)base_addr;
		sz   = atomic_load_explicit(&oids[oid].size, memory_order_relaxed);

		/*
		 * Refill. Publish base/size before the {oid,epoch} key so that an
		 * async signal re-entering this function on the same thread can only
		 * see a stale-but-consistent entry or a clean miss -- never a fresh
		 * key paired with another object's base/size. The fence is
		 * compiler-only: the cache is thread-private TLS, so no CPU barrier
		 * is needed, only prevention of store reordering across a signal.
		 */
		cache->base = base;
		cache->size = sz;
		atomic_signal_fence(memory_order_release);
		cache->oid   = oid;
		cache->epoch = epoch;
	}

	/* Check [real_addr, real_addr + size) ⊆ [base, base + sz). */
	if (unlikely(size > sz || real_addr < base || real_addr > base + sz - size)) {
		dw_report_oob(oid, base, sz, real_addr, size,
			      oids[oid].alloc_ip, seed_ctx);
		return false;
	}

	return true;
}

DW_INTERNAL bool dw_check_access(const void *ptr, size_t size)
{
	return dw_check_access_ctx(ptr, size, NULL);
}

/*
 * Silent bounds predicate for the SIGSEGV emulate-and-skip fast path. Returns
 * true iff [ptr, ptr + size) lies within the live object named by ptr's taint
 * (or ptr carries no taint to check). Unlike dw_check_access_ctx() it emits no
 * report and touches no cache: a false result -- invalid/freed taint or
 * out-of-bounds -- tells the fast path to fall back to the single-step path,
 * which performs the access natively and emits the single authoritative
 * violation report. Restricting the inline emulation to the in-bounds case
 * guarantees the address it dereferences is backed by a live allocation, so the
 * load/store cannot nested-fault inside the signal handler.
 */
DW_INTERNAL bool dw_access_in_bounds(const void *ptr, size_t size)
{
	uintptr_t raw_addr = (uintptr_t)ptr;

	/* Pointers with MSB set are not checked (mirrors dw_check_access_ctx). */
	if (unlikely(raw_addr & (1ULL << 63)))
		return true;

	unsigned oid = raw_addr >> 48;
	uintptr_t real_addr = raw_addr & untaint_mask;

	if (oid == 0)
		return true;

	if (unlikely(oid >= oids_size))
		return false;

	void *base_addr = atomic_load_explicit(&oids[oid].base_addr, memory_order_acquire);
	if (unlikely(base_addr == NULL))
		return false;

	uintptr_t base = (uintptr_t)base_addr;
	size_t sz = atomic_load_explicit(&oids[oid].size, memory_order_relaxed);

	return !(size > sz || real_addr < base || real_addr > base + sz - size);
}

size_t dw_get_size(void *ptr)
{
	unsigned oid = (uintptr_t) ptr >> 48;

	if (oid == 0)
		return malloc_usable_size(ptr);

	if (unlikely(oid > oids_size - 1))
		goto invalid;

	if (unlikely(atomic_load_explicit(&oids[oid].base_addr, memory_order_acquire) == NULL)) {
invalid:
		DW_LOG(WARNING, PROTECT, "Invalid taint value %u for %p\n", oid, ptr);
		return 0;
	}
	return atomic_load_explicit(&oids[oid].size, memory_order_relaxed);
}

void* dw_get_base_addr(void *ptr)
{
	unsigned oid = (uintptr_t) ptr >> 48;

	if (oid == 0)
		return 0;

	if (unlikely(oid > oids_size - 1))
		goto invalid;

	void *base_addr = atomic_load_explicit(&oids[oid].base_addr, memory_order_acquire);
	if (unlikely(base_addr == NULL)) {
invalid:
		DW_LOG(WARNING, PROTECT, "Invalid taint value %u for %p\n", oid, ptr);
		return 0;
	}
	return base_addr;
}

/*
 * Add the object to the oid table and taint the pointer.
 */
static void *dw_protect(void *ptr, size_t size, void* caller)
{
	unsigned oid = dw_oid_alloc();
	if (unlikely(oid == 0)) {
		//DW_LOG(WARNING, PROTECT, "OID table //exhausted, cannot taint pointer %p\n", ptr);
		return ptr;
	}

	oids[oid].alloc_ip = caller;
	atomic_store_explicit(&oids[oid].size, size, memory_order_relaxed);
	atomic_store_explicit(&oids[oid].base_addr, ptr, memory_order_release);

	uintptr_t p   = (uintptr_t)ptr & ~taint_mask;       // clear tag field
	uintptr_t tag = (uintptr_t)oid << 48;

	return (void *) (p | tag);
}

/*
 * Put back the taint on the modified (incremented) pointer.
 */
DW_INTERNAL inline void *dw_reprotect(const void *ptr, const void *old_ptr)
{
	if (unlikely(!ptr))
		return NULL;

	if (unlikely((uintptr_t)old_ptr & (1ULL << 63))) /*MSB*/
		return (void*) ptr;

	uintptr_t taint_bits = (uintptr_t) old_ptr & taint_mask;

	// No taint to reapply
	if (taint_bits == 0)
		return (void *)ptr;

	// Decode tag
	uintptr_t oid = taint_bits >> 48;

	/*
	 * The saved taint cannot be reapplied: there is no live object to re-tag.
	 * Drop the taint and return the value as-is -- we must not leave a stale or
	 * out-of-range OID on it, or the next dw_check_access() would index oids[]
	 * out of bounds. Both sub-cases below are recoverable and handled the way
	 * dw_get_size()/dw_get_base_addr() handle them: a non-fatal WARNING rather
	 * than a fatal ERROR that would abort the whole process. The trade-off is
	 * that this particular pointer is no longer bounds-checked -- unavoidable
	 * once its backing object is gone.
	 */
	if (unlikely(oid >= oids_size)) {
		/*
		 * Out of range: the allocator never hands out an OID this large, so
		 * this is corrupted tag bits or a non-pointer value misidentified as
		 * tainted -- not a freed object. Kept non-fatal (aborting would kill
		 * correct programs on a misidentification) but logged distinctly.
		 */
		DW_LOG(WARNING, PROTECT,
		       "Cannot reapply taint: oid %u out of range (old pointer %p); dropping taint\n",
		       (unsigned)oid, old_ptr);
		return (void *)ptr;
	}

	if (unlikely(atomic_load_explicit(&oids[oid].base_addr, memory_order_acquire) == NULL)) {
		/*
		 * Freed / no longer live: the application kept a pointer whose object
		 * was freed before this retaint ran (a deferred post-handler, or a
		 * dangling pointer left in a register). Expected and benign.
		 */
		DW_LOG(WARNING, PROTECT,
		       "Cannot reapply taint: oid %u (old pointer %p) is no longer live\n",
		       (unsigned)oid, old_ptr);
		return (void *)ptr;
	}

	return (void *) (((uintptr_t) ptr & ~taint_mask) | ((uintptr_t) old_ptr & taint_mask));
}

/*
 * Alloc and return the tainted pointer.
 */
void *dw_malloc_protect(size_t size, void* caller)
{
	void *result = __libc_malloc(size);
	if (likely(result != NULL))
		result = dw_protect(result, size, caller);
	return result;
}

/*
 * Remove the taint and free the object.
 *
 * The OID and the freed pointer are validated before any state is mutated:
 * the object is released to glibc and its metadata recycled only for an exact
 * free of a live object (dw_unprotect(ptr) == tracked base_addr). A stale or
 * double free, an out-of-range taint, or a free of an interior pointer is
 * reported and ignored, so we never hand glibc a pointer it did not allocate
 * and never free the same object twice.
 */
void dw_free_protect(void *ptr)
{
	unsigned oid = (uintptr_t) ptr >> 48;

	/* Untainted pointer: nothing is tracked, free the raw allocation. */
	if (oid == 0) {
		__libc_free(ptr);
		return;
	}

	if (oid > oids_size - 1) {
		DW_LOG(WARNING, PROTECT, "Invalid free: taint %u out of range for %p\n", oid, ptr);
		return;
	}

	void *base = atomic_load_explicit(&oids[oid].base_addr, memory_order_acquire);
	void *real = dw_unprotect(ptr);

	/* Stale taint: the slot is not live (already freed, or never allocated). */
	if (base == NULL) {
		DW_LOG(WARNING, PROTECT,
			   "Invalid free: oid %u is not live (double free?) for %p\n", oid, ptr);
		return;
	}

	/* Interior free: the pointer does not match the tracked allocation base. */
	if (real != base) {
		DW_LOG(WARNING, PROTECT,
			   "Invalid free: interior pointer %p does not match base %p (oid %u)\n",
			   ptr, base, oid);
		return;
	}

	/*
	 * Claim the slot: only succeed while base_addr is still exactly our base.
	 * A compare-exchange (not a blind exchange) means a slot freed and recycled
	 * by another thread is left intact, and a concurrent double free can win at
	 * most once.
	 */
	void *expected = base;
	if (!atomic_compare_exchange_strong_explicit(&oids[oid].base_addr, &expected, NULL,
						     memory_order_acq_rel, memory_order_acquire)) {
		DW_LOG(WARNING, PROTECT,
			   "Invalid free: concurrent free race on oid %u for %p\n", oid, ptr);
		return;
	}

	/*
	 * Invalidate every thread's one-entry OID cache *before* the slot is
	 * recycled below. Any cached {base,size} for any OID may no longer be
	 * trusted once this slot can be reused. The base_addr -> NULL claim above
	 * is sequenced before this release bump, so a reader that observes the new
	 * epoch also observes the freed slot. Bumping here -- ahead of
	 * dw_oid_free() returning the slot to the free list -- closes the window in
	 * which another thread could pop this slot off the free list and install a
	 * different object while a stale cache, still at the old epoch, is trusted.
	 */
	atomic_fetch_add_explicit(&dw_oid_epoch, 1, memory_order_release);

	dw_oid_free(oid);
	__libc_free(base);
}

/*
 * Memalign and return the tainted pointer.
 */
void *dw_memalign_protect(size_t alignment, size_t size, void* caller)
{
	void *result = __libc_memalign(alignment, size);
	if (likely(result != NULL))
		result = dw_protect(result, size, caller);
	return result;
}

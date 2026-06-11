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

/*
 * Cold out-of-bounds report body. Compiled normally (SSE allowed): the symbol
 * lookup and the formatted DW_LOG_APP both emit SSE. It is reached only through
 * dw_report_oob_xmm_safe(), which brackets it with an explicit save/restore of
 * the application's xmm0-7. Kept noinline so the general-regs-only wrapper never
 * absorbs this SSE codegen (a target-attribute mismatch already prevents
 * inlining; noinline makes the call boundary explicit and robust).
 */
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

static DW_NOINLINE
void dw_report_invalid_taint(unsigned oid, const void *ptr)
{
	DW_LOG(WARNING, PROTECT,
	       "Invalid taint value %u for %p\n", oid, ptr);
}

/*
 * xmm-preserving bracket for the cold OOB report path.
 *
 * The probe runs with libpatch's xmm0-7 save/restore skipped (the callback
 * chain is declared SSE-free, TRAMPOLINE_SKIP_XMM), so the application's live
 * xmm0-7 are still in the physical registers when we get here. dw_report_oob()
 * emits SSE and would clobber them, so this wrapper explicitly stashes xmm0-7
 * to a stack buffer and restores them around the call. Compiled
 * general-regs-only so the compiler itself emits no SSE; the only xmm traffic
 * is the explicit movdqu below (opaque to the target attribute, handled by the
 * assembler). The %%xmm registers are intentionally NOT in a clobber list
 * (which general-regs-only would reject); the "memory" clobber plus the
 * volatile asm ordering is sufficient since nothing else reads them here.
 */
#pragma GCC push_options
#pragma GCC target("general-regs-only")

static inline DW_ALWAYS_INLINE void dw_save_xmm0_7(unsigned char *xmm)
{
	__asm__ __volatile__(
		"movdqu %%xmm0, 0x00(%0)\n\t"
		"movdqu %%xmm1, 0x10(%0)\n\t"
		"movdqu %%xmm2, 0x20(%0)\n\t"
		"movdqu %%xmm3, 0x30(%0)\n\t"
		"movdqu %%xmm4, 0x40(%0)\n\t"
		"movdqu %%xmm5, 0x50(%0)\n\t"
		"movdqu %%xmm6, 0x60(%0)\n\t"
		"movdqu %%xmm7, 0x70(%0)\n\t"
		: : "r"(xmm) : "memory");
}

static inline DW_ALWAYS_INLINE void dw_restore_xmm0_7(unsigned char *xmm)
{
	__asm__ __volatile__(
		"movdqu 0x00(%0), %%xmm0\n\t"
		"movdqu 0x10(%0), %%xmm1\n\t"
		"movdqu 0x20(%0), %%xmm2\n\t"
		"movdqu 0x30(%0), %%xmm3\n\t"
		"movdqu 0x40(%0), %%xmm4\n\t"
		"movdqu 0x50(%0), %%xmm5\n\t"
		"movdqu 0x60(%0), %%xmm6\n\t"
		"movdqu 0x70(%0), %%xmm7\n\t"
		: : "r"(xmm) : "memory");
}

static DW_NOINLINE
void dw_report_oob_xmm_safe(unsigned oid, uintptr_t base, size_t sz,
			    uintptr_t real_addr, size_t size, void *alloc_ip,
			    const struct patch_exec_context *seed_ctx)
{
	unsigned char xmm[128] DW_ALIGNED(16);

	dw_save_xmm0_7(xmm);
	dw_report_oob(oid, base, sz, real_addr, size, alloc_ip, seed_ctx);
	dw_restore_xmm0_7(xmm);
}

static DW_NOINLINE
void dw_report_invalid_taint_xmm_safe(unsigned oid, const void *ptr)
{
	unsigned char xmm[128] DW_ALIGNED(16);

	dw_save_xmm0_7(xmm);
	dw_report_invalid_taint(oid, ptr);
	dw_restore_xmm0_7(xmm);
}
#pragma GCC pop_options

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

	if (unlikely(oid >= oids_size))
		goto invalid;

	void *base_addr = atomic_load_explicit(&oids[oid].base_addr, memory_order_acquire);
	if (unlikely(base_addr == NULL)) {
invalid:
		dw_report_invalid_taint_xmm_safe(oid, ptr);
		return false;
	}

	uintptr_t base = (uintptr_t)base_addr;
	size_t sz = atomic_load_explicit(&oids[oid].size, memory_order_relaxed);

	/* Check [real_addr, real_addr + size) ⊆ [base, base + sz). */
	if (unlikely(size > sz || real_addr < base || real_addr > base + sz - size)) {
		/*
		 * Cold violation path. Route through the xmm-preserving wrapper so
		 * the SSE-emitting report body cannot corrupt the application's
		 * live xmm0-7 (libpatch skipped saving them for this SSE-free
		 * probe). dw_check_access_ctx itself stays xmm-clean: only integer
		 * compares and this call.
		 */
		dw_report_oob_xmm_safe(oid, base, sz, real_addr, size,
				       oids[oid].alloc_ip, seed_ctx);
		return false;
	}

	return true;
}

DW_INTERNAL bool dw_check_access(const void *ptr, size_t size)
{
	return dw_check_access_ctx(ptr, size, NULL);
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
		DW_LOG(WARNING, PROTECT, "OID table exhausted, cannot taint pointer %p\n", ptr);
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

	if (unlikely(oid >= oids_size ||
		     atomic_load_explicit(&oids[oid].base_addr, memory_order_acquire) == NULL)) {
		DW_LOG(ERROR, PROTECT, "Invalid taint bits %p from old pointer %p\n", (void *)taint_bits, old_ptr);
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

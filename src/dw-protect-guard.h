#ifndef DW_PROTECT_GUARD_H
#define DW_PROTECT_GUARD_H

#include <stdbool.h>
#include <stddef.h>

#include "attributes.h"

/*
 * Guard-page allocation backend (the "mprotect" object-protection model).
 *
 * Unlike the pointer-tainting OID backend (dw-protect.h), guard allocations are
 * returned as plain, untainted, canonical pointers. The object is backed by an
 * anonymous mmap whose end abuts a trailing PROT_NONE page, so an overflow past
 * the object traps in hardware with no per-access instrumentation. This is the
 * classic Electric Fence model and is opt-in / size-gated; see DW_GUARD_* env
 * vars parsed in dw_init().
 *
 * All hooks below are cheap no-ops (a single bool test) when guard mode is
 * disabled, so the default OID path is untouched.
 */

/*
 * Configure the backend from the environment. min_size == 0 disables guard
 * mode. max_objects caps the number of concurrently-live guarded allocations.
 * abort_on_fault aborts after reporting a guard fault.
 */
void dw_guard_configure(size_t min_size, size_t max_objects, bool abort_on_fault);

/* True when guard mode is enabled and a request of this size is guard-eligible. */
bool dw_guard_enabled_for_size(size_t size);

/*
 * Allocate a guarded object. Returns a canonical (untainted) user pointer, or
 * NULL on any failure (guard mode disabled, table full, mmap/mprotect failure)
 * so the caller can fall back to the OID path.
 */
void *dw_guard_malloc(size_t size, void *caller);

/*
 * Free a guarded object. Returns true if ptr was a live guarded allocation
 * (now munmap'd); false if ptr is not owned by this backend (caller should fall
 * through to its normal free path). Cheap O(1) reject for non-guard pointers.
 */
bool dw_guard_free(void *ptr);

/*
 * Look up the user-visible (requested) size of a guarded object. Returns true
 * and fills *size_out on a hit; false if ptr is not a guarded allocation.
 */
bool dw_guard_get_size(void *ptr, size_t *size_out);

/*
 * Attempt an in-place resize of a guarded allocation. If ptr is a live guard
 * allocation and new_size fits within the existing mapping's accessible region
 * (from user to guard_page), updates requested_size and returns true — the
 * caller can return ptr unchanged, with no new allocation, copy, or munmap.
 * Returns false if ptr is not a guard allocation or new_size exceeds capacity.
 */
bool dw_guard_realloc_inplace(void *ptr, size_t new_size);

/*
 * Signal-handler entry. If fault_addr lies in a known guard page, report the
 * out-of-bounds access and (if configured) abort. In non-abort mode, temporarily
 * permit the page and arm a single-step trap so the faulting instruction can
 * complete. Returns true if the fault was handled, or false if the address is
 * not a stable guard-page snapshot and normal fault handling should continue.
 */
bool dw_guard_handle_fault(void *fault_addr, void *context);

/*
 * Complete a non-aborting guard single-step. Restores PROT_NONE after RIP
 * advances; returns true only for a trace trap armed by dw_guard_handle_fault().
 */
bool dw_guard_handle_trap(void *context);

#endif /* DW_PROTECT_GUARD_H */

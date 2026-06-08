#ifndef DW_PROTECT_H
#define DW_PROTECT_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"

/*
 * There are different ways to protect heap objects.
 *
 * One is pointer tainting, dereferencing the pointer will trigger a SIGSEGV
 * giving control to check the access.
 *
 * Another is mprotect, protecting the object storage, triggering a SIGSEGV
 * when the mprotected memory is accessed.
 *
 * This header can accomodate only the first model.
 */


/*
 * We are within the MallocSan internals, do not protect heap objects
 * This variable should be thread local storage for multi-threading
 */
extern __thread bool dw_protect_active __attribute__((tls_model("initial-exec")));

/* Initialize the module */
void dw_protect_init();

/* Check that the pointer to the object is within bounds */
DW_INTERNAL bool dw_check_access(const void *ptr, size_t size);

/*
 * Same bounds check, but used on the patch-probe (handler) path. On a
 * violation it makes the supplied probe context available to the APP backtrace
 * so the report unwinds the application stack rather than libpatch internals.
 * The seed is set only on the (rare) out-of-bounds path, so the in-bounds
 * steady-state access pays no thread-local store. A NULL ctx behaves exactly
 * like dw_check_access().
 */
struct patch_exec_context;
DW_INTERNAL bool dw_check_access_ctx(const void *ptr, size_t size,
						 const struct patch_exec_context *ctx);

/* Get the allocated size of a protected object */
size_t dw_get_size(void *ptr);

/* Get the base address of a protected object */
void* dw_get_base_addr(void *ptr);

/*
 * Check if the object is protected (the pointer carries a taint tag).
 *
 * Defined inline in the header because this is on the steady-state patched
 * access path and is called several times per protected access; an out-of-line
 * definition in the OID backend would otherwise be reached through the PLT.
 */
static inline bool dw_is_protected(const void *ptr)
{
	uintptr_t p = (uintptr_t)ptr;

	/* No taint when the MSB is set or when the 15-bit tag field is zero
	 * (this also covers the null pointer). */
	if (unlikely(p & (1ULL << 63)))
		return false;
	return (p >> 48) != 0;
}

/* Return the untainted pointer (inlined for the same reason as above). */
static inline void *dw_unprotect(const void *ptr)
{
	if (!dw_is_protected(ptr))
		return (void *)ptr;
	return (void *)((uintptr_t)ptr & (uintptr_t)0x0000ffffffffffffULL);
}

/*
 * Reapply the taint from the old pointer to ptr. Sometimes a function returns
 * an updated pointer to a buffer (e.g., advancing the current position while
 * you parse the content).
 */
DW_INTERNAL void* dw_reprotect(const void *ptr, const void *old_ptr);

/* Alloc a protected object */
void* dw_malloc_protect(size_t size, void* caller);

/* Memalign a protected object */
void* dw_memalign_protect(size_t alignment, size_t size, void* caller);

/* Free a protected object */
void dw_free_protect(void *ptr);

extern void *__libc_malloc(size_t size);
extern void __libc_free(void *ptr);
extern void *__libc_calloc(size_t nmemb, size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_memalign(size_t alignment, size_t size);

#endif /* DW_LOG_H */

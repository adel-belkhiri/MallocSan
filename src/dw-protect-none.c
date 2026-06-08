#include <malloc.h>

#include "dw-log.h"
#include "dw-protect.h"
#include "stdint.h"

/*
 * This is mostly a stub for now. We taint pointers with 0x0001 in the MS bytes
 * Normally we would keep an object table with the bounds of each object
 * and use the object id as taint. We would add a dw_check_access function.
 */

const uintptr_t taint_mask    = (uintptr_t) 0xffff000000000000;
const uintptr_t untaint_mask  = (uintptr_t) 0x0000ffffffffffff;
const uintptr_t default_taint = (uintptr_t) 0x0001000000000000;

/* Start without protecting objects, wait until libdw is fully initialized */
__thread bool dw_protect_active __attribute__((tls_model("initial-exec"))) = false;

void dw_protect_init()
{
}

DW_INTERNAL bool dw_check_access(const void *ptr, size_t size)
{
	if (ptr == NULL)
		DW_LOG(WARNING, PROTECT, "Null pointer access\n");

	if (size == 0)
		DW_LOG(WARNING, PROTECT, "Zero size access\n");

	return 0;
}

/*
 * Add a taint to a pointer.
 */
void *dw_protect(const void *ptr)
{
	return (void *) ((uintptr_t) ptr | default_taint);
}

/*
 * Put back the taint on the modified (incremented) pointer.
 */
DW_INTERNAL void *dw_reprotect(const void *ptr, const void *old_ptr)
{
	return (void *) ((uintptr_t) ptr | ((uintptr_t) old_ptr & taint_mask));
}

/*
 * Alloc and return the tainted pointer
 */
void *dw_malloc_protect(size_t size)
{
	void *result = __libc_malloc(size);
	result = dw_protect(result);
	return result;
}

/*
void* dw_realloc_protect(void *ptr, size_t size)
{
	void *result = __libc_malloc(size);
	result = dw_protect(result);
	return result;
}
*/

/*
 * Remove the taint and free the object.
 */
void dw_free_protect(void *ptr)
{
	void *result = dw_unprotect(ptr);
	__libc_free(result);
}

/*
 * Memalign and return the tainted pointer.
 */
void *dw_memalign_protect(size_t alignment, size_t size)
{
	void *result = __libc_memalign(alignment, size);
	result = dw_protect(result);
	return result;
}

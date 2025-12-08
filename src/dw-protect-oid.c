#include <malloc.h>
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
	void *base_addr;
	size_t size;
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
static unsigned oids_head = 0;
static struct object_id oids[32767];

/* Start without protecting objects, wait until libdw is fully initialized. */
bool dw_protect_active = false;

void dw_protect_init()
{
	for (int i = 0; i < oids_size; i++) {
		oids[i].base_addr = NULL;
		oids[i].size = i + 1;
	}
	oids_head = 1;
	oids[oids_size - 1].size = 0;
}

bool dw_check_access(const void *ptr, size_t size)
{
	uintptr_t raw_addr = (uintptr_t)ptr;

	/* Skip checking for pointers with MSB set */
	if (raw_addr & (1ULL << 63))
		return true;

	unsigned oid = raw_addr >> 48;
	uintptr_t real_addr = raw_addr & untaint_mask;

	/* Skip checking when the pointer does not hold a taint */
	if (oid == 0)
		return true;

	if (oid >= oids_size || oids[oid].base_addr == NULL) {
		DW_LOG(WARNING, PROTECT,
			   "Invalid taint value %u for %p\n", oid, ptr);
		return false;
	}

	uintptr_t base = (uintptr_t)oids[oid].base_addr;
	size_t sz = oids[oid].size;

	/* Check [real_addr, real_addr + size) ⊆ [base, base + sz). */
	if (size > sz || real_addr < base || real_addr > base + sz - size) {
		DW_LOG(ERROR, PROTECT,
			   "Invalid access (oid %u): 0x%llx size %zu not between 0x%llx and 0x%llx\n",
			   oid, real_addr, size, base, (base + sz));
		return false;
	}

	return true;
}

size_t dw_get_size(void *ptr)
{
	unsigned oid = (uintptr_t) ptr >> 48;

	if (oid == 0)
		return malloc_usable_size(ptr);

	if (oid > oids_size - 1 || oids[oid].base_addr == 0) {
		DW_LOG(WARNING, PROTECT, "Invalid taint value %u for %p\n", oid, ptr);
		return 0;
	}
	return oids[oid].size;
}

void* dw_get_base_addr(void *ptr)
{
	unsigned oid = (uintptr_t) ptr >> 48;

	if (oid == 0)
		return 0;

	if (oid > oids_size - 1 || oids[oid].base_addr == 0) {
		DW_LOG(WARNING, PROTECT, "Invalid taint value %u for %p\n", oid, ptr);
		return 0;
	}
	return oids[oid].base_addr;
}

/*
 * Add the object to the oid table and taint the pointer.
 */
static void *dw_protect(void *ptr, size_t size)
{
	if (oids_head == 0) {
		DW_LOG(WARNING, PROTECT, "OID table full, cannot taint pointer %p\n", ptr);
		return ptr;
	}

	unsigned oid       = oids_head;
	unsigned next_head = oids[oids_head].size;

	oids[oids_head].base_addr = ptr;
	oids[oids_head].size = size;
	oids_head = next_head;

	uintptr_t p   = (uintptr_t)ptr & ~taint_mask;       // clear tag field
	uintptr_t tag = (uintptr_t)oid << 48;

	return (void *) (p | tag);
}

/*
 * Put back the taint on the modified (incremented) pointer.
 */
inline void *dw_reprotect(const void *ptr, const void *old_ptr)
{
	if (!ptr)
		return NULL;

	if ((uintptr_t)old_ptr & (1ULL << 63)) /*MSB*/
		return (void*) ptr;

	uintptr_t taint_bits = (uintptr_t) old_ptr & taint_mask;

	// No taint to reapply
	if (taint_bits == 0)
		return (void *)ptr;

	// Decode tag
	uintptr_t oid = taint_bits >> 48;

	if (oid >= oids_size || oids[oid].base_addr == 0) {
		DW_LOG(ERROR, PROTECT, "Invalid taint bits %p from old pointer %p\n", (void *)taint_bits, old_ptr);
		return (void *)ptr;
	}

	return (void *) (((uintptr_t) ptr & ~taint_mask) | ((uintptr_t) old_ptr & taint_mask));
}

/*
 * Remove the taint or mprotect.
 */
inline void *dw_unprotect(const void *ptr)
{
	if (!dw_is_protected(ptr))
		return (void*) ptr;

	return (void *) ((uintptr_t) ptr & untaint_mask);
}


inline bool dw_is_protected(const void *ptr)
{
	if (!ptr)
		return false;

	if ((uintptr_t)ptr & (1ULL << 63)) /*MSB*/
		return false;

	unsigned oid = (uintptr_t) ptr >> 48;
	if (oid == 0)
		return false;

	// Case of dangling freed object
	//if (oid >= oids_size || oids[oid].base_addr == 0)
	//	return false;

	return true;
}

/*
 * Alloc and return the tainted pointer.
 */
void *dw_malloc_protect(size_t size)
{
	void *result = __libc_malloc(size);
	if (result != NULL)
		result = dw_protect(result, size);
	return result;
}

/*
 * Remove the taint and free the object.
 */
void dw_free_protect(void *ptr)
{
	unsigned oid = (uintptr_t) ptr >> 48;
	if (oid != 0) {
		if (oid > oids_size - 1 || oids[oid].base_addr == 0)
			DW_LOG(WARNING, PROTECT, "Invalid taint value %u for %p\n", oid, ptr);
		else {
			oids[oid].size = oids_head;
			oids[oid].base_addr = NULL;
			oids_head = oid;
		}
	}
	__libc_free(dw_unprotect(ptr));
}

/*
 * Memalign and return the tainted pointer.
 */
void *dw_memalign_protect(size_t alignment, size_t size)
{
	void *result = __libc_memalign(alignment, size);
	if (result != NULL)
		result = dw_protect(result, size);
	return result;
}

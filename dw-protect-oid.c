#include <malloc.h>
#include "dw-protect.h"
#include "dw-log.h"
#include "stdint.h"

const uintptr_t taint_mask =    (uintptr_t)0xffff000000000000;
const uintptr_t untaint_mask =  (uintptr_t)0x0000ffffffffffff;

/* Table of malloc objects tracked by tainted pointers
   The taint is the index + 1 since a taint of 0 would not
   trigger a SIGSEGV. With the base_addr and the size, we can check
   if the bytes accessed are within the allocated bounds for the object.

   The base_addr field is NULL when the entry is not in use. 
   In that case, the size field contains the index of the next
   entry in the free list, or 0 if this is the free list end.
   The array entry at index zero is not used since this would
   correspond to a null taint, no taint. Moreover, index 0 is
   reserved for the free list end. */
   
struct object_id {
    void *base_addr;
    size_t size;
};

// We have 2 unused bytes to store the object id. We are limited to less than 2^16.
static const unsigned oids_size = 65000;
static unsigned oids_head = 0;
static struct object_id oids[65000];

// Start without protecting objects, wait until libdw is fully initialized
bool dw_protect_active = false;

void dw_protect_init()
{
    for(int i = 0; i < oids_size; i++) {
        oids[i].base_addr = NULL;
        oids[i].size = i + 1;
    }
    oids_head = 1;
    oids[oids_size - 1].size = 0;
}

int dw_check_access(const void *ptr, size_t size)
{
    unsigned oid = (uintptr_t)ptr >> 48;
    void *real_addr = (void *)((uintptr_t)ptr & untaint_mask);
    
    if(oid == 0) return 0;
    if(oid > (oids_size - 1) || oids[oid].base_addr == 0) {
        dw_log(PROTECT, WARNING, "Invalid taint value %u for %p\n", oid, ptr);
        return 1;
    }

    if(real_addr < oids[oid].base_addr || real_addr + size > oids[oid].base_addr + oids[oid].size) {
        dw_log(ERROR, PROTECT, "Invalid access (%x)%p size %d not between %p and %p\n", 
            oid, real_addr, size, oids[oid].base_addr, oids[oid].base_addr + oids[oid].size);
        return 1;
    }
    return 0;
}

size_t dw_get_size(void *ptr)
{
    unsigned oid = (uintptr_t)ptr >> 48;
    if(oid == 0) return malloc_usable_size(ptr);
    if(oid > oids_size - 1 || oids[oid].base_addr == 0) {
        dw_log(PROTECT, WARNING, "Invalid taint value %u for %p\n", oid, ptr);
        return 0;
    }
    return oids[oid].size;            
}

// Add the object to the oid table and taint the pointer
static void*
dw_protect(void *ptr, size_t size)
{
    if(oids_head == 0) {
        dw_log(WARNING, PROTECT, "OID table full, cannot taint pointer %p\n", ptr);
        return ptr;
    }
    unsigned next_head = oids[oids_head].size;
    oids[oids_head].base_addr = ptr;
    oids[oids_head].size = size;
    void *result = (void *)((uintptr_t)ptr | ((uintptr_t)oids_head) << 48); 
    oids_head = next_head;
    return result;
}

// This would be used with the mprotect method
void
dw_reprotect(const void *ptr)
{
}

void*
dw_untaint(const void *ptr)
{
    return (void *)((uintptr_t)ptr & untaint_mask);
}

// Put back the taint on the modified (incremented) pointer
void*
dw_retaint(const void *ptr, const void *old_ptr)
{
    return (void *)((uintptr_t)ptr | ((uintptr_t)old_ptr & taint_mask));
}

// Remove the taint or mprotect
void*
dw_unprotect(const void *ptr)
{
    return (void *)((uintptr_t)ptr & untaint_mask);
}

// For now insure that it is the taint that we put, and not corruption
int
dw_is_protected(const void *ptr)
{
    uintptr_t taint = (uintptr_t)ptr >> 48;
    if(taint == 0) return 0;
    return 1;
}

// For now insure that it is the taint that we put, and not corruption
int
dw_is_protected_index(const void *ptr)
{
    uintptr_t taint = (uintptr_t)ptr >> 63;
    if(taint == 0) return dw_is_protected(ptr);
    return 0;
}

// Alloc and return the tainted pointer
void*
dw_malloc_protect(size_t size)
{
    void *result = __libc_malloc(size);
    result = dw_protect(result, size);
    return result;
}

// Remove the taint and free the object
void
dw_free_protect(void *ptr)
{
    unsigned oid = (uintptr_t)ptr >> 48;
    if(oid != 0) {
        if(oid > oids_size - 1 || oids[oid].base_addr == 0)
            dw_log(PROTECT, WARNING, "Invalid taint value %u for %p\n", oid, ptr);
        else {
            oids[oid].size = oids_head;
            oids[oid].base_addr = NULL;
            oids_head = oid;
        }
    }
    __libc_free(dw_untaint(ptr));
}

// Memalign and return the tainted pointer
void*
dw_memalign_protect(size_t alignment, size_t size)
{
    void *result = __libc_memalign(alignment, size);
    result = dw_protect(result, size);
    return result;
}


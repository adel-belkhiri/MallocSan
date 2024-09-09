#ifndef DW_PROTECT_H
#define DW_PROTECT_H

#include <stdbool.h>

// There are different ways to protect heap objects. 
//
// One is pointer tainting, dereferencing the pointer
// will trigger a SIGSEGV giving control to check the access.
//
// Another is mprotect, protecting the object storage, triggering
// a SIGSEGV when the mprotected memory is accessed.
//
// This header can accomodate both models.

// We are within the MallocSan internals, do not protect heap objects
// This variable should be thread local storage for multi-threading
extern bool dw_protect_active;

// Initialize the module
void dw_protect_init();

// Check that the pointer to the object is within bounds 
void dw_check_access(const void *ptr, size_t size);

// Get the allocated size of a protected object
size_t dw_get_size(void *ptr);

// The pointed object should be reprotected (e.g. mprotect)
// The pointer will be discarded and need not be retainted
void dw_reprotect(const void *ptr);

// Return the untainted pointer 
void* dw_untaint(const void *ptr);

// Reapply the taint from the old pointer to ptr.
// Sometimes a function returns an updated pointer to a buffer,
// e.g., advancing the current position while you parse the content
void* dw_retaint(const void *ptr, const void *old_ptr);

// Remove the protection from the object (taint or mprotect)
void* dw_unprotect(const void *ptr);

// Check if the object is protected
int dw_is_protected(const void *ptr);

// Check if the object is protected (not just a negative index)
int dw_is_protected_index(const void *ptr);

// Alloc a protected object
void* dw_malloc_protect(size_t size);

// Memalign a protected object.
void* dw_memalign_protect(size_t alignment, size_t size);

// Free a protected object.
void dw_free_protect(void *ptr);

extern void *__libc_malloc(size_t size);
extern void __libc_free(void *ptr);
extern void *__libc_calloc(size_t nmemb, size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_memalign(size_t alignment, size_t size);

#endif /* DW_LOG_H */

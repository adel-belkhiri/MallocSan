#define _GNU_SOURCE

#include "dw-log.h"
#include "dw-disassembly.h"
#include "dw-protect.h"
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <limits.h>
#include <ucontext.h>
#include <strings.h>
#include <string.h>
#include <sys/user.h>
#include <sys/mman.h>

static size_t nb_insn_olx_entries = 10000;

// Add size to check access in wrappers?

// In the current version, we will only try PATCH_TRAP which should always work.
// This should let us debug two aspects. The first is libc wrappers to insure that no tainted
// pointers leak to system calls. A trace of system calls with arguments and a stack dump
// can let us check if a tainted pointer is passed as argument and by which call path.
// The second aspect is the untainting / retainting of pointers. We know that we 
// currently do not handle vector indirect access instructions such as 
// VPGATHERQQ ymm11, qword ptr [ymm9], ymm10
// du benchmark 502.gcc_r de SPEC cpu2017

static enum dw_strategies dw_strategy = DW_PATCH_TRAP;

static instruction_table *insn_table;

// Handler executed before and after instructions that possibly access tainted pointers
// when an instruction is "patched" to insert pre and post probes.

static void patch_handler(struct patch_exec_context *ctx, uint8_t post)
{
    if(!post) dw_unprotect_context(ctx);
    else dw_reprotect_context(ctx);
}

// A protected object was presumably accessed, raising a signal (SIGSEGV or SIGBUS)

void signal_protected(int sig, siginfo_t *info, void *context)
{
    struct insn_entry *entry;

    // We should not have any tainted pointer access while in the handler.
    // It is not reentrant and signals are blocked anyway.
    bool success;
    bool save_active = dw_protect_active;
    dw_protect_active = false;

    // Check if we are within wrapped / inactive functions where this signal should not happen
    if(!save_active) 
        dw_log(WARNING, MAIN, "Signal received while within wrappers\n");
    
    // Get the instruction address
    ucontext_t* uctx = ((ucontext_t*)context);
    uintptr_t fault_insn = uctx->uc_mcontext.gregs[REG_RIP];
    uintptr_t next_insn;
      
    // Check if it is the first time that we encounter this address
    entry = dw_get_instruction_entry(insn_table, fault_insn);

    // Once the instruction is patched, we should not get this handler called any more
    if(entry != NULL) dw_log(ERROR, MAIN, "SIGSEGV handler called for already patched instruction 0x%llx\n", entry->insn);

    // New address, create an entry in the table
    entry = dw_create_instruction_entry(insn_table, fault_insn, &next_insn, uctx);
    dw_log(INFO, MAIN, "Created entry for instruction 0x%llx\n", entry->insn);

    // Here we want to patch all instructions accessing protected pointers
    // If we cannot install the patch, we fall back to the olx buffer strategy
    if(dw_strategy == DW_PATCH_JUMP) {
        success = dw_instruction_entry_patch(entry, DW_PATCH_JUMP, patch_handler);
        if(success) {     
            dw_log(INFO, MAIN, "Patched instruction 0x%llx\n", entry->insn);
            entry->strategy = DW_PATCH_JUMP;
            dw_protect_active = save_active;
            return;
        } else dw_log(WARNING, MAIN, "Patch jump failed for instruction 0x%llx\n", entry->insn);
    }
    else if(dw_strategy != DW_PATCH_TRAP) dw_log(ERROR, MAIN, "Unknown strategy %d\n", dw_strategy);
        
    // This strategy should always work.
    success = dw_instruction_entry_patch(entry, DW_PATCH_TRAP, patch_handler);
    if(!success) dw_log(ERROR, MAIN, "Patch trap failed for instruction 0x%llx\n", entry->insn);
    entry->strategy = DW_PATCH_TRAP;
    // We return and it will trap again, but this time libpatch will call the patch_handler
    dw_protect_active = save_active;
    return;  
}

// Since this library is activated by LD_PRELOAD, we cannot use the main function argv
// to receive arguments. We use environment variables instead.

// Range of object sizes to protect, by default protect all
static size_t 
  min_protect_size = 0, 
  max_protect_size = ULONG_MAX;

// What objects in sequence to protect, from (first) to (first + max)
// By default protect all

static long unsigned 
  nb_protected = 0, 
  nb_protected_candidates = 0, 
  first_protected = 0, 
  max_nb_protected = ULONG_MAX;
 
static bool check_handling = true;

static enum dw_log_level log_level = 0;

// Generate a statistics file with instructions hits
// static char *stats_file = NULL;
static char *stats_file = ".taintstats.txt";

// This is the initialisation function called at preload time
extern void __attribute__((constructor(65535))) 
dw_init()
{
    // Get the parameters passed as environment variables
    char *arg = getenv("DW_MIN_SIZE");
    if(arg != NULL) min_protect_size = atol(arg);
    arg = getenv("DW_MAX_SIZE");
    if(arg != NULL) max_protect_size = atol(arg);
    arg = getenv("DW_MAX_NB_PROTECTED");
    if(arg != NULL) max_nb_protected = atol(arg);
    arg = getenv("DW_FIRST_PROTECTED");
    if(arg != NULL) first_protected = atol(arg);
    arg = getenv("DW_INSN_ENTRIES");
    if(arg != NULL) nb_insn_olx_entries = atol(arg);
    arg = getenv("DW_LOG_LEVEL");
    if(arg != NULL) { log_level = atoi(arg); dw_set_log_level(log_level); }
    arg = getenv("DW_STATS_FILE");
    if(arg != NULL) stats_file = arg;
    arg = getenv("DW_STRATEGY");
    if(arg != NULL) dw_strategy = atoi(arg);
    arg = getenv("DW_CHECK_HANDLING");
    if(arg != NULL && atoi(arg) == 0) { check_handling = false; dw_set_check_handling(check_handling); }

    dw_log(INFO, MAIN, "Starting program dw\n");
    dw_log(INFO, MAIN, "Min protect size %lu, max protect size %lu, max nb protected %lu, first protected %lu\n", 
        min_protect_size, max_protect_size, max_nb_protected, first_protected);
    dw_log(INFO, MAIN, "Instruction entries %lu, log level %d, stats file %s, strategy %d, check handling %d\n", 
        nb_insn_olx_entries, log_level, stats_file, dw_strategy, check_handling);

    // Initialise the different modules
    insn_table = dw_init_instruction_table(nb_insn_olx_entries);
    dw_protect_init();
    dw_patch_init();
    dw_log(INFO, MAIN, "Patch init\n");

    // Insert the SIGSEGV signal handler to catch protected pointers
    // We use an alternate stack to allow the handler to save
    // tainted registers on the application stack.
    
    stack_t ss;
    size_t ss_size = 16 * PAGE_SIZE;
    int ret;
    struct sigaction sa;
    
    ss.ss_sp = malloc(ss_size);
    ss.ss_size = ss_size;
    ss.ss_flags = 0;
    ret = sigaltstack(&ss, NULL);
    if(ret < 0) dw_log(ERROR, MAIN, "Sigaltstack failed\n");

    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&sa.sa_mask);
    sa.sa_sigaction = signal_protected;
    ret = sigaction(SIGSEGV, &sa, NULL);
    if(ret < 0) dw_log(ERROR, MAIN, "Sigaction SIGSEGV failed\n");
    ret = sigaction(SIGBUS, &sa, NULL);
    if(ret < 0) dw_log(ERROR, MAIN, "Sigaction SIGBUS failed\n");
    
    // start intercepting allocation functions        
    dw_protect_active = true;
}

extern void
__attribute__((destructor)) dw_fini()
{
    // Generate a statistics file
    if(stats_file != NULL) {
        int fd = open(stats_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
        if(fd < 0) dw_log(WARNING, MAIN, "Cannot open file '%s' to write statistics\n", stats_file);
        else {
            dw_fprintf(fd, "There was a total of %d protected malloc on %d candidates\n\n", 
                nb_protected, nb_protected_candidates);
            dw_print_instruction_entries(insn_table, fd);
            close(fd);
        }
    }
    dw_protect_active = false;
    // If there could be remaining tainted pointers, do not free the table
    // dw_fini_instruction_table(insn_table);
    // dw_patch_fini();
}

// Filter the objects to be tainted according to size range and
// Rank in the allocation sequence.

static bool 
check_candidate(size_t size)
{
    if(size >= min_protect_size && size <= max_protect_size) {
        nb_protected_candidates++;
        if(nb_protected_candidates > first_protected && nb_protected < max_nb_protected) {
            nb_protected++;
            return true;
        }
    }
    return false;
}

// For now we will not taint objects allocated from libraries,
// and we assume that this starts at that address. We should
// read /proc/self/maps and let the user specify which libraries to
// exclude from tainting allocations.

static void *library_start = (void *)0x700000000000;

static bool
check_caller(void *caller)
{
  return caller < library_start;
}

// Common malloc that checks if the object should be tainted

static void*
malloc2(size_t size, void *caller)
{
    void *ret = NULL;
    bool save_active = dw_protect_active;
    dw_protect_active = false;
    
    if(save_active) {
        if(check_caller(caller)) {
            if(check_candidate(size)) ret = dw_malloc_protect(size);
        }
        else dw_log(INFO, MAIN, "Not tainting malloc, caller from library\n");
    }
    if(ret == NULL) ret = __libc_malloc(size);
    
    dw_protect_active = save_active;
    dw_log(INFO, MAIN, "Malloc %p, size %lu, nb_candidates %lu\n", ret, size, nb_protected_candidates);
    return ret;
}

// Normal malloc, note the caller and call the common malloc

void*
malloc(size_t size)
{
    return malloc2(size, __builtin_return_address(0));
}

// We allocate the new object, copy the old to the new, free the old

void*
realloc(void *ptr, size_t size)
{
    void *ret = malloc2(size, __builtin_return_address(0));
    if(ptr != NULL) {
        size_t old_size = dw_get_size(ptr);
        memcpy(ret, ptr, old_size < size ? old_size : size);
        free(ptr);
    }
    return ret;
}

void
free(void *ptr)
{
    bool save_active = dw_protect_active;
    dw_protect_active = false;

    if(dw_is_protected(ptr)) {
        dw_free_protect(ptr);
    } else {
        __libc_free(ptr);
    }
    dw_protect_active = save_active;
    dw_log(INFO, MAIN, "Free %p\n", ptr);
}

void*
memalign(size_t alignment, size_t size)
{
    void *ret;
    bool save_active = dw_protect_active;
    dw_protect_active = false;
    
    if(save_active && check_candidate(size)) ret = dw_memalign_protect(alignment, size);
    else ret = __libc_memalign(alignment, size);
    
    dw_protect_active = save_active;
    dw_log(INFO, MAIN, "Memalign %p, size %lu, nb_candidates %lu\n", ret, size, nb_protected_candidates);
    return ret;
}

void*
calloc(size_t nmemb, size_t size)
{
    void *ret = malloc2(nmemb * size, __builtin_return_address(0));
    bzero(ret, nmemb * size);
    return ret;
}


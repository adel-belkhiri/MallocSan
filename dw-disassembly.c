
#define _GNU_SOURCE

#include "dw-disassembly.h"
#include "dw-log.h"
#include "dw-protect.h"
#include "dw-registers.h"
#include <capstone/capstone.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

// When an instruction accesses a protected object, we need to create an entry to
// tell us the affected registers, a buffer to emulate the instruction, and an
// epilogue to reprotect the registers if needed.

struct insn_table {
    size_t size;
    struct insn_entry *entries;
    csh handle;
    cs_insn *insn;
};

// Allocate the instruction hash table and initialize libcapstone

instruction_table*
dw_init_instruction_table(size_t size)
{
    instruction_table *table = malloc(sizeof(instruction_table));
    table->size = 2 * size - 1; // have a hash table about twice as large, and a power of two -1 
    table->entries = calloc(sizeof(struct insn_entry), table->size);

    cs_err csres = cs_open(CS_ARCH_X86, CS_MODE_64, &(table->handle));
    if(csres != CS_ERR_OK) dw_log(ERROR, DISASSEMBLY, "cs_open failed, returned %d\n", csres);
    csres = cs_option(table->handle, CS_OPT_DETAIL, CS_OPT_ON);
    table->insn = cs_malloc(table->handle);    
    return table;
}

// Deallocate the instruction hash table and close libcapstone

void
dw_fini_instruction_table(instruction_table *table) {
    free(table->entries);
    cs_free(table->insn, 1);
    cs_close(&(table->handle));
    free(table);
}

// Get the entry for this instruction address

struct insn_entry*
dw_get_instruction_entry(instruction_table *table, uintptr_t fault)
{
    size_t hash = fault % table->size;
    size_t cursor = hash;

    while((void *)table->entries[cursor].insn != NULL) {
        if(table->entries[cursor].insn == fault) return &(table->entries[cursor]);
        cursor = (cursor + 1) % table->size;
        if(cursor == hash) break;
    }
    return NULL;
}

// Is that register in the list or registers modified by the instruction?
// There is a lot of aliasing between registers, e.g. al, ax, eax, rax,
// all refer to the same register or portion thereof.
static bool
dw_reg_written(struct insn_entry *entry, unsigned reg)
{
  if(reg == X86_REG_INVALID) return false;
  
  for(int i = 0; i < entry->gregs_write_count; i++) 
      if(dw_get_reg_entry(entry->gregs_written[i])->ucontext_index == dw_get_reg_entry(reg)->ucontext_index)
          return true;
  return false;
}

static bool
dw_reg_si_di(struct insn_entry *entry, unsigned reg)
{
  if((reg == X86_REG_RSI || reg == X86_REG_RDI) && entry->repeat) return true;
  else return false;
}

// Create a new entry for this instruction address

#define UNW_LOCAL_ONLY
#include <libunwind.h>

struct insn_entry*
dw_create_instruction_entry(instruction_table *table, uintptr_t fault, uintptr_t *next, ucontext_t *uctx)
{
    size_t hash = fault % table->size;
    size_t cursor = hash;

    while((void *)table->entries[cursor].insn != NULL) {
        if(table->entries[cursor].insn == fault) dw_log(ERROR, DISASSEMBLY, "Trying to add existing instruction in hash table\n"); 
        cursor = (cursor + 1) % table->size;
        if(cursor == hash) dw_log(ERROR, DISASSEMBLY, "Instruction hash table full\n");
    }

    // We insert the new entry at the first empty location following the hash code index
    table->entries[cursor].insn = fault;
    struct insn_entry *entry = &(table->entries[cursor]);
    
    size_t sizeds = 100;
    const uint8_t *code = (uint8_t *)fault;
    uint64_t instr_addr = (uint64_t) fault;
    unsigned reg, base, index;
    uintptr_t addr, scale, displacement, base_addr = 0, index_addr = 0;
    unsigned i, j;
    unsigned arg_m = 0, arg_r = 0;
    bool success;
    int error_code;
    struct reg_entry *re;
    
    // Disassemble the instruction with Capstone
    success = cs_disasm_iter(table->handle, &code , &sizeds, &instr_addr, table->insn);
    error_code = cs_errno(table->handle);
    if(!success) dw_log(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n", fault, error_code);

    // Get the symbol of the containing function, to help in debugging
    unw_cursor_t cur;
    unw_context_t context;
    unw_getcontext(&context);
    unw_init_local(&cur, &context);
    unw_word_t offset;
    unw_word_t pc = fault;
    unw_set_reg(&cur, UNW_REG_IP, pc);
    char proc_name[256];
    if (unw_get_proc_name(&cur, proc_name, sizeof(proc_name), &offset) != 0) {
        strcpy(proc_name, "-- no symbol --");
        offset = 0;
    }

    entry->insn_length = table->insn->size;
    entry->next_insn = *next = instr_addr;
    entry->post_handler = true;
    snprintf(entry->disasm_insn, sizeof(entry->disasm_insn), "%.11s %.51s", table->insn->mnemonic, table->insn->op_str);
    
    code = (uint8_t *)fault;
    char insn_code[256], *c = insn_code;
    int ret, length = 256;
    for(int i = 0; i < entry->insn_length; i++) { 
        ret = snprintf(c, length, "%02x ", *code);
        c += ret; length -= ret; code++;
    }
    
    // This is info, not a warning, but we need it for debug purposes for now
    dw_log(WARNING, DISASSEMBLY, "Instruction 0x%llx (%s+0x%lx), entry %lu (%llx + %lx * %lx = %llx), %d, %d, 0x%lx: %s %s, (%hu) %s\n", 
        fault, proc_name, offset, cursor, table->entries, cursor, sizeof(struct insn_entry), entry, success, 
        error_code, table->insn->address, table->insn->mnemonic, table->insn->op_str, table->insn->size,
        insn_code);    

    cs_detail *detail = table->insn->detail;
    cs_x86 *x86 = &(detail->x86);

    // On control transfer instructions, the post handler hooks do not work.
    // Thus, the tainted pointer will not be retainted after the execution.
    // This is not a problem if the register value is not reused. Otherwise,
    // a subsequent access may not be checked, or the program logic may be
    // compromised if the untainted pointer is compared with a tainted pointer.
    if(detail->groups_count > 0) {
        for(i = 0; i < detail->groups_count; i++) {
            if(detail->groups[i] < X86_GRP_VM) {
                dw_log(WARNING, DISASSEMBLY, "Trap on control transfer instruction, post handler cannot be used %llx\n", fault);
                entry->post_handler = false;
                break;
            }
        }
    }
        
    cs_regs regs_read, regs_write;
    uint8_t read_count = 0, write_count = 0;
    error_code = cs_regs_access(table->handle, table->insn, regs_read, &read_count, regs_write, &write_count);
    if(error_code != CS_ERR_OK) dw_log(ERROR, DISASSEMBLY, "Capstone cannot give register accesses\n");
    if(read_count > MAX_MOD_REG) dw_log(ERROR, DISASSEMBLY, "More registers read %d than expected %d\n", read_count, MAX_MOD_REG);
    if(write_count > MAX_MOD_REG) dw_log(ERROR, DISASSEMBLY, "More registers written %d than expected %d\n", write_count, MAX_MOD_REG);
    entry->gregs_read_count = read_count;
    entry->gregs_write_count = write_count;
    
    if(x86->prefix[0] == X86_PREFIX_REP || x86->prefix[0] == X86_PREFIX_REPE || x86->prefix[0] == X86_PREFIX_REPNE) 
        entry->repeat = true;
    else entry->repeat = false;

    for (i = 0; i < min(read_count, MAX_MOD_REG); i++) {
        reg = entry->gregs_read[i] = regs_read[i];
        dw_log(INFO, DISASSEMBLY, "read: %s; (%d)\n", cs_reg_name(table->handle, reg), reg);
    }

    for (i = 0; i < min(write_count, MAX_MOD_REG); i++) {
        reg = entry->gregs_written[i] = regs_write[i];
        dw_log(INFO, DISASSEMBLY, "write: %s; (%d)\n", cs_reg_name(table->handle, reg), reg);
    }

    // Loop over all the instruction arguments
    unsigned nb_protected = 0;
    for (i = 0; i < x86->op_count; i++){
        switch(x86->operands[i].type) {
        
            // We need to know the overwritten registers to avoid retainting them
    	    case X86_OP_REG: 
    	        reg = x86->operands[i].reg;
    	        re = dw_get_reg_entry(reg);
    	        if(re->ucontext_index >= 0) {
    	            if(arg_r >= MAX_REG_ARG) dw_log(ERROR, DISASSEMBLY, "Too many destination register arguments\n");
    	            entry->arg_r[arg_r].reg = reg;
    	            entry->arg_r[arg_r].length = re->size;
    	            entry->arg_r[arg_r].access = x86->operands[i].access;
    	            arg_r++; 
    	        }
    	        dw_log(INFO, DISASSEMBLY, "Register operand %lu, reg %s, access %hhu\n", i, cs_reg_name(table->handle, x86->operands[i].reg), x86->operands[i].access);
    	        break;
    	        
            // The memory address is given by base + (index * scale) + displacement
            case X86_OP_MEM:
    	        if(arg_m >= MAX_MEM_ARG) dw_log(ERROR, DISASSEMBLY, "Too many memory arguments\n");

                // Check if we have a base register and if it is a general purpose register
                entry->arg_m[arg_m].base = base = x86->operands[i].mem.base;
                if(base == X86_REG_INVALID) base_addr = 0; // no base register
                else {
                    re = dw_get_reg_entry(base);
                    if(re->ucontext_index < 0)  
                        dw_log(ERROR, DISASSEMBLY, "Base register %s not general register\n", re->name);
                    else base_addr = dw_get_register(uctx, re->ucontext_index);
                }

                // Check if we have an index register and if it is a general purpose register
                entry->arg_m[arg_m].index = index = x86->operands[i].mem.index;
                if(index == X86_REG_INVALID) index_addr = 0;
                else { 
                    re = dw_get_reg_entry(index);
                    if(re->ucontext_index < 0) 
                        dw_log(ERROR, DISASSEMBLY, "Index register %s not general register\n", re->name);
                    else index_addr = dw_get_register(uctx, re->ucontext_index);
                }
                
                entry->arg_m[arg_m].scale = scale = x86->operands[i].mem.scale;
                entry->arg_m[arg_m].displacement = displacement = x86->operands[i].mem.disp;
                entry->arg_m[arg_m].length = x86->operands[i].size;
                entry->arg_m[arg_m].access = x86->operands[i].access;  

                addr = base_addr + (index_addr * scale) + displacement;
                entry->arg_m[arg_m].base_taint = entry->arg_m[arg_m].index_taint = 0;

    	        dw_log(INFO, DISASSEMBLY, 
    	            "Memory operand %lu, segment %d, base %s (0x%llx) + (index %s (0x%llx) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n", i, 
    	            x86->operands[i].mem.segment, cs_reg_name(table->handle, base), base_addr, cs_reg_name(table->handle, index), index_addr, scale, displacement, addr, x86->operands[i].access);

                // Check that the segmentation violation is related to a tainted pointer
                if(dw_is_protected((void *)base_addr)) {
    	            nb_protected++;
    	            entry->arg_m[arg_m].base_taint = base_addr;
    	            if(dw_is_protected_index((void *)index_addr)) 
    	                dw_log(ERROR, DISASSEMBLY,"Both base and index registers are protected\n");
    	        }
    	        else if(dw_is_protected_index((void *)index_addr)) {
    	            nb_protected++;
    	            entry->arg_m[arg_m].index_taint = index_addr;
    	        }
    	        
                arg_m++;
                break;
                
            case X86_OP_IMM:
                dw_log(INFO, DISASSEMBLY, "Immediate operand %lu, value %lu\n", i, x86->operands[i].imm);
                break;
            default:
                dw_log(INFO, DISASSEMBLY, "Invalid operand %lu\n", i);
                break;
        }
    }
    
    entry->nb_arg_m = arg_m;
    entry->nb_arg_r = arg_r;
    
    for(i = 0; i < arg_m; i++) {
        // We need to retaint the register unless it is overwritten by the instruction
        entry->arg_m[i].base_access = entry->arg_m[i].index_access = 0;  // CS_AC_INVALID

        // Check if the base or index register, that may become tainted, is also a register argument
        for(j = 0; j < arg_r; j++) {
            if(dw_get_reg_entry(entry->arg_r[j].reg)->ucontext_index == 
               dw_get_reg_entry(entry->arg_m[i].base)->ucontext_index) {
                entry->arg_m[i].base_access = entry->arg_r[j].access;
  
                if(entry->arg_m[arg_m].access == (CS_AC_READ | CS_AC_WRITE))
                    dw_log(WARNING, DISASSEMBLY, "Memory argument is unexpectedly read and written\n"); 

                if(arg_r != 1) dw_log(WARNING, DISASSEMBLY, "More than one register argument, may be ambiguous\n");
            }
 
            if(dw_get_reg_entry(entry->arg_r[j].reg)->ucontext_index == 
               dw_get_reg_entry(entry->arg_m[i].index)->ucontext_index) {
                entry->arg_m[i].index_access = entry->arg_r[j].access;

                if(entry->arg_m[arg_m].access == (CS_AC_READ | CS_AC_WRITE))
                    dw_log(WARNING, DISASSEMBLY, "Memory argument is unexpectedly read and written\n"); 

                if(arg_r != 1) dw_log(WARNING, DISASSEMBLY, "More than one register argument, may be ambiguous\n");
            }
        }

        // Registers rsi and rdi are auto-incremented for some instructions with the rep prefix.
        // This is accounted for by reapplying the taint, not restoring the saved register value.
        // Here we check if there exists other cases apart from rsi and rdi with rep instructions.
        if(dw_reg_written(entry, entry->arg_m[i].base) && (entry->arg_m[i].base_access & CS_AC_WRITE) == 0 &&
           !dw_reg_si_di(entry, entry->arg_m[i].base))
            dw_log(WARNING, DISASSEMBLY, "Instruction 0x%llx, base register %s implicitly modified\n", 
                   entry->insn, dw_get_reg_entry(entry->arg_m[i].base)->name);
        
        if(dw_reg_written(entry, entry->arg_m[i].index) && (entry->arg_m[i].index_access & CS_AC_WRITE) == 0 &&
           !dw_reg_si_di(entry, entry->arg_m[i].index))
            dw_log(WARNING, DISASSEMBLY, "Instruction 0x%llx, index register %s implicitly modified\n", 
                   entry->insn, dw_get_reg_entry(entry->arg_m[i].index)->name);
    }
    
    if(nb_protected == 0) dw_log(ERROR, DISASSEMBLY,"No protected memory argument but generates a fault\n");
    return entry;
}

static void
check_patch(patch_status s, char *msg) 
{
    if(s == PATCH_OK) return;
    struct patch_error e;
    patch_last_error(&e);
    dw_log(WARNING, DISASSEMBLY, "Patch lib return value not OK, %d, for %s, origin %s, irritant %s, message %s\n", s, msg, e.origin, e.irritant, e.message);
}

void
dw_patch_init() 
{
    const struct patch_option options[] = {{.type = PATCH_OPT_ENABLE_WXE, .enable_wxe = 0}};
    (void)patch_init(options, sizeof(options) / sizeof(struct patch_option));
}

// Patch the instruction accessing a protected object and attach a pre and post handler
// to unprotect and reprotect the tainted registers

bool
dw_instruction_entry_patch(struct insn_entry *entry, enum dw_strategies strategy, dw_patch_probe patch_handler)
{
    struct patch_location location = {
        .type = PATCH_LOCATION_ADDRESS,
	.direction = PATCH_LOCATION_FORWARD,
	.algorithm = PATCH_LOCATION_FIRST,
	.address = entry->insn,
    };

    struct patch_exec_model exec_model = {
        .type = PATCH_EXEC_MODEL_PROBE_AROUND_STEP,
	.probe.read_registers = 0,
	.probe.write_registers = 0,
	.probe.clobber_registers = PATCH_REGS_ALL,
	.probe.user_data = entry,
	.probe.procedure = patch_handler,
    };

    patch_t patch;
    patch_attr attr;
    patch_status s;

    // On control transfer instructions, post handlers are not available.
    if(!(entry->post_handler)) exec_model.type = PATCH_EXEC_MODEL_PROBE;
    
    s = patch_attr_init(&attr); check_patch(s, "attr init");
    if(strategy == DW_PATCH_TRAP) {
        s= patch_attr_set_trap_policy(&attr, PATCH_TRAP_POLICY_FORCE); check_patch(s, "set policy FORCE");
    } 
    else if(strategy == DW_PATCH_JUMP) {
        s= patch_attr_set_trap_policy(&attr, PATCH_TRAP_POLICY_FORBID); check_patch(s, "set policy FORBID");
    } 
    else dw_log(ERROR, DISASSEMBLY, "Unknown patching strategy\n");
  
    s = patch_attr_set_initial_state(&attr, PATCH_ENABLED); check_patch(s, "set enabled");
    s = patch_make(&location, &exec_model, &attr, &patch, NULL); check_patch(s, "make"); if(s != PATCH_OK) return false;
    s = patch_commit(); check_patch(s, "commit"); if(s != PATCH_OK) return false;
    return true;
}

// With PATCH_EXEC_MODEL_AROUND_STEP_TRAP or PATCH_EXEC_MODEL_AROUND_STEP, the SIGSEGV handler will not
// get called, the patch handler (pre and post) will be called instead. It will be called either through
// the target instruction patched by a trap (int3), intercepted by libpatch with their own handler,
// or through the target instruction patched by a jump.
//
// Eventually, to avoid the cost of saving a lot of registers and making a call, we may use 
// PATCH_EXEC_MODEL_DIVERT to jump to an OLX buffer that untaints, executes the relocated 
// instruction, and retaints in assembly directly.
//
// We save all the relevant registers in a static structure to check if some
// registers are unexpectedly modified by the stepped instruction. This
// structure should be Thread Local Storage for multi-threaded programs.
// Once the algorithm is well tested and debugged, this saving and comparison
// step will be removed.

void
dw_print_regs(struct patch_exec_context *ctx)
{
    for(int i = 0; i < dw_nb_saved_registers; i++)
        dw_log(INFO, DISASSEMBLY, "%s, %llx\n", dw_get_reg_entry(dw_saved_registers[i])->name, ctx->general_purpose_registers[i]);
}

static bool dw_check_handling = false;

void dw_set_check_handling(bool f) { dw_check_handling = f; }

// A potentially tainted pointer is accessed, unprotect it before the access
// (Check use of unprotect / retaint versus flavors other than OID, single unprotect / reprotect)

void 
dw_unprotect_context(struct patch_exec_context *ctx)
{
    struct insn_entry *entry = ctx->user_data;
    struct reg_entry *re, *reb, *rei;
    struct memory_arg *arg;
    unsigned i, reg, regb, regi;
    uintptr_t valueb, valuei, addr;

    if(dw_check_handling) {
        dw_log(INFO, DISASSEMBLY, "Unprotect instruction 0x%llx: %s\n", entry->insn, entry->disasm_insn);
        dw_print_regs(ctx);
    }

    // Untaint all possibly tainted memory arguments   
    for(i = 0; i < entry->nb_arg_m; i++) {
        arg = &(entry->arg_m[i]);
        regb = arg->base;
        reb = dw_get_reg_entry(regb);
        if(regb == X86_REG_INVALID) valueb = 0; // no base register
        else valueb = dw_get_register(ctx, reb->libpatch_index);
                
        regi = arg->index;
        rei = dw_get_reg_entry(regi);
        if(regi == X86_REG_INVALID) valuei = 0;
        else valuei = dw_get_register(ctx, rei->libpatch_index);
            
        addr = valueb + valuei * arg->scale + arg->displacement;

        if(dw_is_protected((void *)valueb)) {
            if(arg->base_taint == 0) 
                dw_log(INFO, DISASSEMBLY, "Newly tainted base for mem arg %d\n", i);
            if(dw_is_protected_index((void *)valuei)) 
                dw_log(WARNING, DISASSEMBLY, "Both index and base tainted for mem arg %d\n", i);
            arg->base_taint = valueb;
            valueb = (uintptr_t)dw_unprotect((void *)valueb);
            dw_set_register(ctx, reb->libpatch_index, valueb);
            arg->index_taint = 0;

            // The base register is a pointer, if less than 8 bytes are read, this is suspicious.
            if((arg->base_access & CS_AC_READ) && (arg->length < 8))
                dw_log(WARNING, DISASSEMBLY, 
                    "Instruction 0x%llx, base register %s only partially copied to/from memory\n", 
                    entry->insn, dw_get_reg_entry(regb)->name);
        }

        else if(dw_is_protected_index((void *)valuei)) {
            if(arg->index_taint == 0) 
                dw_log(INFO, DISASSEMBLY, "Newly tainted index for mem arg %d\n", i);
            arg->index_taint = valuei;
            valuei = (uintptr_t)dw_unprotect((void *)valuei);
            dw_set_register(ctx, rei->libpatch_index, valuei);
            arg->base_taint = 0;
            
            // The index register is a pointer, if less than 8 bytes are read, this is suspicious.
            if((arg->index_access & CS_AC_READ) && (arg->length < 8))
                dw_log(WARNING, DISASSEMBLY, 
                    "Instruction 0x%llx, index register %s only partially copied to/from memory\n", 
                    entry->insn, dw_get_reg_entry(regi)->name);
        }
        
        else {
            arg->base_taint = 0;
            arg->index_taint = 0;
            continue;
        }
                
        // With the computed tainted address, check if the access is valid.
        // We take the argument length, and use the repeat count if present.
        if(entry->repeat) {
            size_t count = dw_get_register(ctx, dw_get_reg_entry(X86_REG_RCX)->libpatch_index);
            dw_check_access((void *)addr, arg->length * count);
        }
        else dw_check_access((void *)addr, arg->length);

        // We have a special case, the same register is used to access the memory and as argument.
        // - For a memory read, register write, do not retaint the ovewritten register in post handler.
        //
        // - For a memory read, register read, it is presumably a comparison. We must untaint the register and
        //   the memory for a proper comparison, and retaint both the register and memory in the post handler.
        //   We save the memory address and value, and untaint the value. In the post handler 
        //   we retaint the register, and restore the saved value at the saved address
        //
        // - For a memory write, register read, the untainted register is stored in memory, we should retaint
        //   both the register and memory in the post handler.
        //
        // - For a memory write, register write, not sure what to do. Not retaint the register but retaint memory?
        
        if((arg->base_access && arg->base_taint != 0) || (arg->index_access && arg->index_taint != 0)) {
            arg->saved_address = valueb + valuei * arg->scale + arg->displacement;
            addr = (uintptr_t)dw_unprotect((void *)addr);
            if(addr != arg->saved_address) 
                dw_log(WARNING, DISASSEMBLY, "Both ways to unprotect address differ 0x%llx 0x%llx\n", 
                    addr, arg->saved_address);
            if((arg->access & CS_AC_READ) && 
               (((arg->base_access & CS_AC_READ) && arg->base_taint) || 
                ((arg->index_access & CS_AC_READ) && arg->index_taint))) {
                arg->saved_value = (uintptr_t)(*((void **)arg->saved_address));
                *((void **)arg->saved_address) = dw_unprotect((void *)(arg->saved_value));
            }
        }
    }

    if(dw_check_handling) {  
        for(i = 0; i < dw_nb_saved_registers; i++) {
            reg = dw_saved_registers[i];
            re = dw_get_reg_entry(reg);
            dw_save_regs[i] = dw_get_register(ctx, re->libpatch_index);
            dw_log(INFO, DISASSEMBLY, "%s, %llx\n", re->name, ctx->general_purpose_registers[i]);
        }
    }

    entry->hit_count++;
}

// In the post handler, we normally retaint all registers which were untainted in the pre handler.
// There are a few special cases when the same register is used as a base or index to access the memory 
// and as argument.

void
dw_reprotect_context(struct patch_exec_context *ctx)
{
    struct insn_entry *entry = ctx->user_data;
    struct memory_arg *arg;
    struct reg_entry *re;
    unsigned i, reg;
    uintptr_t value;

    if(dw_check_handling) {
        dw_log(INFO, DISASSEMBLY, "Reprotect instruction 0x%llx: %s\n", entry->insn, entry->disasm_insn);
        dw_print_regs(ctx);
        for(i = 0; i < dw_nb_saved_registers; i++) {
            // dw_log(INFO, MAIN, "%s = 0x%llx\n", dw_get_patch_reg_name(i), ctx->gregs[i]);
            reg = dw_saved_registers[i];
            re = dw_get_reg_entry(reg);
            value = dw_get_register(ctx, re->libpatch_index);
            if((dw_save_regs[i] != value) && dw_reg_written(entry, reg) == false)
                dw_log(WARNING, MAIN, "Instruction 0x%llx, register %s modified but should not, now 0x%llx vs 0x%llx\n", 
                    entry->insn, re->name, value, dw_save_regs[i]);
        }
    }
        
    for(int i = 0; i < entry->nb_arg_m; i++) {
        arg = &(entry->arg_m[i]);

        // The tainted register, base or index, is retainted unless the same register
        // was also an overwritten register argument.

        if(arg->base_taint && ((arg->base_access & CS_AC_WRITE) == 0)) {
            reg = arg->base;
            re = dw_get_reg_entry(reg);
            value = dw_get_register(ctx, re->libpatch_index);            
            dw_set_register(ctx, re->libpatch_index, (uint64_t)dw_retaint((void *)value, (void *)arg->base_taint));
        }

        if(arg->index_taint && ((arg->index_access & CS_AC_WRITE) == 0)) {
            reg = arg->index;
            re = dw_get_reg_entry(reg);
            value = dw_get_register(ctx, re->libpatch_index);            
            dw_set_register(ctx, re->libpatch_index, (uint64_t)dw_retaint((void *)value, (void *)arg->index_taint));
        }

        // If the tainted register, base or index, was also a register argument, 
        // we have special cases to consider.       
        if((arg->base_access && arg->base_taint) || (arg->index_access && arg->index_taint)) {

            // If the memory was read and the tainted register, base or index, was a read register argument,
            // we presumably have a comparison. The memory value was untainted in the pre handler and should
            // be restored here.
            if(arg->access & CS_AC_READ) {
                if(((arg->base_access & CS_AC_READ) && arg->base_taint) || ((arg->index_access & CS_AC_READ) && arg->index_taint))
                    *((void **)arg->saved_address) = (void *)(arg->saved_value);
            }
            
            // If the memory was written and the tainted register, base or index, was also a register argument
            // we suppose that the untainted register was stored in memory and we need to retaint the memory 
            // with the saved register taint
            else if(arg->access & CS_AC_WRITE) {
                uintptr_t saved_taint;
                if(arg->base_taint) saved_taint = arg->base_taint;
                else saved_taint = arg->index_taint;
                *((void **)arg->saved_address) = dw_retaint(*((void **)arg->saved_address), (void *)saved_taint);
            }
        }
    }    
}

// Dump the content of the instruction table, for knowing the
// number of instructions accessing protected objects,
// and the number of hits for each instruction.
// Print statistics about each instruction patched

void
dw_print_instruction_entries(instruction_table *table, int fd)
{
    struct insn_entry *entry;
    unsigned count = 0;

    for(int i = 0; i < table->size; i++) {
        entry = &(table->entries[i]);
        if((void *)entry->insn != NULL) {
            dw_fprintf(fd, "%4d 0x%lx: %9u: %2u: %1u %s;\n", count, entry->insn, entry->hit_count, entry->insn_length, entry->strategy, entry->disasm_insn);
            count++;
        }
    }
}


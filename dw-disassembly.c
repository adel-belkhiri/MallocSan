
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

static bool
dw_reg_written(struct insn_entry *entry, unsigned reg)
{
  for(int i = 0; i < entry->gregs_write_count; i++) 
      if(dw_get_reg_entry(entry->gregs_written[i])->ucontext_index == dw_get_reg_entry(reg)->ucontext_index) return true;
  return false;
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
    
    success = cs_disasm_iter(table->handle, &code , &sizeds, &instr_addr, table->insn);
    error_code = cs_errno(table->handle);
    if(!success) dw_log(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n", fault, error_code);

    unw_cursor_t cur;
    unw_context_t context;
    unw_getcontext(&context);
    unw_init_local(&cur, &context);
    unw_word_t offset, pc = fault;
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
    
    dw_log(INFO, DISASSEMBLY, "Instruction 0x%llx (%s+0x%lx), %d, %d, 0x%lx: %s %s, (%hu) %s\n", fault, proc_name, offset, success, 
        error_code, table->insn->address, table->insn->mnemonic, table->insn->op_str, table->insn->size, insn_code);    

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
    uint8_t read_count, write_count;
    read_count = write_count = 0;
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
            // Is the base (or even index with scale = 1) tainted? Mark it as protected
            case X86_OP_MEM:
    	        if(arg_m >= MAX_MEM_ARG) dw_log(ERROR, DISASSEMBLY, "Too many memory arguments\n");
    	        
                entry->arg_m[arg_m].base = base = x86->operands[i].mem.base;
                re = dw_get_reg_entry(base);
                if(base == X86_REG_INVALID) base_addr = 0; // no base register
                else if(re->ucontext_index < 0)  dw_log(ERROR, DISASSEMBLY, "Base register not general register\n");
                else base_addr = dw_get_register(uctx, re->ucontext_index);
                
                entry->arg_m[arg_m].index = index = x86->operands[i].mem.index;
                re = dw_get_reg_entry(index);
                if(index == X86_REG_INVALID) index_addr = 0;
                else if(re->ucontext_index < 0) dw_log(ERROR, DISASSEMBLY, "Index register not general register\n");
                else index_addr = dw_get_register(uctx, re->ucontext_index);
                
                entry->arg_m[arg_m].scale = scale = x86->operands[i].mem.scale;
                entry->arg_m[arg_m].displacement = displacement = x86->operands[i].mem.disp;
                entry->arg_m[arg_m].length = x86->operands[i].size;

                addr = base_addr + (index_addr * scale) + displacement;                        
                if(dw_is_protected((void *)base_addr)) {
                    entry->arg_m[arg_m].is_protected = true;
                    entry->arg_m[arg_m].protected_reg = entry->arg_m[arg_m].base;                    
                } else if(dw_is_protected_index((void *)index_addr)) {
                    entry->arg_m[arg_m].is_protected = true;
                    entry->arg_m[arg_m].protected_reg = entry->arg_m[arg_m].index;
                    dw_log(WARNING, DISASSEMBLY,"Index register is protected instead of base\n");
                } else entry->arg_m[arg_m].is_protected = false;

    	        dw_log(INFO, DISASSEMBLY, 
    	            "Memory operand %lu, segment %d, base %s (0x%llx) + (index %s (0x%llx) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n", i, 
    	            x86->operands[i].mem.segment, cs_reg_name(table->handle, base), base_addr, cs_reg_name(table->handle, index), index_addr, scale, displacement, addr, x86->operands[i].access);

    	        if(dw_is_protected((void *)base_addr) && dw_is_protected_index((void *)index_addr)) 
    	            dw_log(ERROR, DISASSEMBLY,"Both base and index registers are protected\n");
    	            
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
    
    // We need to have at least one protected register as memory argument.
    // Otherwise we should not have a segmentation violation.
    entry->nb_arg_m = arg_m;
    entry->nb_arg_r = arg_r;
    unsigned nb_protected = 0;
    unsigned nb_reprotect = 0;
    
    for(i = 0; i < arg_m; i++) {
        if(entry->arg_m[i].is_protected) {
            nb_protected++;
            
            // We need to retaint the register unless it is overwritten by the instruction
            entry->arg_m[i].reprotect = true;
            entry->arg_m[i].reprotect_mem = false;
            
            for(j = 0; j < arg_r; j++) {
                if(dw_get_reg_entry(entry->arg_r[j].reg)->ucontext_index == dw_get_reg_entry(entry->arg_m[i].protected_reg)->ucontext_index) {
                    if(entry->arg_r[j].access & CS_AC_WRITE) {
                        entry->arg_m[i].reprotect = false;
                        if(entry->arg_r[j].length < 4) 
                            dw_log(ERROR, DISASSEMBLY, "Instruction 0x%llx, tainted register %s only partially overwritten\n", 
                                entry->insn, dw_get_reg_entry(entry->arg_r[j].reg)->name);
                    }
                    if(entry->arg_r[j].access & CS_AC_READ) {
                        entry->arg_m[i].reprotect_mem = true;
                        dw_log(WARNING, DISASSEMBLY, "Source register is also address, stored value will be retainted %llx\n", fault);
                        if(entry->arg_r[j].length != 8) dw_log(WARNING, DISASSEMBLY, "Tainted register not stored in full\n");
                    }
                }
            }
            if(entry->arg_m[i].reprotect) {
                nb_reprotect++;
                if(dw_reg_written(entry, entry->arg_m[i].protected_reg))
                    dw_log(INFO, DISASSEMBLY, "Instruction 0x%llx, tainted register %s implicitly modified\n", 
                        entry->insn, dw_get_reg_entry(entry->arg_m[i].protected_reg)->name);
            }
        }
        else entry->arg_m[i].reprotect = false;
    }
    
    if(nb_protected == 0) dw_log(ERROR, DISASSEMBLY,"No protected memory argument but generates a fault\n");
    entry->nb_reprotect = nb_reprotect;
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
// Eventually, to avoid the cost of saving a lot of registers and making a call, we may use PATCH_EXEC_MODEL_DIVERT
// to jump to an OLX buffer that untaints, executes the relocated instruction, and retaints in assembly directly.
//
// We have the list of tainted registers. Save those registers and they will be restored in the
// prologue or post handler. Some tainted registers may be vector registers.
//
// Some assumptions that we may want to check:
// - registers expected to be tainted are indeed tainted
// - only "written" registers are modified
// - base or index tainted as expected
// - number of vector registers tainted / accessed
// - a register used as tainted address is not stored while temporarily untainted

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

// A potentially tainted pointer is accessed, unprotect it before the access

/*
rep movsq qword ptr [rdi], qword ptr [rsi], (3) f3 48 a5
read: rdi, rsim rflags, rcx;
write: rdi, rsi, rcx;
Memory operand 0, segment 0, base rdi (0x2562ab2c8f4d8) + (index (null) (0x0) x scale 0x1) + disp 0x0 = 0x2562ab2c8f4d8, access 2
Memory operand 1, segment 0, base rsi (0x7fffc9926478) + (index (null) (0x0) x scale 0x1) + disp 0x0 = 0x7fffc9926478, access 1
*/

static bool dw_check_handling = true;

void dw_set_check_handling(bool f) { dw_check_handling = f; }

// Check use of unprotect / retaint versus flavors other than OID (single unprotect / reprotect)

void 
dw_unprotect_context(struct patch_exec_context *ctx)
{
    struct insn_entry *entry = ctx->user_data;
    struct reg_entry *re, *reb, *rei;
    unsigned i, reg, regb, regi;
    uintptr_t value, valueb, valuei, addr;

    if(dw_check_handling) {
        dw_log(INFO, DISASSEMBLY, "Unprotect instruction 0x%llx: %s\n", entry->insn, entry->disasm_insn);
        dw_print_regs(ctx);
    }
    
    // Untaint all possibly tainted memory arguments, save the tainted pointer to retaint afterwards   
    for(i = 0; i < entry->nb_arg_m; i++) {
        if(entry->arg_m[i].is_protected) {
            reg = entry->arg_m[i].protected_reg;
            re = dw_get_reg_entry(reg);
            value = dw_get_register(ctx, re->libpatch_index);
            entry->arg_m[i].saved_taint = value;

            regb = entry->arg_m[i].base;
            reb = dw_get_reg_entry(regb);
            if(regb == X86_REG_INVALID) valueb = 0; // no base register
            else valueb = dw_get_register(ctx, reb->libpatch_index);
                
            regi = entry->arg_m[i].index;
            rei = dw_get_reg_entry(regi);
            if(regi == X86_REG_INVALID) valuei = 0;
            else valuei = dw_get_register(ctx, rei->libpatch_index);
            
            addr = valueb + valuei * entry->arg_m[i].scale + entry->arg_m[i].displacement;

            if(dw_check_handling) {
                // We have both a base and index, check that their usage has not changed
                if(regi != X86_REG_INVALID && regb != X86_REG_INVALID) {
                    if((dw_is_protected_index((void *)valuei) && regi != reg) || (dw_is_protected((void *)valueb) && regb != reg))
                        dw_log(ERROR, DISASSEMBLY, "Registers not tainted as expected, protected %s (%llx), index %s (%llx), base %s (%llx)\n",
                            re->name, value, rei->name, valuei, reb->name, valueb);
                }
            }
            
            if(entry->repeat) {
                size_t count = dw_get_register(ctx, dw_get_reg_entry(X86_REG_RCX)->libpatch_index);
                dw_check_access((void *)addr, entry->arg_m[i].length * count);
            }
            else dw_check_access((void *)addr, entry->arg_m[i].length);

            if(dw_check_handling) {
                dw_log(INFO, DISASSEMBLY, "Instruction 0x%llx, register %s untainted, 0x%llx becomes 0x%llx, addr 0x%llx + 0x%llx * 0x%llx + 0x%llx = 0x%llx\n", 
                    entry->insn, re->name, value, (uint64_t)dw_unprotect((void *)value), valueb, valuei, entry->arg_m[i].scale, entry->arg_m[i].displacement, entry->arg_m[i].saved_address);
            }

            if(entry->arg_m[i].reprotect_mem) {
                if(reg == regb) valueb = (uintptr_t)dw_unprotect((void *)valueb);
                if(reg == regi && dw_is_protected_index((void *)valuei)) valuei = (uintptr_t)dw_unprotect((void *)valuei);
                entry->arg_m[i].saved_address = valueb + valuei * entry->arg_m[i].scale + entry->arg_m[i].displacement;
            }

            dw_set_register(ctx, re->libpatch_index, (uintptr_t)dw_unprotect((void *)value));
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

// Retaint registers, called from patch post-handler
// - restore all the saved registers

void
dw_reprotect_context(struct patch_exec_context *ctx)
{
    struct insn_entry *entry = ctx->user_data;
    struct reg_entry *re;
    unsigned i, reg;
    uintptr_t value;
    void *before, *after;

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
        if(entry->arg_m[i].reprotect) {
            int reg = entry->arg_m[i].protected_reg;
            re = dw_get_reg_entry(reg);
            value = dw_get_register(ctx, re->libpatch_index);
            
            // If that register changed and was not flagged as "written" by the instruction, it will be detected above
            // if(dw_untaint((void *)(entry->arg_m[i].saved_taint)) != (void *)value) 
            //     dw_log(WARNING, MAIN, "Instruction 0x%llx, reprotect register %s differs now 0x%llx vs 0x%llx\n", 
            //     entry->insn, re->name, value, entry->arg_m[i].saved_taint);

            dw_set_register(ctx, re->libpatch_index, (uint64_t)dw_retaint((void *)value, (void *)entry->arg_m[i].saved_taint));
        }
        
        if(entry->arg_m[i].reprotect_mem) {
            if(dw_check_handling) before = *((void **)entry->arg_m[i].saved_address);

            *((void **)entry->arg_m[i].saved_address) = dw_retaint(*((void **)entry->arg_m[i].saved_address), (void *)entry->arg_m[i].saved_taint);

            if(dw_check_handling) {
                after = *((void **)entry->arg_m[i].saved_address);
                dw_log(INFO, DISASSEMBLY, "Reprotect_mem before 0x%llx, after 0x%llx\n", before, after);
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
    struct reg_entry *re;
    unsigned reg, count = 0;
    
    for(int i = 0; i < table->size; i++) {
        entry = &(table->entries[i]);
        if((void *)entry->insn != NULL) {
            dw_fprintf(fd, "%4d 0x%lx: %9u: %2u: %1u %s; protected", count, entry->insn, entry->hit_count, entry->insn_length, entry->strategy, entry->disasm_insn);
            count++;
            for(int j = 0; j < entry->nb_arg_m; j++) {
                if(entry->arg_m[j].is_protected) {
                    reg = entry->arg_m[j].protected_reg;
                    re = dw_get_reg_entry(reg);
                    dw_fprintf(fd, " %s", re->name);
                }
            }
            dw_fprintf(fd, "\n");
        }
    }
}

#if 0

#include <olx/olx.h>

#define MAX_EPILOGUE_SIZE 40

// A simple mmap allocator to provide libolx with chunks of executable memory.
// It is not thread safe and no free is provided.

static void
    *alloc_reserve_current = NULL,
    *alloc_reserve_end = NULL;

static size_t alloc_chunk_size = 2 * PAGE_SIZE;

static void *alloc_olx(size_t *size)
{
    size_t actual_size = *size;
    if(actual_size % 64) actual_size = ((actual_size >> 6) + 1) << 6;
    *size = actual_size;
    
    if(alloc_reserve_current == NULL || alloc_reserve_current + actual_size > alloc_reserve_end) {
        alloc_reserve_current = mmap(NULL, alloc_chunk_size, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if(alloc_reserve_current == MAP_FAILED) dw_log(ERROR, DISASSEMBLY, "Cannot allocate memory for OLX buffers\n");
        alloc_reserve_end = alloc_reserve_current + alloc_chunk_size;
        if(actual_size > alloc_chunk_size) dw_log(ERROR, DISASSEMBLY, "OLX buffer allocation request too large\n");
    }
    void *ret = alloc_reserve_current;
    alloc_reserve_current += actual_size;
    return ret;
}

/* 
- Quel code est utilisé dans le memcpy/memmove qui segfault ? Il est
possible qu'il passe à une implémentation SSE ou autre au-delà d'une
certaine taille,

- Ça peut être causé par un problème de comparaison entre l'adresse de
fin et la valeur actuelle du pointeur. Certaines causes possibles:

1) Omettre de remettre le taint sur le pointeur après une lecture ou
écriture, alors que l'adresse de fin a le taint.

2) Si le taint flag set le bit de signe (most significant bit), si la
comparaison est signée, ça pourrait ne pas avoir l'effet attendu.

3) Avoir une adresse de fin à laquelle il manque le taint, par exemple à
cause d'une erreur de manipulation lors de son incrémentation du nombre
de bytes à copier.

4) memcpy/memmove est un parfait use-case pour les pointeur à
autoincrément, donc valider si c'est ce qui se passe. (e.g. string
instructions telles que MOVS, CMPS, SCAS, LODS, et STOS). La direction
incrément/décrément dépend du flag DF.

5) c'est aussi un use-case parfait pour le préfix "rep", qui va répéter
l'instruction préfixée tant que la condition est vraie.

- VPGATHERQQ ymm11, qword ptr [ymm9], ymm10
    save the whole vector before untaint even if a condition is there, restored after anyway...
    save registers in TLS structure may be easier
    how to access those registers from C if not in saved context...
    register __m128 foo asm("xmm0")

- instruction loop auto-inc rcx?

- Instruction stocke adresse détaintée...

0000000000000000 <fct>:
    0:        48 89 3f                     mov    %rdi,(%rdi)
    3:        c3                           retq

*/

// Create an out of line execution (OLX) buffer for this instruction.
//
// When a tainted pointer is encountered, a signal is received. The handler
// can untaint the pointer, execute the offending instruction out of line,
// execute retainting code and continue with the next instruction.

static void chk(olx_status s)
{
  if(s == OLX_OK) return;
  dw_log(ERROR, DISASSEMBLY, "libolx returned %d\n", s);
}

void
dw_instruction_entry_make_olx(struct insn_entry *entry, uintptr_t next, dw_olx_probe pre_handler, dw_olx_probe post_handler)
{
    olx_stream stream;
    uintptr_t buffer;
    size_t size;
    olx_status ret;

    ret = olx_make(&stream); chk(ret);
    ret = olx_add_call_to_C(stream, OLX_CALL_C_SAVE_X86_64_XSAVE_CONTEXT, pre_handler, entry); chk(ret);
    ret = olx_add_instruction_and_relocate(stream, (void *)entry->insn, entry->insn_length, entry->insn); chk(ret);
    ret = olx_add_call_to_C(stream, OLX_CALL_C_SAVE_X86_64_XSAVE_CONTEXT, post_handler, entry); chk(ret);
    ret = olx_add_branch(stream, entry->next_insn); chk(ret);
    ret = olx_flush(stream, alloc_olx, &buffer, &size); chk(ret);
    ret = olx_drop(stream); chk(ret);
    entry->olx_buffer = buffer; chk(ret);
}


    // We use the OLX buffer, check that the same register is protected, 
    // check that the access is valid, save the protected register 
    // to restore the taint in the epilogue, remove the taint,
    // increase the hit count, and jump to the OLX buffer

    // Skip the red zone before saving anything on the stack

    if(entry->nb_reprotect > 0) mctx->gregs[REG_RSP] -= 128;

    for(int i = 0; i < entry->nb_arg_m; i++) {
        if(entry->arg_m[i].is_protected) {
            int reg = entry->arg_m[i].protected_reg;
            if(entry->arg_m[i].reprotect) {
                mctx->gregs[REG_RSP] -= 8;
                memcpy((void*)mctx->gregs[REG_RSP], &(mctx->gregs[reg]), 8);
            }
            
            if(dw_is_protected((void *)mctx->gregs[reg])) {
                dw_check_access((void *)(mctx->gregs[reg]));
                mctx->gregs[reg] = (long long int)dw_unprotect((void *)mctx->gregs[reg]);
            }
            else dw_log(ERROR, MAIN, "Memory argument register is unexpectedly not protected\n");
        }
    }

    entry->hit_count++;
    mctx->gregs[REG_RIP] = entry->olx_buffer;
    dw_protect_active = save_active;

#endif

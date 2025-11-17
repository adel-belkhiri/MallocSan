
#define _GNU_SOURCE

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>

#include <capstone/capstone.h>

#include "dw-disassembly.h"
#include "dw-log.h"
#include "dw-protect.h"
#include "dw-registers.h"

/*
 * When an instruction accesses a protected object, we need to create an entry
 * to tell us the affected registers, a buffer to emulate the instruction, and
 * an epilogue to reprotect the registers if needed.
 */
struct insn_table {
	size_t size;
	struct insn_entry *entries;
	csh handle;
	cs_insn *insn;
};

/*
 * Allocate the instruction hash table and initialize libcapstone.
 */
instruction_table *dw_init_instruction_table(size_t size)
{
	instruction_table *table = malloc(sizeof(instruction_table));
	// have a hash table about twice as large, and a power of two -1
	table->size = 2 * size - 1;
	table->entries = calloc(sizeof(struct insn_entry), table->size);

	cs_err csres = cs_open(CS_ARCH_X86, CS_MODE_64, &(table->handle));
	if (csres != CS_ERR_OK)
		dw_log(ERROR, DISASSEMBLY, "cs_open failed, returned %d\n", csres);

	csres = cs_option(table->handle, CS_OPT_DETAIL, CS_OPT_ON);
	table->insn = cs_malloc(table->handle);
	return table;
}

/*
 * Deallocate the instruction hash table and close libcapstone.
 */
void dw_fini_instruction_table(instruction_table *table)
{
	free(table->entries);
	cs_free(table->insn, 1);
	cs_close(&(table->handle));
	free(table);
}

/*
 * Get the entry for this instruction address.
 */
struct insn_entry *dw_get_instruction_entry(instruction_table *table, uintptr_t fault)
{
	size_t hash = fault % table->size;
	size_t cursor = hash;

	while ((void *) table->entries[cursor].insn != NULL) {
		if (table->entries[cursor].insn == fault)
			return &(table->entries[cursor]);

		cursor = (cursor + 1) % table->size;
		if (cursor == hash)
			break;
	}
	return NULL;
}

/*
 * Is that register in the list or registers modified by the instruction?
 * There is a lot of aliasing between registers, e.g. al, ax, eax, rax,
 * all refer to the same register or portion thereof.
 */
static bool dw_reg_written(struct insn_entry *entry, unsigned reg)
{
	if (reg == X86_REG_INVALID)
		return false;

	for (int i = 0; i < entry->gregs_write_count; i++)
		if (dw_get_reg_entry(entry->gregs_written[i])->ucontext_index ==
			   dw_get_reg_entry(reg)->ucontext_index)
			return true;

	return false;
}

static bool dw_reg_si_di(struct insn_entry *entry, unsigned reg)
{
	if ((reg == X86_REG_RSI || reg == X86_REG_RDI) && entry->repeat)
		return true;
	else
		return false;
}

/*
 * Check if the instruction, indirectly, overwrites a register.
 */
static inline bool is_reg_zeroing(const cs_insn *insn)
{
	if (insn->id != X86_INS_XOR && insn->id != X86_INS_PXOR && insn->id != X86_INS_SUB)
		return false;

	const cs_x86 *x = &insn->detail->x86;
	return x->op_count == 2 && x->operands[0].type == X86_OP_REG &&
		   x->operands[1].type == X86_OP_REG &&
		   x->operands[0].reg == x->operands[1].reg;
}

/*
 * Check if a given register is read as a regular operand, i.e. not as a memory
 * access base or index register.
 */
static inline bool read_as_regular_operand(uint32_t reg, const cs_x86 *x86)
{
	for (int i = 0; i < x86->op_count; ++i) {
		const cs_x86_op *op = &x86->operands[i];
		if (op->type == X86_OP_REG && op->reg == reg && (op->access & CS_AC_READ))
			return true;
	}
	return false;
}

static bool reg_check_access(uint32_t reg, cs_regs regs, uint8_t count)
{
	if (reg == X86_REG_INVALID || count == 0)
		return false;

	for (uint8_t i = 0; i < count; i++)
		if (dw_get_reg_entry(regs[i])->ucontext_index == dw_get_reg_entry(reg)->ucontext_index)
			return true;

	return false;
}

/*
 * Check if the memory access is similar to the one in the entry. The base and
 * index registers must match, but the displacement, scale, and length can be
 * different. If the latter is the case, we check that the resulting address is
 * within bounds. This is used for deferring further the post-handler.
 */
static inline bool similar_memory_access(const cs_x86_op *arg,
		const struct memory_arg *m,
		ucontext_t *uctx,
		bool repeat)
{
	// Take the fast path if the new memory access is similar to the one in entry
	if (arg->mem.base != m->base || arg->mem.index != m->index)
		return false;

	if (arg->mem.scale == m->scale && arg->mem.disp == m->displacement &&
		   arg->size == m->length)
		return true;

	// Slow path: compute the effective address for this new memory access
	uintptr_t addr = m->base_addr + m->index_addr * arg->mem.scale + arg->mem.disp;

	// Compute access size, considering repeat prefix, then check if the access if valid
	size_t access_size = arg->size;
	if (repeat) {
		size_t count = dw_get_register(uctx, dw_get_reg_entry(X86_REG_RCX)->ucontext_index);
		access_size *= count;
	}

	return dw_check_access((void *) addr, access_size) == 0;
}

#define UNW_LOCAL_ONLY
#include <libunwind.h>

static bool get_function_bounds(uintptr_t ip, uintptr_t *start, uintptr_t *end)
{
	if (!start || !end)
		return false;

	unw_proc_info_t pi;
	int ret = unw_get_proc_info_by_ip(unw_local_addr_space, (unw_word_t)ip, &pi, NULL);
	if (ret != 0)
		return false;

	*start = (uintptr_t)pi.start_ip;
	*end = (uintptr_t)pi.end_ip;

	if (*start == 0 || *end == 0 || *end <= *start)
		return false;

	return true;
}

/*
 * Check if we can defer the installation of post-handler and if this is the
 * case returns the address where the post-handler should be installed
 */
static uintptr_t dw_defer_post_handler(instruction_table *table,
		struct insn_entry *entry,
		uintptr_t start_addr,
		ucontext_t *uctx,
		unsigned *scanned_count,
		unsigned *similar_access_count)
{
	const uint8_t *code            = (const uint8_t *) start_addr;
	uint64_t instr_addr            = (uint64_t) start_addr;
	uint64_t last_safe_addr        = instr_addr;
	uint64_t last_same_access_addr = 0; /* address of last identical memory access   */
	unsigned count_innocuous_inst  = 0, count_same_access = 0, pending_same_access = 0;
	size_t buff_size;
	unsigned n = 0;
	int error_code;


	uintptr_t func_start = 0, func_end = 0;
	size_t max_bytes = (size_t)MAX_SCAN_INST_COUNT * 15;


	if (get_function_bounds(start_addr, &func_start, &func_end) && func_end > start_addr) {
		size_t func_bytes_left = (size_t)(func_end - start_addr);
		buff_size = func_bytes_left < max_bytes ? func_bytes_left : max_bytes;
	} else {
		// Fallback if libunwind can't provide bounds (keep your existing cap)
		buff_size = max_bytes;
		dw_log(WARNING, DISASSEMBLY,
			   "Cannot get function bounds for address 0x%llx, using max scan size %lu\n",
			   start_addr, buff_size);
	}

	while (n < MAX_SCAN_INST_COUNT && buff_size > 0) {
		bool success = cs_disasm_iter(table->handle, &code, &buff_size, &instr_addr,
								   table->insn);
		if (!success) {
			error_code = cs_errno(table->handle);
			if (error_code != CS_ERR_OK)
				dw_log(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n",
					    instr_addr, error_code);

			goto stop_return;   // End of buffer
		}

		cs_insn *insn = table->insn;
		cs_detail *detail = insn->detail;
		cs_x86 *x86 = &detail->x86;

		// 1) Stop scanning on control-flow change
		for (int i = 0; i < detail->groups_count; i++) {
			if (detail->groups[i] < X86_GRP_VM) {
				/*
				 * We avoid selecting INT3 and JMP instructions, as they may have been
				 * inserted by libpatch. This prevents the need to track and distinguish
				 * already patched instructions, ensuring we don’t attempt to patch them again.
				 */
				if ((last_safe_addr <= last_same_access_addr) &&
					(insn->id != X86_INS_INT3) && (insn->id != X86_INS_JMP)) {
					last_safe_addr = table->insn->address;
					count_same_access += pending_same_access;
				}

				goto stop_return;
			}
		}

		// Does this instruction accesses memory?
		bool does_memory_access = false;
		for (int i = 0; i < x86->op_count && !does_memory_access; i++)
			does_memory_access = (x86->operands[i].type == X86_OP_MEM);

		cs_regs regs_read, regs_write;
		uint8_t read_count = 0, write_count = 0;
		error_code = cs_regs_access(table->handle, insn, regs_read, &read_count,
								   regs_write, &write_count);
		if (error_code != CS_ERR_OK)
			dw_log(ERROR, DISASSEMBLY, "Capstone cannot give register accesses\n");

		// 2) Skip the current instruction as it does not involve any
		// tainted register
		bool taint_involved = false;
		for (int i = 0; i < entry->nb_arg_m && !taint_involved; i++) {
			uint32_t tainted_reg = entry->arg_m[i].base_taint ? entry->arg_m[i].base :
					entry->arg_m[i].index_taint ? entry->arg_m[i].index : 0;

			if (tainted_reg && (reg_check_access(tainted_reg, regs_read, read_count) ||
							    reg_check_access(tainted_reg, regs_write, write_count)))
				taint_involved = true;
		}

		if (!taint_involved) {
			if (!does_memory_access && (last_safe_addr <= last_same_access_addr)) {
				last_safe_addr = table->insn->address;
				count_same_access += pending_same_access;
				pending_same_access = 0;
			}

			dw_log(WARNING, DISASSEMBLY, "Skipping instruction at 0x%llx -> %s %s\n",
				   table->insn->address, table->insn->mnemonic, table->insn->op_str);
			count_innocuous_inst++;
			++n;
			continue;
		}

		// 3) Check memory addresses divergence
		for (int i = 0; i < x86->op_count; i++) {
			const cs_x86_op *op = &x86->operands[i];

			if (op->type != X86_OP_MEM)
				continue;

			for (int j = 0; j < entry->nb_arg_m; j++) {
				const struct memory_arg *m = &entry->arg_m[j];
				bool uses_taint =
					(m->base_taint && op->mem.base == m->base) ||
					(m->index_taint && op->mem.index == m->index);

				if (uses_taint) {
					bool repeat =
						(x86->prefix[0] == X86_PREFIX_REP ||
						 x86->prefix[0] == X86_PREFIX_REPE ||
						 x86->prefix[0] == X86_PREFIX_REPNE);

					if (!similar_memory_access(op, m, uctx, repeat))
						goto stop_return;

					last_same_access_addr = table->insn->address;
					pending_same_access++;
				}
			}
		}

		// 4) We need to stop if one of the memory registers is updated
		// or is tainted and read
		bool every_tainted_reg_written = true;
		struct addr_reg_info {int reg; bool tainted; };
		struct addr_reg_info addr_regs[MAX_MOD_REG];
		unsigned addr_reg_cnt = 0;

		for (int i = 0; i < entry->nb_arg_m; i++) {
			struct memory_arg *arg = &entry->arg_m[i];

			if (!arg->base_taint && !arg->index_taint)
				continue;

			if (arg->base != X86_REG_INVALID)
				addr_regs[addr_reg_cnt++] =
				   (struct addr_reg_info) { arg->base, arg->base_taint != 0};

			if (arg->index != X86_REG_INVALID)
				addr_regs[addr_reg_cnt++] =
				   (struct addr_reg_info) {arg->index, arg->index_taint != 0};
		}

		for (int i = 0; i < addr_reg_cnt; i++) {
			int reg = addr_regs[i].reg;
			bool was_tainted = addr_regs[i].tainted;

			bool read = read_as_regular_operand(reg, x86);
			bool write = reg_check_access(reg, regs_write, write_count);

			// The base or index register is updated, so we need to stop scanning further
			if (read && write) {
				/* If the instruction overwrites the register (e.g., xor eax, eax),
				then we need to disable the post-handler. */
				if (is_reg_zeroing(insn))
					entry->post_handler = false;

				if (!does_memory_access && (last_safe_addr <= last_same_access_addr)) {
					last_safe_addr = table->insn->address;
					count_same_access += pending_same_access;
				}
				goto stop_return;
			}

			// The tainted base or index register is read
			if (read && was_tainted) {
				if (!does_memory_access && (last_safe_addr <= last_same_access_addr)) {
					last_safe_addr = table->insn->address;
					count_same_access += pending_same_access;
				}
				goto stop_return;
			}

			if (!write && was_tainted)
				every_tainted_reg_written = false;
		}

		// All tainted registers are overwritten, so we can skip the post-handler
		if (every_tainted_reg_written) {
			if (!does_memory_access && (last_safe_addr <= last_same_access_addr)) {
				last_safe_addr = table->insn->address;
				count_same_access += pending_same_access;
			}

			entry->post_handler = false;
			goto stop_return;
		}

		// Otherwise, we can safely skip the instruction
		dw_log(WARNING, DISASSEMBLY, "Skipping instruction at 0x%llx -> %s %s\n",
			   table->insn->address, table->insn->mnemonic, table->insn->op_str);

		n++;
		continue;
	}

stop_return:
	if (n == MAX_SCAN_INST_COUNT)
		dw_log(WARNING, DISASSEMBLY,
			   "Max instruction scan count reached while deferring post-handler for 0x%llx!\n",
			   start_addr);

	if (scanned_count)
		*scanned_count = n + 1;

	if (similar_access_count)
		*similar_access_count = count_same_access;

	return last_safe_addr;
}

static unsigned
fill_instruction_operands(struct insn_entry *entry,
			const csh handle,
			const cs_x86 *x86,
			const ucontext_t *uctx)
{
	struct reg_entry *re;
	unsigned reg, base, index, arg_m = 0, arg_r = 0, nb_protected = 0;
	uintptr_t addr, scale, displacement, base_addr = 0, index_addr = 0;

	// Loop over all the instruction arguments
	for (int i = 0; i < x86->op_count; i++) {
		switch (x86->operands[i].type) {
		// We need to know the overwritten registers to avoid retainting them
		case X86_OP_REG:
			reg = x86->operands[i].reg;
			re = dw_get_reg_entry(reg);
			if (re->ucontext_index >= 0) {
				if (arg_r >= MAX_REG_ARG)
					dw_log(ERROR, DISASSEMBLY, "Too many destination register arguments\n");

				entry->arg_r[arg_r].reg = reg;
				entry->arg_r[arg_r].length = re->size;
				entry->arg_r[arg_r].access = x86->operands[i].access;
				arg_r++;
			}

			dw_log(INFO, DISASSEMBLY, "Register operand %lu, reg %s, access %hhu\n",
				   i, cs_reg_name(handle, x86->operands[i].reg), x86->operands[i].access);
			break;

		case X86_OP_MEM:
			if (arg_m >= MAX_MEM_ARG)
				dw_log(ERROR, DISASSEMBLY, "Too many memory arguments\n");

			// Check if we have a base register and if it is a general purpose register
			entry->arg_m[arg_m].base = base = x86->operands[i].mem.base;
			if (base == X86_REG_INVALID)
				base_addr = 0; // no base register
			else {
				re = dw_get_reg_entry(base);
				if (re->ucontext_index < 0)
					dw_log(ERROR, DISASSEMBLY, "Base register %s not general register\n",
						   re->name);
				else
					base_addr = dw_get_register(uctx, re->ucontext_index);
			}

			// Check if we have an index register and if it is a general purpose register
			entry->arg_m[arg_m].index = index = x86->operands[i].mem.index;
			if (index == X86_REG_INVALID)
				index_addr = 0;
			else {
				re = dw_get_reg_entry(index);
				if (re->ucontext_index < 0)
					dw_log(ERROR, DISASSEMBLY, "Index register %s not general register\n",
						   re->name);
				else
					index_addr = dw_get_register(uctx, re->ucontext_index);
			}

			entry->arg_m[arg_m].base_addr = base_addr;
			entry->arg_m[arg_m].index_addr = index_addr;
			entry->arg_m[arg_m].scale = scale = x86->operands[i].mem.scale;
			entry->arg_m[arg_m].displacement = displacement = x86->operands[i].mem.disp;
			entry->arg_m[arg_m].length = x86->operands[i].size;
			entry->arg_m[arg_m].access = x86->operands[i].access;

			entry->arg_m[arg_m].base_taint = entry->arg_m[arg_m].index_taint = 0;
			entry->arg_m[arg_m].base_access = entry->arg_m[arg_m].index_access = 0;

			// The memory address is given by base + (index * scale) + displacement
			addr = base_addr + (index_addr * scale) + displacement;

			dw_log(INFO, DISASSEMBLY,
				   "Memory operand %lu, segment %d, base %s (0x%llx) + (index %s (0x%llx) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n",
				   i, x86->operands[i].mem.segment, cs_reg_name(handle, base), base_addr,
				   cs_reg_name(handle, index), index_addr, scale, displacement, addr,
				   x86->operands[i].access);

			// Check that the segmentation violation is related to a tainted pointer
			if (dw_is_protected((void *) base_addr)) {
				nb_protected++;
				entry->arg_m[arg_m].base_taint = base_addr;
				if (dw_is_protected((void *) index_addr))
					dw_log(WARNING, DISASSEMBLY, "Both base and index registers are protected\n");
			} else if (dw_is_protected((void *) index_addr)) {
				nb_protected++;
				entry->arg_m[arg_m].index_taint = index_addr;
			}

			arg_m++;
			break;

		case X86_OP_IMM:
			dw_log(INFO, DISASSEMBLY, "Immediate operand %lu, value %lu\n", i,
				   x86->operands[i].imm);
			break;

		default:
			dw_log(INFO, DISASSEMBLY, "Invalid operand %lu\n", i);
			break;
		}
	}

	entry->nb_arg_m = arg_m;
	entry->nb_arg_r = arg_r;
	return nb_protected;
}

/*
 * Create a new entry for this instruction address
 */
struct insn_entry*
dw_create_instruction_entry(instruction_table *table,
							uintptr_t fault,
							uintptr_t *next,
							ucontext_t *uctx)
{
	size_t hash = fault % table->size;
	size_t cursor = hash;

	while ((void *) table->entries[cursor].insn != NULL) {
		if (table->entries[cursor].insn == fault)
			dw_log(ERROR, DISASSEMBLY, "Trying to add existing instruction in hash table\n");

		cursor = (cursor + 1) % table->size;
		if (cursor == hash)
			dw_log(ERROR, DISASSEMBLY, "Instruction hash table full\n");
	}

	// We insert the new entry at the first empty location following the hash
	// code index
	table->entries[cursor].insn = fault;
	struct insn_entry *entry = &(table->entries[cursor]);

	size_t sizeds = 15; /* x86 max insn length */
	const uint8_t *code = (uint8_t *)fault;
	uint64_t instr_addr = (uint64_t) fault;

	unsigned i, j;
	bool success;
	int error_code;

	// Disassemble the instruction with Capstone
	success = cs_disasm_iter(table->handle, &code, &sizeds, &instr_addr, table->insn);
	error_code = cs_errno(table->handle);
	if (!success)
		dw_log(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n",
			   fault, error_code);

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
	entry->deferred_post_handler = false;
	snprintf(entry->disasm_insn, sizeof(entry->disasm_insn),
			   "%.11s %.51s", table->insn->mnemonic, table->insn->op_str);

	code = (uint8_t *) fault;
	char insn_code[256], *c = insn_code;
	int ret, length = 256;
	for (int i = 0; i < entry->insn_length; i++) {
		ret = snprintf(c, length, "%02x ", *code);
		c += ret;
		length -= ret;
		code++;
	}

	// This is info, not a warning, but we need it for debug purposes for now
	dw_log(WARNING, DISASSEMBLY,
		   "\n\nInstruction 0x%llx (%s+0x%lx), entry %lu, 0x%lx -> %s %s, (%hu), %s\n",
		   fault, proc_name, offset, cursor, table->insn->address,
		   table->insn->mnemonic, table->insn->op_str,
		   table->insn->size, insn_code);

	cs_detail *detail = table->insn->detail;
	cs_x86 *x86 = &(detail->x86);

	entry->repeat = (x86->prefix[0] == X86_PREFIX_REP ||
					 x86->prefix[0] == X86_PREFIX_REPE ||
					 x86->prefix[0] == X86_PREFIX_REPNE);

	unsigned reg;
	cs_regs regs_read, regs_write;
	uint8_t read_count = 0, write_count = 0;
	error_code = cs_regs_access(table->handle, table->insn,
							   regs_read, &read_count, regs_write, &write_count);

	if (error_code != CS_ERR_OK)
		dw_log(ERROR, DISASSEMBLY, "Capstone cannot give register accesses\n");

	if (read_count > MAX_MOD_REG)
		dw_log(ERROR, DISASSEMBLY, "More registers read %d than expected %d\n",
			   read_count, MAX_MOD_REG);

	if (write_count > MAX_MOD_REG)
		dw_log(ERROR, DISASSEMBLY, "More registers written %d than expected %d\n",
			   write_count, MAX_MOD_REG);

	entry->gregs_read_count = read_count;
	entry->gregs_write_count = write_count;

	for (i = 0; i < min(read_count, MAX_MOD_REG); i++) {
		reg = entry->gregs_read[i] = regs_read[i];
		dw_log(INFO, DISASSEMBLY, "read: %s; (%d)\n", cs_reg_name(table->handle, reg), reg);
	}

	for (i = 0; i < min(write_count, MAX_MOD_REG); i++) {
		reg = entry->gregs_written[i] = regs_write[i];
		dw_log(INFO, DISASSEMBLY, "write: %s; (%d)\n", cs_reg_name(table->handle, reg), reg);
	}

	unsigned nb_protected = fill_instruction_operands(entry, table->handle, x86, uctx);
	if (nb_protected == 0) {
		dw_log(WARNING, DISASSEMBLY,
			   "Instruction 0x%llx generated a fault but no protected memory argument\n",
			   entry->insn);
		bzero((void *)entry, sizeof(struct insn_entry));
		return NULL;
	}

	if (nb_protected > 1)
		dw_log(WARNING, DISASSEMBLY, "Instruction 0x%llx accesses more than one protected object\n",
			   entry->insn);

	bool need_immediate_reprotection = false;
	bool all_tainted_overwritten     = true;
	for (i = 0; i < entry->nb_arg_m; i++) {
		for (j = 0; j < entry->nb_arg_r; j++) {
			if (dw_get_reg_entry(entry->arg_r[j].reg)->ucontext_index ==
				dw_get_reg_entry(entry->arg_m[i].base)->ucontext_index) {

				entry->arg_m[i].base_access = entry->arg_r[j].access;

				if (entry->arg_m[i].access == (CS_AC_READ | CS_AC_WRITE))
					dw_log(WARNING, DISASSEMBLY, "Memory argument is unexpectedly read and written\n");

				if (entry->nb_arg_r != 1)
					dw_log(WARNING, DISASSEMBLY, "More than one register argument, may be ambiguous\n");
			}

			if (dw_get_reg_entry(entry->arg_r[j].reg)->ucontext_index ==
				dw_get_reg_entry(entry->arg_m[i].index)->ucontext_index) {

				entry->arg_m[i].index_access = entry->arg_r[j].access;

				if (entry->arg_m[i].access == (CS_AC_READ | CS_AC_WRITE))
					dw_log(WARNING, DISASSEMBLY,
					   "Memory argument is unexpectedly read and written\n");

				if (entry->nb_arg_r != 1)
					dw_log(WARNING, DISASSEMBLY,
					   "More than one register argument, may be ambiguous\n");
			}
		}

		// If the base or index registers is also a register argument, we need
		// to retaint it immediatly, unless it is overwritten by the instruction.
		if ((entry->arg_m[i].base_access && entry->arg_m[i].base_taint) ||
			(entry->arg_m[i].index_access && entry->arg_m[i].index_taint))
			need_immediate_reprotection = true;

		// Is there a tainted register that is not overwritten?
		if ((entry->arg_m[i].base_taint &&
				(!(entry->arg_m[i].base_access) || (entry->arg_m[i].base_access & CS_AC_READ))) ||
			(entry->arg_m[i].index_taint &&
				(!(entry->arg_m[i].index_access) || (entry->arg_m[i].index_access & CS_AC_READ)))) {
			all_tainted_overwritten = false;
		}
		/*
		 * Registers rsi and rdi are auto-incremented for some
		 * instructions with the rep prefix. This is accounted for by
		 * reapplying the taint, not restoring the saved register value.
		 * Here we check if there exists other cases apart from rsi and
		 * rdi with rep instructions.
		 */
		if (dw_reg_written(entry, entry->arg_m[i].base) &&
			(entry->arg_m[i].base_access & CS_AC_WRITE) == 0 &&
			!dw_reg_si_di(entry, entry->arg_m[i].base))
			dw_log(WARNING, DISASSEMBLY,
				   "Instruction 0x%llx, base register %s implicitly modified\n",
				   entry->insn, dw_get_reg_entry(entry->arg_m[i].base)->name);

		if (dw_reg_written(entry, entry->arg_m[i].index) &&
			(entry->arg_m[i].index_access & CS_AC_WRITE) == 0 &&
			!dw_reg_si_di(entry, entry->arg_m[i].index))
			dw_log(WARNING, DISASSEMBLY,
				   "Instruction 0x%llx, index register %s implicitly modified\n",
				   entry->insn, dw_get_reg_entry(entry->arg_m[i].index)->name);
	}

	// If all tainted registers are overwritten by the instruction,
	// there is no point in installing a post handler
	if (all_tainted_overwritten) {
		dw_log(WARNING, DISASSEMBLY,
			   "Disabling post-handler at 0x%llx because all tainted registers were overwritten.\n",
			   entry->insn, table->insn->mnemonic, table->insn->op_str);
		entry->post_handler = false;
	}

	/*
	 * Scan forward from the faulting instruction to determine whether the
	 * post-handler can be safely skipped or installed at a later instruction.
	 */
	if (entry->post_handler && !need_immediate_reprotection) {
		unsigned scanned_count, similar_acess_count;
		uintptr_t last_safe_addr = dw_defer_post_handler(table, entry,
				instr_addr, uctx, &scanned_count,
				&similar_acess_count);

		dw_log(WARNING, DISASSEMBLY,
			   "Forward scan has stopped at 0x%llx (%s %s), after (%u) instructions.\n",
			   table->insn->address, table->insn->mnemonic, table->insn->op_str, scanned_count);

		if (!entry->post_handler)
		    dw_log(WARNING, DISASSEMBLY, "Post-handler has been DISABLED as a result!\n");
		else if (similar_acess_count > 0) {
			entry->deferred_post_handler = true;
			entry->next_insn = last_safe_addr;

			dw_log(WARNING, DISASSEMBLY,
				   "Post-handler DEFERRED to 0x%llx - skipped (%u) similar memory accesses!\n",
				   last_safe_addr, similar_acess_count);
		}
	}
	return entry;
}

static void check_patch(patch_status s, char *msg)
{
	if (s == PATCH_OK)
		return;

	struct patch_error e;
	patch_last_error(&e);
	dw_log(WARNING, DISASSEMBLY,
		   "Patch lib return value not OK, %d, for %s, origin %s, irritant %s, message %s\n",
		   s, msg, e.origin, e.irritant, e.message);
}

void dw_patch_init()
{
	const struct patch_option options[] = {
			{
				.type       = PATCH_OPT_ENABLE_WXE,
				.enable_wxe = 0
			}
	};

	(void) patch_init(options, sizeof(options) / sizeof(struct patch_option));
}

/*
 * Patch the instruction accessing a protected object and attach a pre and post
 * handler to unprotect and reprotect the tainted registers.
 *
 * With PATCH_EXEC_MODEL_AROUND_STEP_TRAP or PATCH_EXEC_MODEL_AROUND_STEP, the
 * SIGSEGV handler will not get called, the patch handler (pre and post) will be
 * called instead. It will be called either through the target instruction
 * patched by a trap (int3), intercepted by libpatch with their own handler, or
 * through the target instruction patched by a jump.
 *
 * Eventually, to avoid the cost of saving a lot of registers and making a call,
 * we may use PATCH_EXEC_MODEL_DIVERT to jump to an OLX buffer that untaints,
 * executes the relocated instruction, and retaints in assembly directly.
 *
 * We save all the relevant registers in a static structure to check if some
 * registers are unexpectedly modified by the stepped instruction. This
 * structure should be Thread Local Storage for multi-threaded programs.
 * Once the algorithm is well tested and debugged, this saving and comparison
 * step will be removed.
 */
bool dw_instruction_entry_patch(struct insn_entry *entry,
		enum dw_strategies strategy,
		dw_patch_probe patch_handler,
		bool deferred)
{
	struct patch_location location = {
			.type      = PATCH_LOCATION_ADDRESS,
			.direction = PATCH_LOCATION_FORWARD,
			.algorithm = PATCH_LOCATION_FIRST,
			.address   = entry->insn,
	};

	struct patch_exec_model exec_model = {
			.type                    = PATCH_EXEC_MODEL_PROBE,
			.probe.read_registers    = 0,
			.probe.write_registers   = 0,
			.probe.clobber_registers = PATCH_REGS_ALL,
			.probe.user_data         = entry,
			.probe.procedure         = patch_handler,
	};

	patch_t patch;
	patch_attr attr;
	patch_status s;

	if (entry->post_handler && !entry->deferred_post_handler)
		exec_model.type = PATCH_EXEC_MODEL_PROBE_AROUND;

	if (deferred) {
		location.address = entry->next_insn;
		if (!entry->deferred_post_handler)
			dw_log(ERROR, DISASSEMBLY,
				   "Instruction 0x%llx must be associated with a deferred post handler at this point!\n",
				   entry->insn);
	}

	s = patch_attr_init(&attr, sizeof(attr));
	check_patch(s, "attr init");

	if (strategy == DW_PATCH_TRAP) {
		s = patch_attr_set_trap_policy(&attr, PATCH_TRAP_POLICY_FORCE);
		check_patch(s, "set policy FORCE");
	} else if (strategy == DW_PATCH_JUMP) {
		s = patch_attr_set_trap_policy(&attr, PATCH_TRAP_POLICY_FORBID);
		check_patch(s, "set policy FORBID");
	} else
		dw_log(ERROR, DISASSEMBLY, "Unknown patching strategy\n");

	s = patch_attr_set_initial_state(&attr, PATCH_ENABLED);
	check_patch(s, "set enabled");

	s = patch_make(&location, &exec_model, &attr, &patch, NULL);
	check_patch(s, "make");
	if (s != PATCH_OK)
		return false;

	s = patch_commit();
	check_patch(s, "commit");
	if (s != PATCH_OK)
		return false;

	return true;
}

void dw_print_regs(struct patch_exec_context *ctx)
{
	for (int i = 0; i < dw_nb_saved_registers; i++)
		dw_log(INFO, DISASSEMBLY, "%s, %llx\n",
			   dw_get_reg_entry(dw_saved_registers[i])->name, ctx->general_purpose_registers[i]);
}

static bool dw_check_handling = false;

void dw_set_check_handling(bool f) { dw_check_handling = f; }

/*
 * A potentially tainted pointer is accessed, unprotect it before the access
 * (Check use of unprotect / retaint versus flavors other than OID, single
 * unprotect / reprotect)
 */
void dw_unprotect_context(struct patch_exec_context *ctx)
{
	struct insn_entry *entry = ctx->user_data;
	struct reg_entry *re, *reb, *rei;
	struct memory_arg *arg;
	unsigned i, reg, regb, regi;
	uintptr_t valueb, valuei, addr;

	if (dw_check_handling) {
		dw_log(INFO, DISASSEMBLY, "Before unprotecting instruction 0x%llx: %s\n",
			   entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
	}

	// Untaint all possibly tainted memory arguments
	for (i = 0; i < entry->nb_arg_m; i++) {
		arg = &(entry->arg_m[i]);
		regb = arg->base;
		reb = dw_get_reg_entry(regb);

		if (regb == X86_REG_INVALID)
			valueb = 0; // no base register
		else
			valueb = dw_get_register(ctx, reb->libpatch_index);

		regi = arg->index;
		rei = dw_get_reg_entry(regi);
		if (regi == X86_REG_INVALID)
			valuei = 0;
		else
			valuei = dw_get_register(ctx, rei->libpatch_index);

		addr = valueb + valuei * arg->scale + arg->displacement;

		if (dw_is_protected((void *) valueb)) {
			if (arg->base_taint == 0)
				dw_log(INFO, DISASSEMBLY, "Newly tainted base for mem arg %d\n", i);

			if (dw_is_protected((void *) valuei))
				dw_log(WARNING, DISASSEMBLY, "Both index and base tainted for mem arg %d\n", i);

			arg->base_taint = valueb;
			valueb = (uintptr_t) dw_unprotect((void *) valueb);
			dw_set_register(ctx, reb->libpatch_index, valueb);
			arg->index_taint = 0;

			// The base register is a pointer, so if less than 8 bytes
			// are read, this is suspicious.
			if ((arg->base_access & CS_AC_READ) && (arg->length < 8))
				dw_log(WARNING, DISASSEMBLY,
					   "Instruction 0x%llx, base register %s only partially copied to/from memory\n",
					   entry->insn, dw_get_reg_entry(regb)->name);
		}

		else if (dw_is_protected((void *) valuei)) {
			if (arg->index_taint == 0)
				dw_log(INFO, DISASSEMBLY, "Newly tainted index for mem arg %d\n", i);

			arg->index_taint = valuei;
			valuei = (uintptr_t) dw_unprotect((void *) valuei);
			dw_set_register(ctx, rei->libpatch_index, valuei);
			arg->base_taint = 0;

			// The index register is a pointer, so if less than 8 bytes
			// are read, this is suspicious.
			if ((arg->index_access & CS_AC_READ) && (arg->length < 8))
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
		if (entry->repeat) {
			size_t count = dw_get_register(ctx, dw_get_reg_entry(X86_REG_RCX)->libpatch_index);
			dw_check_access((void *) addr, arg->length * count);
		} else
			dw_check_access((void *) addr, arg->length);

		/*
		 * We have a special case, the same register is used to access
		 * the memory and as argument.
		 *
		 * - For a memory read, register write, do not retaint the
		 * ovewritten register in post handler.
		 *
		 * - For a memory read, register read, it is presumably a
		 * comparison. We must untaint the register and the memory for a
		 * proper comparison, and retaint both the register and memory
		 * in the post handler. We save the memory address and value,
		 * and untaint the value. In the post handler we retaint the
		 * register, and restore the saved value at the saved address
		 *
		 * - For a memory write, register read, the untainted register
		 * is stored in memory, we should retaint both the register and
		 * memory in the post handler.
		 *
		 * - For a memory write, register write, not sure what to do.
		 * Not retaint the register but retaint memory?
		 */
		if ((arg->base_access && arg->base_taint != 0) ||
			(arg->index_access && arg->index_taint != 0)) {

			arg->saved_address = valueb + valuei * arg->scale + arg->displacement;
			addr = (uintptr_t) dw_unprotect((void *) addr);

			if (addr != arg->saved_address)
				dw_log(WARNING, DISASSEMBLY, "Both ways to unprotect address differ 0x%llx 0x%llx\n",
					   addr, arg->saved_address);

			if ((arg->access & CS_AC_READ) &&
				(((arg->base_access & CS_AC_READ) && arg->base_taint) ||
				 ((arg->index_access & CS_AC_READ) && arg->index_taint))) {

				arg->saved_value = (uintptr_t)(*((void **)arg->saved_address));
				*((void **)arg->saved_address) = dw_unprotect((void *)(arg->saved_value));
			}
		}
	}

	if (dw_check_handling) {
		dw_log(INFO, DISASSEMBLY, "After unprotecting instruction 0x%llx\n", entry->insn);
		for (i = 0; i < dw_nb_saved_registers; i++) {
			reg = dw_saved_registers[i];
			re = dw_get_reg_entry(reg);
			dw_save_regs[i] = dw_get_register(ctx, re->libpatch_index);
			dw_log(INFO, DISASSEMBLY, "%s, %llx\n", re->name, ctx->general_purpose_registers[i]);
		}
	}

	entry->hit_count++;
}

/*
 * In the post handler, we normally retaint all registers which were untainted
 * in the pre handler. There are a few special cases when the same register is
 * used as a base or index to access the memory and as argument.
 */
void dw_reprotect_context(struct patch_exec_context *ctx)
{
	struct insn_entry *entry = ctx->user_data;
	struct memory_arg *arg;
	struct reg_entry *re;
	unsigned i, reg;
	uintptr_t value;

	if (dw_check_handling) {
		dw_log(INFO, DISASSEMBLY, "Reprotect instruction 0x%llx: %s\n",
			   entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
		for (i = 0; i < dw_nb_saved_registers; i++) {
			// dw_log(INFO, MAIN, "%s = 0x%llx\n",
			// dw_get_patch_reg_name(i), ctx->gregs[i]);
			reg = dw_saved_registers[i];
			re = dw_get_reg_entry(reg);
			value = dw_get_register(ctx, re->libpatch_index);

			if ((dw_save_regs[i] != value) && dw_reg_written(entry, reg) == false)
				dw_log(WARNING, MAIN,
					   "Instruction 0x%llx, register %s modified but should not, now 0x%llx vs 0x%llx\n",
					   entry->insn, re->name, value, dw_save_regs[i]);
		}
	}

	for (int i = 0; i < entry->nb_arg_m; i++) {
		arg = &(entry->arg_m[i]);

		/*
		 * The tainted register, base or index, is retainted unless the
		 * same register was also an overwritten register argument.
		 */
		if (arg->base_taint && ((arg->base_access & CS_AC_WRITE) == 0)) {
			reg = arg->base;
			re = dw_get_reg_entry(reg);
			value = dw_get_register(ctx, re->libpatch_index);
			dw_set_register(ctx, re->libpatch_index,
						   (uint64_t) dw_reprotect((void *) value, (void *) arg->base_taint));
		}

		if (arg->index_taint && ((arg->index_access & CS_AC_WRITE) == 0)) {
			reg = arg->index;
			re = dw_get_reg_entry(reg);
			value = dw_get_register(ctx, re->libpatch_index);
			dw_set_register(ctx, re->libpatch_index,
						   (uint64_t) dw_reprotect((void *) value, (void *) arg->index_taint));
		}

		/*
		 * If the tainted register, base or index, was also a register
		 * argument, we have special cases to consider.
		 */
		if ((arg->base_access && arg->base_taint) || (arg->index_access && arg->index_taint)) {
			/*
			 * If the memory was read and the tainted register, base
			 * or index, was a read register argument, we presumably
			 * have a comparison. The memory value was untainted in
			 * the pre handler and should be restored here.
			 */
			if (arg->access & CS_AC_READ) {
				if (((arg->base_access & CS_AC_READ) && arg->base_taint) ||
				    ((arg->index_access & CS_AC_READ) && arg->index_taint))
					*((void **) arg->saved_address) = (void *) (arg->saved_value);
			}
			/*
			 * If the memory was written and the tainted register,
			 * base or index, was also a register argument we
			 * suppose that the untainted register was stored in
			 * memory and we need to retaint the memory with the
			 * saved register taint
			 */
			else if (arg->access & CS_AC_WRITE) {
				uintptr_t saved_taint;
				if (arg->base_taint)
					saved_taint = arg->base_taint;
				else
					saved_taint = arg->index_taint;

				*((void **) arg->saved_address) =
					dw_reprotect(*((void **) arg->saved_address), (void *) saved_taint);
			}
		}
	}
}

/*
 * Dump the content of the instruction table, for knowing the
 * number of instructions accessing protected objects, and the number of hits
 * for each instruction. Print statistics about each instruction patched
 */
void dw_print_instruction_entries(instruction_table *table, int fd)
{
	struct insn_entry *entry;
	unsigned count = 0;

	for (int i = 0; i < table->size; i++) {
		entry = &(table->entries[i]);
		if ((void *) entry->insn != NULL) {
			dw_fprintf(fd, "%4d 0x%lx: %9u: %2u: %1u %s;\n",
					   count, entry->insn, entry->hit_count, entry->insn_length,
					   entry->strategy, entry->disasm_insn);
			count++;
		}
	}
}

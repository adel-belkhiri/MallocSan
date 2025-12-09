
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
#include "dw-wrap-glibc.h"

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
	table->entries = calloc(table->size, sizeof(struct insn_entry));

	cs_err csres = cs_open(CS_ARCH_X86, CS_MODE_64, &(table->handle));
	if (csres != CS_ERR_OK)
		DW_LOG(ERROR, DISASSEMBLY, "cs_open failed, returned %d\n", csres);

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
	struct reg_entry *re = dw_get_reg_entry(reg);
	if (!re)
		return false;

	int canon_index = re->canonical_index;
	for (int i = 0; i < entry->gregs_write_count; i++)
		if (dw_get_reg_entry(entry->gregs_written[i])->canonical_index == canon_index)
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

static inline bool reg_check_access(uint32_t reg, const uint16_t *regs, uint8_t count)
{
	struct reg_entry *re = dw_get_reg_entry(reg);
	if (!re)
		return false;

	int reg_canon_idx = re->canonical_index;

	for (uint8_t i = 0; i < count; i++)
		if (dw_get_reg_entry(regs[i])->canonical_index == reg_canon_idx)
			return true;

	return false;
}

static inline void reg_set_add(uint16_t *list, uint8_t *count, size_t cap, uint16_t reg)
{
	struct reg_entry *re = dw_get_reg_entry(reg);
	if (!re || *count >= cap)
		return;

	int reg_canon_idx = re->canonical_index;
	if (reg_canon_idx == X86_REG_INVALID)
		return;

	for (uint8_t i = 0; i < *count; i++) {
		re = dw_get_reg_entry(list[i]);
		if (re && re->canonical_index == reg_canon_idx)
			return;
	}

	list[*count] = reg;
	(*count)++;
}

static inline uint8_t vsib_index_width(x86_insn id)
{
	switch (id)
	{
	/* Gather/Scatter: 32-bit indices */
	case X86_INS_VGATHERDPS:
	case X86_INS_VGATHERDPD:
	case X86_INS_VPGATHERDD:
	case X86_INS_VPGATHERDQ:
	case X86_INS_VSCATTERDPS:
	case X86_INS_VSCATTERDPD:
		return 4;

	/* Gather/Scatter: 64-bit indices */
	case X86_INS_VGATHERQPS:
	case X86_INS_VGATHERQPD:
	case X86_INS_VPGATHERQD:
	case X86_INS_VPGATHERQQ:
	case X86_INS_VSCATTERQPS:
	case X86_INS_VSCATTERQPD:
		return 8;

	/* Not a VSIB instruction, but we must not forget prefetch instructions */
	default:
		DW_LOG(ERROR, DISASSEMBLY, "Instruction %u is not a Gather/Scatter VSIB instruction\n", id);
		return 0;
	}
}

/*
 * This function is used for deferring the post-handler. It checks if the memory
 * access is similar to the one in the entry. The base and index registers must
 * match, but the displacement, scale, and length can be different. In the latter
 * case, we check that the resulting address is within bounds.
 */
static bool similar_memory_access(unsigned int ins_id, const cs_x86_op *arg,
		const struct memory_arg *m, ucontext_t *uctx, bool repeat)
{
	uintptr_t addr;

	/* Fast path: same addressing mode (base/index/scale/disp) and size. */
	if (arg->mem.base != m->base || arg->mem.index != m->index)
		return false;

	/*
	 * LEA instructions compute a new pointer from a (possibly tainted) base/index register
	 * without performing a memory access. When the pre-handler has already unprotected the
	 * base/index register, an instruction like `lea rX, [rY + z]` produces a new, untagged
	 * alias in rX. This alias can then escape the post-handler’s taint-tracking logic.
	 */
	if (ins_id == X86_INS_LEA)
		return false;

	if (arg->mem.scale == m->scale &&
	    arg->mem.disp  == m->displacement &&
	    arg->size      == m->length)
		return true;

	/*
	 * Slow path: recompute the effective addresses for the new memory
	 * access and check that they stay within the bounds of the original
	 * protected object.
	 *
	 * VSIB case: base + index[i] * scale + disp.
	 */
	if (reg_is_avx(m->index)) {
		uint8_t index_width = vsib_index_width(ins_id);
		uint8_t count       = m->indices_count;

		if (index_width != m->index_width || !count)
			return false;

		for (uint8_t i = 0; i < count; i++) {
			uint64_t index_val;

			/* Skip lanes that are masked out. */
			if (!(m->mask_bv & (1ull << i)))
				continue;

			if (index_width == MIN_VSIB_INDEX_WIDTH)
				index_val = *((uint32_t *)(m->indices + i * index_width));
			else
				index_val = *((uint64_t *)(m->indices + i * index_width));

			addr = m->base_addr + index_val * arg->mem.scale + arg->mem.disp;

			if (!dw_check_access((void *) addr, arg->size))
				return false;
		}
		return true;
	}

	/*
	 * SIB case: base + index * scale + disp.
	 */
	{
		uintptr_t index_addr = (m->index != X86_REG_INVALID) ? m->index_addr : 0;
		size_t access_size = arg->size;

		addr = m->base_addr + index_addr * arg->mem.scale + arg->mem.disp;

		if (repeat) {
			size_t count = dw_get_register(uctx,
					dw_get_reg_entry(X86_REG_RCX)->ucontext_index);
			access_size *= count;
		}

		return dw_check_access((void *) addr, access_size);
	}
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

static void dw_lookup_symbol(uintptr_t ip, char *proc_name, size_t name_len, unw_word_t *offset_out)
{
	unw_cursor_t cur;
	unw_context_t context;

	if (offset_out)
		*offset_out = 0;

	unw_getcontext(&context);
	unw_init_local(&cur, &context);
	unw_set_reg(&cur, UNW_REG_IP, (unw_word_t)ip);

	if (unw_get_proc_name(&cur, proc_name, name_len, offset_out) != 0) {
		strncpy(proc_name, "-- no symbol --", name_len);
		proc_name[name_len - 1] = '\0';
		if (offset_out)
			*offset_out = 0;
	}
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
	unsigned count_same_access = 0, pending_same_access = 0;
	size_t buff_size;
	unsigned n = 0;
	int error_code;
	uint16_t tainted_regs[MAX_MEM_ARG * 2] = {0};
	uint8_t tainted_regs_count = 0;

	uintptr_t func_start = 0, func_end = 0;
	size_t max_bytes = (size_t)MAX_SCAN_INST_COUNT * 15;

	if (get_function_bounds(start_addr, &func_start, &func_end) && func_end > start_addr) {
		size_t func_bytes_left = (size_t)(func_end - start_addr);
		buff_size = func_bytes_left < max_bytes ? func_bytes_left : max_bytes;
	} else {
		// Fallback if libunwind can't provide bounds
		buff_size = max_bytes;
		DW_LOG(WARNING, DISASSEMBLY,
			   "Cannot get function bounds for address 0x%llx, using max scan size %lu\n",
			   start_addr, buff_size);
	}

		/* Identify which registers from the original instructions are tainted */
	for (int i = 0; i < entry->nb_arg_m; i++) {
		struct memory_arg *mem = &entry->arg_m[i];

		if (mem->base_taint)
			reg_set_add(tainted_regs, &tainted_regs_count, sizeof(tainted_regs)/sizeof(tainted_regs[0]), mem->base);

		if (reg_is_gpr(mem->index) && mem->index_taint)
			reg_set_add(tainted_regs, &tainted_regs_count, sizeof(tainted_regs)/sizeof(tainted_regs[0]), mem->index);

		else if (reg_is_avx(mem->index) && mem->index_is_tainted)
			reg_set_add(tainted_regs, &tainted_regs_count, sizeof(tainted_regs)/sizeof(tainted_regs[0]), mem->index);
	}

	while (n < MAX_SCAN_INST_COUNT && buff_size > 0) {
		bool success = cs_disasm_iter(table->handle, &code, &buff_size, &instr_addr,
								   table->insn);
		if (!success) {
			error_code = cs_errno(table->handle);
			if (error_code != CS_ERR_OK)
				DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n",
					    instr_addr, error_code);

			goto stop_return;   // End of buffer
		}

		cs_insn *insn = table->insn;
		cs_detail *detail = insn->detail;
		cs_x86 *x86 = &detail->x86;
		cs_regs regs_read, regs_write;
		uint8_t read_count = 0, write_count = 0;
		uint16_t reg_ops[16], mem_ops[16];
		uint8_t reg_ops_count = 0, mem_ops_count = 0;
		bool is_memory_access_instruction = false;

		error_code = cs_regs_access(table->handle, insn, regs_read, &read_count,
								   regs_write, &write_count);
		if (error_code != CS_ERR_OK)
			DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot give register accesses\n");

		for (int i = 0; i < x86->op_count; ++i) {
			const cs_x86_op *op = &x86->operands[i];

			if (op->type == X86_OP_REG) {
				reg_set_add(reg_ops, &reg_ops_count, sizeof(reg_ops) / sizeof(reg_ops[0]), op->reg);
			} else if (op->type == X86_OP_MEM) {
				is_memory_access_instruction = true;
				reg_set_add(mem_ops, &mem_ops_count, sizeof(mem_ops) / sizeof(mem_ops[0]), op->mem.base);
				reg_set_add(mem_ops, &mem_ops_count, sizeof(mem_ops) / sizeof(mem_ops[0]), op->mem.index);
			}
		}

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

		// 2) Skip the current instruction if it does not involve any tainted register
		bool taint_involved = false;
		for (unsigned i = 0; i < tainted_regs_count; i++) {
			int tainted_reg = tainted_regs[i];
			if (reg_check_access(tainted_reg, regs_read, read_count) ||
				reg_check_access(tainted_reg, regs_write, write_count) ||
				reg_check_access(tainted_reg, mem_ops, mem_ops_count)) {
				taint_involved = true;
				break;
			}
		}

		if (!taint_involved) {
			// We cannot patch memory access instructions as they might fault and require to be repatched
			if (!is_memory_access_instruction && (last_safe_addr <= last_same_access_addr)) {
				last_safe_addr = table->insn->address;
				count_same_access += pending_same_access;
				pending_same_access = 0;
			}

			DW_LOG(INFO, DISASSEMBLY, "Skipping instruction at 0x%llx -> %s %s\n",
				   table->insn->address, table->insn->mnemonic, table->insn->op_str);
			++n;
			continue;
		}

		// 3) Check memory addresses divergence
		bool repeat = (x86->prefix[0] == X86_PREFIX_REP ||
					   x86->prefix[0] == X86_PREFIX_REPE ||
					   x86->prefix[0] == X86_PREFIX_REPNE);

		for (int i = 0; i < x86->op_count; i++) {
			const cs_x86_op *op = &x86->operands[i];

			if (op->type != X86_OP_MEM)
				continue;

			bool uses_taint =
			    reg_check_access(op->mem.base, tainted_regs, tainted_regs_count) ||
			    reg_check_access(op->mem.index, tainted_regs, tainted_regs_count);

			if (uses_taint) {
				for (int j = 0; j < entry->nb_arg_m; j++) {
					struct memory_arg *mem = &entry->arg_m[j];

					if (!similar_memory_access(insn->id, op, mem, uctx, repeat))
						goto stop_return;
				}
				last_same_access_addr = table->insn->address;
				pending_same_access++;
			}
		}

		// 4) We need to stop if one of the memory registers is tainted and updated or read
		bool every_tainted_reg_written = true;
		for (unsigned i = 0; i < tainted_regs_count; i++) {
			int reg = tainted_regs[i];
			bool is_operand = reg_check_access(reg, reg_ops, reg_ops_count);
			bool read = is_operand && reg_check_access(reg, regs_read, read_count);
			bool write = reg_check_access(reg, regs_write, write_count);

			// The base or index register is modified, so we need to stop scanning further
			if (read && write) {
				/* If the instruction overwrites the register (e.g., xor eax, eax),
				then we need to disable the post-handler. */
				if (is_reg_zeroing(insn)) {
					DW_LOG(INFO, DISASSEMBLY, "Post-handler has been DISABLED because of register-zeroing instruction.\n");
					entry->post_handler = false;
				}

				if (!is_memory_access_instruction && (last_safe_addr <= last_same_access_addr)) {
					last_safe_addr = table->insn->address;
					count_same_access += pending_same_access;
				}
				goto stop_return;
			}

			// The tainted base or index register is read
			if (read) {
				if (!is_memory_access_instruction && (last_safe_addr <= last_same_access_addr)) {
					last_safe_addr = table->insn->address;
					count_same_access += pending_same_access;
				}
				goto stop_return;
			}

			if (!write)
				every_tainted_reg_written = false;
		}

		// All tainted registers are overwritten, so we can skip the post-handler
		if (every_tainted_reg_written) {
			if (!is_memory_access_instruction && (last_safe_addr <= last_same_access_addr)) {
				last_safe_addr = table->insn->address;
				count_same_access += pending_same_access;
			}

			DW_LOG(INFO, DISASSEMBLY, "Post-handler has been DISABLED because all tainted registers are overwritten!\n");
			entry->post_handler = false;
			goto stop_return;
		}

		// Otherwise, we can safely skip the instruction
		DW_LOG(INFO, DISASSEMBLY, "Skipping instruction at 0x%llx -> %s %s\n",
			    table->insn->address, table->insn->mnemonic, table->insn->op_str);

		n++;
		continue;
	}

stop_return:
	if (n == MAX_SCAN_INST_COUNT)
		DW_LOG(INFO, DISASSEMBLY,
			    "Max instruction scan count reached while deferring post-handler for 0x%llx\n",
			    start_addr);

	if (scanned_count)
		*scanned_count = n + 1;

	if (similar_access_count)
		*similar_access_count = count_same_access;

	return last_safe_addr;
}

static bool
fill_memory_operand(struct memory_arg* arg, const cs_x86_op *op, const csh handle,
				    const cs_insn *insn, const cs_x86 *x86, const ucontext_t *uctx)
{
	struct reg_entry *re;
	unsigned base, index;
	uintptr_t addr, index_addr, base_addr = 0;
	int scale;
	int64_t displacement;
	bool register_is_protected = false;

	arg->scale = scale = op->mem.scale;
	arg->displacement = displacement = op->mem.disp;
	arg->length = op->size;
	arg->access = op->access;

	arg->base = base = op->mem.base;
	arg->index = index = op->mem.index;

	// Handle the base register
	re = dw_get_reg_entry(base);
	if (re && base != X86_REG_INVALID) {
		if (!reg_is_gpr(base))
			DW_LOG(ERROR, DISASSEMBLY, "Base register %s is not a General-Purpose Register\n", re->name);

		arg->base_addr = base_addr = dw_get_register(uctx, re->ucontext_index);
		if (dw_is_protected((void *) base_addr)) {
			register_is_protected = true;
			arg->base_taint = base_addr;
		}
	}

	if (index == X86_REG_INVALID) {
		addr = base_addr + (0 * scale) + displacement;
		DW_LOG(INFO, DISASSEMBLY,
			"Memory operand (segment %d): base %s (0x%llx) + (index %s (0x0) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n",
			op->mem.segment, cs_reg_name(handle, base), base_addr, cs_reg_name(handle, index),
			scale, displacement, addr, op->access);
		return register_is_protected;
	}

	// Handle the index register according to SIB/VSIB access modes
	re = dw_get_reg_entry(index);
	if (reg_is_gpr(index)) {
		arg->index_addr = index_addr = dw_get_register(uctx, re->ucontext_index);
		if (dw_is_protected((void *) index_addr)) {
			arg->index_taint = index_addr;
			register_is_protected = true;
		}

		// The memory address is given by base + (index * scale) + displacement
		addr = base_addr + (index_addr * scale) + displacement;

		DW_LOG(INFO, DISASSEMBLY,
			"Memory operand (segment %d): base %s (0x%llx) + (index %s (0x%llx) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n",
			op->mem.segment, cs_reg_name(handle, base), base_addr, cs_reg_name(handle, index),
			index_addr, scale, displacement, addr, op->access);
	} else {
		// VSIB access
		if (!reg_is_avx(index))
			DW_LOG(ERROR, DISASSEMBLY, "Index register %s not AVX or GP register\n", re->name);

		/* Calculate the width of each of the indices and their count */
		uint8_t index_width = arg->index_width = vsib_index_width(insn->id);
		if (index_width != MIN_VSIB_INDEX_WIDTH && index_width != MAX_VSIB_INDEX_WIDTH)
			DW_LOG(ERROR, DISASSEMBLY, "Invalid width (%d) for the indices within the %s register\n",
				   arg->index_width, dw_get_reg_entry(index)->name);

		arg->indices_count = re->size / index_width;

		if (index_width == MAX_VSIB_INDEX_WIDTH)
			register_is_protected = true;
	}

	return register_is_protected;
}

/*
 * This function assigns access type (READ, WRITE, or both) to base and index registers when they
 * also appear as register operands. It matches the base and index from each memory argument with
 * the register arguments to propagate access types.
 */
static void assign_base_index_access(struct insn_entry *entry)
{
	for (unsigned i = 0; i < entry->nb_arg_m; i++) {
		struct memory_arg *arg_m = &entry->arg_m[i];
		struct reg_entry *base_re = dw_get_reg_entry(arg_m->base);
		struct reg_entry *index_re = dw_get_reg_entry(arg_m->index);
		for (unsigned j = 0; j < entry->nb_arg_r; j++) {
			struct reg_entry *re_arg_r = dw_get_reg_entry(entry->arg_r[j].reg);

			if (base_re && re_arg_r && (base_re->canonical_index == re_arg_r->canonical_index)) {
				arg_m->base_access = entry->arg_r[j].access;

				if (arg_m->access == (CS_AC_READ | CS_AC_WRITE))
					DW_LOG(WARNING, DISASSEMBLY, "Memory argument is unexpectedly read and written\n");

				if (entry->nb_arg_r != 1)
					DW_LOG(WARNING, DISASSEMBLY, "More than one register argument, may be ambiguous\n");
			}

			if (index_re && re_arg_r && (index_re->canonical_index == re_arg_r->canonical_index)) {
				arg_m->index_access = entry->arg_r[j].access;

				if (arg_m->access == (CS_AC_READ | CS_AC_WRITE))
					DW_LOG(WARNING, DISASSEMBLY, "Memory argument is unexpectedly read and written\n");

				if (entry->nb_arg_r != 1)
					DW_LOG(WARNING, DISASSEMBLY, "More than one register argument, may be ambiguous\n");
			}
		}
	}
}

static inline unsigned int get_avx512_mask_register(unsigned int gregs_reads[],
													    unsigned int gregs_read_count) {
	for (int i = 0; i < gregs_read_count; i++) {
			if (gregs_reads[i] >= X86_REG_K0 && gregs_reads[i] <= X86_REG_K7)
				return (gregs_reads[i]);
	}
	return X86_REG_INVALID;
}

static unsigned
fill_instruction_operands(struct insn_entry *entry, const csh handle, const cs_insn *insn,
						  const cs_x86 *x86, const ucontext_t *uctx)
{
	struct reg_entry *re;
	unsigned arg_m = 0, arg_r = 0, nb_protected = 0;

	// Loop over all the instruction arguments
	for (int i = 0; i < x86->op_count; i++)
	{
		const cs_x86_op *op = &x86->operands[i];
		switch (op->type)
		{
		case X86_OP_REG:
			re = dw_get_reg_entry(op->reg);
			if (re && re->canonical_index != X86_REG_INVALID) {
				if (arg_r >= MAX_REG_ARG)
					DW_LOG(ERROR, DISASSEMBLY, "Too many destination register arguments\n");

				entry->arg_r[arg_r].reg = op->reg;
				entry->arg_r[arg_r].length = re->size;
				entry->arg_r[arg_r].access = op->access;
				arg_r++;
			}

			DW_LOG(INFO, DISASSEMBLY, "Register operand %lu, reg %s, access %hhu\n",
				   i, cs_reg_name(handle, op->reg), op->access);
			break;

		case X86_OP_MEM:
			if (arg_m >= MAX_MEM_ARG)
				DW_LOG(ERROR, DISASSEMBLY, "Too many memory arguments\n");

			if (fill_memory_operand(&entry->arg_m[arg_m], op, handle, insn, x86, uctx)) {
				nb_protected++;

				// For AVX-512 scatter/gather operations, the mask register (k0..k1) is optional
				if (reg_is_avx512(entry->arg_m[arg_m].index)) {
					entry->arg_m[arg_m].mask =
						get_avx512_mask_register(entry->gregs_read, entry->gregs_read_count);
				}
				else if (reg_is_sse(entry->arg_m[arg_m].index) ||
						 reg_is_avx2(entry->arg_m[arg_m].index)) {
					// For AVX-2 gather operations, the mask register (XMM0..YMM31) is mandatory
					if (x86->op_count < 3)
						DW_LOG(ERROR, DISASSEMBLY, "Too few operands for an AVX-2 gather operation\n");

					entry->arg_m[arg_m].mask = x86->operands[i + 1].reg;
				}
			}

			arg_m++;
			break;

		case X86_OP_IMM:
			DW_LOG(INFO, DISASSEMBLY, "Immediate operand %lu, value %lu\n", i,
				   op->imm);
			break;

		default:
			DW_LOG(WARNING, DISASSEMBLY, "Invalid operand %lu\n", i);
			break;
		}
	}

	entry->nb_arg_m = arg_m;
	entry->nb_arg_r = arg_r;

	assign_base_index_access(entry);
	return nb_protected;
}

/*
 * Create a new entry for this instruction address
 */
struct insn_entry*
dw_create_instruction_entry(instruction_table *table, uintptr_t fault, uintptr_t *next, ucontext_t *uctx)
{
	size_t hash = fault % table->size;
	size_t cursor = hash;

	while ((void *) table->entries[cursor].insn != NULL) {
		if (table->entries[cursor].insn == fault)
			DW_LOG(ERROR, DISASSEMBLY, "Trying to add existing instruction in hash table\n");

		cursor = (cursor + 1) % table->size;
		if (cursor == hash)
			DW_LOG(ERROR, DISASSEMBLY, "Instruction hash table full\n");
	}

	// We insert the new entry at the first empty location following the hash code index
	table->entries[cursor].insn = fault;
	struct insn_entry *entry = &(table->entries[cursor]);

	size_t sizeds = 15; /* x86 max insn length */
	const uint8_t *code = (uint8_t *)fault;
	uint64_t instr_addr = (uint64_t) fault;

	bool success;
	int error_code;

	// Disassemble the instruction with Capstone
	success = cs_disasm_iter(table->handle, &code, &sizeds, &instr_addr, table->insn);
	error_code = cs_errno(table->handle);
	if (!success)
		DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n",
			   fault, error_code);

	entry->insn_length = table->insn->size;
	entry->next_insn = *next = instr_addr;
	entry->post_handler = true;
	entry->deferred_post_handler = false;
	snprintf(entry->disasm_insn, sizeof(entry->disasm_insn),
			   "%.11s %.51s", table->insn->mnemonic, table->insn->op_str);

	if (dw_log_enabled(WARNING, DISASSEMBLY)) {
		code = (uint8_t *) fault;
		char insn_code[256], *c = insn_code;
		int ret, length = 256;
		for (int i = 0; i < entry->insn_length; i++) {
			ret = snprintf(c, length, "%02x ", *code);
			c += ret;
			length -= ret;
			code++;
		}

		// Get the symbol of the containing function, to help in debugging
		unw_word_t offset = 0;
		char proc_name[256];
		dw_lookup_symbol(fault, proc_name, sizeof(proc_name), &offset);

		// This is info, not a warning, but we need it for debug purposes for now
		dw_log(WARNING, DISASSEMBLY,
			"==> Instruction 0x%llx (%s+0x%lx), entry %lu, disasm -> %s %s, (%hu), %s\n",
			fault, proc_name, offset, (entry - table->entries), table->insn->mnemonic,
			table->insn->op_str, table->insn->size, insn_code);
	}

	cs_detail *detail = table->insn->detail;
	cs_x86 *x86 = &(detail->x86);

	// TODO: Remove once libpatch supports immediate execution of post-handlers
	// for call instructions.
	if (cs_insn_group(table->handle, table->insn, X86_GRP_CALL)) {
		DW_LOG(WARNING, DISASSEMBLY,
		    "Call instruction %llx with protected memory operands, post handler cannot be used\n", fault);
		entry->post_handler = false;
	}

	entry->repeat =
				(x86->prefix[0] == X86_PREFIX_REP ||
				 x86->prefix[0] == X86_PREFIX_REPE ||
				 x86->prefix[0] == X86_PREFIX_REPNE);

	unsigned reg;
	cs_regs regs_read, regs_write;
	uint8_t read_count = 0, write_count = 0;
	error_code = cs_regs_access(table->handle, table->insn,
							   regs_read, &read_count, regs_write, &write_count);

	if (error_code != CS_ERR_OK)
		DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot give register accesses\n");

	if (read_count > MAX_MOD_REG)
		DW_LOG(ERROR, DISASSEMBLY, "More registers read %d than expected %d\n",
			   read_count, MAX_MOD_REG);

	if (write_count > MAX_MOD_REG)
		DW_LOG(ERROR, DISASSEMBLY, "More registers written %d than expected %d\n",
			   write_count, MAX_MOD_REG);

	entry->gregs_read_count = read_count;
	entry->gregs_write_count = write_count;

	for (int i = 0; i < min(read_count, MAX_MOD_REG); i++) {
		reg = entry->gregs_read[i] = regs_read[i];
		DW_LOG(INFO, DISASSEMBLY, "read: %s; (%d)\n", cs_reg_name(table->handle, reg), reg);
	}

	for (int i = 0; i < min(write_count, MAX_MOD_REG); i++) {
		reg = entry->gregs_written[i] = regs_write[i];
		DW_LOG(INFO, DISASSEMBLY, "write: %s; (%d)\n", cs_reg_name(table->handle, reg), reg);
	}

	unsigned nb_protected = fill_instruction_operands(entry, table->handle, table->insn, x86, uctx);
	if (nb_protected == 0) {
		DW_LOG(WARNING, DISASSEMBLY,
			   "Instruction 0x%llx generated a fault but no protected memory argument\n",
			   entry->insn);
		dw_memset((void *)entry, 0, sizeof(struct insn_entry));
		return NULL;
	}

	if (nb_protected > 1)
		DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx accesses more than one protected object\n",
			   entry->insn);

	bool need_immediate_reprotection = false;
	bool all_tainted_overwritten = true;
	for (int i = 0; i < entry->nb_arg_m; i++) {

		// If the base or index registers is also a register argument, we need
		// to retaint it immediatly, unless it is overwritten by the instruction.
		if ((entry->arg_m[i].base_access && entry->arg_m[i].base_taint) ||
			(!reg_is_avx(entry->arg_m[i].index) && entry->arg_m[i].index_access && entry->arg_m[i].index_taint) ||
			(reg_is_avx(entry->arg_m[i].index) && entry->arg_m[i].index_access && entry->arg_m[i].index_is_tainted)) {
			need_immediate_reprotection = true;
			DW_LOG(INFO, DISASSEMBLY, "Immediate reprotection is required at 0x%llx\n", entry->insn);
		}

		// Is there a tainted register that is not overwritten?
		if ((entry->arg_m[i].base_taint && (!(entry->arg_m[i].base_access) ||
			   (entry->arg_m[i].base_access & CS_AC_READ))) ||
			(entry->arg_m[i].index_taint && (!(entry->arg_m[i].index_access) ||
			   (entry->arg_m[i].index_access & CS_AC_READ)))) {
			all_tainted_overwritten = false;
		}

		/*
		 * Registers rsi and rdi are auto-incremented for some instructions with the rep prefix.
		 * This is accounted for by reapplying the taint, not restoring the saved register value.
		 * Here we check if there exists other cases apart from rsi and rdi with rep instructions.
		 */
		if (dw_reg_written(entry, entry->arg_m[i].base) && !(entry->arg_m[i].base_access & CS_AC_WRITE) &&
			!dw_reg_si_di(entry, entry->arg_m[i].base))
			DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx, base register %s implicitly modified\n",
				   entry->insn, dw_get_reg_entry(entry->arg_m[i].base)->name);

		if (dw_reg_written(entry, entry->arg_m[i].index) && !(entry->arg_m[i].index_access & CS_AC_WRITE) &&
			!dw_reg_si_di(entry, entry->arg_m[i].index)) //FIXME: to check for AVX index_is_tainted
			DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx, index register %s implicitly modified\n",
				   entry->insn, dw_get_reg_entry(entry->arg_m[i].index)->name);
	}

 	// If all tainted registers are overwritten by the instruction, there is no point in installing a post handler
	if (all_tainted_overwritten) {
		DW_LOG(INFO, DISASSEMBLY,
			   "Disabling post-handler at 0x%llx (%s %s) because all tainted registers were overwritten.\n",
			   entry->insn, table->insn->mnemonic, table->insn->op_str);
		entry->post_handler = false;
	}

	// Instructions with repeat prefix need immediate reprotection
	if (entry->repeat)
		need_immediate_reprotection = true;

	/*
	 * Scan forward from the faulting instruction to determine whether the post-handler can be
	 * safely skipped or installed at a later instruction.
	 */

	if (entry->post_handler && !need_immediate_reprotection) {
		unsigned insn_scan_count, similar_acess_count;
		uintptr_t last_safe_addr = dw_defer_post_handler(table, entry,
				instr_addr, uctx, &insn_scan_count,
				&similar_acess_count);

		DW_LOG(INFO, DISASSEMBLY,
			   "Forward scan has stopped at 0x%llx (%s %s), after (%u) instructions.\n",
			   table->insn->address, table->insn->mnemonic, table->insn->op_str, insn_scan_count);

		if (entry->post_handler && similar_acess_count > 0) {
			entry->deferred_post_handler = true;
			entry->next_insn = last_safe_addr;

			DW_LOG(INFO, DISASSEMBLY,
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
	DW_LOG(INFO, DISASSEMBLY,
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
			DW_LOG(ERROR, DISASSEMBLY,
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
		DW_LOG(ERROR, DISASSEMBLY, "Unknown patching strategy\n");

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
		DW_LOG(INFO, DISASSEMBLY, "%s, %llx\n",
			   dw_get_reg_entry(dw_saved_registers[i])->name, ctx->general_purpose_registers[i]);
}

static bool dw_check_handling = false;

void dw_set_check_handling(bool f) { dw_check_handling = f; }

static inline void decode_avx_mask(const uint8_t *mask_buffer, int num_lanes, int lane_width,
						    uint64_t *out_bits)
{
	uint64_t bits = 0;

	if (!mask_buffer || !out_bits || num_lanes <= 0 || num_lanes > 64)
		goto done;

	for (int i = 0; i < num_lanes; ++i) {
		// Sign-bit position for lane i
		int bit_offset = (i + 1) * lane_width - 1;
		int byte_index = bit_offset >> 3;
		int bit_index  = bit_offset & 7;

		uint8_t byte_val = mask_buffer[byte_index];
		uint8_t sign_bit = (byte_val >> bit_index) & 1u;

		if (sign_bit) bits |= (1ull << i);
	}

done:
	*out_bits = bits;
}

static void check_vsib_access(struct memory_arg *arg, unsigned index, uintptr_t valueb,
					    unsigned idx, void *xsave_ptr)
{
	uint8_t width, count;
	uint8_t index_buffer[64] = {0}; /* ZMM registers are 64 bytes */
	size_t bytes_count, index_size, mask_size = 0;
	const int mask_reg = arg->mask;

	width = arg->index_width;
	count = arg->indices_count;

	if (!width || (width != MIN_VSIB_INDEX_WIDTH && width != MAX_VSIB_INDEX_WIDTH)) {
		DW_LOG(ERROR, DISASSEMBLY, "Invalid VSIB index width %u for mem arg %u\n", width, idx);
		return;
	}

	if (!count) {
		DW_LOG(ERROR, DISASSEMBLY, "Zero VSIB lanes for mem arg %u\n", idx);
		return;
	}

	index_size = dw_get_reg_entry(index)->size;

	if (index_size > sizeof(index_buffer) || index_size != count * width)
		DW_LOG(WARNING, DISASSEMBLY, "Unexpected index register size %zu (width %u, lanes %u) for mem arg %u\n",
			index_size, width, count, idx);

	arg->index_is_tainted = false;

	/* Decode the indices from the XSAVE area. */
	bytes_count = decode_extended_states(index, xsave_ptr, index_buffer);
	if (bytes_count != index_size)
		DW_LOG(ERROR, DISASSEMBLY,
			"Failed to decode index register %s (decoded %zu / expected %zu)\n",
			dw_get_reg_entry(index)->name, bytes_count, index_size);

	/* Save the original indices as they might be tainted. */
	memcpy(arg->indices, index_buffer, bytes_count);

	/*
	 * Decode the mask register:
	 * - X86_REG_INVALID or K0: all lanes enabled
	 * - AVX-512 k1..k7: direct bit mask
	 * - AVX2/XMM|YMM: derive a bit mask from MSB of each lane.
	 */
	if (mask_reg == X86_REG_INVALID || mask_reg == X86_REG_K0) {
		arg->mask_bv = ~0ULL; /* all lanes enabled */
	} else if (reg_is_avx512_opmask(mask_reg)) {
		mask_size = dw_get_reg_entry(mask_reg)->size;
		bytes_count = decode_extended_states(mask_reg, xsave_ptr,
						     (uint8_t *)&arg->mask_bv);

		if (bytes_count != mask_size)
			DW_LOG(ERROR, DISASSEMBLY, "Failed to decode mask register %s (decoded %zu / expected %zu)\n",
				dw_get_reg_entry(mask_reg)->name, bytes_count, mask_size);
	} else if (reg_is_sse(mask_reg) || reg_is_avx2(mask_reg)) {
		uint8_t mask_buffer[32] = {0};

		mask_size = dw_get_reg_entry(mask_reg)->size;
		bytes_count = decode_extended_states(mask_reg, xsave_ptr, mask_buffer);
		if (bytes_count != mask_size)
			DW_LOG(ERROR, DISASSEMBLY,
				"Failed to decode mask register %s (decoded %zu / expected %zu)\n",
				dw_get_reg_entry(mask_reg)->name, bytes_count, mask_size);

		decode_avx_mask(mask_buffer, count, width * 8, &arg->mask_bv);
	} else {
		DW_LOG(ERROR, DISASSEMBLY, "Invalid mask register %s for mem arg %u\n",
			dw_get_reg_entry(mask_reg)->name, idx);
	}

	for (int i = 0; i < count; i++) {
		uintptr_t valuei;

		if (width == MIN_VSIB_INDEX_WIDTH)
			valuei = *((uint32_t *)(index_buffer + i * width));
		else
			valuei = *((uint64_t *)(index_buffer + i * width));

		/* Check whether the access is valid for each enabled lane. */
		if (arg->mask_bv & (1ull << i)) {
			uintptr_t addr = valueb + valuei * arg->scale + arg->displacement;
			dw_check_access((void *) addr, arg->length);
		}

		/* If the index width is 8 bytes, it might be a protected absolute address. */
		if (width != MAX_VSIB_INDEX_WIDTH ||
		    !(arg->mask_bv & (1ull << i)) ||
		    !dw_is_protected((void *) valuei))
			continue;

		arg->index_is_tainted = true;
		*((uint64_t *)(index_buffer + i * width)) = (uint64_t) dw_unprotect((void *) valuei);

		if (dw_is_protected((void *) valueb))
			DW_LOG(WARNING, DISASSEMBLY,
				"Both index and base tainted for mem arg %u\n", idx);
	}

	if (arg->index_is_tainted) {
		bytes_count = save_extended_states(index, xsave_ptr, index_buffer);
		if (bytes_count != index_size)
			DW_LOG(ERROR, DISASSEMBLY,
				"Failed to save indices to register %s (encoded %zu / expected %zu)\n",
				dw_get_reg_entry(index)->name, bytes_count, index_size);
	}
}


static void check_sib_access(uintptr_t insn, struct memory_arg *arg, unsigned regi, unsigned regb,
					uintptr_t valueb, unsigned idx, bool repeat, struct patch_exec_context *ctx)
{
	struct reg_entry *re;
	bool index_is_protected, base_is_protected;
	uintptr_t valuei = 0, valuei_clean = 0, addr;

	index_is_protected = false;
	base_is_protected = dw_is_protected((void *) valueb);

	if (regi != X86_REG_INVALID) {
		re = dw_get_reg_entry(regi);
		valuei = dw_get_register(ctx, re->libpatch_index);
		arg->index_addr = valuei_clean = valuei;
		index_is_protected = dw_is_protected((void *) valuei);

		if (index_is_protected) {
			if (base_is_protected)
				DW_LOG(WARNING, DISASSEMBLY, "Both index and base tainted for mem arg %u\n", idx);

			if (arg->index_taint == 0)
				DW_LOG(INFO, DISASSEMBLY, "Newly tainted index for mem arg %u\n", idx);

			arg->index_taint = valuei;
			valuei_clean = (uintptr_t) dw_unprotect((void *) valuei);
			dw_set_register(ctx, re->libpatch_index, valuei_clean);

			// The index register is a pointer, so if less than 8 bytes are read, this is suspicious.
			if ((arg->index_access & CS_AC_READ) && (arg->length < sizeof(uintptr_t)))
				DW_LOG(ERROR, DISASSEMBLY, "index register %s only partially copied to/from memory\n",
					dw_get_reg_entry(regi)->name);

		} else {
			arg->index_taint = 0;
		}
	}

	if (!base_is_protected && !index_is_protected)
		return;

	// The effective address computed from tainted base and/or tainted index
	addr = valueb + valuei * arg->scale + arg->displacement;

	// Check if the access is valid, and use the repeat count if present.
	if (repeat) {
		size_t count = dw_get_register(ctx, dw_get_reg_entry(X86_REG_RCX)->libpatch_index);
		dw_check_access((void *) addr, arg->length * count);
	} else {
		dw_check_access((void *) addr, arg->length);
	}

	/*
	* We have a special case, the same register is used to access the memory and as argument.
	*
	* - For a memory read, register write, do not retaint the ovewritten register in post handler.
	*
	* - For a memory read, register read, it is presumably a comparison. We must untaint the
	* register and the memory for a proper comparison, and retaint both the register and memory
	* in the post handler. We save the memory address and value, and untaint the value. In the post
	* handler we retaint the register, and restore the saved value at the saved address
	*
	* - For a memory write, register read, the untainted register is stored in memory, we should
	* retaint both the register and memory in the post handler.
	*
	* - For a memory write, register write, not sure what to do. Not retaint the register but
	* retaint memory?
	*/

	if ((arg->length == sizeof(uintptr_t)) &&
		((arg->base_access && arg->base_taint != 0) || (arg->index_access && arg->index_taint != 0))) {

		uintptr_t valueb_clean = (uintptr_t) dw_unprotect((void *) valueb);
		arg->saved_address = valueb_clean + valuei_clean * arg->scale + arg->displacement;

		if ((arg->access & CS_AC_READ) &&
			    (((arg->base_access & CS_AC_READ) && arg->base_taint) ||
			    ((arg->index_access & CS_AC_READ) && arg->index_taint))) {

			arg->saved_value = (uintptr_t) *((void **)arg->saved_address);
			*((void **)arg->saved_address) = dw_unprotect((void *)(arg->saved_value));
		}
	}
}

void dw_unprotect_context(struct patch_exec_context *ctx)
{
	struct insn_entry *entry = ctx->user_data;
	struct reg_entry *reb;
	struct memory_arg *arg;
	unsigned regb, regi;
	uintptr_t valueb;

	if (dw_check_handling) {
		DW_LOG(DEBUG, DISASSEMBLY, "(-) Before unprotecting instruction 0x%llx: %s\n",
			    entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
	}

	entry->pending_post_handler = true;

	for (int i = 0; i < entry->nb_arg_m; i++) {
		arg = &(entry->arg_m[i]);
		regb = arg->base;

		// Handle the base register
		valueb = 0;
		if (regb != X86_REG_INVALID) {
			reb = dw_get_reg_entry(regb);
			valueb = dw_get_register(ctx, reb->libpatch_index);
			arg->base_addr = valueb;

			if (dw_is_protected((void *) valueb)) {
				if (arg->base_taint == 0)
					DW_LOG(INFO, DISASSEMBLY, "Newly tainted base for mem arg %d\n", i);

				arg->base_taint = valueb;
				dw_set_register(ctx, reb->libpatch_index, (uintptr_t) dw_unprotect((void *) valueb));

				// The base register is a pointer, so if less than 8 bytes are read, this is suspicious.
				if ((arg->base_access & CS_AC_READ) && (arg->length < sizeof(uintptr_t)))
					DW_LOG(WARNING, DISASSEMBLY,
					    "Instruction 0x%llx, base register %s only partially copied to/from memory\n",
					    entry->insn, dw_get_reg_entry(regb)->name);
			} else {
				arg->base_taint = 0;
			}
		}

		// Handle the index register
		regi = arg->index;
		if (regi == X86_REG_INVALID || reg_is_gpr(regi))
			check_sib_access(entry->insn, arg, regi, arg->base, valueb, i, entry->repeat, ctx);
		else if (reg_is_avx(regi))
			check_vsib_access(arg, regi, valueb, i, ctx->extended_states);
		else
			DW_LOG(ERROR, DISASSEMBLY, "Invalid index register %u for mem arg %u\n", regi, i);
	}

	if (dw_check_handling) {
		DW_LOG(DEBUG, DISASSEMBLY, "-- After unprotecting instruction 0x%llx\n", entry->insn);
		for (int i = 0; i < dw_nb_saved_registers; i++) {
			struct reg_entry *re = dw_get_reg_entry(dw_saved_registers[i]);
			dw_save_regs[i] = dw_get_register(ctx, re->libpatch_index);
			DW_LOG(DEBUG, DISASSEMBLY, "%s, %llx\n", re->name, ctx->general_purpose_registers[i]);
		}
	}

	entry->hit_count++;
}

static void check_updated_regs (struct insn_entry *entry, struct patch_exec_context *ctx) {
	struct reg_entry *re;
	bool should_check[dw_nb_saved_registers];
	dw_memset(should_check, 0, sizeof(should_check));

	if (!entry->deferred_post_handler) {
		for (size_t i = 0; i < dw_nb_saved_registers; i++)
			should_check[i] = true;
	} else {
		for (int m = 0; m < entry->nb_arg_m; m++) {
			struct memory_arg *arg = &(entry->arg_m[m]);

			if (arg->base_taint) {
				re = dw_get_reg_entry(arg->base);
				if (re) {
					for (size_t i = 0; i < dw_nb_saved_registers; i++) {
						struct reg_entry *saved_re = dw_get_reg_entry(dw_saved_registers[i]);
						if (saved_re->canonical_index == re->canonical_index) {
							should_check[i] = true;
							break;
						}
					}
				}
			}

			re = dw_get_reg_entry(arg->index);
			if (re && re->canonical_index != X86_REG_INVALID && arg->index_taint) {
				for (size_t i = 0; i < dw_nb_saved_registers; i++) {
					struct reg_entry *saved_re = dw_get_reg_entry(dw_saved_registers[i]);
					if (saved_re->canonical_index == re->canonical_index) {
						should_check[i] = true;
						break;
					}
				}
			}
		}
	}

	for (size_t i = 0; i < dw_nb_saved_registers; i++) {
		if (!should_check[i])
			continue;

		unsigned reg = dw_saved_registers[i];
		re = dw_get_reg_entry(reg);
		if (!re || re->libpatch_index < 0)
			continue;

		uintptr_t value = dw_get_register(ctx, re->libpatch_index);
		if (dw_save_regs[i] != value && !dw_reg_written(entry, reg)) {
			DW_LOG(WARNING, DISASSEMBLY,
				"Instruction 0x%llx, register %s modified but should not, now 0x%llx vs 0x%llx\n",
				entry->insn, re->name, value, dw_save_regs[i]);
		}
	}
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
	unsigned reg;

	if (!entry->pending_post_handler)
		return;

	entry->pending_post_handler = false;

	if (dw_check_handling) {
		DW_LOG(INFO, DISASSEMBLY, "(+) Before reprotecting instruction 0x%llx: %s\n",
				    entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
		check_updated_regs(entry, ctx);
	}

	for (int i = 0; i < entry->nb_arg_m; i++) {
		arg = &(entry->arg_m[i]);

		/*
		 * The tainted register, base or index, is retainted unless the same register was also
		 * an overwritten register argument.
		 */
		if (arg->base_taint && ((arg->base_access & CS_AC_WRITE) == 0)) {
			reg = arg->base;
			re = dw_get_reg_entry(reg);
			const void* valueb_new = (const void*) dw_get_register(ctx, re->libpatch_index);
			dw_set_register(ctx, re->libpatch_index, (uint64_t) dw_reprotect(valueb_new, (void *) arg->base_taint));
		}

		// Handle the VSIB case
		if (arg->index != X86_REG_INVALID && reg_is_avx(arg->index)) {
			if (arg->index_is_tainted) {
				reg = arg->index;
				size_t saved_bytes = save_extended_states(reg, ctx->extended_states, arg->indices);
				if (saved_bytes != (arg->indices_count * arg->index_width))
					DW_LOG(ERROR, DISASSEMBLY,
						"Failed to save the indices from register %s into the XSAVE area!\n",
						dw_get_reg_entry(reg)->name);
				// Reset this flag as it will be set again in the pre-handler
				arg->index_is_tainted = false;
			}
			continue;
		}

		// Handle the SIB case
		if (arg->index_taint && ((arg->index_access & CS_AC_WRITE) == 0)) {
			reg = arg->index;
			re = dw_get_reg_entry(reg);
			const void* valuei_new = (const void*) dw_get_register(ctx, re->libpatch_index);
			dw_set_register(ctx, re->libpatch_index,
					(uint64_t) dw_reprotect((void *) valuei_new, (void *) arg->index_taint));
		}

		/*
		* If the tainted register, base or index, was also a register argument, we have special
		* cases to consider.
		*/
		if ((arg->length == sizeof(uintptr_t)) &&
			((arg->base_access && arg->base_taint) || (arg->index_access && arg->index_taint))) {
			/*
			* If the memory was read and the tainted register, base or index, was a read register
			* argument, we presumably have a comparison. The memory value was untainted in
			* the pre handler and should be restored here.
			*/

			/* arg->saved_address must be set in the pre-handler. e.g., cmovne rdi, qword ptr [rdi + 0x10]*/

			if (arg->access & CS_AC_READ) {
				if (((arg->base_access & CS_AC_READ) && arg->base_taint) ||
					((arg->index_access & CS_AC_READ) && arg->index_taint))
					*((void **) arg->saved_address) = (void *) (arg->saved_value);
			}
			/*
			* If the memory was written and the tainted register, base or index, was also a
			* register argument we suppose that the untainted register was stored in memory and we
			* need to retaint the memory with the saved register taint.
			*/
			else if (arg->access & CS_AC_WRITE) {
				uintptr_t saved_taint;
				if(arg->base_taint) saved_taint = arg->base_taint;
				else saved_taint = arg->index_taint;

				if (saved_taint != 0) {
					*((void **) arg->saved_address) =
						    dw_reprotect(*((void **) arg->saved_address), (void *) saved_taint);

				} else {
					DW_LOG(ERROR, DISASSEMBLY,
						"Instruction 0x%llx: cannot retaint memory at 0x%llx with unprotected taint 0x%llx\n",
						entry->insn, arg->saved_address, saved_taint);
				}
			}
		}
	}

	if (dw_check_handling) {
		DW_LOG(DEBUG, DISASSEMBLY, "-- After reprotecting instruction 0x%llx: %s\n",
			entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
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

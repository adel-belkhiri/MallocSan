
#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>

#include <capstone/capstone.h>

#include "dw-disassembly.h"
#include "dw-patch.h"
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
};

__thread struct insn_entry_runtime insn_rt_slots[MAX_SCAN_INST_COUNT];

struct capstone_context {
	csh handle;
	cs_insn *insn;
	bool ready;
};

__thread struct capstone_context cs_ctx;
static pthread_key_t cs_key;
static pthread_once_t cs_key_once = PTHREAD_ONCE_INIT;

static void capstone_context_cleanup(void *arg)
{
	(void) arg;
	if (!cs_ctx.ready)
		return;
	cs_free(cs_ctx.insn, 1);
	cs_close(&cs_ctx.handle);
	cs_ctx.ready = false;
}

static void dw_capstone_make_key(void)
{
	pthread_key_create(&cs_key, capstone_context_cleanup);
}

static inline struct capstone_context *capstone_get_context(void)
{
	pthread_once(&cs_key_once, dw_capstone_make_key);

	if (!cs_ctx.ready) {
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_ctx.handle) != CS_ERR_OK)
			DW_LOG(ERROR, DISASSEMBLY, "cs_open failed!\n");

		cs_option(cs_ctx.handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_ctx.insn = cs_malloc(cs_ctx.handle);
		if (!cs_ctx.insn) {
			cs_close(&cs_ctx.handle);
			DW_LOG(ERROR, DISASSEMBLY, "cs_malloc failed!\n");
		}
		cs_ctx.ready = true;
		pthread_setspecific(cs_key, (void *)1);
	}
	return &cs_ctx;
}

static inline void add_post_safe_site(struct post_safe_site_rb *rb, uintptr_t addr, uint16_t size, unsigned skipped_same_access)
{
	if (!rb || size < DW_MIN_SAFE_CANDIDATE_SIZE)
		return;

	unsigned idx;
	if (rb->count < MAX_SAFE_SITE_COUNT) {
		idx = (rb->head + rb->count) % MAX_SAFE_SITE_COUNT;
		rb->count++;
	} else {
		idx = rb->head;
		rb->head = (rb->head + 1) % MAX_SAFE_SITE_COUNT;
	}

	rb->entries[idx].addr = addr;
	rb->entries[idx].skipped_same_access = skipped_same_access;
}

static inline size_t hash_addr(uintptr_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	return (size_t)x;
}

static inline size_t get_pow2(size_t x)
{
	return 1ULL << (64 - __builtin_clzl(x - 1));
}

/*
 * Allocate the instruction hash table and initialize libcapstone.
 */
instruction_table *dw_init_instruction_table(size_t size)
{
	instruction_table *table = malloc(sizeof(instruction_table));
	// have a hash table about twice as large, and a power of two
	table->size = get_pow2(2 * size);
	table->entries = calloc(table->size, sizeof(struct insn_entry));

	return table;
}

/*
 * Deallocate the instruction hash table and close libcapstone.
 */
void dw_fini_instruction_table(instruction_table *table)
{
	free(table->entries);
	free(table);
}

/*
 * Get the entry for this instruction address.
 */
struct insn_entry *dw_get_instruction_entry(instruction_table *table, uintptr_t fault)
{
	size_t mask   = table->size - 1;
	size_t start  = hash_addr(fault) & mask;
	size_t cursor = start;

	while (1) {
		struct insn_entry *e = &table->entries[cursor];
		int state = atomic_load_explicit(&e->state, memory_order_acquire);

		if (state == ENTRY_EMPTY)
			return NULL;

		if (state == ENTRY_INITIALIZING) {
			do {
				state = atomic_load_explicit(&e->state, memory_order_acquire);
			} while (state == ENTRY_INITIALIZING);

			if (state == ENTRY_EMPTY)
				return NULL;
		}

		if (e->insn == fault)
			return (state == ENTRY_READY) ? e : NULL;

		cursor = (cursor + 1) & mask;
		if (cursor == start)
			break;
	}
	return NULL;
}

static inline bool dw_acquire_runtime_slot(struct insn_entry *entry, int *idx_out)
{
	for (int i = 0; i < MAX_SCAN_INST_COUNT; ++i) {
		if (!insn_rt_slots[i].used) {
			*idx_out = i;
			insn_rt_slots[i].used = true;
			insn_rt_slots[i].entry = entry;
			return true;
		}

		if (insn_rt_slots[i].entry == entry)
			DW_LOG(ERROR, DISASSEMBLY,
				   "Runtime slot %d for instruction 0x%llx shouldn't be used!\n",
				   i, entry->insn);
	}
	// Out of slots
	DW_LOG(ERROR, DISASSEMBLY, "Runtime slots shouldn't be exhausted!\n");
	return false;
}

static inline bool dw_find_runtime_slot(struct insn_entry *entry, int *idx_out)
{
	for (int i = 0; i < MAX_SCAN_INST_COUNT; i++) {
		if (insn_rt_slots[i].used && insn_rt_slots[i].entry == entry) {
			if (idx_out)
				*idx_out = i;
			return true;
		}
	}

	return false;
}

static inline void dw_release_rt_slot(int idx)
{
	if (idx < 0 || idx >= MAX_SCAN_INST_COUNT)
		return;

	insn_rt_slots[idx].entry = NULL;
	insn_rt_slots[idx].used = false;
}

/*
 * Is that register in the list or registers modified by the instruction?
 * There is a lot of aliasing between registers, e.g. al, ax, eax, rax,
 * all refer to the same register or portion thereof.
 */
static bool dw_reg_written(struct insn_entry *entry, unsigned reg)
{
	const struct reg_entry *re = dw_get_reg_entry(reg);
	if (!re)
		return false;

	int canon_index = re->canonical_index;
	for (int i = 0; i < entry->gregs_write_count; i++) {
		if (dw_get_reg_entry(entry->gregs_written[i])->canonical_index == canon_index)
			return true;
	}

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
	const struct reg_entry *re = dw_get_reg_entry(reg);
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
	const struct reg_entry *re = dw_get_reg_entry(reg);
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

static inline bool reg_is_overwritten(uint32_t reg, uint8_t op_access, const uint16_t *regs_written,
								   uint8_t write_count)
{
	if (reg == X86_REG_INVALID)
		return false;

	bool written = (op_access & CS_AC_WRITE) || reg_check_access(reg, regs_written, write_count);
	if (!written)
		return false;

	bool data_read = (op_access & CS_AC_READ) != 0;
	return !data_read;
}

static inline bool base_index_overwritten(const cs_insn *insn,
										  const struct insn_entry *entry,
										  const struct insn_entry_runtime *entry_rt,
										  unsigned idx)
{
	const struct memory_arg *m = &entry->arg_m[idx];
	const struct memory_arg_runtime *m_rt = &entry_rt->arg_m[idx];
	bool is_vsib = reg_is_avx(m->index);

	bool base_overwritten = true;
	bool index_overwritten = true;

	bool is_xadd_xchg = insn && (insn->id == X86_INS_XCHG || insn->id == X86_INS_XADD);

	// Base
	if (m_rt->base_taint && m->base != X86_REG_INVALID) {
		base_overwritten = false;
		if (is_xadd_xchg && (m->base_access & CS_AC_WRITE))
			base_overwritten = true; // override (xadd/xchg overwrite reg operand)
		else
			base_overwritten = reg_is_overwritten(m->base, m->base_access, entry->gregs_written,
											   entry->gregs_write_count);
	}

	// Index
	if (m->index != X86_REG_INVALID) {
		bool idx_tainted = (!is_vsib && m_rt->index_taint) ||
						   (is_vsib && m_rt->index_is_tainted);

		if (idx_tainted) {
			index_overwritten = false;
			if (is_xadd_xchg && (m->index_access & CS_AC_WRITE))
				index_overwritten = true;
			else
				index_overwritten = reg_is_overwritten(m->index, m->index_access, entry->gregs_written,
												   entry->gregs_write_count);
		}
	}

	return base_overwritten && index_overwritten;
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
		const struct memory_arg *m, const struct memory_arg_runtime *m_rt, ucontext_t *uctx, bool repeat)
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
	 * TODO: For now, we do not check similar accesses for VSIB instructions.
	 */
	if (reg_is_avx(m->index))
		return false;

	/*
	 * SIB case: base + index * scale + disp.
	 */
	uintptr_t index_addr = (m->index != X86_REG_INVALID) ? m_rt->index_addr : 0;
	size_t access_size = arg->size;

	addr = m_rt->base_addr + index_addr * arg->mem.scale + arg->mem.disp;

	if (repeat) {
		size_t count = dw_get_register(uctx, dw_get_reg_entry(X86_REG_RCX)->ucontext_index);
		access_size *= count;
	}

	return dw_check_access((void *) addr, access_size);
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
 * Defer post-handler installation by scanning forward for safe instruction sites.
 *
 * This function scans instructions starting from the next instruction after a fault,
 * looking for locations where a post-handler can be safely installed.
 *
 * The scan stops when:
 * - A control-flow instruction is encountered (branch, call, return, etc.)
 * - A tainted register is read or modified
 * - All tainted registers are overwritten
 * - Memory access patterns diverge from the original fault
 * - The maximum instruction count is reached
 */
static uintptr_t dw_defer_post_handler(struct insn_entry *entry,
				   struct insn_entry_runtime *entry_rt,
				   uintptr_t start_addr,
				   ucontext_t *uctx,
				   struct capstone_context *cs,
				   unsigned *scanned_count,
				   unsigned *similar_access_count,
				   struct post_safe_site_rb *rb)
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
	struct memory_arg *mem;
	struct memory_arg_runtime *mem_rt;
	unsigned tail_budget = 0;

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
		mem = &entry->arg_m[i];
		mem_rt = &entry_rt->arg_m[i];
		int taint_reg = X86_REG_INVALID;

		if (mem_rt->base_taint)
			taint_reg = mem->base;

		if ((reg_is_gpr(mem->index) && mem_rt->index_taint) ||
			(reg_is_avx(mem->index) && mem_rt->index_is_tainted))
			taint_reg = mem->index;

		if (taint_reg != X86_REG_INVALID)
			reg_set_add(tainted_regs, &tainted_regs_count, sizeof(tainted_regs)/sizeof(tainted_regs[0]), taint_reg);
	}

	while (n < MAX_SCAN_INST_COUNT && buff_size > 0) {
		bool success = cs_disasm_iter(cs->handle, &code, &buff_size, &instr_addr, cs->insn);
		if (!success) {
			error_code = cs_errno(cs->handle);
			if (error_code != CS_ERR_OK)
				DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n",
					    instr_addr, error_code);

			goto stop_return;   // End of buffer
		}

		cs_insn *insn = cs->insn;
		cs_detail *detail = insn->detail;
		cs_x86 *x86 = &detail->x86;
		cs_regs regs_read, regs_write;
		uint8_t read_count = 0, write_count = 0;
		uint16_t reg_ops[16], mem_ops[16];
		uint8_t reg_ops_count = 0, mem_ops_count = 0;
		bool is_memory_access_instruction = false;

		error_code = cs_regs_access(cs->handle, insn, regs_read, &read_count,
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
					last_safe_addr = insn->address;
					count_same_access += pending_same_access;
					pending_same_access = 0;
					add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access);
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
			/*
			 * When a safe site is found, we record a few "tail" safe sites as fallback
			 * in case the preferred site is not patchable with a JUMP.
			 */
			if (!is_memory_access_instruction) {
				if (last_safe_addr <= last_same_access_addr) {
					last_safe_addr = insn->address;
					count_same_access += pending_same_access;
					pending_same_access = 0;
					tail_budget = DW_TAIL_CANDIDATE_BUDGET;
					add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access);
				} else if (count_same_access > 0 && tail_budget > 0) {
					add_post_safe_site(rb, insn->address, insn->size, count_same_access);
					tail_budget--;
				}
			}

			DW_LOG(DEBUG, DISASSEMBLY, "Skipping instruction at 0x%llx -> %s %s, (%u)\n",
				   insn->address, insn->mnemonic, insn->op_str, insn->size);
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
					mem = &entry->arg_m[j];
					mem_rt = &entry_rt->arg_m[j];

					if (!similar_memory_access(insn->id, op, mem, mem_rt, uctx, repeat))
						goto stop_return;
					}
					last_same_access_addr = insn->address;
					pending_same_access++;
					tail_budget = 0;
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
					DW_LOG(DEBUG, DISASSEMBLY, "Post-handler has been DISABLED because of register-zeroing instruction.\n");
					entry->post_handler = false;
				}

				if (!is_memory_access_instruction && (last_safe_addr <= last_same_access_addr)) {
					last_safe_addr = insn->address;
					count_same_access += pending_same_access;
					add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access);
				}
				goto stop_return;
			}

			// The tainted base or index register is read
			if (read) {
				if (!is_memory_access_instruction && (last_safe_addr <= last_same_access_addr)) {
					last_safe_addr = insn->address;
					count_same_access += pending_same_access;
					add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access);
				}
				goto stop_return;
			}

			if (!write)
				every_tainted_reg_written = false;
		}

		// All tainted registers are overwritten, so we can skip the post-handler
		if (every_tainted_reg_written) {
			if (!is_memory_access_instruction && (last_safe_addr <= last_same_access_addr)) {
				last_safe_addr = insn->address;
				count_same_access += pending_same_access;
				add_post_safe_site(rb, last_safe_addr, insn->size, count_same_access);
			}

			DW_LOG(DEBUG, DISASSEMBLY, "Post-handler has been DISABLED because all tainted registers are overwritten!\n");
			entry->post_handler = false;
			goto stop_return;
		}

		// Otherwise, we can safely skip the instruction
		DW_LOG(DEBUG, DISASSEMBLY, "Skipping instruction at 0x%llx -> %s %s, (%u)\n",
			    insn->address, insn->mnemonic, insn->op_str, insn->size);

		n++;
		continue;
	}

stop_return:
	if (n == MAX_SCAN_INST_COUNT)
		DW_LOG(DEBUG, DISASSEMBLY,
			    "Max instruction scan count reached while deferring post-handler for 0x%llx\n",
			    start_addr);

	if (scanned_count)
		*scanned_count = n + 1;

	if (similar_access_count)
		*similar_access_count = count_same_access;

	return last_safe_addr;
}

static bool
fill_memory_operand(struct memory_arg* m, struct memory_arg_runtime* m_rt, const cs_x86_op *op, const csh handle,
				    const cs_insn *insn, const cs_x86 *x86, const ucontext_t *uctx)
{
	const struct reg_entry *re;
	unsigned base, index;
	uintptr_t addr, index_addr, base_addr = 0;
	int scale;
	int64_t displacement;
	bool register_is_protected = false;

	m->scale = scale = op->mem.scale;
	m->displacement = displacement = op->mem.disp;
	m->length = op->size;
	m->access = op->access;

	m->base = base = op->mem.base;
	m->index = index = op->mem.index;
	m->base_re = (base != X86_REG_INVALID) ? dw_get_reg_entry(base) : NULL;
	m->index_re = (index != X86_REG_INVALID) ? dw_get_reg_entry(index) : NULL;

	// Handle the base register
	re = m->base_re;
	if (re) {
		if (!reg_is_gpr(base))
			DW_LOG(ERROR, DISASSEMBLY, "Base register %s not a General-Purpose Register\n", re->name);

		m_rt->base_addr = base_addr = dw_get_register(uctx, re->ucontext_index);
		if (dw_is_protected((void *) base_addr)) {
			register_is_protected = true;
			m_rt->base_taint = base_addr;
		}
	}

	if (index == X86_REG_INVALID) {
		addr = base_addr + (0 * scale) + displacement;
		DW_LOG(DEBUG, DISASSEMBLY,
			"Memory operand (segment %d): base %s (0x%llx) + (index %s (0x0) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n",
			op->mem.segment, cs_reg_name(handle, base), base_addr, cs_reg_name(handle, index),
			scale, displacement, addr, op->access);
		return register_is_protected;
	}

	// Handle the index register according to SIB/VSIB access modes
	re = m->index_re;
	if (reg_is_gpr(index)) {
		m_rt->index_addr = index_addr = re ? dw_get_register(uctx, re->ucontext_index) : 0;
		if (dw_is_protected((void *) index_addr)) {
			m_rt->index_taint = index_addr;
			register_is_protected = true;
		}

		// The memory address is given by base + (index * scale) + displacement
		addr = base_addr + (index_addr * scale) + displacement;

		DW_LOG(DEBUG, DISASSEMBLY,
			"Memory operand (segment %d): base %s (0x%llx) + (index %s (0x%llx) x scale 0x%llx) + disp 0x%llx = 0x%llx, access %hhu\n",
			op->mem.segment, cs_reg_name(handle, base), base_addr, cs_reg_name(handle, index),
			index_addr, scale, displacement, addr, op->access);
	} else {
		// VSIB access
		if (!reg_is_avx(index))
			DW_LOG(ERROR, DISASSEMBLY, "Index register %s not AVX or GP register\n", re->name);

		/* Calculate the width of each of the indices and their count */
		uint8_t index_width = m->index_width = vsib_index_width(insn->id);
		if (index_width != MIN_VSIB_INDEX_WIDTH && index_width != MAX_VSIB_INDEX_WIDTH)
			DW_LOG(ERROR, DISASSEMBLY, "Invalid width (%d) for the indices within the %s register\n",
				   m->index_width, re->name);

		m->indices_count = (re && index_width) ? (re->size / index_width) : 0;

		// This is just a heuristic: we consider the index tainted if its width is equal to 8 bytes
		if (index_width == MAX_VSIB_INDEX_WIDTH) {
			m_rt->index_is_tainted = true;
			register_is_protected = true;
		}
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
		const struct reg_entry *base_re  = arg_m->base_re;
		const struct reg_entry *index_re = arg_m->index_re;

		for (unsigned j = 0; j < entry->nb_arg_r; j++) {
			const struct reg_entry *re_arg_r = dw_get_reg_entry(entry->arg_r[j].reg);

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

static inline unsigned int get_avx512_mask_register(uint16_t gregs_reads[],
												   uint8_t gregs_read_count) {
	for (int i = 0; i < gregs_read_count; i++) {
			if (gregs_reads[i] >= X86_REG_K0 && gregs_reads[i] <= X86_REG_K7)
				return (gregs_reads[i]);
	}
	return X86_REG_INVALID;
}

static unsigned
fill_instruction_operands(struct insn_entry *entry, struct insn_entry_runtime* entry_rt, const csh handle, const cs_insn *insn,
						  const cs_x86 *x86, const ucontext_t *uctx)
{
	const struct reg_entry *re;
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

			DW_LOG(DEBUG, DISASSEMBLY, "Register operand %lu, reg %s, access %hhu\n",
				   i, cs_reg_name(handle, op->reg), op->access);
			break;

		case X86_OP_MEM:
			if (arg_m >= MAX_MEM_ARG)
				DW_LOG(ERROR, DISASSEMBLY, "Too many memory arguments\n");

			if (fill_memory_operand(&entry->arg_m[arg_m], &entry_rt->arg_m[arg_m], op, handle, insn, x86, uctx)) {
				nb_protected++;

				// We need a VSIB flag per entry to know if we will need XSAVE/XRSTOR when patching the instruction
				int index = entry->arg_m[arg_m].index;
				entry->has_vsib |= reg_is_avx(index);

				// For AVX-512 scatter/gather operations, the mask register (k0..k1) is optional
				if (reg_is_avx512(index)) {
					entry->arg_m[arg_m].mask =
						get_avx512_mask_register(entry->gregs_read, entry->gregs_read_count);
				}
				else if (reg_is_sse(index) || reg_is_avx2(index)) {
					// For AVX-2 gather operations, the mask register (XMM0..YMM31) is mandatory
					if (x86->op_count < 3)
						DW_LOG(ERROR, DISASSEMBLY, "Too few operands for an AVX-2 gather operation\n");

					entry->arg_m[arg_m].mask = x86->operands[i + 1].reg;
				}
			}

			arg_m++;
			break;

		case X86_OP_IMM:
			DW_LOG(DEBUG, DISASSEMBLY, "Immediate operand %lu, value %lu\n", i,
				   op->imm);
			break;

		default:
			DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx: Invalid operand %lu (type %d)\n",
				    entry->insn, i, op->type);
			break;
		}
	}

	entry->nb_arg_m = arg_m;
	entry->nb_arg_r = arg_r;

	assign_base_index_access(entry);
	return nb_protected;
}

/*
 * Disassembles a faulted instruction, and populates the entry with register and memory operand
 * information.
 */
static bool dw_populate_instruction_entry(instruction_table *table, struct insn_entry *entry,
					   uintptr_t fault, ucontext_t *uctx,
					   struct post_safe_site_rb *safe_sites)
{
	size_t sizeds = 15; /* x86 max insn length */
	bool success;
	int error_code;
	const uint8_t *code = (uint8_t *)fault;
	uint64_t insn_addr = (uint64_t) fault;

	// Disassemble the instruction with Capstone
	struct capstone_context * cs = capstone_get_context();
	success = cs_disasm_iter(cs->handle, &code, &sizeds, &insn_addr, cs->insn);
	error_code = cs_errno(cs->handle);
	if (!success)
		DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n",
			   fault, error_code);

	entry->insn = fault;
	entry->insn_length = cs->insn->size;
	entry->next_insn = insn_addr;
	entry->post_handler = true;
	entry->deferred_post_handler = false;
	snprintf(entry->disasm_insn, sizeof(entry->disasm_insn), "%.11s %.51s", cs->insn->mnemonic, cs->insn->op_str);

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
		DW_LOG(INFO, DISASSEMBLY,
			"[%u] ==> Instruction 0x%llx (%s+0x%lx), entry %lu, disasm -> %s %s, (%hu), %s\n",
			gettid(), fault, proc_name, offset, (entry - table->entries), cs->insn->mnemonic,
			cs->insn->op_str, cs->insn->size, insn_code);
	}

	cs_detail *detail = cs->insn->detail;
	cs_x86 *x86 = &(detail->x86);

	// TODO: To be removed once libpatch supports immediate execution of post-handlers
	// for call instructions.
	if (cs_insn_group(cs->handle, cs->insn, X86_GRP_CALL)) {
		DW_LOG(WARNING, DISASSEMBLY,
		    "Call instruction %llx (%s %s) has protected memory operands, post handler cannot be used\n",
		    fault, cs->insn->mnemonic, cs->insn->op_str);
		entry->post_handler = false;
	}

	entry->repeat =
				(x86->prefix[0] == X86_PREFIX_REP ||
				 x86->prefix[0] == X86_PREFIX_REPE ||
				 x86->prefix[0] == X86_PREFIX_REPNE);

	unsigned reg;
	cs_regs regs_read, regs_write;
	uint8_t read_count = 0, write_count = 0;
	error_code = cs_regs_access(cs->handle, cs->insn,
							   regs_read, &read_count, regs_write, &write_count);

	if (error_code != CS_ERR_OK)
		DW_LOG(ERROR, DISASSEMBLY, "Capstone cannot give register accesses\n");

	if (read_count > MAX_MOD_REG)
		DW_LOG(ERROR, DISASSEMBLY, "More registers read %d than expected %d\n",
			   read_count, MAX_MOD_REG);

	if (write_count > MAX_MOD_REG)
		DW_LOG(ERROR, DISASSEMBLY, "More registers written %d than expected %d\n",
			   write_count, MAX_MOD_REG);

	entry->gregs_read_count = min(read_count, MAX_MOD_REG);
	entry->gregs_write_count = min(write_count, MAX_MOD_REG);

	for (int i = 0; i < entry->gregs_read_count; i++) {
		reg = entry->gregs_read[i] = regs_read[i];
		DW_LOG(DEBUG, DISASSEMBLY, "read: %s; (%d)\n", cs_reg_name(cs->handle, reg), reg);
	}

	for (int i = 0; i < entry->gregs_write_count; i++) {
		reg = entry->gregs_written[i] = regs_write[i];
		DW_LOG(DEBUG, DISASSEMBLY, "write: %s; (%d)\n", cs_reg_name(cs->handle, reg), reg);
	}

	struct insn_entry_runtime entry_rt = {0};
	entry_rt.entry = entry;
	unsigned nb_protected = fill_instruction_operands(entry, &entry_rt, cs->handle, cs->insn, x86, uctx);
	if (nb_protected == 0) {
		DW_LOG(WARNING, DISASSEMBLY,
			   "Instruction 0x%llx generated a fault but no protected memory argument\n", entry->insn);
		return false;
	}

	if (nb_protected > 1)
		DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx accesses more than one protected object\n",
			   entry->insn);

	bool need_immediate_reprotection = false;
	bool all_tainted_overwritten = true;
	for (int i = 0; i < entry->nb_arg_m; i++) {
		if (!base_index_overwritten(cs->insn, entry, &entry_rt, i)) {
			// If the base or index register is not fully overwritten and corresponds to
			// a register argument, it must be immediately re-tainted.
			bool is_vsib = reg_is_avx(entry->arg_m[i].index);
			if ((entry->arg_m[i].base_access && entry_rt.arg_m[i].base_taint) ||
				(!is_vsib && entry->arg_m[i].index_access && entry_rt.arg_m[i].index_taint) ||
				(is_vsib && entry->arg_m[i].index_access && entry_rt.arg_m[i].index_is_tainted)) {
				need_immediate_reprotection = true;
			}

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
				   entry->insn, (entry->arg_m[i].base_re)->name);

		if (dw_reg_written(entry, entry->arg_m[i].index) && !(entry->arg_m[i].index_access & CS_AC_WRITE) &&
			!dw_reg_si_di(entry, entry->arg_m[i].index))
			DW_LOG(WARNING, DISASSEMBLY, "Instruction 0x%llx, index register %s implicitly modified\n",
				   entry->insn, (entry->arg_m[i].index_re)->name);
	}

	// If all tainted registers are overwritten by the instruction, there is no point in installing a post handler
	if (all_tainted_overwritten) {
		entry->post_handler = false;

		DW_LOG(DEBUG, DISASSEMBLY,
			   "Disabling post-handler at 0x%llx (%s %s) because all tainted registers were overwritten.\n",
			   entry->insn, cs->insn->mnemonic, cs->insn->op_str);
	}

	// Instructions with repeat prefix need immediate reprotection
	if (entry->repeat)
		need_immediate_reprotection = true;

	/*
	 * Scan forward from the faulting instruction to determine whether the post-handler can be
	 * safely skipped or installed at a later instruction.
	 */
	if (entry->post_handler && !need_immediate_reprotection) {
		unsigned int insn_scan_count, similar_access_count;
		uintptr_t last_safe_addr;

		last_safe_addr = dw_defer_post_handler(entry, &entry_rt, insn_addr, uctx, cs,
							   &insn_scan_count, &similar_access_count, safe_sites);

		DW_LOG(DEBUG, DISASSEMBLY,
			   "Forward scan has stopped at 0x%llx (%s %s), after (%u) instructions.\n",
			   cs->insn->address, cs->insn->mnemonic, cs->insn->op_str, insn_scan_count);

		if (entry->post_handler && similar_access_count > 0) {
			entry->deferred_post_handler = true;
			entry->next_insn = last_safe_addr;
			DW_LOG(DEBUG, DISASSEMBLY,
				   "Post-handler DEFERRED to 0x%llx - skipped (%u) similar memory accesses!\n",
				   last_safe_addr, similar_access_count);
		}
	}
	return true;
}

static inline void dw_unprotect_entry_regs_ucontext(const struct insn_entry *e, ucontext_t *uctx)
{
	for (unsigned i = 0; i < e->nb_arg_m; i++) {
		uintptr_t valueb = 0, valuei = 0;
		bool tainted = false;
		const struct memory_arg *mem = &(e->arg_m[i]);
		const struct reg_entry *re_base = mem->base_re;
		if (re_base && re_base->ucontext_index >= 0) {
			valueb = dw_get_register(uctx, re_base->ucontext_index);
			if (dw_is_protected((void *)valueb)) {
				tainted = true;
				dw_set_register(uctx, re_base->ucontext_index,
						(uintptr_t)dw_unprotect((void *)valueb));
			}
		}

		const struct reg_entry *re_index = mem->index_re;
		if (re_index && re_index->ucontext_index >= 0) {
			valuei = dw_get_register(uctx, re_index->ucontext_index);
			if (dw_is_protected((void *)valuei)) {
				tainted = true;
				dw_set_register(uctx, re_index->ucontext_index,
						(uintptr_t)dw_unprotect((void *)valuei));
			}
		}

		if (tainted) {
			uintptr_t addr = valueb + valuei * mem->scale + mem->displacement;
			dw_check_access((void *) addr, mem->length);
		}
	}
}

/*
 * Create a new entry for this instruction address
 */
struct insn_entry *dw_create_instruction_entry(instruction_table *table, uintptr_t fault,
											   ucontext_t *uctx, bool *created_out,
											   struct post_safe_site_rb *safe_sites_out)
{
	size_t mask   = table->size - 1;
	size_t start  = hash_addr(fault) & mask;
	size_t cursor = start;

	*created_out = false;
	if (safe_sites_out) {
		safe_sites_out->head = 0;
		safe_sites_out->count = 0;
	}

	static const uintptr_t library_start = 0x700000000000ULL;
	const bool patch_disabled = (fault >= library_start);

	while (1) {
		struct insn_entry *e = &table->entries[cursor];
		int entry_state = atomic_load_explicit(&e->state, memory_order_acquire);

		if (entry_state == ENTRY_EMPTY) {
			int expected = ENTRY_EMPTY;
			/* Try to become the creator for this entry slot */
			if (atomic_compare_exchange_strong_explicit(&e->state, &expected, ENTRY_INITIALIZING,
				    memory_order_acq_rel, memory_order_relaxed)) {

				struct post_safe_site_rb safe_sites;
				safe_sites.head = 0;
				safe_sites.count = 0;

				bool ok = dw_populate_instruction_entry(table, e, fault, uctx, &safe_sites);
				if (!ok) {
					atomic_store_explicit(&e->state, ENTRY_FAILED, memory_order_release);
					DW_LOG(WARNING, MAIN, "Problem creating entry for instruction 0x%llx\n", fault);
					return NULL;
				}

				//TODO: Temporary workaround until libpatch supports overlapping patches
				e->patch_disabled = patch_disabled;
				e->strategy = DW_PATCH_UNKNOWN;

				if (e->patch_disabled) {
					dw_unprotect_entry_regs_ucontext(e, uctx);
					DW_LOG(WARNING, DISASSEMBLY,
						   "Instruction 0x%llx is within a library/OLX area, patching is disabled\n",
						   (unsigned long long)fault);
					atomic_store_explicit(&e->state, ENTRY_READY, memory_order_release);
				} else if (safe_sites_out) {
					*safe_sites_out = safe_sites;
				} else {
					atomic_store_explicit(&e->state, ENTRY_FAILED, memory_order_release);
					DW_LOG(WARNING, MAIN,
						   "Cannot create patch request for instruction 0x%llx: safe_sites_out is "
						   "NULL\n",
						   (unsigned long long)fault);
					return NULL;
				}

				*created_out = true;
				return e;
			}
			/* lost the race, go around and re-read the entry's state */
			continue;
		}

		if (entry_state == ENTRY_INITIALIZING) {
			/* Another thread is creating this slot; wait until it finishes. */
			do {
				entry_state = atomic_load_explicit(&e->state, memory_order_acquire);
			} while (entry_state == ENTRY_INITIALIZING);

			if (e->insn == fault) {
				if (entry_state == ENTRY_READY && e->patch_disabled)
					dw_unprotect_entry_regs_ucontext(e, uctx);
				return (entry_state == ENTRY_READY) ? e : NULL;
			}
		}
		else if (entry_state == ENTRY_READY)
		{
			if (e->insn == fault) {
				if (e->patch_disabled)
					dw_unprotect_entry_regs_ucontext(e, uctx);
				return e;
			}
		}
		else if (entry_state == ENTRY_FAILED) {
			if (e->insn == fault)
				return NULL;
		}

		cursor = (cursor + 1) & mask;
		if (cursor == start) {
			DW_LOG(ERROR, DISASSEMBLY, "Instruction hash table full\n");
			break;
		}
	}

	return NULL;
}

void dw_print_regs(struct patch_exec_context *ctx)
{
	for (int i = 0; i < dw_nb_saved_registers; i++)
		DW_LOG(DEBUG, DISASSEMBLY, "%s, %llx\n",
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

static void check_vsib_access(struct memory_arg *mem, struct memory_arg_runtime *mem_rt,
					    uintptr_t valueb, unsigned idx, void *xsave_ptr)
{
	uint8_t width, count;
	uint8_t index_buffer[64] = {0}; /* ZMM registers are 64 bytes */
	size_t bytes_count, index_size;
	unsigned index = mem->index;
	const int mask_reg = mem->mask;
	const struct reg_entry *index_re = mem->index_re;
	const struct reg_entry *mask_re = dw_get_reg_entry(mask_reg);

	width = mem->index_width;
	count = mem->indices_count;

	if (!width || (width != MIN_VSIB_INDEX_WIDTH && width != MAX_VSIB_INDEX_WIDTH)) {
		DW_LOG(ERROR, DISASSEMBLY, "Invalid VSIB index width %u for mem arg %u\n", width, idx);
		return;
	}

	if (!count) {
		DW_LOG(ERROR, DISASSEMBLY, "Zero VSIB lanes for mem arg %u\n", idx);
		return;
	}

	index_size = index_re ? index_re->size : 0;

	if (index_size > sizeof(index_buffer) || index_size != count * width)
		DW_LOG(WARNING, DISASSEMBLY, "Unexpected index register size %zu (width %u, lanes %u) for mem arg %u\n",
			index_size, width, count, idx);

	mem_rt->index_is_tainted = false;
	mem_rt->mask_bv = ~0ULL;

	/* Decode the indices from the XSAVE area. */
	bytes_count = decode_extended_states(index, xsave_ptr, index_buffer);
	if (bytes_count != index_size)
		DW_LOG(ERROR, DISASSEMBLY,
			   "Failed to decode index register %s (decoded %zu / expected %zu)\n",
			   index_re->name, bytes_count, index_size);

	/* Save the original indices as they might be tainted. */
	__builtin_memcpy(mem_rt->indices, index_buffer, bytes_count);

	/*
	 * Decode the mask register:
	 * - X86_REG_INVALID or K0: all lanes enabled
	 * - AVX-512 k1..k7: direct bit mask
	 * - AVX2/XMM|YMM: derive a bit mask from MSB of each lane.
	 */
	if (mask_reg == X86_REG_INVALID || mask_reg == X86_REG_K0) {
		mem_rt->mask_bv = ~0ULL; /* all lanes enabled */
	} else if (reg_is_avx512_opmask(mask_reg)) {
		bytes_count = decode_extended_states(mask_reg, xsave_ptr,
						     (uint8_t *)&mem_rt->mask_bv);

		if (bytes_count != mask_re->size)
			DW_LOG(ERROR, DISASSEMBLY, "Failed to decode mask register %s (decoded %zu / expected %zu)\n",
				mask_re->name, bytes_count, mask_re->size);
	} else if (reg_is_sse(mask_reg) || reg_is_avx2(mask_reg)) {
		uint8_t mask_buffer[32] = {0};

		bytes_count = decode_extended_states(mask_reg, xsave_ptr, mask_buffer);
		if (bytes_count != mask_re->size)
			DW_LOG(ERROR, DISASSEMBLY,
				"Failed to decode mask register %s (decoded %zu / expected %zu)\n",
				mask_re->name, bytes_count, mask_re->size);

		decode_avx_mask(mask_buffer, count, width * 8, &mem_rt->mask_bv);
	} else {
		DW_LOG(ERROR, DISASSEMBLY, "Invalid mask register %s for mem arg %u\n",
			mask_re ? mask_re->name : "<unknown>", idx);
	}

	for (int i = 0; i < count; i++) {
		uintptr_t valuei;

		if (width == MIN_VSIB_INDEX_WIDTH)
			valuei = *((uint32_t *)(index_buffer + i * width));
		else
			valuei = *((uint64_t *)(index_buffer + i * width));

		/* Check whether the access is valid for each enabled lane. */
		if (mem_rt->mask_bv & (1ull << i)) {
			uintptr_t addr = valueb + valuei * mem->scale + mem->displacement;
			dw_check_access((void *) addr, mem->length);
		}

		/* If the index width is 8 bytes, it might be a protected absolute address. */
		if (width != MAX_VSIB_INDEX_WIDTH ||
		    !(mem_rt->mask_bv & (1ull << i)) ||
		    !dw_is_protected((void *) valuei))
			continue;

		mem_rt->index_is_tainted = true;
		*((uint64_t *)(index_buffer + i * width)) = (uint64_t) dw_unprotect((void *) valuei);

		if (dw_is_protected((void *) valueb))
			DW_LOG(WARNING, DISASSEMBLY, "Both index and base tainted for mem arg %u\n", idx);
	}

	if (mem_rt->index_is_tainted) {
		bytes_count = save_extended_states(index, xsave_ptr, index_buffer);
		if (bytes_count != index_size)
			DW_LOG(ERROR, DISASSEMBLY,
				   "Failed to save indices to register %s (encoded %zu / expected %zu)\n",
				   index_re->name, bytes_count, index_size);
	}
}


static void check_sib_access(struct memory_arg *mem, struct memory_arg_runtime* mem_rt,
					uintptr_t valueb, unsigned idx, bool repeat,
					struct patch_exec_context *ctx)
{
	bool index_is_protected, base_is_protected;
	uintptr_t valuei = 0, valuei_clean = 0, addr;
	unsigned regi = mem->index;

	mem_rt->index_taint = 0;
	mem_rt->index_addr = 0;
	mem_rt->saved_address = 0;
	mem_rt->saved_value = 0;

	index_is_protected = false;
	base_is_protected = dw_is_protected((void *) valueb);

	const struct reg_entry *re = mem->index_re;
	if (re != NULL && regi != X86_REG_INVALID) {
		valuei = dw_get_register(ctx, re->libpatch_index);
		mem_rt->index_addr = valuei_clean = valuei;
		index_is_protected = dw_is_protected((void *) valuei);

		if (index_is_protected) {
			if (base_is_protected)
				DW_LOG(WARNING, DISASSEMBLY, "Both index and base tainted for mem arg %u\n", idx);

			mem_rt->index_taint = valuei;
			valuei_clean = (uintptr_t) dw_unprotect((void *) valuei);
			dw_set_register(ctx, re->libpatch_index, valuei_clean);

		} else {
			mem_rt->index_taint = 0;
		}
	}

	if (!base_is_protected && !index_is_protected)
		return;

	// The effective address computed from tainted base and/or tainted index
	addr = valueb + valuei * mem->scale + mem->displacement;

	// Check if the access is valid, and use the repeat count if present.
	if (repeat) {
		size_t count = dw_get_register(ctx, dw_get_reg_entry(X86_REG_RCX)->libpatch_index);
		dw_check_access((void *) addr, mem->length * count);
	} else {
		dw_check_access((void *) addr, mem->length);
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
	if ((mem->length == sizeof(uintptr_t)) &&
	    ((mem->base_access && mem_rt->base_taint != 0) || (mem->index_access && mem_rt->index_taint != 0))) {

		/* Saving memory address must be done in the pre-handler. e.g., mov rdi, qword ptr [rdi+0x10] */
		uintptr_t valueb_clean = (uintptr_t) dw_unprotect((void *) valueb);
		mem_rt->saved_address = valueb_clean + valuei_clean * mem->scale + mem->displacement;

		if ((mem->access & CS_AC_READ) &&
			    (((mem->base_access & CS_AC_READ) && mem_rt->base_taint) ||
			    ((mem->index_access & CS_AC_READ) && mem_rt->index_taint))) {

			mem_rt->saved_value = (uintptr_t) *((void **)mem_rt->saved_address);
			*((void **)mem_rt->saved_address) = dw_unprotect((void *)(mem_rt->saved_value));
		}
	}
}

void dw_unprotect_context(struct patch_exec_context *ctx)
{
	struct insn_entry *entry = ctx->user_data;
	struct memory_arg *mem;
	struct memory_arg_runtime *mem_rt;
	unsigned regb;
	uintptr_t valueb;
	struct insn_entry_runtime rt_slot, *rt_slot_p;

	dw_bt_seed_patch_set(ctx);

	if (dw_check_handling) {
		DW_LOG(DEBUG, DISASSEMBLY, "(-) Before unprotecting instruction 0x%llx: %s\n",
			    entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
	}

	if (entry->post_handler) {
		int rt_idx = 0;
		if (!dw_acquire_runtime_slot(entry, &rt_idx))
			DW_LOG(ERROR, DISASSEMBLY, "Problem getting a runtime slot for instruction 0x%llx\n", entry->insn);

		rt_slot_p = &insn_rt_slots[rt_idx];
	} else {
		rt_slot.entry = entry;
		rt_slot_p = &rt_slot;
	}

	for (int i = 0; i < entry->nb_arg_m; i++) {
		mem_rt = &(rt_slot_p->arg_m[i]);
		mem_rt->base_taint = 0;
		mem_rt->base_addr = 0;

		// Handle the base register
		mem = &(entry->arg_m[i]);
		regb = mem->base;
		valueb = 0;
		if (regb != X86_REG_INVALID) {
			const struct reg_entry *reb = mem->base_re;
			valueb = dw_get_register(ctx, reb->libpatch_index);
			mem_rt->base_addr = valueb;

			if (dw_is_protected((void *) valueb)) {
				mem_rt->base_taint = valueb;
				dw_set_register(ctx, reb->libpatch_index, (uintptr_t) dw_unprotect((void *) valueb));
			} else {
				mem_rt->base_taint = 0;
			}
		}

		// Handle the index register
		if (mem->index == X86_REG_INVALID || reg_is_gpr(mem->index))
			check_sib_access(mem, mem_rt, valueb, i, entry->repeat, ctx);
		else if (reg_is_avx(mem->index))
			check_vsib_access(mem, mem_rt, valueb, i, ctx->extended_states);
		else
			DW_LOG(ERROR, DISASSEMBLY, "Invalid index register %u for mem arg %u\n", mem->index, i);
	}

	atomic_fetch_add_explicit(&entry->hit_count, 1, memory_order_relaxed);

	if (dw_check_handling) {
			DW_LOG(DEBUG, DISASSEMBLY, "-- After unprotecting instruction 0x%llx\n", entry->insn);
			for (int i = 0; i < dw_nb_saved_registers; i++) {
				struct reg_entry *re = dw_get_reg_entry(dw_saved_registers[i]);
				dw_save_regs[i] = dw_get_register(ctx, re->libpatch_index);
				DW_LOG(DEBUG, DISASSEMBLY, "%s, %llx\n", re->name, ctx->general_purpose_registers[i]);
			}
	}

	if (!entry->post_handler)
		dw_bt_seed_patch_clear();
}

static void check_updated_regs (struct insn_entry *entry, struct insn_entry_runtime *entry_rt, struct patch_exec_context *ctx) {
	struct memory_arg *mem;
	struct memory_arg_runtime *mem_rt;
	bool should_check[dw_nb_saved_registers];
	__builtin_memset(should_check, 0, sizeof(should_check));

	if (!entry->deferred_post_handler) {
		for (int i = 0; i < dw_nb_saved_registers; i++)
			should_check[i] = true;
	} else {
		for (int i = 0; i < entry->nb_arg_m; i++) {
			mem = &(entry->arg_m[i]);
			mem_rt = &(entry_rt->arg_m[i]);

			if (mem_rt->base_taint) {
				const struct reg_entry *reb = mem->base_re;
				if (reb) {
					for (size_t j = 0; j < dw_nb_saved_registers; j++) {
						const struct reg_entry *saved_re = dw_get_reg_entry(dw_saved_registers[j]);
						if (saved_re->canonical_index == reb->canonical_index) {
							should_check[j] = true;
							break;
						}
					}
				}
			}

			const struct reg_entry *rei = mem->index_re;
			if (rei && rei->canonical_index != X86_REG_INVALID && mem_rt->index_taint) {
				for (size_t j = 0; j < dw_nb_saved_registers; j++) {
					const struct reg_entry *saved_re = dw_get_reg_entry(dw_saved_registers[j]);
					if (saved_re->canonical_index == rei->canonical_index) {
						should_check[j] = true;
						break;
					}
				}
			}
		}
	}

	for (int i = 0; i < dw_nb_saved_registers; i++) {
		if (!should_check[i])
			continue;

		unsigned reg = dw_saved_registers[i];
		const struct reg_entry *re = dw_get_reg_entry(reg);
		if (!re || re->libpatch_index < 0)
			continue;

		uintptr_t value = dw_get_register(ctx, re->libpatch_index);
		if (dw_save_regs[i] != value && !dw_reg_written(entry, reg)) {
			DW_LOG(ERROR, DISASSEMBLY,
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
	struct memory_arg *mem;
	struct memory_arg_runtime *mem_rt;
	const struct reg_entry *re;
	unsigned reg;
	int slot_idx;

	/* If the runtime slot was not found, it means we jumped into an address between the
	   pre- and post-handler. Therefore, we simply ignore the post-handler invocation */
	if (!dw_find_runtime_slot(entry, &slot_idx))
		return;

	struct insn_entry_runtime *runtime_slot = &insn_rt_slots[slot_idx];

	if (dw_check_handling) {
		DW_LOG(DEBUG, DISASSEMBLY, "(+) Before reprotecting instruction 0x%llx: %s\n",
				    entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
		check_updated_regs(entry, runtime_slot, ctx);
	}

	for (int i = 0; i < entry->nb_arg_m; i++) {
		mem = &(entry->arg_m[i]);
		mem_rt = &runtime_slot->arg_m[i];

		/*
		 * The tainted register, base or index, is retainted unless the same register was also
		 * an overwritten register argument.
		 */
		if (mem_rt->base_taint && ((mem->base_access & CS_AC_WRITE) == 0)) {
			reg = mem->base;
			re = mem->base_re;
			const void* valueb_new = (const void*) dw_get_register(ctx, re->libpatch_index);
			dw_set_register(ctx, re->libpatch_index, (uint64_t) dw_reprotect(valueb_new, (void *) mem_rt->base_taint));
		}

		// Handle the VSIB case
		if (mem->index != X86_REG_INVALID && reg_is_avx(mem->index)) {
			re = mem->index_re;
			if (mem_rt->index_is_tainted) {
				reg = mem->index;
				size_t saved_bytes = save_extended_states(reg, ctx->extended_states, mem_rt->indices);
				if (saved_bytes != (mem->indices_count * mem->index_width))
					DW_LOG(ERROR, DISASSEMBLY,
						   "Failed to save the indices from register %s into the XSAVE area!\n",
						   re->name);
				// Reset this flag as it will be set again in the pre-handler
				mem_rt->index_is_tainted = false;
			}
			continue;
		}

		// Handle the SIB case
		if (mem_rt->index_taint && ((mem->index_access & CS_AC_WRITE) == 0)) {
			reg = mem->index;
			re = mem->index_re;

			const void* valuei_new = (const void*) dw_get_register(ctx, re->libpatch_index);
			dw_set_register(ctx, re->libpatch_index,
					(uint64_t) dw_reprotect((void *) valuei_new, (void *) mem_rt->index_taint));
		}

		/*
		* If the tainted register, base or index, was also a register argument, we have special
		* cases to consider.
		*/
		if ((mem->length == sizeof(uintptr_t)) && ((mem->base_access && mem_rt->base_taint) || (mem->index_access && mem_rt->index_taint))) {
			/*
			* If the memory was read and the tainted register, base or index, was a read register
			* argument, we presumably have a comparison. The memory value was untainted in
			* the pre handler and should be restored here.
			*/

			if (mem->access & CS_AC_READ) {
				if (((mem->base_access & CS_AC_READ) && mem_rt->base_taint) ||
					((mem->index_access & CS_AC_READ) && mem_rt->index_taint))
					*((void **) mem_rt->saved_address) = (void *) (mem_rt->saved_value);

			}
			/*
			* If the memory was written and the tainted register, base or index, was also a
			* register argument we suppose that the untainted register was stored in memory and we
			* need to retaint the memory with the saved register taint.
			*/
			else if (mem->access & CS_AC_WRITE) {
				uintptr_t saved_taint;
				if(mem_rt->base_taint) saved_taint = mem_rt->base_taint;
				else saved_taint = mem_rt->index_taint;

				*((void **) mem_rt->saved_address) =
						dw_reprotect(*((void **) mem_rt->saved_address), (void *) saved_taint);
			}
		}
	}

	if (dw_check_handling) {
		DW_LOG(DEBUG, DISASSEMBLY, "-- After reprotecting instruction 0x%llx: %s\n",
			entry->insn, entry->disasm_insn);
		dw_print_regs(ctx);
	}

	dw_release_rt_slot(slot_idx);
	dw_bt_seed_patch_clear();
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
		if (atomic_load_explicit(&entry->state, memory_order_acquire) == ENTRY_READY) {
			dw_fprintf(fd, "%4d 0x%lx: %9u: %2u: %1u %s;\n",
					   count, entry->insn, atomic_load(&entry->hit_count), entry->insn_length,
					   entry->strategy, entry->disasm_insn);
			count++;
		}
	}
}

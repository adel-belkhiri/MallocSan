#ifndef DW_DISASSEMBLY_H
#define DW_DISASSEMBLY_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <ucontext.h>
#include <unistd.h>

#include <libpatch/patch.h>

#include "dw-protect.h"

#define MAX_MEM_ARG 3
#define MAX_REG_ARG 6
#define MAX_MOD_REG 6
#define MAX_SCAN_INST_COUNT 256
#define MAX_SAFE_SITE_COUNT (MAX_SCAN_INST_COUNT/8)
#define DW_MIN_SAFE_CANDIDATE_SIZE 0
#define DW_TAIL_CANDIDATE_BUDGET 2
/* Loop-exit deferral (#5) installs exactly ONE post at the loop's fall-through
 * exit. The mechanism is single-exit-only by construction: loop_exit_defer_site
 * returns a single fall-through address and the patch path stages one post.
 * Deferring more than one exit would need atomic multi-post staging and per-exit
 * slot release, neither of which exists -- do not add multi-exit support without
 * building both. */
/* Loop-exit deferral: how far past the latch's fall-through we scan for a
 * provably-non-heap retaint site, skipping heap-faulting instructions (each of
 * those faults and is patched on its own). Bounded so a long run of pointer
 * dereferences after the loop simply declines deferral rather than scanning the
 * whole function. */
#define DW_LE_EXIT_SCAN_MAX 32
#define MAX_VSIB_INDEX_WIDTH 8  // 64 bits index
#define MIN_VSIB_INDEX_WIDTH 4  // 32 bits index

DW_INTERNAL extern bool dw_stats_enabled;

/*
 * Effective address of a SIB memory operand:
 *   EA = base + index * scale + displacement
 * computed in 64-bit modular arithmetic, matching x86 address generation.
 */
static inline uintptr_t
dw_sib_effective_address(uintptr_t base, uintptr_t index, int scale, int64_t disp)
{
	return base + index * (uint64_t)scale + (uint64_t)disp;
}

/*
 * Detect a "compound taint" SIB operand.
 *
 * MallocSan normally finds the object-id taint inside a single base or index
 * register. But strength-reduced address arithmetic can distribute the taint
 * across several operands so that no single register is recognized as
 * protected, while the *aggregate* effective address still carries exactly one
 * valid object-id. The shape the compiler typically emits is:
 *
 *   index = P + c1               (recognized as protected)
 *   base  = (1 - scale) * P + c2 (looks non-canonical/negative, NOT protected)
 *   EA    = base + index*scale + disp  ==  P + offset  (protected)
 *
 * We detect it generically and coefficient-agnostically: the index is the
 * protected operand, the base is not individually protected, scale > 1 (so the
 * taint cannot be carried cleanly by the index alone), and the aggregate EA
 * computed from the *original* register values resolves to a live object-id.
 * The final dw_is_protected() check is self-certifying: an unrelated base value
 * will not make the aggregate resolve to a live object-id.
 *
 * `base`/`index` are the original (pre-untaint) register values.
 */
static inline bool
dw_sib_base_carries_compound_taint(uintptr_t base, uintptr_t index, int scale,
				   int64_t disp, bool base_protected,
				   bool index_protected)
{
	if (base_protected || !index_protected || scale <= 1)
		return false;

	return dw_is_protected((void *)dw_sib_effective_address(base, index, scale, disp));
}

/*
 * Value to load into the base register before executing a compound-taint SIB
 * instruction so that the executed effective address equals the clean target.
 *
 * Solved coefficient-agnostically from the aggregate, absorbing all residual
 * taint into the base:
 *   EA_clean  = dw_unprotect(base + index*scale + disp)
 *   base_exec = EA_clean - index_clean*scale - disp
 *
 * `base`/`index` are the original (pre-untaint) values; `index_clean` is the
 * value the index register will hold at execution time.
 */
static inline uintptr_t
dw_sib_compound_base_exec(uintptr_t base, uintptr_t index, uintptr_t index_clean,
						  int scale, int64_t disp)
{
	uintptr_t ea = dw_sib_effective_address(base, index, scale, disp);
	uintptr_t ea_clean = (uintptr_t)dw_unprotect((void *)ea);

	return ea_clean - index_clean * (uint64_t)scale - (uint64_t)disp;
}


/* x86 RFLAGS direction flag: when set, string operations decrement RSI/RDI. */
#define DW_EFLAGS_DF (1ULL << 10)

/*
 * Compute the memory range a (possibly REP-prefixed) string memory operand
 * touches, for bounds checking. The result is written to *out_addr / *out_size.
 *
 *   addr        : effective address of the first element (current RSI/RDI)
 *   length      : element size in bytes
 *   count       : RCX iteration count (only consulted when repeat is set)
 *   repeat      : the instruction carries a REP/REPE/REPNE prefix
 *   conditional : REPE/REPNE CMPS/SCAS, where RCX is only an upper bound on the
 *                 iteration count (the scan stops on a data condition)
 *   df          : direction flag; when true the pointers decrement
 */
static inline void
string_access_range(uintptr_t addr, size_t length, uint64_t count,
				    bool repeat, bool conditional, bool df,
				    uintptr_t *out_addr, size_t *out_size)
{
	/*
	 * RCX == 0: a REP-prefixed instruction performs no memory access at
	 * all (conditional or not). Callers must skip the bounds check when
	 * the returned size is 0: the pointer may legally rest anywhere.
	 */
	if (repeat && count == 0) {
		*out_addr = addr;
		*out_size = 0;
		return;
	}

	/*
	 * Non-repeating access, or a data-terminated scan (REPE/REPNE
	 * CMPS/SCAS): only the first element at `addr` is guaranteed to be
	 * touched. For the conditional scans RCX is just an upper bound, so
	 * multiplying by it would falsely flag strlen/strcmp-style loops whose
	 * RCX is a large sentinel. The post handlers validate the full extent
	 * of conditional scans after execution (string_scan_extent), when
	 * the final pointer value is known.
	 */
	if (!repeat || conditional) {
		*out_addr = addr;
		*out_size = length;
		return;
	}

	/*
	 * Total span of the count elements, clamped so length*count cannot
	 * overflow size_t. An overflowing count is necessarily out of bounds,
	 * which the size check in dw_check_access then reports.
	 */
	size_t span;
	if (length != 0 && count > (size_t)-1 / length)
		span = (size_t)-1;
	else
		span = (size_t)(length * count);

	/*
	 * DF=1: pointers decrement. The elements touched are addr,
	 * addr-length, ..., addr-length*(count-1); the lowest address is
	 * addr-length*(count-1) and the range ends one element above addr.
	 * When the span saturated, keep `addr` as the range start: the size
	 * alone exceeds any object, and the subtraction would wrap to a
	 * meaningless address that garbles the report.
	 */
	if (df && span != (size_t)-1)
		*out_addr = addr - (span - length);
	else
		*out_addr = addr;
	*out_size = span;
}

/*
 * Exact post-execution range of a REP string scan, derived from the pointer
 * register's value before (initial) and after (final) the instruction; both
 * untainted. Hardware leaves the pointer one element past the last accessed
 * element, in the scan direction, so the direction is inferred from the
 * pointer movement and the caller does not need DF. Used for REPE/REPNE
 * CMPS/SCAS, whose pre-execution extent is unknowable (RCX is only an upper
 * bound). Returns false when no element was accessed (final == initial).
 */
static inline bool
string_scan_extent(uintptr_t initial, uintptr_t final, size_t length,
					  uintptr_t *out_addr, size_t *out_size)
{
	if (final == initial)
		return false;

	if (final > initial) {
		/* DF=0: elements at initial .. final-length. */
		*out_addr = initial;
		*out_size = (size_t)(final - initial);
	} else {
		/* DF=1: elements at initial down to final+length. */
		*out_addr = final + length;
		*out_size = (size_t)(initial - final);
	}
	return true;
}

enum dw_strategies {DW_PATCH_TRAP=0, DW_PATCH_JUMP, DW_PATCH_MIXED, DW_PATCH_EMULATE, DW_PATCH_UNKNOWN};

/*
 * Fast-path classification of an instruction site (Stage 1 of the
 * SIGSEGV emulate-and-skip plan). DW_FAST_MOV_FIXED_FIELD marks a simple
 * fixed-field `mov` (single memory operand, GPR base + constant displacement,
 * no index/VSIB, no RIP-relative or segment override, scalar width 1/2/4/8)
 * that the SIGSEGV handler can emulate and skip in a single signal instead of
 * the two-signal single-step dance. The metadata below is precomputed here so
 * the signal handler needs no register-table lookup on the hot path.
 */
enum dw_fast_kind {DW_FAST_NONE = 0, DW_FAST_MOV_FIXED_FIELD};

enum entry_state {ENTRY_EMPTY = 0, ENTRY_INITIALIZING /* one thread is creating this entry */, ENTRY_READY /* fully initialized */, ENTRY_FAILED /* creation failed, don't retry */};

/*
 * The instruction table contains all the information about the instructions
 * that access tainted pointers. This is in order to untaint the pointers,
 * emulate the access and retaint the pointers. The structure is not opaque for
 * now because it is accessed from a few files. More abstraction is likely in
 * the future, especially when multiple architectures will be supported.
 */
struct insn_table;
struct post_safe_site_rb;

typedef struct insn_table instruction_table;

/*
 * The x86_64 instructions can have several memory arguments.
 * Each can contain a tainted pointer. Typically, the base register
 * is tainted, but sometimes the index register is tainted instead.
 * On some instructions with two memory arguments, it may happen that
 * both are tainted. Sometimes only one is tainted but not always the same.
 * Thus, the detection of which argument is tainted must be dynamic.
 *
 * For a VSIB (Vector Scatter/Gather) instruction, a vector register is used
 * to held many indices. A single memory operand, therefore, can refer to
 * multiple memory locations.
 */
struct memory_arg {
	/* Common fields for both SIB (scalar index) and VSIB (vector index).
	 * The fields of this struct are extracted from Capstone. If unused,
	 * base/index are X86_REG_INVALID. Whether this is SIB or VSIB is
	 * determined by the class of `index` (GPR ⇒ SIB, XMM/YMM/ZMM ⇒ VSIB). */
	int scale;
	int64_t displacement;
	unsigned access;
	int base, index;
	const struct reg_entry *base_re;
	const struct reg_entry *index_re;

	/* If the same register as the base or index is also a register argument, base_access or
	 * index_access will be non zero and set to CS_AC_READ / CS_AC_WRITE. In that case, some care
	 * is needed when untainting and retainting that register. */
	unsigned base_access, index_access;

	/* Size of the memory operand in bytes */
	unsigned length;

	/* VSIB only: width of each index within the register. It can be 32 bits or 64 bits */
	uint8_t index_width;
	/* VSIB only: number of indices within the index register */
	uint8_t indices_count;
	/* VSIB only: the mask register (i.e., YMM0..YMM15 for AVX2, and k0..k7 for AVX-512). */
	int mask;
};

struct memory_arg_runtime {
	/* When the unprotect handler is called, if the base or index register
	 * is tainted, this taint is saved, otherwise the field is set to zero.
	 * It will be used to retaint the register in the reprotect handler,
	 * and to detect if the tainted register, base or index, changes
	 * between different executions of that instruction. */
	uintptr_t base_taint;

	/* The value of base register before untainting. We need
	 * this values to compute and check similar memory accesses. The latter
	 * are memory accesses with the same base and index registers as the
	 * original, but with different displacement, scale and/or size. */
	uintptr_t base_addr;

	union {
		//SIB:
		struct {
			/* If the index register is tainted, the taint is saved here, otherwise
			 * the field is set to zero */
			uintptr_t index_taint;
			/* The value of the index register before untainting */
			uintptr_t index_addr;
			/*
			 * When a register is untainted before its value is read from or
			 * written to memory, because it is at the same time a base pointer
			 * and register argument, we need to fix the value at that address
			 * in the unprotect handler. We thus save the address and the value.
			 */
			uintptr_t saved_address, saved_value;
			/*
			 * Compound-taint compensation (strength-reduced SIB): when the
			 * taint is carried by the aggregate base+index*scale+disp rather
			 * than a single register, the base is rewritten to an execution
			 * value before the access and must be restored to its original
			 * (still-tainted) value afterwards. saved_base_value holds the
			 * original base; restore_base flags that the restore is pending.
			 */
			uintptr_t saved_base_value;
			bool restore_base;
		};
		//VSIB:
		struct {
			/* The index register is a vector register, so we can have multiple indices */
			uint8_t indices[64];
			/* set to true if the index is tainted */
			bool index_is_tainted;
			/* per-execution mask bits: Stores the decoded mask register value. One bit per lane to indicate whether the
			 * corresponding memory access must be performed or not */
			uint64_t mask_bv;
		};
	};
};

struct insn_entry_runtime {
	struct memory_arg_runtime arg_m[MAX_MEM_ARG];
};

extern enum dw_strategies dw_strategy;

static inline const char *strategy_name(enum dw_strategies s)
{
	switch (s) {
		case DW_PATCH_TRAP: return "TRAP";
		case DW_PATCH_JUMP: return "JUMP";
		case DW_PATCH_MIXED: return "MIXED";
		case DW_PATCH_EMULATE: return "EMULATE";
		default: return "UNKNOWN";
	}
}

extern __thread struct insn_entry_runtime insn_rt_slots[MAX_SCAN_INST_COUNT];

/*
 * Compact, per-thread ownership map for the runtime slots above. slot_owner[i]
 * is the insn_entry that currently owns insn_rt_slots[i], or NULL when the slot
 * is free. It is the single source of truth for slot occupancy. Keeping it as a
 * separate, densely-packed array (one pointer per slot) means the acquire/find
 * scans touch ~2 KiB of contiguous, prefetchable memory instead of striding the
 * first/last cache line of every 304-byte insn_entry_runtime, which matters on
 * the hot probe pre-handler path.
 */
extern __thread struct insn_entry *slot_owner[MAX_SCAN_INST_COUNT];

struct reg_arg {
	unsigned reg;
	unsigned length;
	unsigned access;
};

/* Maximum number of invariant bases that can coalesce onto a single shared
 * loop-exit post (#5). members[0] is the owner (it installed the physical
 * post); the rest are siblings whose retaint was relocated onto the owner's
 * exit. If a loop has more distinct invariant bases than this, the overflow
 * bases fall back to their own per-iteration posts (graceful, no correctness
 * impact). */
#define DW_LE_PLAN_MAX_MEMBERS 8

/* Shared loop-exit plan (#5 coalescing). One plan per distinct fall-through
 * exit address. All mutation (create-owner, append-sibling, lookup) happens on
 * the single patch worker thread, so it is unlocked; the only cross-context
 * access is the owner's exit post, which fires from signal/trap context on
 * arbitrary threads and reads members[]/nb_members lock-free via acquire,
 * paired with the worker's release store on append. */
struct le_plan {
	uintptr_t exit_target;
	_Atomic unsigned nb_members;
	struct insn_entry *members[DW_LE_PLAN_MAX_MEMBERS];
};

struct insn_entry {
	_Atomic int state;
	struct memory_arg arg_m[MAX_MEM_ARG];
	struct reg_arg arg_r[MAX_REG_ARG];
	unsigned nb_arg_m;
	unsigned nb_arg_r;
	bool repeat;
	bool repeat_conditional;
	bool post_handler;
	bool deferred_post_handler;
	bool patch_disabled;
	bool has_vsib;
	/* Loop-exit post-handler deferral (#5). loop_exit_defer marks an entry whose
	 * retaint was relocated to the loop's fall-through exit (set by both variants,
	 * used for logging/stats/site-priority). loop_exit_activate is set ONLY for
	 * Variant A (fault inside the loop, no pre-probe): the SIGSEGV handler strips
	 * the invariant base once per loop entry and only the loop-exit post is armed. */
	bool loop_exit_defer;
	bool loop_exit_activate;
	/* Footprint of all fixed-field body accesses admitted for #5 (fault-to-latch
	 * range only). When loop_exit_footprint is true, activation must bounds-check
	 * [base + loop_exit_disp_lo, base + loop_exit_disp_hi) — using the tainted
	 * base pointer so dw_check_access(_ctx) actually inspects the OID — instead
	 * of only the single fault-EA displacement. disp_hi is exclusive. */
	bool    loop_exit_footprint;
	int64_t loop_exit_disp_lo;
	int64_t loop_exit_disp_hi;
	/* Fall-through exit address (latch + latch_size) where this entry's #5
	 * retaint post is/was staged. Keys the shared-exit plan registry that lets
	 * sibling invariant bases in one loop coalesce onto a single exit post.
	 * 0 when not a #5 entry. */
	uintptr_t loop_exit_target;
	/* Shared-exit coalescing (#5). loop_exit_plan is set ONLY on the owner
	 * (members[0]) at commit time; its exit post walks the plan and retaints
	 * every active member. A sibling that joined a committed owner's exit
	 * installs no post and keeps loop_exit_plan NULL (it is identified at
	 * runtime by holding its own activation slot, not by a flag). NULL for
	 * non-coalesced #5 entries. The owner/sibling election is decided at commit
	 * time under dw_le_plan_mu, never during analysis. */
	struct le_plan *loop_exit_plan;
	uintptr_t insn;
	uintptr_t patch_insn;
	uintptr_t next_insn;
	uintptr_t olx_buffer;
	atomic_ulong hit_count;
	char disasm_insn[64];
	unsigned strategy;
	unsigned insn_length;
	/* Fast-path (SIGSEGV emulate-and-skip) metadata; see enum dw_fast_kind.
	 * Populated at decode time, consumed by the signal handler (later stages). */
	uint8_t fast_kind;       /* enum dw_fast_kind */
	uint8_t fast_base_uctx;  /* ucontext_index of base reg (dw_get/set_register) */
	uint8_t fast_dst_uctx;   /* load: dest reg slot; store: src reg slot */
	uint8_t fast_width;      /* access width in bytes: 1/2/4/8 */
	bool fast_is_load;       /* true: mem->reg (load); false: reg->mem (store) */
	int64_t fast_disp;       /* constant displacement */
	uint8_t gregs_read_count;
	uint8_t gregs_write_count;
	uint16_t gregs_read[MAX_MOD_REG]; // test
	uint16_t gregs_written[MAX_MOD_REG]; // test
};

/* For now the instruction table cannot be expanded after initialization */
instruction_table *dw_init_instruction_table(size_t size);

/* Free the instruction table. Difficult to be sure that no tainted pointer
 remains. */
void dw_fini_instruction_table(instruction_table *table);

/* Check if an entry already exists for that instruction address */
struct insn_entry *dw_get_instruction_entry(
		instruction_table *table, uintptr_t fault);

/* Create a new entry for that instruction address */
struct insn_entry *dw_create_instruction_entry(instruction_table *table,
		uintptr_t fault,
		ucontext_t *uctx,
		bool *created_out,
		struct post_safe_site_rb *safe_sites_out);

/* A potentially tainted pointer is accessed, unprotect it before the access */
DW_INTERNAL void dw_unprotect_context(struct patch_exec_context *ctx);

/* A potentially tainted pointer was accessed, reprotect it after the access */
DW_INTERNAL void dw_reprotect_context(struct patch_exec_context *ctx);

/* Shared loop-exit post (#5 coalescing): reprotect every active member of the
 * firing owner's plan. Resolves each member's runtime slot in the CURRENT
 * thread, retaints the ones that hold a slot, and skips the rest (a member may
 * not have faulted this loop entry on this thread). Unlike dw_reprotect_context
 * it must NOT bail on the first missing slot. */
DW_INTERNAL void dw_reprotect_plan_context(struct patch_exec_context *ctx);

/* Variant A loop-exit activation: strip the invariant base once per loop entry
 * from the SIGSEGV context, bounds-checking the access. Returns true if at least
 * one protected base was stripped (the context was modified and a runtime slot
 * acquired for the loop-exit post). */
DW_INTERNAL bool dw_loop_exit_activate_context(struct insn_entry *entry, ucontext_t *uctx);

/* Shared loop-exit plan registry (#5 coalescing). These are the WRITER side of
 * the registry, called from the commit path (patch_entry_sync). That path is
 * usually the patch worker but can also run on arbitrary faulting threads, so
 * the caller MUST hold the registry lock (dw_le_plan_lock/unlock) across a whole
 * lookup -> create/attach election so it is atomic w.r.t. other writers. The
 * async-signal post-handler reader (dw_reprotect_plan_context) never takes the
 * lock; it reads members[]/nb_members lock-free via acquire.
 *  - lock/unlock: serialize the writers.
 *  - exit_is_filled: true if the insn at `addr` is an INT3/JMP fill or
 *    undecodable, i.e. NOT a safe empty owner-install site.
 *  - lookup: return the committed plan keyed on exit_target, or NULL.
 *  - create_owner: register `owner` as members[0] of a new plan for exit_target
 *    and return it (NULL if the table is full).
 *  - attach: append `sibling` to an existing plan via a release store on
 *    nb_members; return false if members[] is full (caller falls back to its own
 *    per-iteration post). */
DW_INTERNAL void dw_le_plan_lock(void);
DW_INTERNAL void dw_le_plan_unlock(void);
DW_INTERNAL bool dw_exit_is_filled(uintptr_t addr);
DW_INTERNAL struct le_plan *dw_le_plan_lookup(uintptr_t exit_target);
DW_INTERNAL struct le_plan *dw_le_plan_create_owner(struct insn_entry *owner,
		uintptr_t exit_target);
DW_INTERNAL bool dw_le_plan_attach(struct le_plan *plan, struct insn_entry *sibling);

/* List all the instructions in the table along with their statistics */
void dw_print_instruction_entries(instruction_table *table, int fd);

/* Activate or deactivate extensive checking in tainting/untainting handler */
void dw_set_check_handling(bool f);

#define min(a, b) ((a) < (b) ? (a) : (b))
#endif /* DW_DISASSEMBLY_H */

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
#define DW_MIN_SAFE_CANDIDATE_SIZE 4
#define DW_TAIL_CANDIDATE_BUDGET 2
#define MAX_VSIB_INDEX_WIDTH 8  // 64 bits index
#define MIN_VSIB_INDEX_WIDTH 4  // 32 bits index

/*
 * Effective address of a SIB memory operand:
 *   EA = base + index * scale + displacement
 * computed in 64-bit modular arithmetic, matching x86 address generation.
 */
static inline uintptr_t dw_sib_effective_address(uintptr_t base, uintptr_t index,
						 int scale, int64_t disp)
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
static inline bool dw_sib_base_carries_compound_taint(uintptr_t base, uintptr_t index,
						      int scale, int64_t disp,
						      bool base_protected,
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
static inline uintptr_t dw_sib_compound_base_exec(uintptr_t base, uintptr_t index,
						  uintptr_t index_clean,
						  int scale, int64_t disp)
{
	uintptr_t ea = dw_sib_effective_address(base, index, scale, disp);
	uintptr_t ea_clean = (uintptr_t)dw_unprotect((void *)ea);

	return ea_clean - index_clean * (uint64_t)scale - (uint64_t)disp;
}


enum dw_strategies {DW_PATCH_TRAP=0, DW_PATCH_JUMP, DW_PATCH_MIXED, DW_PATCH_UNKNOWN};

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
	struct insn_entry *entry;
	struct memory_arg_runtime arg_m[MAX_MEM_ARG];
	bool used;
};

extern enum dw_strategies dw_strategy;

static inline const char *strategy_name(enum dw_strategies s)
{
	switch (s) {
		case DW_PATCH_TRAP: return "TRAP";
		case DW_PATCH_JUMP: return "JUMP";
		case DW_PATCH_MIXED: return "MIXED";
		default: return "UNKNOWN";
	}
}

extern __thread struct insn_entry_runtime insn_rt_slots[MAX_SCAN_INST_COUNT];

struct reg_arg {
	unsigned reg;
	unsigned length;
	unsigned access;
};

struct insn_entry {
	_Atomic int state;
	struct memory_arg arg_m[MAX_MEM_ARG];
	struct reg_arg arg_r[MAX_REG_ARG];
	unsigned nb_arg_m;
	unsigned nb_arg_r;
	bool repeat;
	bool post_handler;
	bool deferred_post_handler;
	bool patch_disabled;
	bool has_vsib;
	uintptr_t insn;
	uintptr_t next_insn;
	uintptr_t olx_buffer;
	atomic_ulong hit_count;
	char disasm_insn[64];
	unsigned strategy;
	unsigned insn_length;
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
void dw_unprotect_context(struct patch_exec_context *ctx);

/* A potentially tainted pointer was accessed, reprotect it after the access */
void dw_reprotect_context(struct patch_exec_context *ctx);

/* List all the instructions in the table along with their statistics */
void dw_print_instruction_entries(instruction_table *table, int fd);

/* Activate or deactivate extensive checking in tainting/untainting handler */
void dw_set_check_handling(bool f);

#define min(a, b) ((a) < (b) ? (a) : (b))
#endif /* DW_DISASSEMBLY_H */

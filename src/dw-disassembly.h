#ifndef DW_DISASSEMBLY_H
#define DW_DISASSEMBLY_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <ucontext.h>
#include <unistd.h>

#include <libpatch/patch.h>

#define MAX_MEM_ARG 3
#define MAX_REG_ARG 6
#define MAX_MOD_REG 6
#define MAX_SCAN_INST_COUNT 32
#define MAX_SAFE_SITE_COUNT (MAX_SCAN_INST_COUNT/4)
#define DW_MIN_SAFE_CANDIDATE_SIZE 4
#define DW_TAIL_CANDIDATE_BUDGET 2
#define MAX_VSIB_INDEX_WIDTH 8  // 64 bits index
#define MIN_VSIB_INDEX_WIDTH 4  // 32 bits index


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
	unsigned gregs_read_count;
	unsigned gregs_write_count;
	unsigned gregs_read[MAX_MOD_REG]; // test
	unsigned gregs_written[MAX_MOD_REG]; // test
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
		bool *created_out);

/* Initialize libpatch */
void dw_patch_init();

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

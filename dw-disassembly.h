#ifndef DW_DISASSEMBLY_H
#define DW_DISASSEMBLY_H

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

enum dw_strategies {DW_PATCH_TRAP=0, DW_PATCH_JUMP, DW_PATCH_MIXED, DW_PATCH_UNKNOWN};

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
 * x86_64 instructions can have several memory arguments.
 * Each can contain a tainted pointer. Normally, the base register
 * is tainted but sometimes the index register is tainted instead.
 * On some instructions with two memory arguments, it may happen that
 * both are tainted. Sometimes only one is tainted but not always the same.
 * Thus, the detection of which argument is tainted must be dynamic.
 */
struct memory_arg {
	/* Those fields are extracted directly from the Capstone library
	 * The base and index are set to X86_REG_INVALID if not used. */
	uintptr_t scale;
	uintptr_t displacement;
	int base;
	int index;
	unsigned length;
	unsigned access;

	/* If the same register as the base or index is also a register
	 * argument, base_access or index_access will be non zero and set
	 * to CS_AC_READ / CS_AC_WRITE, and some care is needed when
	 * untainting and retainting that register. */
	unsigned base_access, index_access;

	/* When the unprotect handler is called, if the base or index register
	 * is tainted, this taint is saved, otherwise the field is set to zero.
	 * It will be used to retaint the register in the reprotect handler,
	 * and to detect if the tainted register, base or index, changes
	 * between different executions of that instruction. */
	uintptr_t base_taint, index_taint;

	/* The address of base and index registers after unprotection */
	uintptr_t base_addr, index_addr;

	/* When a register is untainted before its value is read from or written
	 * to memory, because it is at the same time a base pointer and register
	 * argument, we need to fix the value at that address in the unprotect
	 * handler. We thus save the address and the value. */
	uintptr_t saved_address, saved_value;
};

struct reg_arg {
	unsigned reg;
	unsigned length;
	unsigned access;
};

struct insn_entry {
	struct memory_arg arg_m[MAX_MEM_ARG];
	struct reg_arg arg_r[MAX_REG_ARG];
	unsigned nb_arg_m;
	unsigned nb_arg_r;
	bool repeat;
	bool post_handler;
	bool deferred_post_handler;
	uintptr_t insn;
	uintptr_t next_insn;
	uintptr_t olx_buffer;
	unsigned hit_count;
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
		uintptr_t *next,
		ucontext_t *uctx);

/* Initialize libpatch */
void dw_patch_init();

typedef void (*dw_patch_probe)(struct patch_exec_context *ctx, uint8_t post_or_ret);

/* Patch the instruction described by that entry and have
 * the specified handler called before and after that instruction */
bool dw_instruction_entry_patch(struct insn_entry *entry,
								enum dw_strategies strategy,
								dw_patch_probe patch_handler,
								bool deferred_post_handler);

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

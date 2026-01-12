#define _GNU_SOURCE

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>

#include <libpatch/patch.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <stdbool.h>

#include "dw-backtrace.h"
#include "dw-log.h"

extern void* libc_memset(void *s, int c, size_t n);

struct bt_patch_seed {
	int valid;
	patch_reg pc;
	patch_reg sp;
	patch_reg gprs[PATCH_ARCH_GREGS_COUNT];
};

__thread void *bt_signal_seed = NULL;
static __thread struct bt_patch_seed bt_patch_seed;



void dw_bt_seed_patch_set(const struct patch_exec_context *ctx)
{
	if (!ctx) {
		bt_patch_seed.valid = 0;
		return;
	}

	bt_patch_seed.pc = ctx->program_counter;
	bt_patch_seed.sp = ctx->stack_pointer;
	__builtin_memcpy(bt_patch_seed.gprs, ctx->general_purpose_registers, sizeof(bt_patch_seed.gprs));
	bt_patch_seed.valid = 1;
}

void dw_bt_seed_patch_clear(void)
{
	bt_patch_seed.valid = 0;
}

/*
 * Get the base address of our shared object MallocSan
 */
static void *dw_self_fbase(void)
{
	static void *fbase = NULL;
	static int inited = 0;

	if (inited)
		return fbase;

	Dl_info info;
	if (dladdr((void *)&dw_self_fbase, &info) && info.dli_fbase)
		fbase = info.dli_fbase;

	inited = 1;
	return fbase;
}

/*
 * Check if the given instruction address is within MallocSan
 */
static inline bool dw_ip_in_self(unw_word_t pc)
{
	void *self = dw_self_fbase();
	if (!self)
		return false;

	Dl_info info;
	if (!dladdr((void *)(uintptr_t)pc, &info) || !info.dli_fbase)
		return false;

	return info.dli_fbase == self;
}

/*
 * Print a single frame of the backtrace
 */
static inline void dw_unwind_print_ip(int fd, unw_cursor_t *cur, unw_word_t pc, unsigned *frame)
{
	unw_word_t off = 0;
	char name[256];

	if (unw_get_proc_name(cur, name, sizeof(name), &off) == 0)
		dw_fprintf(fd, "    #%u 0x%lx (%s+0x%lx)\n", (*frame)++, (unsigned long)pc, name, (unsigned long)off);
	else
		dw_fprintf(fd, "    #%u 0x%lx -- No symbol\n", (*frame)++, (unsigned long)pc);
}

static void dw_unwind_print(int fd, unw_cursor_t *cur, unsigned skip)
{
	// Skip internal frames if requested
	for (int i = 0; i < (int)skip; i++) {
		if (unw_step(cur) <= 0)
			return;
	}

	unsigned frame = 0;
	while (1) {
		unw_word_t pc = 0;

		unw_get_reg(cur, UNW_REG_IP, &pc);
		if (!pc)
			break;

		dw_unwind_print_ip(fd, cur, pc, &frame);

		if (unw_step(cur) <= 0)
			break;
	}
}

static void dw_unwind_print_filtered(int fd, unw_cursor_t *cur, enum dw_backtrace_kind kind)
{
	// MSAN: print internal frames only (stop once we leave libmallocsan).
	// APP: skip internal frames first, then print external frames only.
	bool printed_any = false;
	unsigned frame = 0;

	while (1) {
		unw_word_t pc = 0;
		bool in_self = false;

		unw_get_reg(cur, UNW_REG_IP, &pc);
		if (!pc)
			break;

		in_self = dw_ip_in_self(pc);
		bool want = (kind == DW_BT_MSAN) ? in_self : !in_self;

		if (want) {
			printed_any = true;
			dw_unwind_print_ip(fd, cur, pc, &frame);
		} else if (printed_any && kind == DW_BT_MSAN) {
			break;
		} else if (printed_any && kind == DW_BT_APP && in_self) {
			break;
		}

		if (unw_step(cur) <= 0)
			break;
	}
}

static inline void dw_set_cursor_from_patch_seed(unw_cursor_t *cur)
{
	unw_set_reg(cur, UNW_REG_IP, (unw_word_t)bt_patch_seed.pc);
	unw_set_reg(cur, UNW_REG_SP, (unw_word_t)bt_patch_seed.sp);

	unw_set_reg(cur, UNW_X86_64_RAX, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_RAX]);
	unw_set_reg(cur, UNW_X86_64_RBX, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_RBX]);
	unw_set_reg(cur, UNW_X86_64_RCX, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_RCX]);
	unw_set_reg(cur, UNW_X86_64_RDX, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_RDX]);
	unw_set_reg(cur, UNW_X86_64_RSI, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_RSI]);
	unw_set_reg(cur, UNW_X86_64_RDI, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_RDI]);
	unw_set_reg(cur, UNW_X86_64_RBP, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_RBP]);
	unw_set_reg(cur, UNW_X86_64_R8, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_R8]);
	unw_set_reg(cur, UNW_X86_64_R9, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_R9]);
	unw_set_reg(cur, UNW_X86_64_R10, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_R10]);
	unw_set_reg(cur, UNW_X86_64_R11, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_R11]);
	unw_set_reg(cur, UNW_X86_64_R12, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_R12]);
	unw_set_reg(cur, UNW_X86_64_R13, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_R13]);
	unw_set_reg(cur, UNW_X86_64_R14, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_R14]);
	unw_set_reg(cur, UNW_X86_64_R15, (unw_word_t)bt_patch_seed.gprs[PATCH_X86_64_R15]);
}

void dw_backtrace(int fd, enum dw_backtrace_kind kind)
{
	unw_cursor_t cur;

	// Print APP backtrace from signal context (fault context).
	if (kind == DW_BT_APP && bt_signal_seed != NULL &&
	    unw_init_local2(&cur, (unw_context_t *)bt_signal_seed, UNW_INIT_SIGNAL_FRAME) >= 0) {
		dw_unwind_print(fd, &cur, 0);
		return;
	}

	// Print APP backtrace from libpatch probe context
	if (kind == DW_BT_APP && bt_patch_seed.valid) {
		unw_context_t uc;
		unw_getcontext(&uc);
		if (unw_init_local(&cur, &uc) < 0)
			return;

		// Reconstruct cursor from saved registers
		dw_set_cursor_from_patch_seed(&cur);

		if (!dw_self_fbase()) {
			dw_unwind_print(fd, &cur, 0);
			return;
		}

		dw_unwind_print_filtered(fd, &cur, kind);
		return;
	}

	// Current stack
	unw_context_t uc;
	unw_getcontext(&uc);
	if (unw_init_local(&cur, &uc) < 0)
		return;

	// If we can't resolve MallocSan base address, fall back to a conservative skip.
	if (!dw_self_fbase()) {
		unsigned skip = (kind == DW_BT_APP) ? 3 : 1;
		dw_unwind_print(fd, &cur, skip);
		return;
	}

	// Skip logging frames regardless of kind.
	for (unsigned i = 0; i < 3; i++) {
		if (unw_step(&cur) <= 0)
			return;
	}

	dw_unwind_print_filtered(fd, &cur, kind);
}

void dw_lookup_symbol(uintptr_t ip, char *proc_name, size_t name_len, uint64_t *offset_out)
{
	unw_cursor_t cur;
	unw_context_t context;

	if (offset_out)
		*offset_out = 0;

	unw_getcontext(&context);
	unw_init_local(&cur, &context);
	unw_set_reg(&cur, UNW_REG_IP, (unw_word_t)ip);

	unw_word_t off = 0;
	if (unw_get_proc_name(&cur, proc_name, name_len, &off) != 0) {
		string_copy(proc_name, "-- no symbol --", name_len);
		proc_name[name_len - 1] = '\0';
		off = 0;
	}
	if (offset_out)
		*offset_out = (uint64_t)off;
}

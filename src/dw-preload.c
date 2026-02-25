#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <ucontext.h>

#include <capstone/capstone.h> /* CS_AC_* */
#include <libpatch/tools.h>

#include "dw-cpuid.h"
#include "dw-disassembly.h"
#include "dw-log.h"
#include "dw-patch.h"
#include "dw-protect.h"
#include "dw-registers.h"
#include "dw-wrap-glibc.h"

_Atomic int dw_fully_initialized = 0;

/* Number of instructions accessing tainted pointers that we can track. */
static size_t nb_insn_olx_entries = 30000;

/*
 * In the current version, we will only use PATCH_JUMP and fall back to PATCH_TRAP only when
 * libpatch cannot generate a jump-based solution for a given patch site.
 *
 * This should let us debug two aspects. The first is libc wrappers to insure
 * that no tainted pointers leak to system calls. A trace of system calls with
 * arguments and a stack dump can let us check if a tainted pointer is passed as
 * argument and by which call path. The second aspect is the untainting /
 * retainting of pointers. We know that we currently do not handle vector
 * indirect access instructions such as VPGATHERQQ ymm11, qword ptr [ymm9],
 * ymm10
 */

enum dw_strategies dw_strategy = DW_PATCH_JUMP;

static instruction_table *insn_table;

struct trampoline_gpr_frame {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rbp;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t rbx;
	uint64_t rax;
	uint64_t rflags;
};

struct trampoline_context {
	uintptr_t fault_rip;
	void *fault_context;
	greg_t fault_gregs[NGREG];
	int sig;
	bool has_siginfo;
	siginfo_t siginfo;
};

static __thread struct trampoline_context tramp_ctx;

static bool forward_to_saved_handler(int sig, siginfo_t *info, void *uctx);

#define DW_EFLAGS_TF (1ULL << 8)
#define DW_STEP_MAX_REGS 8

struct step_reg {
	int ucontext_index;
	uintptr_t taint;
	bool should_reprotect;
};

struct step_state {
	bool active;
	uintptr_t fault_rip;
	bool repeat_insn;
	size_t nb_regs;
	struct step_reg regs[DW_STEP_MAX_REGS];
};

static __thread struct step_state step_state;

static inline void step_state_clear(void)
{
	step_state.active = false;
	step_state.fault_rip = 0;
	step_state.repeat_insn = false;
	step_state.nb_regs = 0;
}

static void step_state_add_reg(int ucontext_index, uintptr_t taint, bool should_reprotect)
{
	for (size_t i = 0; i < step_state.nb_regs; i++) {
		if (step_state.regs[i].ucontext_index != ucontext_index)
			continue;

		/* If any alias indicates the register is overwritten, skip reprotect. */
		step_state.regs[i].should_reprotect &= should_reprotect;
		return;
	}

	if (step_state.nb_regs >= DW_STEP_MAX_REGS)
		return;

	step_state.regs[step_state.nb_regs++] = (struct step_reg){
		.ucontext_index = ucontext_index, .taint = taint, .should_reprotect = should_reprotect};
}

/*
 * Prepare single-step processing for a patch-disabled faulting instruction.
 * We unprotect tainted registers in the signal ucontext, remember their
 * original tainted values for later reprotection in signal_trap(), and arm TF.
 */
static bool prepare_patch_disabled_step(const struct insn_entry *entry, ucontext_t *uctx)
{
	step_state_clear();
	if (!entry || !uctx)
		return false;

	step_state.fault_rip = entry->insn;
	step_state.repeat_insn = entry->repeat;
	size_t repeat_count = 1;

	if (entry->repeat) {
		const struct reg_entry *rcx_re = dw_get_reg_entry(X86_REG_RCX);
		if (rcx_re && rcx_re->ucontext_index >= 0)
			repeat_count = dw_get_register(uctx, rcx_re->ucontext_index);
	}

	for (unsigned i = 0; i < entry->nb_arg_m; i++) {
		const struct memory_arg *mem = &entry->arg_m[i];
		const struct reg_entry *re_base = mem->base_re;
		const struct reg_entry *re_index = mem->index_re;

		uintptr_t valueb = 0, valuei = 0;
		bool base_protected = false, index_protected = false;

		if (re_base && re_base->ucontext_index >= 0) {
			valueb = dw_get_register(uctx, re_base->ucontext_index);
			base_protected = dw_is_protected((void *)valueb);
		}
		if (re_index && re_index->ucontext_index >= 0) {
			valuei = dw_get_register(uctx, re_index->ucontext_index);
			index_protected = dw_is_protected((void *)valuei);
		}

		if (base_protected) {
			bool reprotect = ((mem->base_access & CS_AC_WRITE) == 0);
			step_state_add_reg(re_base->ucontext_index, valueb, reprotect);
			dw_set_register(uctx, re_base->ucontext_index, (uintptr_t)dw_unprotect((void *)valueb));
		}

		if (index_protected) {
			bool reprotect = ((mem->index_access & CS_AC_WRITE) == 0);
			step_state_add_reg(re_index->ucontext_index, valuei, reprotect);
			dw_set_register(uctx, re_index->ucontext_index,
							(uintptr_t)dw_unprotect((void *)valuei));
		}

		if (base_protected || index_protected) {
			uintptr_t addr = valueb + valuei * mem->scale + mem->displacement;
			size_t access_size = mem->length;

			if (entry->repeat) {
				/* RCX==0 means REP does not perform any memory access. */
				if (repeat_count == 0)
					continue;

				if (mem->length > ((size_t)-1) / repeat_count)
					access_size = (size_t)-1;
				else
					access_size = mem->length * repeat_count;
			}

			dw_check_access((void *)addr, access_size);
		}
	}

	if (step_state.nb_regs == 0)
		return false;

	step_state.active = true;
	uctx->uc_mcontext.gregs[REG_EFL] |= (greg_t)DW_EFLAGS_TF;
	return true;
}

static inline void dw_copy_fault_gregs(greg_t dst[NGREG], const greg_t src[NGREG])
{
	for (size_t i = 0; i < NGREG; i++)
		dst[i] = src[i];
}

static inline void dw_fault_gregs_to_uctx(ucontext_t *uctx, const greg_t gregs[NGREG])
{
	for (size_t i = 0; i < NGREG; i++)
		uctx->uc_mcontext.gregs[i] = gregs[i];
}

static inline void dw_uctx_to_trampoline_frame(const ucontext_t *uctx,
											   struct trampoline_gpr_frame *frame)
{
	frame->rax = uctx->uc_mcontext.gregs[REG_RAX];
	frame->rbx = uctx->uc_mcontext.gregs[REG_RBX];
	frame->rcx = uctx->uc_mcontext.gregs[REG_RCX];
	frame->rdx = uctx->uc_mcontext.gregs[REG_RDX];
	frame->rsi = uctx->uc_mcontext.gregs[REG_RSI];
	frame->rdi = uctx->uc_mcontext.gregs[REG_RDI];
	frame->rbp = uctx->uc_mcontext.gregs[REG_RBP];
	frame->r8 = uctx->uc_mcontext.gregs[REG_R8];
	frame->r9 = uctx->uc_mcontext.gregs[REG_R9];
	frame->r10 = uctx->uc_mcontext.gregs[REG_R10];
	frame->r11 = uctx->uc_mcontext.gregs[REG_R11];
	frame->r12 = uctx->uc_mcontext.gregs[REG_R12];
	frame->r13 = uctx->uc_mcontext.gregs[REG_R13];
	frame->r14 = uctx->uc_mcontext.gregs[REG_R14];
	frame->r15 = uctx->uc_mcontext.gregs[REG_R15];
	frame->rflags = uctx->uc_mcontext.gregs[REG_EFL];
}

/* Preserving AVX/AVX-512 state across trampoline calls. */
static int dw_xsave_enabled = 0;
static uint64_t dw_xsave_size = 0;
static uint64_t dw_xsave_mask = 0;

static inline uint64_t dw_xgetbv(uint32_t index)
{
	uint32_t eax, edx;
	__asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(eax), "=d"(edx) : "c"(index));
	return ((uint64_t)edx << 32) | eax;
}

static void dw_init_xsave_state(void)
{
	unsigned int eax, ebx, ecx, edx;

	dw_xsave_enabled = 0;
	dw_xsave_size = 0;
	dw_xsave_mask = 0;

	if (!dw_cpuid_has_leaf(1))
		return;
	dw_cpuid(1, 0, &eax, &ebx, &ecx, &edx);

	if ((ecx & ((1u << 26) | (1u << 27))) != ((1u << 26) | (1u << 27)))
		return;

	if (!dw_cpuid_has_leaf(0xD))
		return;
	dw_cpuid(0xD, 0, &eax, &ebx, &ecx, &edx);

	uint64_t supported = ((uint64_t)edx << 32) | eax;
	uint64_t xcr0 = dw_xgetbv(0);
	uint64_t mask = xcr0 & supported;

	if (mask == 0 || ebx < 512 + 64)
		return;

	dw_xsave_mask = mask;
	dw_xsave_size = ebx;
	dw_xsave_enabled = 1;
}

__attribute__((noinline, used))
static uintptr_t handle_seg_fault(struct trampoline_gpr_frame *frame)
{
	uintptr_t fault_rip = tramp_ctx.fault_rip;
	uintptr_t resume_rip = fault_rip;
	bool save_active = dw_protect_active;
	bool created_out = false;
	ucontext_t fault_uctx = {0};
	struct post_safe_site_rb safe_sites = {.head = 0, .count = 0};

	dw_protect_active = false;

	dw_fault_gregs_to_uctx(&fault_uctx, tramp_ctx.fault_gregs);

	struct insn_entry *entry =
		dw_create_instruction_entry(insn_table, fault_rip, &fault_uctx, &created_out, &safe_sites);

	if (entry == NULL) {
		ucontext_t *forward_uctx = (ucontext_t *)tramp_ctx.fault_context;
		if (!forward_uctx)
			forward_uctx = &fault_uctx;

		void *saved_bt_seed = bt_signal_seed;
		bt_signal_seed = forward_uctx;
		DW_LOG(WARNING, MAIN,
			   "Segfault on instruction (0x%llx) without protected memory arguments, forwarding to "
			   "saved handler\n",
			   fault_rip);

		bool success = forward_to_saved_handler(
			tramp_ctx.sig, tramp_ctx.has_siginfo ? &tramp_ctx.siginfo : NULL, forward_uctx);
		if (!success) {
			DW_LOG(ERROR, MAIN,
				   "Segfault on instruction (0x%llx) without protected memory arguments, "
				   "no saved handler\n",
				   fault_rip);
		}
		bt_signal_seed = saved_bt_seed;
		resume_rip = (uintptr_t)forward_uctx->uc_mcontext.gregs[REG_RIP];
		dw_uctx_to_trampoline_frame(forward_uctx, frame);
		goto out;
	}

	if (created_out)
		DW_LOG(DEBUG, MAIN, "Thread %u has created a new entry for instruction 0x%llx\n", gettid(),
			   entry->insn);

	if (entry) {
		if (created_out && !entry->patch_disabled) {
			int patch_rc = dw_patch_entry(entry, &safe_sites);
			if (patch_rc == 0) {
				atomic_store_explicit(&entry->state, ENTRY_READY, memory_order_release);
				DW_LOG(DEBUG, MAIN,
					   "Patch summary for 0x%llx: Post-handler: %s, Deferred: %s, Strategy: %s\n",
					   entry->insn, entry->post_handler ? "Yes" : "No",
					   entry->deferred_post_handler ? "Yes" : "No", strategy_name(entry->strategy));
			} else {
				atomic_store_explicit(&entry->state, ENTRY_FAILED, memory_order_release);
				DW_LOG(WARNING, MAIN, "Failed to patch instruction 0x%llx (rc=%d)\n", entry->insn,
					   patch_rc);
			}
		}
	}

out:
	tramp_ctx.fault_context = NULL;
	tramp_ctx.has_siginfo = false;
	dw_protect_active = save_active;
	return resume_rip;
}

/*
 * Trampoline to transfer control to handle_seg_fault function to avoid disassembling and patching
 * instructions in the signal handler. The trampoline performs the following steps:
 *    1. Preserve faulting thread registers and flags
 *    2. Call the function responsible for disassembly and patching instructions
 *    3. Jump back to the original faulting RIP
 */
__attribute__((naked, used))
static void handle_seg_fault_trampoline(void)
{
	__asm__ volatile(
		/* Avoid clobbering the SysV red zone of the faulting frame */
		"subq $128, %%rsp\n\t"
		"subq $8, %%rsp\n\t"
		/* Save flags/GPRs */
		"pushfq\n\t"
		"pushq %%rax\n\t"
		"pushq %%rbx\n\t"
		"pushq %%rcx\n\t"
		"pushq %%rdx\n\t"
		"pushq %%rsi\n\t"
		"pushq %%rdi\n\t"
		"pushq %%rbp\n\t"
		"pushq %%r8\n\t"
		"pushq %%r9\n\t"
		"pushq %%r10\n\t"
		"pushq %%r11\n\t"
		"pushq %%r12\n\t"
		"pushq %%r13\n\t"
		"pushq %%r14\n\t"
		"pushq %%r15\n\t"
		/* Keep a pointer to the saved frame. */
		"movq %%rsp, %%r12\n\t"
		/* Choose XSAVE when enabled, otherwise use FXSAVE. */
		"cmpl $0, %0\n\t"
		"je fxsave_path\n\t"
		/* Save/restore full XSAVE state (AVX/AVX-512). */
		"subq %1, %%rsp\n\t"
		"andq $-64, %%rsp\n\t"
		"lea 512(%%rsp), %%rdi\n\t"
		"cld\n\t"
		"xorl %%eax, %%eax\n\t"
		"movl $8, %%ecx\n\t"
		"rep stosq\n\t"
		"movq %2, %%rax\n\t"
		"movq %%rax, %%rdx\n\t"
		"shr $32, %%rdx\n\t"
		"xsave64 (%%rsp)\n\t"
		/* Call our trampoline */
		"movq %%r12, %%rdi\n\t"
		"callq handle_seg_fault\n\t"
		"movq %%rax, %%r11\n\t"
		"movq %2, %%rax\n\t"
		"movq %%rax, %%rdx\n\t"
		"shr $32, %%rdx\n\t"
		"xrstor64 (%%rsp)\n\t"
		"jmp restore_path\n\t"
		"fxsave_path:\n\t"
		/* Save/restore x87+SSE state to keep the injected call transparent. */
		"subq $528, %%rsp\n\t"
		"andq $-16, %%rsp\n\t"
		"fxsave64 (%%rsp)\n\t"
		/* Call our trampoline */
		"movq %%r12, %%rdi\n\t"
		"callq handle_seg_fault\n\t"
		"movq %%rax, %%r11\n\t"
		"fxrstor64 (%%rsp)\n\t"
		"restore_path:\n\t"
		/* Restore GPRs/flags and resume at the saved RIP.*/
		"movq %%r12, %%rsp\n\t"
		"movq %%r11, 128(%%rsp)\n\t"
		"popq %%r15\n\t"
		"popq %%r14\n\t"
		"popq %%r13\n\t"
		"popq %%r12\n\t"
		"popq %%r11\n\t"
		"popq %%r10\n\t"
		"popq %%r9\n\t"
		"popq %%r8\n\t"
		"popq %%rbp\n\t"
		"popq %%rdi\n\t"
		"popq %%rsi\n\t"
		"popq %%rdx\n\t"
		"popq %%rcx\n\t"
		"popq %%rbx\n\t"
		"popq %%rax\n\t"
		"popfq\n\t"
		"addq $8, %%rsp\n\t"
		"addq $128, %%rsp\n\t"
		/* Jump back to faulting RIP */
		"jmp *-136(%%rsp)\n\t"
		:
		: "m"(dw_xsave_enabled), "m"(dw_xsave_size), "m"(dw_xsave_mask)
		: "memory");
}

/*
 * Forward a signal to any previously installed handler.
 *
 * Some runtimes (e.g., Fortran) may install their own handlers. Therefore, the role
 * of this function is to forward the signal to one of them.
 */
static bool forward_to_saved_handler(int sig, siginfo_t *info, void *uctx)
{
	struct sigaction saved;

	if (!get_saved_sigaction(sig, &saved))
		return false;

	/* If the handler expects the 3-argument form */
	if ((saved.sa_flags & SA_SIGINFO) &&
		saved.sa_sigaction != NULL &&
		saved.sa_sigaction != (void *)SIG_DFL &&
		saved.sa_sigaction != (void *)SIG_IGN)
	{
		saved.sa_sigaction(sig, info, uctx);
		return true;
	}

	/* Otherwise fall back to the classic one-argument handler */
	sighandler_t handler = saved.sa_handler;

	if (handler == SIG_IGN || handler == NULL)
		return false;

	if (handler == SIG_DFL)
	{
		/* Hand control back to the kernel’s default behaviour */
		dw_libc_sigaction(sig, &saved);
		raise(sig);
		return true;
	}

	handler(sig);
	return true;
}

/*
 * Single-step trap is used to retaint pointers after executing patch-disabled instructions.
 * We delegate breakpoint traps to libpatch.
 */
static void signal_trap(int sig, siginfo_t *info, void *context)
{
	ucontext_t *uctx = (ucontext_t *)context;

	/* Single-step trap triggered by TF. */
	if (info && info->si_code == TRAP_TRACE) {
		if (step_state.active && uctx) {
			uintptr_t trap_rip = (uintptr_t)uctx->uc_mcontext.gregs[REG_RIP];
			bool same_rip = (trap_rip == step_state.fault_rip);

			/*
			 * REP instructions can trigger TRAP_TRACE while RIP still points at
			 * the same instruction (single-step per iteration). If we re-taint
			 * immediately, the next iteration can fault again on the same RIP.
			 */
			if (step_state.repeat_insn && same_rip) {
				uctx->uc_mcontext.gregs[REG_EFL] |= (greg_t)DW_EFLAGS_TF;
				return;
			}

			/* Stop single-stepping first. */
			uctx->uc_mcontext.gregs[REG_EFL] &= ~(greg_t)DW_EFLAGS_TF;

			for (size_t i = 0; i < step_state.nb_regs; i++) {
				const struct step_reg *r = &step_state.regs[i];
				if (!r->should_reprotect)
					continue;

				uintptr_t value_new = dw_get_register(uctx, r->ucontext_index);
				dw_set_register(uctx, r->ucontext_index,
								(uintptr_t)dw_reprotect((void *)value_new, (void *)r->taint));
			}

			step_state_clear();
			return;
		}

		/*
		 * This trap was not generated by us and libpatch does not use this kind of traps.
		 */
		DW_LOG(WARNING, MAIN, "Received a trap signal (TF) with no active single-step state.\n");
		if (!forward_to_saved_handler(sig, info, context))
			DW_LOG(ERROR, MAIN,
				   "Failed to forward the trap signal (TF) to a registered handler.\n");
		return;
	}

	/* Breakpoint / other SIGTRAP (int3): let libpatch handle it. */
	libpatch_on_trap(sig, info, context);
}

/*
 * A protected object was presumably accessed, raising a signal (SIGSEGV or SIGBUS)
 */
void signal_protected(int sig, siginfo_t *info, void *context)
{
	bt_signal_seed = context;

	/*
	 * We should not have any tainted pointer access while in the handler.
	 * It is not reentrant and signals are blocked anyway.
	 */
	bool save_active = dw_protect_active;
	dw_protect_active = false;

	/*
	 * Check if we are within wrapped / inactive functions where this signal
	 * should not happen
	 */
	if (!save_active)
		DW_LOG(ERROR, MAIN, "Signal received while within wrappers\n");

	// Get the instruction address
	ucontext_t *uctx = ((ucontext_t *) context);
	uintptr_t fault_insn = uctx->uc_mcontext.gregs[REG_RIP];
	struct insn_entry *entry = dw_get_instruction_entry(insn_table, fault_insn);

	/*
	 * Fast-path for known patch-disabled (library/OLX) instructions.
	 * We untaint and arm TF directly in the actual signal ucontext instead of
	 * going through the trampoline, avoiding early TRAP_TRACE in trampoline code.
	 */
	if (entry && entry->patch_disabled) {
		atomic_fetch_add_explicit(&entry->hit_count, 1, memory_order_relaxed);

		if (prepare_patch_disabled_step(entry, uctx)) {
			dw_protect_active = save_active;
			bt_signal_seed = NULL;
			return;
		}

		DW_LOG(WARNING, MAIN,
			   "Patch-disabled instruction 0x%llx could not arm single-step "
			   "(no supported tainted GPR operands), forwarding to saved handler\n",
			   (unsigned long long)entry->insn);

		dw_protect_active = save_active;
		bt_signal_seed = NULL;
		bool success = forward_to_saved_handler(sig, info, context);
		if (!success) {
			DW_LOG(ERROR, MAIN,
				   "Patch-disabled instruction 0x%llx could not arm single-step and no saved "
				   "handler is installed\n",
				   (unsigned long long)entry->insn);
		}
		return;
	}

	/* Fallback path: create/patch entry through the trampoline context. */
	tramp_ctx.sig = sig;
	tramp_ctx.has_siginfo = (info != NULL);
	if (info)
		tramp_ctx.siginfo = *info;

	tramp_ctx.fault_rip = fault_insn;
	tramp_ctx.fault_context = context;
	dw_copy_fault_gregs(tramp_ctx.fault_gregs, uctx->uc_mcontext.gregs);
	uctx->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)handle_seg_fault_trampoline;

	dw_protect_active = save_active;
	bt_signal_seed = NULL;
}

/*
 * Since this library is activated by LD_PRELOAD, we cannot use the main function argv
 * to receive arguments. We use environment variables instead.
 */

/* Range of object sizes to protect, by default protect all */
static size_t min_protect_size = 0, max_protect_size = ULONG_MAX;

/*
 * What objects in sequence to protect, from (first) to (first + max)
 * By default protect all
 */
static atomic_ulong nb_protected = 0, nb_protected_candidates = 0;
static long unsigned first_protected = 0, max_nb_protected = ULONG_MAX;

/* Use extended checking of coherency */
static bool check_handling = false;
static bool dump_memory_map = false;

/* Verbosity of messages */
static enum dw_log_level log_level = 0;

/*
 * Generate a statistics file with instructions hits
 * static char *stats_file = NULL;
 */
static char *stats_file = ".taintstats.txt";

/*
 * This is the initialisation function called at preload time
 */
extern void __attribute__((constructor(65535)))
dw_init()
{
	// Get the parameters passed as environment variables
	char *arg = getenv("DW_MIN_SIZE");
	if (arg != NULL) min_protect_size = atol(arg);

	arg = getenv("DW_MAX_SIZE");
	if (arg != NULL) max_protect_size = atol(arg);

	arg = getenv("DW_MAX_NB_PROTECTED");
	if (arg != NULL) max_nb_protected = atol(arg);

	arg = getenv("DW_FIRST_PROTECTED");
	if (arg != NULL) first_protected = atol(arg);

	arg = getenv("DW_INSN_ENTRIES");
	if (arg != NULL) nb_insn_olx_entries = atol(arg);

	arg = getenv("DW_LOG_LEVEL");
	if (arg != NULL) { log_level = atoi(arg); dw_set_log_level(log_level); }

	arg = getenv("DW_STATS_FILE");
	if (arg != NULL) stats_file = arg;

	arg = getenv("DW_CHECK_HANDLING");
	if (arg != NULL && atoi(arg) == 1) { check_handling = true; dw_set_check_handling(check_handling); }

	arg = getenv("DW_DUMP_MEMORY_MAP");
	if (arg != NULL && atoi(arg) == 1)
		dump_memory_map = true;
	dw_set_dump_memory_map(dump_memory_map);

	bool show_banner = false;
	arg = getenv("DW_SHOW_BANNER");
	if (arg != NULL && atoi(arg) == 1)
		show_banner = true;

	if (show_banner) {
		dw_fprintf(2,
		"============================================================\n"
		"                  MallocSan Runtime Initialized              \n"
		"                       (LD_PRELOAD active)                   \n"
		"============================================================\n"
		" Object Selection:\n"
		"   min_size            : %lu bytes\n"
		"   max_size            : %lu bytes\n"
		"   first_protected     : %lu (allocation index)\n"
		"   max_nb_protected    : %lu objects\n"
		"\n"
		" Instrumentation:\n"
		"   insn_entries        : %lu\n"
		"   strategy            : %s (fallback TRAP)\n"
		"   check_handling      : %s\n"
		"\n"
		" Logging / Statistics:\n"
		"   log_level           : %d\n"
		"   dump_memory_map     : %s\n"
		"   stats_file          : %s\n"
		"============================================================\n",
		min_protect_size, max_protect_size, first_protected, max_nb_protected,
		nb_insn_olx_entries, strategy_name(dw_strategy), check_handling ? "enabled" : "disabled",
		log_level, dump_memory_map ? "enabled" : "disabled", stats_file);
	}

	// Initialise the different modules
	insn_table = dw_init_instruction_table(nb_insn_olx_entries);
	dw_protect_init();
	dw_init_xsave_state();

	/*
	 * We use an alternate stack to allow handlers to run safely even when the
	 * application stack is near exhaustion.
	 */
	stack_t ss;
	size_t ss_size = 16 * PAGE_SIZE;
	int ret;
	struct sigaction sa;

	ss.ss_sp = malloc(ss_size);
	ss.ss_size = ss_size;
	ss.ss_flags = 0;
	ret = sigaltstack(&ss, NULL);
	if (ret < 0)
		DW_LOG(ERROR, MAIN, "Sigaltstack failed\n");

	dw_patch_runtime_init();
	DW_LOG(DEBUG, PATCH, "Patch init\n");

	/*
	 * Install our SIGTRAP handler after initializing libpatch.
	 *
	 * libpatch may install its own SIGTRAP handler during patch_init(). We need
	 * our handler to stay active to support single-stepping patch-disabled
	 * faults while still delegating non-trace traps to libpatch.
	 */
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigfillset(&sa.sa_mask);
	sa.sa_sigaction = signal_trap;

	ret = dw_libc_sigaction(SIGTRAP, &sa);
	if (ret < 0)
		DW_LOG(ERROR, MAIN, "Sigaction SIGTRAP failed\n");

	/* Insert the SIGSEGV/SIGBUS handlers to catch protected pointers. */
	sa.sa_sigaction = signal_protected;

	ret = dw_libc_sigaction(SIGSEGV, &sa);
	if (ret < 0)
		DW_LOG(ERROR, MAIN, "Sigaction SIGSEGV failed\n");

	ret = dw_libc_sigaction(SIGBUS, &sa);
	if(ret < 0)
		DW_LOG(ERROR, MAIN, "Sigaction SIGBUS failed\n");

	// start intercepting allocation functions
	atomic_store_explicit(&dw_fully_initialized, 1, memory_order_release);
	dw_protect_active = true;
}

extern void __attribute__((destructor)) dw_fini()
{
	// Generate a statistics file
	if (stats_file != NULL) {
		int fd = open(stats_file, O_WRONLY | O_CREAT | O_TRUNC,
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (fd < 0)
			DW_LOG(WARNING, MAIN, "Cannot open file '%s' to write statistics\n", stats_file);
		else {
			dw_fprintf(fd, "There was a total of %d protected malloc on %d candidates\n\n",
				   nb_protected, nb_protected_candidates);
			dw_print_instruction_entries(insn_table, fd);
			close(fd);
		}
	}
	dw_protect_active = false;
	// If there could be remaining tainted pointers, do not free the table
	// dw_fini_instruction_table(insn_table);
	// dw_patch_fini();

	dw_patch_worker_stop();
}

/*
 * Filter the objects to be tainted according to size range and rank in the
 * allocation sequence.
 */
static bool check_candidate(size_t size)
{
	if (size >= min_protect_size && size <= max_protect_size) {
		atomic_fetch_add(&nb_protected_candidates, 1);
		if (nb_protected_candidates > first_protected &&
				nb_protected < max_nb_protected) {
			atomic_fetch_add(&nb_protected, 1);;
			return true;
		}
	}
	return false;
}

/*
 * For now we will not taint objects allocated from libraries, and we assume
 * that this starts at that address. We should read /proc/self/maps and let the
 * user specify which libraries to exclude from tainting allocations.
 */
static void *library_start = (void *)0x700000000000;

static bool check_caller(void *caller)
{
	return caller < library_start;
}

/*
 * Common malloc that checks if the object should be tainted.
 */
static void *malloc2(size_t size, void *caller)
{
	if (!atomic_load_explicit(&dw_fully_initialized, memory_order_acquire)) {
		return __libc_malloc(size);
	}

	void *ret = NULL;
	bool save_active = dw_protect_active;
	dw_protect_active = false;

	if (save_active) {
		if (check_caller(caller)) {
			if (check_candidate(size))
				ret = dw_malloc_protect(size, caller);
		} else
			DW_LOG(TRACE, MAIN, "Not tainting malloc, caller from library\n");
	}
	if (ret == NULL)
		ret = __libc_malloc(size);

	dw_protect_active = save_active;
	DW_LOG(TRACE, MAIN, "Malloc %p, size %lu, caller %p, nb_candidates %lu\n", ret,
		   size, caller, nb_protected_candidates);

	return ret;
}

/*
 * Normal malloc, note the caller and call the common malloc.
 */
void *malloc(size_t size)
{
	return malloc2(size, __builtin_return_address(0));
}

/*
 * We allocate the new object, copy the old to the new, free the old.
 */
void *realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return malloc2(size, __builtin_return_address(0));

	if (size == 0) {
		free(ptr);
		return NULL;
	}

	void *ret = malloc2(size, __builtin_return_address(0));
	if (ret == NULL)
		return NULL;

	size_t old_size = dw_get_size(ptr);
	size_t copy_size = old_size < size ? old_size : size;

	void *dst = dw_unprotect(ret);
	void *src = dw_unprotect(ptr);
	memcpy(dst, src, copy_size);

	free(ptr);
	return ret;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	*memptr = NULL;

	if (!(alignment >= sizeof(void *) && (alignment & (alignment - 1)) == 0))
		return EINVAL;

	if (!atomic_load_explicit(&dw_fully_initialized, memory_order_acquire)) {
		void *ret = __libc_memalign(alignment, size);
		if (!ret)
			return ENOMEM;
		*memptr = ret;
		return 0;
	}

	void *ret = NULL;
	bool save_active = dw_protect_active;
	dw_protect_active = false;

	if (save_active && check_caller(__builtin_return_address(0))) {
		if (check_candidate(size))
			ret = dw_memalign_protect(alignment, size, __builtin_return_address(0));
		else
			ret = NULL;
	}

	if (ret == NULL)
		ret = __libc_memalign(alignment, size);

	dw_protect_active = save_active;

	if (!ret)
		return ENOMEM;

	*memptr = ret;
	DW_LOG(TRACE, MAIN, "posix_memalign %p, size %lu, nb_candidates %lu\n", ret,
		   size, nb_protected_candidates);
	return 0;
}

void *memalign(size_t alignment, size_t size)
{
	if (!atomic_load_explicit(&dw_fully_initialized, memory_order_acquire)) {
		return __libc_memalign(alignment, size);
	}

	void *ret;
	bool save_active = dw_protect_active;
	dw_protect_active = false;

	if (save_active && check_candidate(size))
		ret = dw_memalign_protect(alignment, size, __builtin_return_address(0));
	else
		ret = __libc_memalign(alignment, size);

	dw_protect_active = save_active;
	DW_LOG(TRACE, MAIN, "Memalign %p, size %lu, nb_candidates %lu\n", ret,
		   size, nb_protected_candidates);

	return ret;
}

void *calloc(size_t nmemb, size_t size)
{
	void *ret = malloc2(nmemb * size, __builtin_return_address(0));
	if (ret != NULL)
		__builtin_memset(dw_unprotect(ret), 0, nmemb * size);

	return ret;
}

void free(void *ptr)
{
	/*
	 * We intentionally avoid using TLS variables (i.e., dw_protect_active) in this free() wrapper.
	 * During MallocSan startup, glibc's TLS machinery may call free() while setting up per-thread
	 * TLS blocks; if our wrapper then accesses __thread variables, that TLS access triggers another
	 * free(), causing infinite recursion.
	 *
	 * A global recursion guard (e.g., static int in_free) would prevent this but would let other
	 * threads skip MallocSan while the guard is set, which let dangling records in oids[] array.
	 */
	if (!atomic_load_explicit(&dw_fully_initialized, memory_order_acquire)) {
		__libc_free(ptr);
		return;
	}

	if (dw_is_protected(ptr))
		dw_free_protect(ptr);
	else
		__libc_free(ptr);

	DW_LOG(TRACE, MAIN, "Free %p\n", ptr);
}

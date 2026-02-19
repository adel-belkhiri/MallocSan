#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>

#include "dw-patch.h"
#include "dw-log.h"
#include "dw-protect.h"

typedef struct patch_request {
	struct insn_entry *entry;
	struct post_safe_site_rb safe_sites;
	int rc;
	enum dw_strategies strategy;
	bool done;
	pthread_cond_t done_cv;
	struct patch_request *next;
} patch_request_t;

static pthread_t patch_worker;
static atomic_int patch_w_started = 0;

/* Patch Queue protected by mutex/condition variable. */
static pthread_mutex_t patch_q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t patch_q_cv = PTHREAD_COND_INITIALIZER;
static patch_request_t *patch_q_head = NULL;
static patch_request_t *patch_q_tail = NULL;
static bool patch_q_stop = false;

/* Track worker thread id to avoid accidental self-deadlock. */
static pthread_t worker_tid;
static atomic_int worker_tid_set = 0;

static inline bool patch_q_is_empty(void)
{
	return patch_q_head == NULL;
}

static void patch_q_push_locked(patch_request_t *r)
{
	r->next = NULL;
	if (patch_q_tail)
		patch_q_tail->next = r;
	else
		patch_q_head = r;
	patch_q_tail = r;
}

static patch_request_t *patch_q_pop_locked(void)
{
	patch_request_t *r = patch_q_head;
	if (!r)
		return NULL;

	patch_q_head = r->next;
	if (!patch_q_head)
		patch_q_tail = NULL;
	r->next = NULL;
	return r;
}

static void patch_request_complete_locked(patch_request_t *r, int rc, enum dw_strategies strategy)
{
	r->rc = rc;
	r->strategy = strategy;
	r->done = true;
	(void)pthread_cond_signal(&r->done_cv);
}

static void check_patch(patch_status s, const char *msg)
{
	if (s == PATCH_OK)
		return;

	struct patch_error e;
	patch_last_error(&e);
	DW_LOG(DEBUG, PATCH,
		   "Patch lib return value not OK, %d, for %s, origin %s, irritant %s, message %s\n", s,
		   msg, e.origin, e.irritant, e.message);
}

/*
 * Handler executed before and after instructions that possibly access tainted
 * pointers when an instruction is "patched" to insert pre and post probes.
 */
static void patch_handler(struct patch_exec_context *ctx, uint8_t post)
{
	struct insn_entry *entry = ctx->user_data;
	if (post || ctx->program_counter != entry->insn)
		dw_reprotect_context(ctx);
	else
		dw_unprotect_context(ctx);
}

/*
 * Patch one instruction using an explicit strategy
 */
static bool dw_instruction_entry_patch_strategy(struct insn_entry *entry,
						enum dw_strategies strategy,
						bool deferred)
{
	struct patch_location location = {
		.type = PATCH_LOCATION_ADDRESS,
		.direction = PATCH_LOCATION_FORWARD,
		.algorithm = PATCH_LOCATION_FIRST,
		.address = entry->insn,
	};

	struct patch_exec_model exec_model = {
		.type = PATCH_EXEC_MODEL_PROBE,
		.probe.read_registers = 0,
		.probe.write_registers = 0,
		.probe.clobber_registers = (1ULL << PATCH_ARCH_GREGS_COUNT) - 1,
		.probe.user_data = entry,
		.probe.procedure = patch_handler,
	};

	patch_t patch;
	patch_attr attr;
	patch_status s;

	if (entry->has_vsib)
		exec_model.probe.clobber_registers = PATCH_REGS_ALL;

	if (entry->post_handler && !entry->deferred_post_handler)
		exec_model.type = PATCH_EXEC_MODEL_PROBE_AROUND;

	if (deferred) {
		location.address = entry->next_insn;
		if (!entry->deferred_post_handler)
			DW_LOG(ERROR, PATCH,
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
	} else {
		DW_LOG(ERROR, PATCH, "Unknown patching strategy\n");
	}

	s = patch_attr_set_initial_state(&attr, PATCH_ENABLED);
	check_patch(s, "set enabled");

	s = patch_make(&location, &exec_model, &attr, &patch, NULL);
	check_patch(s, "make");
	if (s != PATCH_OK)
		return false;

	s = patch_commit();
	check_patch(s, "commit");
	return s == PATCH_OK;
}

/*
 * Patch the initial or deferred site and return the strategy that eventually worked.
 */
static enum dw_strategies do_patch(struct insn_entry *entry, bool deferred)
{
	const char *patch_type = deferred ? "deferred" : "initial";
	uintptr_t patch_addr = deferred ? entry->next_insn : entry->insn;
	enum dw_strategies strategy = DW_PATCH_UNKNOWN;

	if (dw_instruction_entry_patch_strategy(entry, DW_PATCH_JUMP, deferred))
		strategy = DW_PATCH_JUMP;
	else if (dw_instruction_entry_patch_strategy(entry, DW_PATCH_TRAP, deferred))
		strategy = DW_PATCH_TRAP;
	else
		DW_LOG(ERROR, PATCH, "Patching %s location 0x%llx failed (origin 0x%llx).\n",
			   patch_type, patch_addr, entry->insn);

	DW_LOG(DEBUG, PATCH, "Patched %s site 0x%llx with %s strategy.\n",
		   patch_type, patch_addr, strategy_name(strategy));

	return strategy;
}

/*
 * Try to patch one of the deferred safe sites with JUMP strategy.
 */
static bool patch_deferred_site(struct insn_entry *entry,
				const struct post_safe_site_rb *safe_sites)
{
	for (int i = (int)safe_sites->count - 1; i >= 0; i--) {
		unsigned idx = (safe_sites->head + i) % MAX_SAFE_SITE_COUNT;

		entry->next_insn = safe_sites->entries[idx].addr;
		if (dw_instruction_entry_patch_strategy(entry, DW_PATCH_JUMP, true)) {
			DW_LOG(DEBUG, PATCH, "Successfully patched deferred site 0x%llx with %s strategy.\n",
				   entry->next_insn, strategy_name(DW_PATCH_JUMP));
			return true;
		}

		DW_LOG(DEBUG, PATCH,
			   "Deferred JUMP patch failed at 0x%llx (origin 0x%llx), trying next candidate.\n",
			   entry->next_insn, entry->insn);
	}

	return false;
}

/*
 * Patches an instruction along with its corresponding deferred counterpart.
 */
static int patch_entry_sync(struct insn_entry *entry, const struct post_safe_site_rb *safe_sites)
{
	if (!entry || !safe_sites)
		return -EINVAL;

	if (!entry->post_handler || !entry->deferred_post_handler) {
		entry->strategy = do_patch(entry, false);
		return (entry->strategy == DW_PATCH_UNKNOWN) ? -1 : 0;
	}

	/*
	 * Either we can patch one of the deferred sites with JUMP, or we cancel
	 * deferring and patch the initial site (with JUMP->TRAP fallback).
	 */
	if (patch_deferred_site(entry, safe_sites)) {
		enum dw_strategies initial_strategy = do_patch(entry, false);
		if (initial_strategy == DW_PATCH_UNKNOWN) {
			entry->strategy = DW_PATCH_UNKNOWN;
			return -1;
		}

		entry->strategy = (initial_strategy != DW_PATCH_JUMP) ? DW_PATCH_MIXED : initial_strategy;
		return 0;
	}

	DW_LOG(DEBUG, PATCH,
		   "Deferred JUMP patch failed for all candidates (origin 0x%llx), canceling deferring.\n",
		   (unsigned long long)entry->insn);

	entry->deferred_post_handler = false;
	entry->strategy = do_patch(entry, false);
	return (entry->strategy == DW_PATCH_UNKNOWN) ? -1 : 0;
}

void dw_patch_runtime_init(void)
{
	const struct patch_option options[] = {
		{
			.type = PATCH_OPT_ENABLE_WXE,
			.enable_wxe = 0,
		},
	};

	(void)patch_init(options, sizeof(options) / sizeof(struct patch_option));
}

static void *patcher_main(void *arg)
{
	(void)arg;

	/*
	 * This is an internal runtime thread. We keep its allocations untracked to
	 * avoid polluting application-level tainting decisions.
	 */
	dw_protect_active = false;

	(void)pthread_setname_np(pthread_self(), "patch-worker");

	worker_tid = pthread_self();
	atomic_store_explicit(&worker_tid_set, 1, memory_order_release);

	for (;;) {
		(void)pthread_mutex_lock(&patch_q_mu);
		while (patch_q_is_empty() && !patch_q_stop)
			(void)pthread_cond_wait(&patch_q_cv, &patch_q_mu);

		if (patch_q_stop && patch_q_is_empty()) {
			(void)pthread_mutex_unlock(&patch_q_mu);
			break;
		}

		patch_request_t *r = patch_q_pop_locked();
		(void)pthread_mutex_unlock(&patch_q_mu);
		if (r == NULL)
			continue;

		int rc = patch_entry_sync(r->entry, &r->safe_sites);
		enum dw_strategies s = r->entry ? (enum dw_strategies)r->entry->strategy : DW_PATCH_UNKNOWN;
		(void)pthread_mutex_lock(&patch_q_mu);
		patch_request_complete_locked(r, rc, s);
		(void)pthread_mutex_unlock(&patch_q_mu);
	}

	atomic_store_explicit(&worker_tid_set, 0, memory_order_release);
	return NULL;
}

void dw_patch_worker_start(void)
{
	int expected = 0;
	if (!atomic_compare_exchange_strong_explicit(
		    &patch_w_started, &expected, 1, memory_order_acq_rel, memory_order_acquire))
		return;

	(void)pthread_mutex_lock(&patch_q_mu);
	patch_q_stop = false;
	(void)pthread_mutex_unlock(&patch_q_mu);

	int rc = pthread_create(&patch_worker, NULL, patcher_main, NULL);
	if (rc != 0) {
		atomic_store_explicit(&patch_w_started, 0, memory_order_release);
		DW_LOG(WARNING, PATCH, "Failed to create patch worker thread: %d\n", rc);
	}
}

void dw_patch_worker_stop(void)
{
	if (!atomic_exchange_explicit(&patch_w_started, 0, memory_order_acq_rel))
		return;

	(void)pthread_mutex_lock(&patch_q_mu);
	patch_q_stop = true;
	(void)pthread_cond_broadcast(&patch_q_cv);
	(void)pthread_mutex_unlock(&patch_q_mu);

	if (atomic_load_explicit(&worker_tid_set, memory_order_acquire) &&
	    pthread_equal(pthread_self(), worker_tid))
		return;

	(void)pthread_join(patch_worker, NULL);
}

int dw_patch_entry(struct insn_entry *entry, const struct post_safe_site_rb *safe_sites)
{
	if (!entry || !safe_sites)
		return -EINVAL;

	if (!atomic_load_explicit(&patch_w_started, memory_order_acquire))
		return patch_entry_sync(entry, safe_sites);

	/* Abort if patching is requested from the worker thread itself. */
	if (atomic_load_explicit(&worker_tid_set, memory_order_acquire) &&
	    pthread_equal(pthread_self(), worker_tid))
		DW_LOG(ERROR, PATCH,
			   "Cannot patch instruction from worker patch thread itself.\n");

	patch_request_t req = {
		.entry = entry,
		.safe_sites = *safe_sites,
		.rc = -EINTR,
		.strategy = DW_PATCH_UNKNOWN,
		.done = false,
		.done_cv = PTHREAD_COND_INITIALIZER,
		.next = NULL,
	};

	(void)pthread_mutex_lock(&patch_q_mu);
	if (patch_q_stop) {
		(void)pthread_mutex_unlock(&patch_q_mu);
		return patch_entry_sync(entry, safe_sites);
	}

	patch_q_push_locked(&req);
	(void)pthread_cond_signal(&patch_q_cv);
	while (!req.done)
		(void)pthread_cond_wait(&req.done_cv, &patch_q_mu);
	(void)pthread_mutex_unlock(&patch_q_mu);
	(void)pthread_cond_destroy(&req.done_cv);

	entry->strategy = req.strategy;
	return req.rc;
}

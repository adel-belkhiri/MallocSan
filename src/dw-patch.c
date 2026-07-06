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
	uintptr_t patch_insn = entry->patch_insn ? entry->patch_insn : entry->insn;
	if (post || ctx->program_counter != patch_insn) {
		/*
		 * Shared loop-exit post (#5 coalescing): when this entry owns a plan,
		 * its single exit post must retaint every coalesced member, not just
		 * itself. Otherwise the ordinary single-entry retaint applies.
		 */
		if (entry->loop_exit_plan)
			dw_reprotect_plan_context(ctx);
		else
			dw_reprotect_context(ctx);
	} else
		dw_unprotect_context(ctx);
}

/* Route non-relocated base-only entries directly to their specialized probes. */
static void patch_handler_base_only(struct patch_exec_context *ctx, uint8_t post)
{
	struct insn_entry *entry = ctx->user_data;

	if (post || ctx->program_counter != entry->insn)
		dw_reprotect_base_only(ctx);
	else
		dw_unprotect_base_only(ctx);
}

static inline uintptr_t entry_initial_addr(const struct insn_entry *entry)
{
	return entry->patch_insn ? entry->patch_insn : entry->insn;
}

/*
 * Stage a single probe in the DISABLED state (made but not yet live). On
 * success the handle is stored in *out and true is returned; the caller must
 * later either enable_and_commit() it or drop_probes() it to cancel.
 *
 * trap_policy selects the patching class:
 *   PATCH_TRAP_POLICY_ALLOW - jump-class. May plant int3 in neighbouring or
 *       padding bytes, but normal control flow still enters through the jump,
 *       so it is NOT the expensive primary-trap strategy.
 *   PATCH_TRAP_POLICY_FORCE - primary int3 at the instruction; fires on every
 *       execution. Only used when a jump cannot be installed.
 *
 * around selects the execution model: PROBE_AROUND installs both a pre- and a
 * post-probe on the instruction; PROBE installs a single probe (a pre-probe at
 * the instruction, or a deferred post-probe at a safe site).
 */
static bool make_probe(struct insn_entry *entry, uintptr_t address, bool around,
		       enum patch_trap_policy trap_policy, patch_t *out)
{
	struct patch_location location = {
		.type = PATCH_LOCATION_ADDRESS,
		.direction = PATCH_LOCATION_FORWARD,
		.algorithm = PATCH_LOCATION_FIRST,
		.address = address,
	};

	struct patch_exec_model exec_model = {
		.type = around ? PATCH_EXEC_MODEL_PROBE_AROUND : PATCH_EXEC_MODEL_PROBE,
		.probe.read_registers = 0,
		.probe.write_registers = 0,
		.probe.clobber_registers = entry->has_vsib ? PATCH_REGS_ALL
							   : ((1ULL << PATCH_ARCH_GREGS_COUNT) - 1),
		.probe.user_data = entry,
		.probe.procedure = dw_entry_base_only_fast(entry) ? patch_handler_base_only : patch_handler,
	};

	patch_attr attr;
	patch_status s;

	s = patch_attr_init(&attr, sizeof(attr));
	check_patch(s, "attr init");

	s = patch_attr_set_trap_policy(&attr, trap_policy);
	check_patch(s, "set trap policy");

	/* Staged disabled: the batch goes live atomically in patch_commit(). */
	s = patch_attr_set_initial_state(&attr, PATCH_DISABLED);
	check_patch(s, "set disabled");

	/*
	 * Overlap children (patch_insn != 0) only ever take the entry->patch_insn
	 * branch of patch_entry_sync, so within make_probe a non-zero patch_insn
	 * reliably identifies an overlap-child make. For those, capture the
	 * per-candidate results so a failed make exposes the real libpatch reason
	 * (e.g. an OLX rebuild landing-pad miss or a region admission reject).
	 * Without this, find_solution() reset_error()s the specific error and
	 * returns the generic "could not find solution", so even check_patch at
	 * DEBUG cannot show why an overlap child was rejected. The common
	 * (non-overlap) path keeps passing NULL and is left untouched.
	 */
	const bool diag = entry->patch_insn != 0;
	struct patch_location_results results = {0};

	s = patch_make(&location, &exec_model, &attr, out, diag ? &results : NULL);
	check_patch(s, "make");

	if (s != PATCH_OK && diag) {
		bool logged = false;

		for (size_t i = 0; i < results.count; i++) {
			const struct patch_error *pe = results.results[i].error;

			DW_LOG(WARNING, PATCH,
				   "Overlap make candidate 0x%llx rejected: %s [origin %s, irritant %s]\n",
				   (unsigned long long)results.results[i].candidate,
				   pe ? pe->message : "(none)",
				   pe ? pe->origin : "(none)",
				   pe ? pe->irritant : "(none)");
			logged = true;
		}

		if (!logged) {
			/* Failure before find_solution (resolve/candidates): the
			 * thread-local last error is still intact here. */
			struct patch_error e;

			patch_last_error(&e);
			DW_LOG(WARNING, PATCH,
				   "Overlap make failed with no per-candidate detail: %s [origin %s, irritant %s]\n",
				   e.message, e.origin, e.irritant);
		} else if (results.count > 0 && !results.results[0].error) {
			/*
			 * libpatch returned a bare PATCH_ERR_FAIL with no pushed error.
			 * On the overlap path that is the silent region_idx == 0 guard in
			 * add_overlap_child(): the OLX instruction's original PC is itself
			 * a patch HEAD, and libpatch only accepts overlap children on the
			 * displaced non-head region instructions (idx >= 1).
			 */
			DW_LOG(WARNING, PATCH,
				   "  (no libpatch error string: original PC is a patch head / not an "
				   "overlap-child slot)\n");
		}
	}

	if (results.results)
		(void)patch_drop_location_results(&results);

	return s == PATCH_OK;
}

/*
 * Enable every staged probe and commit the batch atomically (single
 * patch_commit). All transitions in a batch go live together, so a pre/post
 * pair is never momentarily live with only one half installed.
 */
static bool enable_and_commit(const patch_t *patches, int n)
{
	patch_status s;

	for (int i = 0; i < n; i++) {
		s = patch_enable(patches[i]);
		/*
		 * PATCH_NOP means the patch is already in the enabled state and
		 * patch_enable still (re)queues it -- this is the idempotent
		 * success case for an OLX overlapping patch whose make returned an
		 * existing live handle. Treat it like PATCH_OK; only a real error
		 * aborts the batch (and must not trigger a drop of a live patch).
		 */
		if (s != PATCH_OK && s != PATCH_NOP) {
			check_patch(s, "enable");
			return false;
		}
	}

	s = patch_commit();
	if (s != PATCH_OK && s != PATCH_NOP) {
		check_patch(s, "commit");
		return false;
	}
	return true;
}

/*
 * Cancel staged probes. Patches that were made (and possibly enable-queued) but
 * never committed are still DISABLED, so patch_drop tears them down immediately
 * with no commit required.
 */
static void drop_probes(const patch_t *patches, int n)
{
	for (int i = 0; i < n; i++) {
		patch_status s = patch_drop(patches[i]);
		check_patch(s, "drop");
	}
}

/*
 * Stage a deferred post-probe (DISABLED) at the newest viable safe site. On
 * success records the chosen site in entry->next_insn, stores the handle in
 * *out, and returns true.
 */
static bool make_deferred_post(struct insn_entry *entry,
			       const struct post_safe_site_rb *safe_sites,
			       enum patch_trap_policy trap_policy, patch_t *out)
{
	for (int i = (int)safe_sites->count - 1; i >= 0; i--) {
		unsigned idx = (safe_sites->head + i) % MAX_SAFE_SITE_COUNT;
		uintptr_t addr = safe_sites->entries[idx].addr;

		if (make_probe(entry, addr, false, trap_policy, out)) {
			entry->next_insn = addr;
			DW_LOG(DEBUG, PATCH, "Staged deferred post-probe at 0x%llx (origin 0x%llx).\n",
				   addr, entry->insn);
			return true;
		}

		/*
		 * Loop-exit sites fire at most once per loop entry, so a primary int3
		 * (TRAP) post is acceptable there even when the exit insn is too short
		 * for a jump-class patch. Only sites explicitly flagged trap_ok opt in,
		 * and only when the caller has not already forced TRAP.
		 */
		if (safe_sites->entries[idx].trap_ok &&
		    trap_policy != PATCH_TRAP_POLICY_FORCE &&
		    make_probe(entry, addr, false, PATCH_TRAP_POLICY_FORCE, out)) {
			entry->next_insn = addr;
			DW_LOG(DEBUG, PATCH, "Staged deferred post-probe (TRAP) at 0x%llx (origin 0x%llx).\n",
				   addr, entry->insn);
			return true;
		}

		DW_LOG(DEBUG, PATCH,
			   "Deferred post-probe could not be staged at 0x%llx (origin 0x%llx), trying next.\n",
			   addr, entry->insn);
	}

	return false;
}

/*
 * Stage the Variant-A owner post at the single loop fall-through exit address
 * directly (no ring-buffer scan). On success the handle is in *out and
 * entry->next_insn records the exit. Jump-class first (ALLOW), then a primary
 * int3 (FORCE) -- a loop-exit post fires at most once per loop entry, so a trap
 * there is acceptable when the exit insn is too short for a jump-class patch.
 */
static bool make_loop_exit_post(struct insn_entry *entry, uintptr_t addr, patch_t *out)
{
	if (make_probe(entry, addr, false, PATCH_TRAP_POLICY_ALLOW, out)) {
		entry->next_insn = addr;
		return true;
	}
	if (make_probe(entry, addr, false, PATCH_TRAP_POLICY_FORCE, out)) {
		entry->next_insn = addr;
		return true;
	}
	return false;
}

/*
 * Patches an instruction along with its corresponding deferred counterpart.
 *
 * Trap-policy convention: ALLOW for every jump-preferred plan (keeps punning /
 * alias opportunities; not the costly trap fallback), FORCE only when a primary
 * int3 is deliberately accepted because a jump cannot be installed.
 *
 * Every early return either commits a fully-assembled plan or drops everything
 * it staged; no path leaves a made-but-uncommitted patch dangling.
 */
static int patch_entry_sync(struct insn_entry *entry, const struct post_safe_site_rb *safe_sites)
{
	if (!entry || !safe_sites)
		return -EINVAL;

	const uintptr_t initial = entry_initial_addr(entry);
	const bool fast = (entry->fast_kind == DW_FAST_MOV_FIXED_FIELD && !entry->patch_insn);
	const bool want_defer = entry->post_handler && entry->deferred_post_handler;
	patch_t pre, post, single;

	/*
	 * OLX overlap child (relocated instruction, patch_insn != 0). patch_make
	 * does NOT create a fresh patch here: it resolves to the shared parent
	 * patch that owns the relocated region, registers this address as an
	 * overlap child, and returns the parent's (already live) handle. Two
	 * consequences drive the handling:
	 *   - patch_enable on that handle returns PATCH_NOP (the parent is already
	 *     enabled); enable_and_commit() treats PATCH_NOP as success.
	 *   - patch_drop on that handle would tear down the PARENT and every
	 *     sibling child, not just this probe. So an overlap child has no safe
	 *     cancel path: we make + commit, or we degrade WITHOUT dropping.
	 * Overlap children never defer (they need immediate reprotection), so this
	 * is a single probe -- AROUND when a post is needed, else pre-only. We try
	 * jump-class first, then a trap-policy make ONLY if the jump-class make
	 * itself failed (if it succeeded the child slot is taken and a re-make would
	 * be rejected as a duplicate).
	 */
	if (entry->patch_insn) {
		const bool around = entry->post_handler;

		entry->deferred_post_handler = false;

		if (make_probe(entry, initial, around, PATCH_TRAP_POLICY_ALLOW, &single)) {
			if (enable_and_commit(&single, 1))
				entry->strategy = DW_PATCH_JUMP;
			else
				/* Child is registered on the parent; do NOT drop. */
				entry->strategy = DW_PATCH_UNKNOWN;
			goto overlap_done;
		}

		if (make_probe(entry, initial, around, PATCH_TRAP_POLICY_FORCE, &single)) {
			if (enable_and_commit(&single, 1))
				entry->strategy = DW_PATCH_TRAP;
			else
				entry->strategy = DW_PATCH_UNKNOWN;
			goto overlap_done;
		}

		entry->strategy = DW_PATCH_UNKNOWN;

overlap_done:
		if (entry->strategy == DW_PATCH_UNKNOWN) {
			DW_LOG(WARNING, PATCH,
				   "Overlap-child patching 0x%llx failed (origin 0x%llx); "
				   "falling back to single-step.\n",
				   (unsigned long long)initial, (unsigned long long)entry->insn);
			return -1;
		}
		return 0;
	}

	/*
	 * Variant A loop-exit: fault-driven activation strips the invariant base
	 * once per loop entry from the SIGSEGV handler, so there is NO pre-probe.
	 * Install ONLY the deferred post (retaint) at the loop fall-through exit.
	 * Must precede the fast (emulate) path: a fixed-field mov that is also a
	 * loop-exit candidate has to take this path, not emulate-and-skip.
	 */
	if (want_defer && entry->loop_exit_activate) {
		/*
		 * Shared loop-exit coalescing (#5). Owner/sibling election is decided
		 * HERE, at commit, under dw_le_plan_mu -- never trusting an analysis-time
		 * verdict (analysis runs on faulting threads and races other commits).
		 * The whole lookup -> emptiness re-check -> install -> create_owner/attach
		 * sequence is one critical section, so two entries can never both become
		 * owner of the same exit: the first registers the plan before unlocking,
		 * the second sees it and attaches.
		 */
		bool committed = false;

		dw_le_plan_lock();
		struct le_plan *plan = dw_le_plan_lookup(entry->loop_exit_target);
		if (plan) {
			/*
			 * A committed owner already holds this exit -> SIBLING. Install NO
			 * physical post: join the owner's plan; the owner's single exit post
			 * retaints us.
			 */
			committed = dw_le_plan_attach(plan, entry);
			dw_le_plan_unlock();
		} else if (!dw_exit_is_filled(entry->loop_exit_target) &&
			   make_loop_exit_post(entry, entry->loop_exit_target, &post)) {
			/*
			 * No owner yet and the exit decodes to a real (unfilled) instruction
			 * -> try to BECOME the owner. The emptiness re-check under the lock
			 * removes all dependence on libpatch's occupied-make semantics: we
			 * only ever install on a verifiably-empty exit.
			 */
			if (enable_and_commit(&post, 1)) {
				dw_le_plan_create_owner(entry, entry->loop_exit_target);
				dw_le_plan_unlock();
				committed = true;
			} else {
				drop_probes(&post, 1);
				dw_le_plan_unlock();
			}
		} else {
			dw_le_plan_unlock();
		}

		if (committed) {
			entry->deferred_post_handler = true;
			entry->patch_disabled = true;
			entry->strategy = DW_PATCH_JUMP;
			return 0;
		}

		/*
		 * Could neither own nor join the exit. Abandon Variant A and fall
		 * through to the generic pre+post deferral path below (the entry keeps
		 * its normal pre-probe). Reset deferred_post_handler too so a later
		 * size-floor revert does not see a stale flag; want_defer was captured
		 * const at function entry, so the generic path still runs.
		 */
		entry->loop_exit_activate = false;
		entry->loop_exit_defer = false;
		entry->deferred_post_handler = false;
	}

	/*
	 * Fast in-place mov: jump-class (ALLOW) only -- never a primary TRAP.
	 * An int3 at the instruction fires on every execution and does more work
	 * per hit than the SIGSEGV emulate-and-skip path, which faults only when
	 * the pointer is actually tainted. So when no jump can be installed we
	 * degrade to DW_PATCH_EMULATE (patch_disabled) instead of forcing a trap.
	 * OLX overlap children (patch_insn != 0) are excluded and take the
	 * generic path below.
	 */
	if (fast) {
		/*
		 * Deferrable cluster: a pre-only jump at the instruction plus a
		 * post jump at a safe site preserves the deferral skip across the
		 * similar accesses (the base stays clean, so they do not re-fault).
		 */
		if (want_defer &&
		    make_probe(entry, initial, false, PATCH_TRAP_POLICY_ALLOW, &pre)) {
			if (make_deferred_post(entry, safe_sites, PATCH_TRAP_POLICY_ALLOW, &post)) {
				if (enable_and_commit((patch_t[]){pre, post}, 2)) {
					entry->deferred_post_handler = true;
					entry->strategy = DW_PATCH_JUMP;
					return 0;
				}
				drop_probes((patch_t[]){pre, post}, 2);
				goto fast_emulate;
			}
			drop_probes(&pre, 1);
		}

		/*
		 * Standalone (no deferral, or no safe site took the deferred
		 * jump): a single jump-class probe on the instruction -- AROUND
		 * when a post is needed, else pre-only.
		 */
		entry->deferred_post_handler = false;
		if (make_probe(entry, initial, entry->post_handler, PATCH_TRAP_POLICY_ALLOW, &single)) {
			if (enable_and_commit(&single, 1)) {
				entry->strategy = DW_PATCH_JUMP;
				return 0;
			}
			drop_probes(&single, 1);
		}

fast_emulate:
		entry->deferred_post_handler = false;
		entry->strategy = DW_PATCH_EMULATE;
		return -1;
	}

	/*
	 * Generic, no deferral: a single probe on the instruction. AROUND when a
	 * post is needed, else pre-only. Jump first, primary trap as fallback.
	 */
	if (!want_defer) {
		const bool around = entry->post_handler;

		if (make_probe(entry, initial, around, PATCH_TRAP_POLICY_ALLOW, &single)) {
			if (enable_and_commit(&single, 1)) {
				entry->strategy = DW_PATCH_JUMP;
				return 0;
			}
			drop_probes(&single, 1);
		}

		if (make_probe(entry, initial, around, PATCH_TRAP_POLICY_FORCE, &single)) {
			if (enable_and_commit(&single, 1)) {
				entry->strategy = DW_PATCH_TRAP;
				return 0;
			}
			drop_probes(&single, 1);
		}

		goto degrade;
	}

	/*
	 * Generic, deferral wanted (post_handler && deferred_post_handler).
	 *
	 * Path A: pre-only jump at the instruction + post jump at a safe site.
	 */
	if (make_probe(entry, initial, false, PATCH_TRAP_POLICY_ALLOW, &pre)) {
		if (make_deferred_post(entry, safe_sites, PATCH_TRAP_POLICY_ALLOW, &post)) {
			if (enable_and_commit((patch_t[]){pre, post}, 2)) {
				entry->deferred_post_handler = true;
				entry->strategy = DW_PATCH_JUMP;
				return 0;
			}
			drop_probes((patch_t[]){pre, post}, 2);
			goto degrade;
		}

		/*
		 * No safe site accepted the post jump: drop the pre, cancel
		 * deferral, and retry as a single AROUND probe (jump, then trap).
		 */
		drop_probes(&pre, 1);
		entry->deferred_post_handler = false;

		if (make_probe(entry, initial, true, PATCH_TRAP_POLICY_ALLOW, &single)) {
			if (enable_and_commit(&single, 1)) {
				entry->strategy = DW_PATCH_JUMP;
				return 0;
			}
			drop_probes(&single, 1);
		}

		if (make_probe(entry, initial, true, PATCH_TRAP_POLICY_FORCE, &single)) {
			if (enable_and_commit(&single, 1)) {
				entry->strategy = DW_PATCH_TRAP;
				return 0;
			}
			drop_probes(&single, 1);
		}

		goto degrade;
	}

	/*
	 * Path B: the pre-only jump could not be installed at the instruction. A
	 * jump-class AROUND needs the same 5-byte landing and would also fail, so
	 * skip straight to trap-based plans.
	 *
	 * Prefer MIXED (pre trap at the instruction + post jump at a safe site):
	 * the pre-trap untaints once and the base stays clean across the deferred
	 * cluster, so the similar accesses do not re-fault and the deferral skip
	 * is preserved. Only when no safe site accepts the post jump do we fall
	 * back to a plain AROUND trap, which retaints immediately and loses that
	 * skip.
	 */
	if (make_deferred_post(entry, safe_sites, PATCH_TRAP_POLICY_ALLOW, &post)) {
		if (make_probe(entry, initial, false, PATCH_TRAP_POLICY_FORCE, &pre)) {
			if (enable_and_commit((patch_t[]){pre, post}, 2)) {
				entry->deferred_post_handler = true;
				entry->strategy = DW_PATCH_MIXED;
				return 0;
			}
			drop_probes((patch_t[]){pre, post}, 2);
			goto degrade;
		}
		drop_probes(&post, 1);
	}

	entry->deferred_post_handler = false;
	if (make_probe(entry, initial, true, PATCH_TRAP_POLICY_FORCE, &single)) {
		if (enable_and_commit(&single, 1)) {
			entry->strategy = DW_PATCH_TRAP;
			return 0;
		}
		drop_probes(&single, 1);
	}

degrade:
	/*
	 * No jump or trap plan could be installed (e.g. a libpatch limitation at
	 * this site, or a failed overlapping patch for a relocated OLX
	 * instruction). Non-fatal: handle_seg_fault degrades the entry to
	 * single-stepping. Warn rather than abort over a recoverable failure.
	 */
	DW_LOG(WARNING, PATCH,
		   "Patching 0x%llx failed (origin 0x%llx); falling back to single-step.\n",
		   (unsigned long long)initial, (unsigned long long)entry->insn);
	entry->deferred_post_handler = false;
	entry->strategy = DW_PATCH_UNKNOWN;
	return -1;
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

	/*
	 * A patch request from the worker thread itself must not be queued: it
	 * would block forever waiting for the worker (us) to drain the queue.
	 * Patch synchronously instead of aborting.
	 */
	if (atomic_load_explicit(&worker_tid_set, memory_order_acquire) &&
	    pthread_equal(pthread_self(), worker_tid)) {
		DW_LOG(WARNING, PATCH,
			   "Patch requested from the worker thread; patching synchronously.\n");
		return patch_entry_sync(entry, safe_sites);
	}

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

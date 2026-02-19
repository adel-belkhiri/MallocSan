#ifndef DW_PATCH_H
#define DW_PATCH_H

#include <stdbool.h>
#include <stdint.h>

#include "dw-disassembly.h"

struct post_safe_site {
	uintptr_t addr;
	unsigned skipped_same_access;
};

struct post_safe_site_rb {
	struct post_safe_site entries[MAX_SAFE_SITE_COUNT];
	unsigned head;
	unsigned count;
};

/* Initialize libpatch runtime exactly once for all patching modes. */
void dw_patch_runtime_init(void);

/* Explicit worker lifecycle helpers. */
void dw_patch_worker_start(void);
void dw_patch_worker_stop(void);

/*
 * Queue a patch request to the dedicated patching thread and wait for
 * completion.
 *
 * Returns 0 on success, negative on failure.
 */
int dw_patch_entry(struct insn_entry *entry, const struct post_safe_site_rb *safe_sites);

#endif /* DW_PATCH_H */

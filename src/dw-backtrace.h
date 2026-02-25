#ifndef DW_BACKTRACE_H
#define DW_BACKTRACE_H

#include <stddef.h>
#include <stdint.h>

enum dw_backtrace_kind {DW_BT_MSAN = 0, DW_BT_APP};

#define MAX_FUNC_NAME_LEN 256

struct func_cache_entry {
	uintptr_t start_ip, end_ip;
	char func_name[MAX_FUNC_NAME_LEN];
};

struct patch_exec_context;

extern __thread void *bt_signal_seed;

void dw_bt_seed_patch_set(const struct patch_exec_context *ctx);
void dw_bt_seed_patch_clear(void);

void dw_backtrace(int fd, enum dw_backtrace_kind kind);

void dw_lookup_symbol(uintptr_t ip, char *proc_name, size_t name_len, uintptr_t *start_out,
					  uintptr_t *end_out);

struct func_cache_entry *func_cache_lookup(uintptr_t ip);
struct func_cache_entry *func_cache_insert(uintptr_t start_ip, uintptr_t end_ip,
										   const char *func_name);

#endif /* DW_BACKTRACE_H */

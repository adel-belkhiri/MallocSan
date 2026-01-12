#ifndef DW_BACKTRACE_H
#define DW_BACKTRACE_H

#include <stddef.h>
#include <stdint.h>

enum dw_backtrace_kind {DW_BT_MSAN = 0, DW_BT_APP};

struct patch_exec_context;

extern __thread void *bt_signal_seed;

void dw_bt_seed_patch_set(const struct patch_exec_context *ctx);
void dw_bt_seed_patch_clear(void);

void dw_backtrace(int fd, enum dw_backtrace_kind kind);

void dw_lookup_symbol(uintptr_t ip, char *proc_name, size_t name_len, uint64_t *offset_out);

#endif /* DW_BACKTRACE_H */

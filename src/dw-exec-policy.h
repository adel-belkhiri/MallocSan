#ifndef DW_EXEC_POLICY_H
#define DW_EXEC_POLICY_H

#include <stdbool.h>
#include <stdint.h>

void init_main_object_range(void);
bool dw_main_object_range_available(void);
bool dw_addr_in_main_object(uintptr_t addr);

void dw_exec_policy_init(void);
bool dw_patch_disabled_for_addr(uintptr_t addr);

#endif /* DW_EXEC_POLICY_H */

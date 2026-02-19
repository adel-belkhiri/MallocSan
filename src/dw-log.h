#ifndef DW_LOG_H
#define DW_LOG_H

#include <stdbool.h>
#include <stdint.h>

#include "dw-backtrace.h"

enum dw_log_level {ERROR=0, WARNING, INFO, DEBUG, TRACE};

enum dw_log_category_name {PROTECT=0, DISASSEMBLY, MAIN, PATCH, WRAP};

struct app_backtrace_seed {
	int valid;

	uintptr_t pc;
	unsigned len;

	uintptr_t rsp;
	uintptr_t rbp;
};

unsigned string_copy(char *dest, char *src, size_t n);

void backtrace_from_ucontext_pc(int fd, uintptr_t start_pc, unsigned len);
/* Writes the message to a buffer and then writes its content to fd */
void dw_fprintf(int fd, const char *fmt, ...);

/* Set the log level for all categories */
void dw_set_log_level(enum dw_log_level level);

/* Check if logging is enabled for that level and topic */
bool dw_log_enabled(enum dw_log_level level, enum dw_log_category_name topic);

/*
 * Check the log level and category and writes the message to a buffer,
 * then writes its content to file descriptor 2 (stderr). We only log
 * messages when enabled, avoiding unnecessary formatting work.
 */
void __dw_log_internal(enum dw_log_level level, enum dw_log_category_name topic, enum dw_backtrace_kind bt_kind, const char *fmt, ...);
#define DW_LOG(lvl, topic, ...)                       \
	do {                                              \
		if (dw_log_enabled((lvl), (topic)))           \
			__dw_log_internal((lvl), (topic), DW_BT_MSAN, __VA_ARGS__);      \
	} while (0)

#define DW_LOG2(lvl, topic, bt_kind, ...)                     \
	do {                                                      \
		if (dw_log_enabled((lvl), (topic)))                   \
			__dw_log_internal((lvl), (topic), (bt_kind), __VA_ARGS__); \
	} while (0)

#define DW_LOG_APP(lvl, topic, ...) DW_LOG2((lvl), (topic), DW_BT_APP, __VA_ARGS__)

#endif /* DW_LOG_H */

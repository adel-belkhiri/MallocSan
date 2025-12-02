#ifndef DW_LOG_H
#define DW_LOG_H

#include <stdbool.h>

enum dw_log_level {ERROR=0, WARNING, INFO, DEBUG};

enum dw_log_category_name {PROTECT=0, DISASSEMBLY, MAIN, WRAP};

/*
 * Check the log level and category and writes the message to a buffer,
 * then writes its content to file descriptor 2 (stderr)
 */
void dw_log(enum dw_log_level level, enum dw_log_category_name topic, const char *fmt, ...);

/* Writes the message to a buffer and then writes its content to fd */
void dw_fprintf(int fd, const char *fmt, ...);

/* Set the log level for all categories */
void dw_set_log_level(enum dw_log_level level);

/* Check if logging is enabled for that level and topic */
bool dw_log_enabled(enum dw_log_level level, enum dw_log_category_name topic);

/* Only logs messages when enabled, avoiding unnecessary formatting work */
#define DW_LOG(lvl, topic, ...)                       \
	do {                                              \
		if (dw_log_enabled((lvl), (topic)))           \
			dw_log((lvl), (topic), __VA_ARGS__);      \
	} while (0)

#endif /* DW_LOG_H */

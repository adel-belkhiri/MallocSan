#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "dw-log.h"
#include "dw-backtrace.h"

extern int dw_vsnprintf(char* s, size_t count, const char* format, va_list arg);

char* dw_log_level_name[] = {"ERROR", "WARNING", "INFO", "DEBUG", "TRACE"};

struct dw_log_category {
	char *name;
	int active;
	enum dw_log_level level;
	int backtrace_level;
};

struct dw_log_category dw_log_categories[] = {{"protect", 1, ERROR, 1},
											  {"disassembly", 1, ERROR, 1},
											  {"main", 1, ERROR, 1},
											  {"wrap", 1, ERROR, 1},
											  {"patch", 1, ERROR, 1}};
static bool dump_memory_map_enabled = false;

inline unsigned string_copy(char *dest, char *src, size_t n)
{
	if (n == 0)
		return 0;

	int i = 0;
	for (; i < (int)n - 1 && src[i] != 0; i++)
		dest[i] = src[i];

	dest[i] = 0;
	return (unsigned)i;
}

// We call directly write to avoid the wrappers.
ssize_t __write(int fd, const void *buf, size_t count);

static bool dw_log_v(enum dw_log_level level, enum dw_log_category_name topic,
				    const char *fmt, va_list args)
{
	char buffer[1024];
	char *cursor = buffer;
	unsigned nbc = 1024;

	// Write to a stack buffer and then call the low level write. We avoid
	// any malloc that glibc could do.
	int ret = string_copy(cursor, dw_log_level_name[level], nbc);
	nbc -= ret;
	cursor += ret;
	*cursor = ' ';
	nbc -= 1;
	cursor += 1;
	ret = string_copy(cursor, dw_log_categories[topic].name, nbc);
	nbc -= ret;
	cursor += ret;
	ret = string_copy(cursor, ": ", nbc);
	nbc -= ret;
	cursor += ret;

	// Then write the user supplied format and arguments
	ret = dw_vsnprintf(cursor, nbc, fmt, args);
	nbc -= ret;
	cursor += ret;
	__write(2, buffer, cursor - buffer);

	return true;
}

static inline void dump_memory_map(enum dw_log_level level, enum dw_log_category_name topic)
{
	static bool mapped = false;
	char buffer[1024];

	if (level > dw_log_categories[topic].backtrace_level)
		return;

	// The first time we print a memory map, this helps in debugging
	if (!mapped) {
		mapped = true;
		int fd = open("/proc/self/maps", O_RDONLY);
		int n = 0;
		while (fd >= 0 && (n = read(fd, buffer, sizeof(buffer))) > 0)
			__write(2, buffer, n);
		if (fd >= 0)
			close(fd);
	}
}

void dw_set_dump_memory_map(bool enabled)
{
	dump_memory_map_enabled = enabled;
}

void __dw_log_internal(enum dw_log_level level, enum dw_log_category_name topic, enum dw_backtrace_kind bt_kind, const char *fmt, ...)
{
	va_list args;

	if (dump_memory_map_enabled)
		dump_memory_map(level, topic);

	va_start(args, fmt);
	dw_log_v(level, topic, fmt, args);
	va_end(args);

	if (level <= dw_log_categories[topic].backtrace_level)
		dw_backtrace(2, bt_kind);

	// If the log level is "ERROR", this is fatal and the program exits
	if (level == ERROR)
		abort(); //exit(1);
}

/*
 * Simple fprintf facility that should not use malloc
 */
void dw_fprintf(int fd, const char *fmt, ...)
{
	char buffer[1024];

	va_list args;
	va_start(args, fmt);
	int ret = dw_vsnprintf(buffer, 1024, fmt, args);
	int bytes_to_write = (ret < 0) ? 0 : ((ret < 1024) ? ret : 1023);
	__write(fd, buffer, bytes_to_write);
	va_end(args);
}

/*
 * Set a new log level, the same for all categories.
 * We could eventually allow setting a different level for each category
 */
void dw_set_log_level(enum dw_log_level level)
{
	if (level < ERROR || level > TRACE)
		return;

	for (int i = 0; i < (sizeof(dw_log_categories) / sizeof(dw_log_categories[0])); i++)
		dw_log_categories[i].level = level;
}

inline bool dw_log_enabled(enum dw_log_level level, enum dw_log_category_name topic)
{
	if (level < ERROR || level > TRACE)
		return false;
	return dw_log_categories[topic].active && level <= dw_log_categories[topic].level;
}

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "dw-log.h"

char* dw_log_level_name[] = {"ERROR", "WARNING", "INFO", "DEBUG"};

struct dw_log_category {
	char *name;
	int active;
	enum dw_log_level level;
	int backtrace_level;
};

struct dw_log_category dw_log_categories[] = {
	{"protect", 1, ERROR, 1},
	{"disassembly", 1, ERROR, 1},
	{"main", 1, ERROR, 1},
	{"wrap", 1, ERROR, 1}
};

// We call directly write to avoid the wrappers.
ssize_t __write(int fd, const void *buf, size_t count);

#define UNW_LOCAL_ONLY
#include <libunwind.h>

void dw_backtrace(int fd)
{
	unw_cursor_t cursor;
	unw_context_t context;

	unw_getcontext(&context);
	unw_init_local(&cursor, &context);

	while (unw_step(&cursor) > 0) {
		unw_word_t offset, pc;
		unw_get_reg(&cursor, UNW_REG_IP, &pc);
		if (pc == 0)
			break;

		char proc_name[256];
		if (unw_get_proc_name(&cursor, proc_name, sizeof(proc_name), &offset) == 0) {
			dw_fprintf(fd, "0x%lx: (%s+0x%lx)\n", pc, proc_name, offset);
		} else {
			dw_fprintf(fd, "0x%lx: -- No symbol \n", pc);
		}
	}
}

static unsigned string_copy(char *dest, char *src, size_t n)
{
	int i = 0;
	for (; i < n - 1 && src[i] != 0; i++)
		dest[i] = src[i];

	dest[i] = 0;
	return i;
}

void dw_log(enum dw_log_level level, enum dw_log_category_name topic, const char *fmt, ...)
{
	char buffer[1024];
	static bool mapped = false;
	char *cursor = buffer;
	unsigned nbc = 1024;

	// This message is not within the log level, return without printing it
	if (dw_log_categories[topic].active == 0 || level > dw_log_categories[topic].level)
		return;

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
	va_list args;
	va_start(args, fmt);
	ret = vsnprintf(cursor, nbc, fmt, args);
	nbc -= ret;
	cursor += ret;
	__write(2, buffer, cursor - buffer);
	va_end(args);

	// The first time we print a memory map, this helps in debugging
	if (level <= dw_log_categories[topic].backtrace_level) {
		if (!mapped) {
			mapped = true;
			int fd = open("/proc/self/maps", O_RDONLY);
			int n = 0;
			while ((n = read(fd, buffer, 1024)) > 0) {
				__write(2, buffer, n);
			}
			close(fd);
		}
		dw_backtrace(2);
	}

	// If the log level is "ERROR", this is fatal and the program exits
	// if(level == ERROR) exit(1);
	if (level == ERROR)
		abort();
}

/*
 * Simple fprintf facility that should not use malloc
 */
void dw_fprintf(int fd, const char *fmt, ...)
{
	char buffer[1024];

	va_list args;
	va_start(args, fmt);
	int ret = vsnprintf(buffer, 1024, fmt, args);
	__write(fd, buffer, ret);
	va_end(args);
}

/*
 * Set a new log level, the same for all categories.
 * We could eventually allow setting a different level for each category
 */
void dw_set_log_level(enum dw_log_level level)
{
	if (level < ERROR || level > DEBUG)
		return;

	for (int i = 0; i < (sizeof(dw_log_categories) / sizeof(dw_log_categories[0])); i++)
		dw_log_categories[i].level = level;
}

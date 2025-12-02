#define _GNU_SOURCE

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <libintl.h>
#include <limits.h>
#include <linux/openat2.h>
#include <locale.h>
#include <malloc.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>

#include "dw-log.h"
#include "dw-printf.h"
#include "dw-protect.h"
#include "dw-wrap-glibc.h"

extern void signal_protected(int sig, siginfo_t *info, void *context);

/*
 * We wrap all important calls to glibc to insure that pointers are checked and
 * unprotected before being used internally in glibc or passed to system calls.
 *
 * For each pointer argument, we need to check, unprotect, call the glibc
 * function and reprotect. If a glibc function calls another nested glibc
 * function, there is no need to do further processing, because the arguments
 * should have already been checked and unprotected.

 * Intercepting common glibc functions to check access and remove the protection
 * from pointers is essential for system calls because otherwise they will fail.
 * It is also useful for utility functions, as it can simplify the access check
 * (a single one instead of multiple ones) and avoid some functions that may
 * perform tricky pointer arithmetic (e.g. memcpy / memmove).
 *
 * Only a minimal set of wrappers was implemented, it is far from being
 * complete. Moreover, some of the wrappers are incomplete. For instance, for
 * the execvpe and similar functions, the argv and envp arrays are unprotected,
 * but not the pointers contained within. This would require allocating a new
 * array where to copy the unprotected pointers.
 */

/*
 * Check that we can get the desired symbol.
 */
void *dlsym_check(void *restrict handle, const char *restrict symbol)
{
	void *ret = dlsym(handle, symbol);
	if (ret == NULL)
		DW_LOG(WARNING, WRAP, "Symbol %s not found\n", symbol);

	return ret;
}
/*
 * Size of argv arguments in execve and similar functions.
 */
static size_t arglen(char *const argv[])
{
	size_t i = 0;
	for (; argv[i] != NULL; i++)
		;
	return sizeof(char *) * (i + 1);
}

/*
 * Have our own strlen, not called with tainted pointers, that will
 * not be instrumented by libpatch.
 */
size_t dw_strlen(const char *s)
{
	const char *cursor;
	for (cursor = s; *cursor != 0; cursor++)
		;
	return (size_t) (cursor - s);
}

/* Declare all the pointers to the original libc functions */
static char* (*libc_strchr)(const char *s, int c);
static char* (*libc_strrchr)(const char *s, int c);
static int (*libc_strcmp)(const char *s1, const char *s2);
static int (*libc_strcasecmp)(const char *s1, const char *s2);
static int (*libc_strncmp)(const char *s1, const char *s2, size_t n);
static int (*libc_strncasecmp)(const char *s1, const char *s2, size_t n);
static int (*libc_fputs)(const char *restrict s, FILE *restrict stream);
static int (*libc_puts)(const char *s);
static size_t (*libc_strlen)(const char *s);
static int (*libc_open)(const char *pathname, int flags, ...);
static int (*libc_open64)(const char *pathname, int flags, ...);
static int (*libc_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*libc_creat)(const char *pathname, mode_t mode);
static int (*libc_access)(const char *pathname, int mode);
static char* (*libc_getcwd)(char *buf, size_t size);
static ssize_t (*libc_getrandom)(void *buf, size_t buflen, unsigned int flags);
static int (*libc_stat)(const char *restrict pathname, struct stat *restrict statbuf);
static int (*libc_fstat)(int fd, struct stat *statbuf);
static int (*libc_lstat)(const char *restrict pathname, struct stat *restrict statbuf);
static int (*libc_fstatat)(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags);
static int (*libc_stat64)(const char *restrict pathname, struct stat64 *restrict statbuf);
static int (*libc_fstat64)(int fd, struct stat64 *statbuf);
static size_t (*libc_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static size_t (*libc_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static FILE* (*libc_fopen)(const char *restrict pathname, const char *restrict mode);
static FILE* (*libc_fopen64)(const char *restrict pathname, const char *restrict mode);
static ssize_t (*libc_pread)(int fd, void *buf, size_t count, off_t offset);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count, off_t offset);
static ssize_t (*libc_read)(int fd, void *buf, size_t count);
extern ssize_t __read(int fd, void *buf, size_t count);
static ssize_t (*libc_write)(int fd, const void *buf, size_t count);
extern ssize_t libc_real_write(int fd, const void *buf, size_t count);
static int (*libc_statfs)(const char *path, struct statfs *buf);
static int (*libc_fstatfs)(int fd, struct statfs *buf);
static ssize_t (*libc_getdents64)(int fd, void *dirp, size_t count);
static DIR* (*libc_opendir)(const char *name);
static int (*libc_bcmp)(const void *s1, const void *s2, size_t n);
static void (*libc_bcopy)(const void *src, void *dest, size_t n);
static void (*libc_bzero)(void *s, size_t n);
static void* (*libc_memccpy)(void *dest, const void *src, int c, size_t n);
static void* (*libc_memchr)(const void *s, int c, size_t n);
static int (*libc_memcmp)(const void *s1, const void *s2, size_t n);
static void* (*libc_memcpy)(void *dest, const void *src, size_t n);
static void* (*libc_memcpy_chk)(void *dest, const void *src, size_t len, size_t destlen);
static void* (*libc_memfrob)(void *s, size_t n);
static void* (*libc_memmem)(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
static void* (*libc_memmove)(void *dest, const void *src, size_t n);
static void* (*libc_memmove_chk)(void *dest, const void *src, size_t len, size_t destlen);
static void* (*libc_mempcpy)(void *restrict dest, const void *restrict src, size_t n);
static void* (*libc_memset)(void *s, int c, size_t n);
static void* (*libc_memset_chk)(void *s, int c, size_t n, size_t destlen);
static int (*libc_sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);
static char* (*libc_strcpy)(char *restrict dest, const char *src);
static void* (*libc_strcpy_chk)(void *dest, const void *src, size_t destlen);
static char* (*libc_strcat)(char *restrict dest, const char *src);
static char* (*libc_strcat_chk)(char *dest, const char *src, size_t destlen);
static char* (*libc_strncat_chk)(char *dest, const char *src, size_t n, size_t destlen);
static char* (*libc_strncpy)(char *restrict dest, const char *restrict src, size_t n);
static void* (*libc_strncpy_chk)(void *dest, const void *src, size_t n, size_t destlen);
static size_t (*libc_strspn)(const char *str1, const char *str2);
static char* (*libc_strstr)(const char *str1, const char *str2);
static size_t (*libc_strcspn)(const char *str1, const char *str2);
static wchar_t* (*libc_wmemmove)(wchar_t *dest, const wchar_t *src, size_t n);
static wchar_t* (*libc_wmempcpy)(wchar_t *restrict dest, const wchar_t *restrict src, size_t n);
static wchar_t* (*libc_wmemcpy)(wchar_t *restrict dest, const wchar_t *restrict src, size_t n);
static char* (*libc_gettext)(const char * msgid);
static char* (*libc_dgettext)(const char * domainname, const char * msgid);
extern char* __dgettext(const char * domainname, const char * msgid);
extern char* __dcgettext(const char * domainname, const char * msgid, int category);
static char* (*libc_ngettext)(const char *msgid, const char *msgid_plural, unsigned long int n);
static char* (*libc_dcngettext)(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category);
static char* (*libc_setlocale)(int category, const char *locale);
static char* (*libc_textdomain)(const char * domainname);
static int (*libc_execve)(const char *pathname, char *const argv[], char *const envp[]);
static int (*libc_execv)(const char *pathname, char *const argv[]);
static int (*libc_execvp)(const char *file, char *const argv[]);
static int (*libc_execvpe)(const char *file, char *const argv[], char *const envp[]);

static struct sigaction saved_sigsegv;
static bool saved_sigsegv_valid = false;
static struct sigaction saved_sigbus;
static bool saved_sigbus_valid = false;
static struct sigaction saved_sigtrap;
static bool saved_sigtrap_valid = false;

int dw_init_stubs = 0;
// size_t (*dw_strlen)(const char *s);

/*
 * Get the address for all the wrapped libc functions. Some of these functions
 * may get called very early. Therefore we do check for initialization right
 * before use with the iss() macro.
 */
void dw_init_syscall_stubs()
{
	libc_strlen = dw_strlen;
	libc_strchr = dlsym_check(RTLD_NEXT, "strchr");
	libc_strrchr = dlsym_check(RTLD_NEXT, "strrchr");
	libc_strcmp = dlsym_check(RTLD_NEXT, "strcmp");
	libc_strcasecmp = dlsym_check(RTLD_NEXT, "strcasecmp");
	libc_strncmp = dlsym_check(RTLD_NEXT, "strncmp");
	libc_strncasecmp = dlsym_check(RTLD_NEXT, "strncasecmp");
	libc_fputs = dlsym_check(RTLD_NEXT, "fputs");
	libc_puts = dlsym_check(RTLD_NEXT, "puts");
	libc_open = dlsym_check(RTLD_NEXT, "open");
	libc_open64 = dlsym_check(RTLD_NEXT, "open64");
	libc_openat = dlsym_check(RTLD_NEXT, "openat");
	libc_creat = dlsym_check(RTLD_NEXT, "creat");
	libc_access = dlsym_check(RTLD_NEXT, "access");
	libc_getcwd = dlsym_check(RTLD_NEXT, "getcwd");
	libc_getrandom = dlsym_check(RTLD_NEXT, "getrandom");
	libc_stat = dlsym_check(RTLD_NEXT, "stat");
	libc_fstat = dlsym_check(RTLD_NEXT, "fstat");
	libc_lstat = dlsym_check(RTLD_NEXT, "lstat");
	libc_fstatat = dlsym_check(RTLD_NEXT, "fstatat");
	libc_stat64 = dlsym_check(RTLD_NEXT, "stat64");
	libc_fstat64 = dlsym_check(RTLD_NEXT, "fstat64");
	libc_fread = dlsym_check(RTLD_NEXT, "fread");
	libc_fwrite = dlsym_check(RTLD_NEXT, "fwrite");
	libc_fopen = dlsym_check(RTLD_NEXT, "fopen");
	libc_fopen64 = dlsym_check(RTLD_NEXT, "fopen64");
	libc_pread = dlsym_check(RTLD_NEXT, "pread");
	libc_pwrite = dlsym_check(RTLD_NEXT, "pwrite");
	libc_read = __read; // dlsym_check(RTLD_NEXT, "read");
	libc_write = dlsym_check(RTLD_NEXT, "write");
	libc_statfs = dlsym_check(RTLD_NEXT, "statfs");
	libc_fstatfs = dlsym_check(RTLD_NEXT, "fstatfs");
	libc_getdents64 = dlsym_check(RTLD_NEXT, "getdents64");
	libc_bcmp = dlsym_check(RTLD_NEXT, "bcmp");
	libc_bcopy = dlsym_check(RTLD_NEXT, "bcopy");
	libc_bzero = dlsym_check(RTLD_NEXT, "bzero");
	libc_memccpy = dlsym_check(RTLD_NEXT, "memccpy");
	libc_memchr = dlsym_check(RTLD_NEXT, "memchr");
	libc_memcmp = dlsym_check(RTLD_NEXT, "memcmp");
	libc_memcpy = dlsym_check(RTLD_NEXT, "memcpy");
	libc_memcpy_chk = dlsym_check(RTLD_NEXT, "__memcpy_chk");
	libc_memfrob = dlsym_check(RTLD_NEXT, "memfrob");
	libc_memmem = dlsym_check(RTLD_NEXT, "memmem");
	libc_memmove = dlsym_check(RTLD_NEXT, "memmove");
	libc_memmove_chk = dlsym_check(RTLD_NEXT, "__memmove_chk");
	libc_mempcpy = dlsym_check(RTLD_NEXT, "mempcpy");
	libc_memset = dlsym_check(RTLD_NEXT, "memset");
	libc_memset_chk = dlsym_check(RTLD_NEXT, "__memset_chk");
	libc_sigaction = dlsym_check(RTLD_NEXT, "sigaction");
	libc_strcpy = dlsym_check(RTLD_NEXT, "strcpy");
	libc_strcpy_chk = dlsym_check(RTLD_NEXT, "__strcpy_chk");
	libc_strcat = dlsym_check(RTLD_NEXT, "strcat");
	libc_strcat_chk = dlsym_check(RTLD_NEXT, "__strcat_chk");
	libc_strncat_chk = dlsym_check(RTLD_NEXT, "__strncat_chk");
	libc_strncpy = dlsym_check(RTLD_NEXT, "strncpy");
	libc_strncpy_chk = dlsym_check(RTLD_NEXT, "__strncpy_chk");
	libc_strspn = dlsym_check(RTLD_NEXT, "strspn");
	libc_strcspn = dlsym_check(RTLD_NEXT, "strcspn");
	libc_strstr = dlsym_check(RTLD_NEXT, "strstr");
	libc_wmemmove = dlsym_check(RTLD_NEXT, "wmemmove");
	libc_wmempcpy = dlsym_check(RTLD_NEXT, "wmempcpy");
	libc_wmemcpy = dlsym_check(RTLD_NEXT, "wmemcpy");
	libc_gettext = dlsym_check(RTLD_NEXT, "gettext");
	libc_dgettext = __dgettext; // dlsym_check(RTLD_NEXT, "dgettext ");
	libc_ngettext = dlsym_check(RTLD_NEXT, "ngettext");
	libc_dcngettext = dlsym_check(RTLD_NEXT, "dcngettext");
	libc_setlocale = dlsym_check(RTLD_NEXT, "setlocale");
	libc_opendir = dlsym_check(RTLD_NEXT, "opendir");
	libc_textdomain = dlsym_check(RTLD_NEXT, "textdomain");
	libc_execve = dlsym_check(RTLD_NEXT, "execve");
	libc_execv = dlsym_check(RTLD_NEXT, "execv");
	libc_execvp = dlsym_check(RTLD_NEXT, "execvp");
	libc_execvpe = dlsym_check(RTLD_NEXT, "execvpe");
	dw_init_stubs = 1;
}

/* Make it shorter, every function calls those */
#define sin() dw_sin()
#define sout() dw_sout()

/*
 * Some applications and runtime environments (e.g., Fortran) might set their
 * own signal handlers. Therefore, we wrap glibc sigaction and signal functions to
 * prevent the overwriting of MallocSan's handlers (i.e., SIGSEGV, SIGBUS, and SIGTRAP),
 * which are critical for its operation.
 */
static inline bool monitor_signal(int signum)
{
	return signum == SIGSEGV || signum == SIGBUS || signum == SIGTRAP;
}

static inline void pick_saved(int signum, struct sigaction **saved, bool **valid)
{
	switch (signum)
	{
	case SIGSEGV:
		*saved = &saved_sigsegv;
		*valid = &saved_sigsegv_valid;
		break;

	case SIGBUS:
		*saved = &saved_sigbus;
		*valid = &saved_sigbus_valid;
		break;

	case SIGTRAP:
		*saved = &saved_sigtrap;
		*valid = &saved_sigtrap_valid;
		break;

	default:
		// We should not be here!
		*saved = NULL;
		*valid = NULL;
	}
}

bool dw_sigaction_get_saved(int signum, struct sigaction *sa)
{
	struct sigaction *saved;
	bool *valid;

	if (!monitor_signal(signum))
		return false;

	pick_saved(signum, &saved, &valid);
	if (!*valid)
		return false;

	*sa = *saved;
	return true;
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	sin();

	if (!monitor_signal(signum)) {
		int ret = libc_sigaction(signum, act, oldact);
		sout();
		return ret;
	}

	struct sigaction *saved;
	bool *valid;
	pick_saved(signum, &saved, &valid);

	// If act is NULL, we just return the old action as info
	if (oldact != NULL) {
		if (*valid) {
			*oldact = *saved;
		} else {
			memset(oldact, 0, sizeof(*oldact));
			oldact->sa_handler = SIG_DFL;
			sigemptyset(&oldact->sa_mask);
		}
	}

	if (act == NULL) {
		sout();
		return 0;
	}

	// If the signal is SIGTRAP, we allow setting it only once
	if (signum == SIGTRAP) {
		if (!*valid || act->sa_sigaction == saved->sa_sigaction ||
		    (void (*)(int)) act->sa_handler == (void (*)(int)) saved->sa_handler) {
			*saved = *act;
			*valid = true;
			int ret = libc_sigaction(signum, act, NULL);
			sout();
			return ret;
		}

		DW_LOG(WARNING, WRAP, "Blocked attempt to overwrite the SIGTRAP handler\n");
		int ret = libc_sigaction(signum, saved, NULL);
		sout();
		return ret;
	}

	// If the action carries out our SIGSEGV and SIGBUS handlers, we let it pass through
	if (act->sa_sigaction == signal_protected ||
	    (void (*)(int)) act->sa_handler == (void (*)(int)) signal_protected) {
		int ret = libc_sigaction(signum, act, NULL);
		sout();
		return ret;
	}

	// Otherwise, we save the new handler and replace it with our protected one
	if (!*valid) {
		*saved = *act;
		*valid = true;
	}

	DW_LOG(WARNING, WRAP,
		    "Blocked attempt to overwrite MallocSan %s handler\n", signum == SIGSEGV ? "SIGSEGV" : "SIGBUS");

	struct sigaction replacement = *act;
	replacement.sa_sigaction = signal_protected;
	replacement.sa_handler = (void (*)(int)) signal_protected;
	replacement.sa_flags |= SA_SIGINFO;

	int ret = libc_sigaction(signum, &replacement, NULL);
	sout();
	return ret;
}

sighandler_t signal(int signum, sighandler_t handler)
{
	struct sigaction act;
	struct sigaction oldact;

	sin();
	memset(&act, 0, sizeof(act));
	act.sa_handler = handler;
	sigemptyset(&act.sa_mask);

#ifdef SA_RESTART
	act.sa_flags = SA_RESTART;
#else
	act.sa_flags = 0;
#endif

	sout();
	if (sigaction(signum, &act, &oldact) < 0)
		return SIG_ERR;

	return oldact.sa_handler;
}

int dw_libc_sigaction(int signum, const struct sigaction *act)
{
	sin();
	int ret = libc_sigaction(signum, act, NULL);
	sout();
	return ret;
}

/*
 * For each tainted pointer passed to a wrapper, we could eventually check if it
 * is accessed properly, given the semantics of the function called and the
 * bounds of the pointed object. The replacements for libc functions for now
 * simply remove the taint before calling the replaced functions. In some cases,
 * the taint must be reapplied. For instance, the memccpy function copies a
 * string to a certain character then returns a pointer to that character. This
 * pointer may be derived from a tainted pointer and the taint must be carried
 * to it from the dest pointer.
 */

size_t strlen(const char *s) { sin(); size_t ret = libc_strlen(dw_unprotect((void *)s)); sout(); return ret; }

static inline void fputc_wrapper(char c, void *extra_arg)
{
	FILE *fp = (FILE *) extra_arg;
	fputc(c, fp);
}

static inline void dputc_wrapper(char c, void *extra_arg)
{
	int fd = (int) ((uintptr_t) extra_arg);
	libc_write(fd, &c, 1);
}

int __fprintf_chk(FILE *stream, int flag, const char *format, ...)
{
	va_list arg;
	va_start(arg, format);
	const int ret = vfctprintf(fputc_wrapper, (void *) stream, format, arg);
	va_end(arg);
	return ret;
}

int fprintf(FILE *stream, const char *format, ...)
{
	va_list arg;
	va_start(arg, format);
	const int ret = vfctprintf(fputc_wrapper, (void *) stream, format, arg);
	va_end(arg);
	return ret;
}

int dprintf(int fd, const char *format, ...)
{
	va_list arg;
	va_start(arg, format);
	const int ret = vfctprintf(dputc_wrapper, (void *) ((uintptr_t) fd), format, arg);
	va_end(arg);
	return ret;
}

int __printf_chk(int flag, const char *format, ...)
{
	va_list arg;
	va_start(arg, format);
	const int ret = vfctprintf(fputc_wrapper, (void *) stdout, format, arg);
	va_end(arg);
	return ret;
}

extern int dw_vsnprintf(char *restrict s, size_t n, const char *restrict fmt, va_list ap)
    __asm__("vsnprintf");

int __sprintf_chk(char *s, int flag, size_t os, const char *fmt, ...)
{
	va_list arg;
	va_start(arg, fmt);
	const int ret = dw_vsnprintf(s, os, fmt, arg);
	va_end(arg);
	return ret;
}

int __snprintf_chk(char *s, size_t maxlen, int flag, size_t os, const char *fmt, ...)
{
	va_list arg;
	va_start(arg, fmt);
	const int ret = dw_vsnprintf(s, os, fmt, arg);
	va_end(arg);
	return ret;
}

int __vsnprintf_chk(char *s, size_t maxlen, int flag, size_t os, const char *fmt, va_list ap)
{
	if (os == (size_t) -1 || os > maxlen)
		os = maxlen;
	return dw_vsnprintf(s, os, fmt, ap);
}

int vfprintf(FILE *restrict stream, const char *restrict format, va_list arg)
{
	return vfctprintf(fputc_wrapper, (void *) stream, format, arg);
}

int vdprintf(int fd, const char *restrict format, va_list arg)
{
	return vfctprintf(dputc_wrapper, (void *) ((uintptr_t) fd), format, arg);
}

int vasprintf(char **strp, const char *format, va_list ap)
{
	sin();

	char **nstrp = (char **)dw_unprotect((void *)strp);
	dw_check_access((void *)strp, sizeof(*strp));

	va_list ap2;
	va_copy(ap2, ap);
	int len = dw_vsnprintf(NULL, 0, format, ap2);
	va_end(ap2);

	if (len < 0)
	{
		*nstrp = NULL;
		sout();
		return -1;
	}

	char *buf = (char *)__libc_malloc((size_t)len + 1);
	if (buf == NULL)
	{
		*nstrp = NULL;
		sout();
		return -1;
	}

	(void)dw_vsnprintf(buf, (size_t)len + 1, format, ap);
	*nstrp = buf;

	sout();
	return len;
}

char *strchr(const char *s, int c) { sin(); char *ns = dw_unprotect((void *)s); dw_check_access((void *)s, libc_strlen(ns) + 1); char *ret = libc_strchr(ns, c); sout(); if(ret == NULL) return ret; return (char *)dw_reprotect(ret, s); }
char *strrchr(const char *s, int c) { sin(); char *ns = dw_unprotect((void *)s); dw_check_access((void *)s, libc_strlen(ns) + 1); char *ret = libc_strrchr(ns, c); sout(); if(ret == NULL) return ret; return (char *)dw_reprotect(ret, s); }
int strcmp(const char *s1, const char *s2) { sin(); char *ns1 = dw_unprotect((void *)s1); dw_check_access((void *)s1, libc_strlen(ns1) + 1); char *ns2 = dw_unprotect((void *)s2); dw_check_access((void *)s2, libc_strlen(ns2) + 1); int ret = libc_strcmp(ns1, ns2); sout(); return ret; }
int strcasecmp(const char *s1, const char *s2) { sin(); char *ns1 = dw_unprotect((void *)s1); dw_check_access((void *)s1, libc_strlen(ns1) + 1); char *ns2 = dw_unprotect((void *)s2); dw_check_access((void *)s2, libc_strlen(ns2) + 1); int ret = libc_strcasecmp(ns1, ns2); sout(); return ret; }
int strncmp(const char *s1, const char *s2, size_t n) { sin(); char *ns1 = dw_unprotect((void *)s1); dw_check_access((void *)s1, MIN(n, libc_strlen(ns1) + 1)); char *ns2 = dw_unprotect((void *)s2); dw_check_access((void *)s2, MIN(n, libc_strlen(ns2) + 1)); int ret = libc_strncmp(ns1, ns2, n); sout(); return ret; }
int strncasecmp(const char *s1, const char *s2, size_t n) { sin(); char *ns1 = dw_unprotect((void *)s1); dw_check_access((void *)s1, MIN(n, libc_strlen(ns1) + 1)); char *ns2 = dw_unprotect((void *)s2); dw_check_access((void *)s2, MIN(n, libc_strlen(ns2) + 1)); int ret = libc_strncasecmp(ns1, ns2, n); sout(); return ret; }
int fputs(const char *restrict s, FILE *restrict stream) { sin(); char *ns = dw_unprotect((void *)s); dw_check_access((void *)s, libc_strlen(ns) + 1); int ret = libc_fputs(ns, stream); sout(); return ret; }
int puts(const char *s) { sin(); char *ns = dw_unprotect((void *)s); dw_check_access((void *)s, libc_strlen(ns) + 1); int ret = libc_puts(ns); sout(); return ret; }

// Open can take 2 or 3 arguments, we handle it just like glibc does it internally.
int open(const char *pathname, int flags, ...)
{
	sin();
	mode_t mode = 0;
	if (__OPEN_NEEDS_MODE(flags)) {
		va_list arg;
		va_start(arg, flags);
		mode = va_arg(arg, mode_t);
		va_end(arg);
	}
	char *npathname = dw_unprotect((void *) pathname);
	dw_check_access((void *) pathname, libc_strlen(npathname) + 1);
	int ret = libc_open(npathname, flags, mode);
	sout();
	return ret;
}


int open64(const char *pathname, int flags, ...)
{
	sin();
	mode_t mode = 0;
	if (__OPEN_NEEDS_MODE(flags))
	{
		va_list arg;
		va_start(arg, flags);
		mode = va_arg(arg, mode_t);
		va_end(arg);
	}
	char *npathname = dw_unprotect((void *)pathname);
	dw_check_access((void *)pathname, libc_strlen(npathname) + 1);
	int ret;
	if (libc_open64)
		ret = libc_open64(npathname, flags, mode);
	else
		ret = libc_open(npathname, flags, mode);
	sout();
	return ret;
}

FILE *fopen(const char *restrict pathname, const char *restrict mode)
{
	sin();
	char *npathname = dw_unprotect((void *)pathname);
	dw_check_access((void *)pathname, libc_strlen(npathname) + 1);
	char *nmode = dw_unprotect((void *)mode);
	dw_check_access((void *)mode, libc_strlen(nmode) + 1);
	FILE *ret = libc_fopen ? libc_fopen(npathname, nmode) : NULL;
	sout();
	return ret;
}

FILE *fopen64(const char *restrict pathname, const char *restrict mode)
{
	sin();
	char *npathname = dw_unprotect((void *)pathname);
	dw_check_access((void *)pathname, libc_strlen(npathname) + 1);
	char *nmode = dw_unprotect((void *)mode);
	dw_check_access((void *)mode, libc_strlen(nmode) + 1);
	FILE *ret = NULL;
	if (libc_fopen64)
		ret = libc_fopen64(npathname, nmode);
	else if (libc_fopen)
		ret = libc_fopen(npathname, nmode);
	sout();
	return ret;
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
	sin();
	mode_t mode = 0;
	if (__OPEN_NEEDS_MODE(flags)) {
		va_list arg;
		va_start(arg, flags);
		mode = va_arg(arg, mode_t);
		va_end(arg);
	}
	char *npathname = dw_unprotect((void *) pathname);
	dw_check_access((void *) pathname, libc_strlen(npathname) + 1);
	int ret = libc_openat(dirfd, npathname, flags, mode);
	sout();
	return ret;
}

int creat(const char *pathname, mode_t mode) { sin(); char *npathname = dw_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); int ret = libc_creat(npathname, mode); sout(); return ret; }
int access(const char *pathname, int mode) { sin(); char *npathname = dw_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); int ret = libc_access(npathname, mode); sout(); return ret; }
char *getcwd(char *buf, size_t size) { sin(); char * nbuf = dw_unprotect((void *)buf); dw_check_access((void *)buf, size); char *ret = libc_getcwd(nbuf, size); sout(); if(ret == nbuf) return buf; return ret; }
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) { sin(); dw_check_access((void *)buf, buflen); ssize_t ret = libc_getrandom(dw_unprotect(buf), buflen, flags); sout(); return ret; }
int stat(const char *restrict pathname, struct stat *restrict statbuf) { sin(); char *npathname = dw_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)statbuf, sizeof(struct stat)); int ret = libc_stat(npathname, (struct stat *)dw_unprotect((void *)statbuf)); sout(); return ret; }
int stat64(const char *restrict pathname, struct stat64 *restrict statbuf) { sin(); char *npathname = dw_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)statbuf, sizeof(struct stat64)); int ret = libc_stat64 ? libc_stat64(npathname, (struct stat64 *)dw_unprotect((void *)statbuf)) : libc_stat(npathname, (struct stat *)dw_unprotect((void *)statbuf)); sout(); return ret; }
int fstat(int fd, struct stat *statbuf) { sin(); dw_check_access((void *)statbuf, sizeof(struct stat)); int ret = libc_fstat(fd, (struct stat *)dw_unprotect(statbuf)); sout(); return ret; }
int fstat64(int fd, struct stat64 *statbuf) { sin(); dw_check_access((void *)statbuf, sizeof(struct stat64)); int ret = libc_fstat64 ? libc_fstat64(fd, (struct stat64 *)dw_unprotect(statbuf)) : libc_fstat(fd, (struct stat *)dw_unprotect(statbuf)); sout(); return ret; }
int lstat(const char *restrict pathname, struct stat *restrict statbuf) { sin(); char *npathname = dw_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)statbuf, sizeof(struct stat)); int ret = libc_lstat(npathname, (struct stat *)dw_unprotect((void *)statbuf)); sout(); return ret; }
int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags) { sin(); char *npathname = dw_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)statbuf, sizeof(struct stat)); int ret = libc_fstatat(dirfd, npathname, (struct stat *)dw_unprotect((void *)statbuf), flags); sout(); return ret; }

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) { sin(); dw_check_access(ptr, size * nmemb); size_t ret = libc_fread(dw_unprotect(ptr), size, nmemb, stream); sout(); return ret; }
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) { sin(); dw_check_access(ptr, size * nmemb); size_t ret = libc_fwrite((const void *)dw_unprotect(ptr), size, nmemb, stream); sout(); return ret; }
ssize_t pread(int fd, void *buf, size_t count, off_t offset) { sin(); dw_check_access(buf, count); ssize_t ret = libc_pread(fd, dw_unprotect(buf), count, offset); sout(); return ret; }
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) { sin(); dw_check_access(buf, count); ssize_t ret = libc_pwrite(fd, (const void *)dw_unprotect(buf), count, offset); sout(); return ret; }
ssize_t read(int fd, void *buf, size_t count) { sin(); dw_check_access(buf, count); ssize_t ret = libc_read(fd, dw_unprotect(buf), count); sout(); return ret; }
ssize_t write(int fd, const void *buf, size_t count) { sin(); dw_check_access(buf, count); ssize_t ret = libc_write(fd, (const void *)dw_unprotect(buf), count); sout(); return ret; }
int statfs(const char *path, struct statfs *buf) { sin(); char *npath = dw_unprotect((void *)path); dw_check_access((void *)path, libc_strlen(npath) + 1); dw_check_access((void *)buf, sizeof(struct statfs)); int ret = libc_statfs(npath, (struct statfs *)dw_unprotect((void *)buf)); sout(); return ret; }
int fstatfs(int fd, struct statfs *buf) { sin(); dw_check_access((void *)buf, sizeof(struct statfs)); int ret = libc_fstatfs(fd, (struct statfs *)dw_unprotect((void *)buf)); sout(); return ret; }
ssize_t getdents64(int fd, void *dirp, size_t count) { sin(); dw_check_access(dirp, count); ssize_t ret = libc_getdents64(fd, dw_unprotect(dirp), count); sout(); return ret; }
DIR *opendir(const char *name) { sin(); char *nname = dw_unprotect((void *)name); dw_check_access((void *)name, libc_strlen(nname) + 1); DIR *ret = libc_opendir(nname); sout(); return ret; }
int bcmp(const void *s1, const void *s2, size_t n) { sin(); dw_check_access(s1, n); dw_check_access(s2, n); int ret = libc_bcmp((const void *)dw_unprotect(s1), (const void *)dw_unprotect(s2), n); sout(); return ret; }
void bcopy(const void *src, void *dest, size_t n) { sin(); dw_check_access(src, n); dw_check_access(dest, n); libc_bcopy((const void *)dw_unprotect(src), (void *)dw_unprotect(dest), n); sout(); }
void bzero(void *s, size_t n) { sin(); dw_check_access(s, n); libc_bzero((void *)dw_unprotect(s), n); sout(); }

void *memccpy(void *dest, const void *src, int c, size_t n) { sin(); dw_check_access(dest, n); dw_check_access(src, n); void *ret = libc_memccpy((void *) dw_unprotect(dest), (const void *) dw_unprotect(src), c, n); sout(); if (ret == NULL) return ret; return (void *) dw_reprotect(ret, dest); }
void *memchr(const void *s, int c, size_t n) { sin(); dw_check_access(s, n); void *ret = libc_memchr((const void *) dw_unprotect(s), c, n); sout(); if (ret == NULL) return ret; return (void *) dw_reprotect(ret, s); }
int memcmp(const void *s1, const void *s2, size_t n) { sin(); dw_check_access(s1, n); dw_check_access(s2, n); int ret = libc_memcmp((const void *)dw_unprotect(s1), (const void *)dw_unprotect(s2), n); sout(); return ret; }
void *memcpy(void *dest, const void *src, size_t n) { sin(); dw_check_access(dest, n); dw_check_access(src, n); libc_memcpy((void *)dw_unprotect(dest), (const void *)dw_unprotect(src), n); sout(); return dest; }
void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) { sin(); dw_check_access(dest, destlen); dw_check_access(src, len); libc_memcpy_chk((void *)dw_unprotect(dest), (const void *)dw_unprotect(src), len, destlen);sout(); return dest; }
// void *memfrob(void *s, size_t n) { sin(); return libc_memfrob(void *s, size_t n); }
void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) { sin(); dw_check_access(haystack, haystacklen); dw_check_access(needle, needlelen); void *ret = libc_memmem((const void *) dw_unprotect(haystack), haystacklen, (const void *) dw_unprotect(needle), needlelen); sout(); if (ret == NULL) return ret; return (void *) dw_reprotect(ret, haystack); }

void *memmove(void *dest, const void *src, size_t n) { sin(); dw_check_access(dest, n); dw_check_access(src, n); libc_memmove((void *)dw_unprotect(dest), (void *)dw_unprotect(src), n); sout(); return dest; }
void *__memmove_chk(void *dest, const void *src, size_t len, size_t destlen) { sin(); dw_check_access(dest, destlen); dw_check_access(src, len); void *ret = libc_memmove_chk(dw_unprotect(dest), dw_unprotect(src), len, destlen); sout(); return ret; }
void *mempcpy(void *restrict dest, const void *restrict src, size_t n) { sin(); dw_check_access(dest, n); dw_check_access(src, n); libc_mempcpy((void *)dw_unprotect(dest), (void *)dw_unprotect(src), n); sout(); return dest; }
void *memset(void *s, int c, size_t n) { sin(); dw_check_access(s, n); libc_memset((void *)dw_unprotect(s), c, n); sout(); return s; }
void *__memset_chk(void *s, int c, size_t n, size_t destlen) { sin(); dw_check_access(s, destlen); void *ret = libc_memset_chk(dw_unprotect(s), c, n, destlen); sout(); return ret; }
char *strcpy(char *restrict dest, const char *src) { sin(); char *ndest = dw_unprotect((void *)dest); char *nsrc = dw_unprotect((void *)src); size_t len = libc_strlen(nsrc) + 1; dw_check_access(dest, len); dw_check_access(src, len); libc_strcpy(ndest, nsrc); sout(); return dest;}
char *__strcpy_chk(char *dest, const char *src, size_t destlen) { sin(); size_t srclen = libc_strlen(dw_unprotect(src)) + 1; dw_check_access(dest, destlen); dw_check_access(src, srclen); char *ret = libc_strcpy_chk(dw_unprotect(dest), dw_unprotect(src), destlen); sout(); return ret; }
char *strcat(char *restrict dest, const char *src) { sin(); char *ndest = dw_unprotect((void *)dest); char *nsrc = dw_unprotect((void *)src); size_t dst_len = libc_strlen(ndest); size_t src_len = libc_strlen(nsrc); dw_check_access(dest, dst_len + src_len + 1); dw_check_access(src, src_len + 1); libc_strcat(ndest, nsrc); sout(); return dest;}
char *__strcat_chk(char *dest, const char *src, size_t destlen) { sin(); size_t srclen = libc_strlen(dw_unprotect(src)) + 1; dw_check_access(dest, destlen); dw_check_access(src, srclen); char *ret = libc_strcat_chk(dw_unprotect(dest), dw_unprotect(src), destlen); sout(); return ret; }
char *__strncat_chk(char *dest, const char *src, size_t n, size_t destlen) { sin(); size_t srclen = libc_strlen(dw_unprotect(src)) + 1; dw_check_access(dest, destlen); dw_check_access(src, srclen < n ? srclen : n); char *ret = libc_strncat_chk(dw_unprotect(dest), dw_unprotect(src), n, destlen); sout(); return ret; }
char *strncpy(char *restrict dest, const char *restrict src, size_t n) { sin(); char *nsrc = dw_unprotect((void *)src); size_t len = libc_strlen(nsrc) + 1; dw_check_access(dest, n); dw_check_access(src, len < n ? len : n); libc_strncpy(dw_unprotect(dest), nsrc, n); sout(); return dest; }
char *__strncpy_chk(char *dest, const char *src, size_t n, size_t destlen) { sin(); size_t srclen = libc_strlen(dw_unprotect(src)) + 1; dw_check_access(dest, destlen); dw_check_access(src, srclen < n ? srclen : n); char *ret = libc_strncpy_chk(dw_unprotect(dest), dw_unprotect(src), n, destlen);sout(); return ret; }
size_t strspn(const char *str1, const char *str2) { sin(); char *ns = dw_unprotect((void *)str1); char *nstr2 = dw_unprotect((void *)str2); dw_check_access((void *)str1, libc_strlen(ns) + 1); dw_check_access((void *)str2, libc_strlen(nstr2) + 1); size_t ret = libc_strspn(ns, nstr2); sout(); return ret; }
size_t strcspn(const char *str1, const char *str2) { sin(); char *ns = dw_unprotect((void *)str1); char *nstr2 = dw_unprotect((void *)str2); dw_check_access((void *)str1, libc_strlen(ns) + 1); dw_check_access((void *)str2, libc_strlen(nstr2) + 1); size_t ret = libc_strcspn(ns, nstr2); sout(); return ret; }
char *strstr(const char *str1, const char *str2) { sin(); char *nstr1 = dw_unprotect((void *)str1); char *nstr2 = dw_unprotect((void *)str2); dw_check_access((void *)str1, libc_strlen(nstr1) + 1); dw_check_access((void *)str2, libc_strlen(nstr2) + 1); char *ret = libc_strstr(nstr1, nstr2); sout(); if (ret == NULL) return ret; return (char *) dw_reprotect(ret, str1); }
wchar_t *wmemmove(wchar_t *dest, const wchar_t *src, size_t n) { sin(); dw_check_access(dest, n * sizeof(wchar_t)); dw_check_access(src, n * sizeof(wchar_t)); libc_wmemmove((wchar_t *)dw_unprotect(dest), (wchar_t *)dw_unprotect(src), n); sout(); return dest; }
wchar_t *wmempcpy(wchar_t *restrict dest, const wchar_t *restrict src, size_t n) { sin(); dw_check_access(dest, n * sizeof(wchar_t)); dw_check_access(src, n * sizeof(wchar_t)); wchar_t *ret = libc_wmempcpy((wchar_t *) dw_unprotect(dest), (wchar_t *) dw_unprotect(src), n); sout(); return (wchar_t *) dw_reprotect(ret, dest); }

/* libintl define macros with same functions' names when optimization is enabled. */
#ifdef gettext
#  undef gettext
#endif
#ifdef dgettext
#  undef dgettext
#endif
#ifdef ngettext
#  undef ngettext
#endif

char *gettext (const char * msgid) { sin(); char *nmsgid = dw_unprotect((void *)msgid); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); char *ret = libc_gettext(nmsgid); sout(); if(ret == nmsgid) return (char *)msgid; else return ret; }
char *dgettext (const char * domainname, const char * msgid) { sin(); char *ndomainname = dw_unprotect((void *)domainname); char *nmsgid = dw_unprotect((void *)msgid); dw_check_access((void *)domainname, libc_strlen(ndomainname) + 1); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); char *ret = libc_dgettext(ndomainname, nmsgid); sout(); if(ret == nmsgid) return (char *)msgid; else return ret; }
char *dcgettext (const char * domainname, const char * msgid, int category) { sin(); char *ndomainname = dw_unprotect((void *)domainname); char *nmsgid = dw_unprotect((void *)msgid); dw_check_access((void *)domainname, libc_strlen(ndomainname) + 1); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); char *ret = __dcgettext (ndomainname, nmsgid, category); sout(); if(ret == nmsgid) return (char *)msgid; else return ret; }
char *ngettext(const char *msgid, const char *msgid_plural, unsigned long int n) { sin(); char *nmsgid = dw_unprotect((void *)msgid); char *nmsgid_plural = dw_unprotect((void *)msgid_plural); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); dw_check_access((void *)msgid_plural, libc_strlen(nmsgid_plural) + 1); char *ret = libc_ngettext(nmsgid, nmsgid_plural, n); sout(); if(ret == nmsgid) return (char *)msgid; else if(ret == nmsgid_plural) return (char *)msgid_plural; else return ret; }
char *dcngettext(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category) { sin(); char *ndomainname = dw_unprotect((void *)domainname); char *nmsgid = dw_unprotect((void *)msgid); char *nmsgid_plural = dw_unprotect((void *)msgid_plural); dw_check_access((void *)domainname, libc_strlen(ndomainname) + 1); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); dw_check_access((void *)msgid_plural, libc_strlen(nmsgid_plural) + 1); char *ret = libc_dcngettext(ndomainname, nmsgid, nmsgid_plural, n, category); sout(); if(ret == nmsgid) return (char *)msgid; else if(ret == nmsgid_plural) return (char *)msgid_plural; else return ret; }

wchar_t *wmemcpy(wchar_t *restrict dest, const wchar_t *restrict src, size_t n) { sin(); dw_check_access(dest, n * sizeof(wchar_t)); dw_check_access(src, n * sizeof(wchar_t)); libc_wmemcpy((wchar_t *)dw_unprotect(dest), (wchar_t *)dw_unprotect(src), n); sout(); return dest; }
char *setlocale(int category, const char *locale) { sin(); char *nlocale = dw_unprotect((void *)locale); dw_check_access((void *)locale, libc_strlen(nlocale) + 1); char *ret = libc_setlocale(category, nlocale); sout(); return ret; }
char *textdomain(const char * domainname) { sin(); char *ndomainname = dw_unprotect((void *)domainname); dw_check_access((void *)domainname, libc_strlen(ndomainname) + 1); char *ret = libc_textdomain(ndomainname); sout(); return ret; }
int execve(const char *pathname, char *const argv[], char *const envp[]) { sin(); char *npathname = dw_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)argv, arglen(argv)); dw_check_access((void *)envp, arglen(envp)); int ret = libc_execve(npathname, dw_unprotect(argv), dw_unprotect(envp)); sout(); return ret; }
int execv(const char *pathname, char *const argv[]) { sin(); char *npathname = dw_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)argv, arglen(argv)); int ret = libc_execv(npathname, dw_unprotect(argv)); sout(); return ret; }
int execvp(const char *file, char *const argv[]) { sin(); char *nfile = dw_unprotect((void *)file); dw_check_access((void *)file, libc_strlen(nfile) + 1); dw_check_access((void *)argv, arglen(argv)); int ret = libc_execvp(nfile, dw_unprotect(argv)); sout(); return ret; }
int execvpe(const char *file, char *const argv[], char *const envp[]) { sin(); char *nfile = dw_unprotect((void *)file); dw_check_access((void *)file, libc_strlen(nfile) + 1); dw_check_access((void *)argv, arglen(argv)); dw_check_access((void *)envp, arglen(envp)); int ret = libc_execvpe(nfile, dw_unprotect(argv), dw_unprotect(envp)); sout(); return ret; }

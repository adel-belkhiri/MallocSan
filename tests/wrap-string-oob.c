/*
 * Regression test for the semantic strncat()/wcscpy() wrappers (which also
 * exercises strnlen() and wcslen()).
 *
 * glibc's optimized implementations of these functions use SIMD accesses that
 * may touch aligned 32/128-byte blocks slightly before or after the logical
 * string range. Without semantic wrappers, MallocSan checks those internal
 * machine accesses against the exact allocation bounds and reports false
 * out-of-bounds errors on correctly sized buffers. The wrappers instead check
 * the API-level range and run the real libc function on untainted pointers.
 *
 * Modes (argv[1]):
 *   strncat-fit  exact-fit strncat: must NOT report, exits 0
 *   strncat-oob  dest one byte too small: must report an OOB access
 *   wcscpy-fit   exact-fit wcscpy: must NOT report, exits 0
 *   wcscpy-oob   dest one wchar_t too small: must report an OOB access
 *
 * The -fit modes also assert that the wrapper returns the original (still
 * protected) destination pointer and that the copy really happened. Build
 * with -fno-builtin so the calls reach libc (and thus the wrappers) instead
 * of being expanded inline by the compiler.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int test_strncat(int oob)
{
	size_t alloc = oob ? 99 : 100;	/* logical need: 99 chars + NUL */
	char *dest = malloc(alloc);
	char source[100];

	if (dest == NULL)
		return 2;

	memset(source, 'A', 99);
	source[99] = '\0';

	dest[0] = '\0';
	char *ret = strncat(dest, source, 100);

	if (ret != dest) {
		fprintf(stderr, "strncat returned %p, expected protected dest %p\n",
			(void *)ret, (void *)dest);
		return 3;
	}
	if (dest[0] != 'A' || dest[98] != 'A' || dest[99] != '\0')
		return 4;
	if (strnlen(dest, 100) != 99)
		return 5;

	free(dest);
	return 0;
}

static int test_wcscpy(int oob)
{
	size_t chars = 50;		/* logical need: 49 characters + NUL */
	wchar_t *dest = malloc((oob ? chars - 1 : chars) * sizeof(wchar_t));
	wchar_t source[50];

	if (dest == NULL)
		return 2;

	for (size_t i = 0; i < chars - 1; i++)
		source[i] = L'B';
	source[chars - 1] = L'\0';

	wchar_t *ret = wcscpy(dest, source);

	if (ret != dest) {
		fprintf(stderr, "wcscpy returned %p, expected protected dest %p\n",
			(void *)ret, (void *)dest);
		return 3;
	}
	if (dest[0] != L'B' || dest[48] != L'B' || dest[49] != L'\0')
		return 4;
	if (wcslen(dest) != chars - 1)
		return 5;

	free(dest);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s strncat-fit|strncat-oob|wcscpy-fit|wcscpy-oob\n",
			argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "strncat-fit") == 0)
		return test_strncat(0);
	if (strcmp(argv[1], "strncat-oob") == 0)
		return test_strncat(1);
	if (strcmp(argv[1], "wcscpy-fit") == 0)
		return test_wcscpy(0);
	if (strcmp(argv[1], "wcscpy-oob") == 0)
		return test_wcscpy(1);
	fprintf(stderr, "unknown mode %s\n", argv[1]);
	return 2;
}

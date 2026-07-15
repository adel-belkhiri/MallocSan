#!/usr/bin/env bash
#
# Regression check for the semantic string wrappers (tests/wrap-string-oob.c):
#
#   1. strncat-fit / wcscpy-fit: exact-fit operations on protected heap
#      buffers must run to completion (exit 0) with NO out-of-bounds report.
#      Without the wrappers, glibc's SIMD implementations touch aligned
#      blocks slightly outside the logical string range and MallocSan reports
#      false positives against correctly sized allocations.
#   2. strncat-oob / wcscpy-oob: a destination one byte / one wchar_t too
#      small must still be reported (the wrappers check the API-level range,
#      they do not suppress genuine overflows).
#
# Usage (from the repo root):
#   tests/wrap-string-oob-check.sh
#
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

SO="$ROOT/build/src/.libs/libmallocsan.so"
BIN="${TMPDIR:-/tmp}/wrap-string-oob"
MARKER="Out-of-bounds access detected"

if [ ! -f "$SO" ]; then
	echo "SKIP: $SO not built (run make -C build first)"
	exit 2
fi

# -fno-builtin keeps the compiler from expanding the string calls inline and
# -D_FORTIFY_SOURCE=0 from redirecting them to the __*_chk variants (Ubuntu
# enables fortify by default at -O2): the plain strncat/wcscpy wrappers under
# test must be the ones reached, as in unfortified -O0 builds (e.g. Juliet).
gcc -O2 -Wall -Wextra -fno-builtin -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
    "$ROOT/tests/wrap-string-oob.c" -o "$BIN" || {
	echo "FAIL: could not build the test"; exit 1; }

fail=0

run_case() { # <mode> <expect_marker: yes|no>
	local mode="$1" expect_marker="$2"
	local log="${TMPDIR:-/tmp}/wrap-string-oob-$mode.log"

	env LD_LIBRARY_PATH="$ROOT/external/libolx/lib:$ROOT/external/libpatch/src/lib" \
	    LD_PRELOAD="$SO" \
	    DW_MIN_SIZE=1 DW_LOG_LEVEL=0 DW_SHOW_BANNER=0 \
	    "$BIN" "$mode" 1>/dev/null 2>"$log"
	local rc=$?

	local has_marker=0
	grep -q "$MARKER" "$log" && has_marker=1

	if [ "$expect_marker" = yes ]; then
		if [ "$has_marker" -eq 1 ]; then
			echo "PASS: $mode reported the out-of-bounds access"
		else
			echo "FAIL: $mode expected an OOB report, got none (rc=$rc, log: $log)"
			fail=1
		fi
	else
		if [ "$has_marker" -eq 0 ] && [ "$rc" -eq 0 ]; then
			echo "PASS: $mode clean (rc=0, no report)"
		else
			echo "FAIL: $mode expected a clean run, rc=$rc marker=$has_marker (log: $log)"
			fail=1
		fi
	fi
}

run_case strncat-fit no
run_case strncat-oob yes
run_case wcscpy-fit  no
run_case wcscpy-oob  yes

exit $fail

AC_PREREQ([2.69])
AC_INIT([MallocSan], [0.1], [adel.belkhiri@polymtl.ca])
AC_CONFIG_SRCDIR([src/dw-preload.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects silent-rules dist-xz no-dist-gzip])
AM_SILENT_RULES([yes])

AC_USE_SYSTEM_EXTENSIONS
AC_LANG([C])

AC_PROG_CC
LT_INIT
PKG_PROG_PKG_CONFIG

dnl ----------------------------------------------------------------------
dnl  --with-bundled-libpatch[=yes|no], default no
dnl ----------------------------------------------------------------------
AC_ARG_WITH([bundled-libpatch],
  [AS_HELP_STRING([--with-bundled-libpatch], [build bundled libpatch])],
  [case "$withval" in
      no)  with_bundled_libpatch=no ;;
      ""|yes) with_bundled_libpatch=yes ;;
      *)   with_bundled_libpatch=yes ;;
   esac],
  [with_bundled_libpatch=no])

AM_CONDITIONAL([BUNDLED_LIBPATCH], [test "x$with_bundled_libpatch" = "xyes"])

AS_IF([test "x$with_bundled_libpatch" = "xyes"], [
  AC_PATH_PROG([GIT],[git])
  AS_IF([test -z "$GIT"], [
    AC_MSG_WARN([git not found; bundled libpatch will not auto-fetch])
  ])
  LIBOLX_BUILD_DIR='$(abs_top_builddir)/third_party/libolx'
  LIBPATCH_BUILD_DIR='$(abs_top_builddir)/third_party/libpatch'
  LIBOLX_SRC_DIR='$(abs_top_srcdir)/external/libolx'
  LIBPATCH_SRC_DIR='$(abs_top_srcdir)/external/libpatch'
  AC_SUBST([GIT])
  AC_SUBST([LIBOLX_SRC_DIR])
  AC_SUBST([LIBPATCH_SRC_DIR])
  AC_SUBST([LIBOLX_BUILD_DIR])
  AC_SUBST([LIBPATCH_BUILD_DIR])
], [
  PKG_CHECK_MODULES([LIBPATCH], [libpatch >= 1.7],
    [AC_SUBST([LIBPATCH_CFLAGS]) AC_SUBST([LIBPATCH_LIBS])],
    [AC_MSG_ERROR([libpatch not found. Install it or use --with-bundled-libpatch])])
])

dnl ----------------------------------------------------------------------
dnl  Capstone dependency
dnl ----------------------------------------------------------------------
CAPSTONE_CFLAGS=""
CAPSTONE_LIBS=""
if test "x$PKG_CONFIG" != "x"; then
  PKG_CHECK_MODULES([CAPSTONE], [capstone >= 4.0],
    [CAPSTONE_CFLAGS="$CAPSTONE_CFLAGS $CAPSTONE_CFLAGS"
     CAPSTONE_LIBS="$CAPSTONE_LIBS $CAPSTONE_LIBS"],
    [:])
fi
if test "x$CAPSTONE_LIBS" = "x"; then
  AC_CHECK_HEADERS([capstone/capstone.h],
    [], [AC_MSG_ERROR([capstone header not found])])
  AC_SEARCH_LIBS([cs_open], [capstone],
    [CAPSTONE_LIBS="$ac_cv_search_cs_open"],
    [AC_MSG_ERROR([capstone library not found])])
fi
AC_SUBST([CAPSTONE_CFLAGS])
AC_SUBST([CAPSTONE_LIBS])

dnl ----------------------------------------------------------------------
dnl  libunwind dependency
dnl ----------------------------------------------------------------------
UNWIND_CFLAGS=""
UNWIND_LIBS=""
if test "x$PKG_CONFIG" != "x"; then
  PKG_CHECK_MODULES([UNWIND], [libunwind >= 1.2],
    [UNWIND_CFLAGS="$UNWIND_CFLAGS $UNWIND_CFLAGS"
     UNWIND_LIBS="$UNWIND_LIBS $UNWIND_LIBS"],
    [:])
fi
if test "x$UNWIND_LIBS" = "x"; then
  AC_CHECK_HEADERS([libunwind.h],
    [], [AC_MSG_ERROR([libunwind header not found])])
  AC_SEARCH_LIBS([unw_init_local], [unwind],
    [UNWIND_LIBS="$ac_cv_search_unw_init_local"],
    [AC_MSG_ERROR([libunwind library not found])])
fi
AC_SUBST([UNWIND_CFLAGS])
AC_SUBST([UNWIND_LIBS])

dnl ------------------------------------------------------
dnl  Option: build tests
dnl ------------------------------------------------------
AC_ARG_ENABLE([tests],
  AS_HELP_STRING([--enable-tests], [build test programs]),
  [build_tests=$enableval],
  [build_tests=no])
AM_CONDITIONAL([BUILD_TESTS], [test "x$build_tests" = "xyes"])

dnl ----------------------------------------------------------------------
dnl  Generate Makefiles
dnl ----------------------------------------------------------------------
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])

AM_COND_IF([BUILD_TESTS], [AC_CONFIG_FILES([tests/Makefile])])

AC_OUTPUT
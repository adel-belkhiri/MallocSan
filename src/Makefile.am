AM_CFLAGS   = -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-builtin -Wall -fPIC -O0 -g3 -fno-omit-frame-pointer -fvar-tracking -fvar-tracking-assignments -fno-inline -fno-optimize-sibling-calls
AM_CPPFLAGS = $(AM_CFLAGS)

lib_LTLIBRARIES = libmallocsan.la
libmallocsan_la_SOURCES = \
    dw-backtrace.c \
    dw-log.c \
    dw-protect-oid.c \
    dw-registers.c \
    dw-disassembly.c \
    dw-patch.c \
    dw-wrap-glibc.c \
    dw-printf.c \
    dw-preload.c

# Library versioning: current:revision:age
libmallocsan_la_LDFLAGS = -no-undefined -version-info 0:0:0
#libmallocsan_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libmallocsan.map

# Dependencies discovered by configure
AM_CPPFLAGS += $(CAPSTONE_CFLAGS) $(UNWIND_CFLAGS)
libmallocsan_la_LIBADD = $(CAPSTONE_LIBS) $(UNWIND_LIBS)

# --- libpatch wiring ---

if BUNDLED_LIBPATCH
# Ensure the external tree is built before we link.
# libmallocsan_la_DEPENDENCIES = $(top_builddir)/libpatch.stamp

# Headers and libs from the in-tree builds
AM_CPPFLAGS += -I$(LIBOLX_SRC_DIR)/include -I$(LIBPATCH_SRC_DIR)/include
libmallocsan_la_LIBADD += -L$(LIBPATCH_BUILD_DIR)/src/lib -lpatch -L$(LIBOLX_BUILD_DIR)/lib -lolx

# rpath so the in-tree libs are found at run time when not installed
libmallocsan_la_LDFLAGS += -Wl,-rpath,$(LIBPATCH_BUILD_DIR)/src/lib:$(LIBOLX_BUILD_DIR)/lib
else
AM_CPPFLAGS += $(LIBPATCH_CFLAGS)
libmallocsan_la_LIBADD += $(LIBPATCH_LIBS)
endif

CLEANFILES = *.so
EXTRA_DIST = libmallocsan.map

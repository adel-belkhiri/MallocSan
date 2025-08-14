AM_CFLAGS   = -Wall -fPIC -g
AM_CPPFLAGS =

lib_LTLIBRARIES = libmallocsan.la
libmallocsan_la_SOURCES = \
    dw-log.c \
    dw-protect-oid.c \
    dw-registers.c \
    dw-disassembly.c \
    dw-wrap-glibc.c \
    dw-printf.c \
    dw-preload.c

# Library versioning: current:revision:age
libmallocsan_la_LDFLAGS = -no-undefined -version-info 0:0:0

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

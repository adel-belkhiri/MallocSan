ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS =

## Project layout ##
SUBDIRS = . src
DIST_SUBDIRS = src

if BUILD_TESTS
SUBDIRS += tests
DIST_SUBDIRS += tests
endif

dist_doc_DATA     = LICENSE README.md
dist_noinst_DATA  = CodingStyle
EXTRA_DIST        = m4
DISTCHECK_CONFIGURE_FLAGS = --with-bundled-libpatch=no

## Build bundled libpatch/libolx in-tree if requested ##
if BUNDLED_LIBPATCH

LIBOLX_CONFIGURE   = $(abs_top_srcdir)/external/libolx/configure
LIBPATCH_CONFIGURE = $(abs_top_srcdir)/external/libpatch/configure
PKGCONFIG_DIR = $(abs_builddir)/pkgconfig
OLX_PC        = $(PKGCONFIG_DIR)/libolx.pc
LIBPATCH_LIB  = $(LIBPATCH_BUILD_DIR)/src/lib/libpatch.so
LIBPATCH_PROJECT_REPL = GUILE_AUTO_COMPILE=0 $$guile_bin -L $(LIBPATCH_BUILD_DIR) -L $(LIBPATCH_SRC_DIR) -L $(LIBPATCH_SRC_DIR)/src/guile -C $(LIBPATCH_BUILD_DIR)/src/guile -c '((@ (project libpatch main) main))'

CLEANFILES = \
  libolx.stamp libpatch.stamp \
  $(OLX_PC)

.PHONY: install-third-party uninstall-third-party
.PHONY: submodules check-libpatch-submodule

all-local: libpatch.stamp

# --- submodules fetchers (makeable prerequisites) ---

submodules:
	@set -e; \
	if test -f "$(LIBOLX_CONFIGURE)" && test -f "$(LIBPATCH_CONFIGURE)"; then \
	  echo "Submodules present: external/libolx external/libpatch"; \
	else \
	  echo "Initializing submodules: external/libolx and external/libpatch"; \
	  test -n "$(GIT)" || { echo "git not available"; exit 1; }; \
	  $(GIT) -C "$(abs_top_srcdir)" submodule update --init --recursive external/libolx external/libpatch; \
	fi; \
	test -f "$(LIBOLX_CONFIGURE)" || { echo "libolx: missing configure after fetch"; exit 1; }; \
	test -f "$(LIBPATCH_CONFIGURE)" || { echo "libpatch: missing configure after fetch"; exit 1; }; \
	$(MAKE) check-libpatch-submodule

check-libpatch-submodule:
	@set -e; \
	if test -z "$(GIT)" || ! $(GIT) -C "$(abs_top_srcdir)" rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
	  exit 0; \
	fi; \
	expected=`$(GIT) -C "$(abs_top_srcdir)" ls-tree HEAD external/libpatch | \
	  $(SED) -n 's/^160000 commit \([0-9a-f][0-9a-f]*\)[[:space:]].*/\1/p'`; \
	test -n "$$expected" || exit 0; \
	actual=`$(GIT) -C "$(LIBPATCH_SRC_DIR)" rev-parse HEAD 2>/dev/null || true`; \
	if test -z "$$actual"; then \
	  echo "external/libpatch is not a git checkout."; \
	  echo "Run: git submodule update --init external/libpatch"; \
	  exit 1; \
	fi; \
	if test "$$actual" != "$$expected"; then \
	  expected_short=`$(GIT) -C "$(abs_top_srcdir)" rev-parse --short "$$expected"`; \
	  actual_short=`$(GIT) -C "$(LIBPATCH_SRC_DIR)" rev-parse --short HEAD`; \
	  echo "external/libpatch is checked out at $$actual_short, but this MallocSan commit records $$expected_short."; \
	  echo "Run: git submodule update --init external/libpatch"; \
	  exit 1; \
	fi

$(LIBOLX_CONFIGURE): submodules
	@:

$(LIBPATCH_CONFIGURE): submodules
	@:

# --- libolx build ---

libolx.stamp: $(LIBOLX_CONFIGURE)
	$(AM_V_at) $(MKDIR_P) "$(LIBOLX_BUILD_DIR)"
	$(AM_V_at) cd "$(LIBOLX_BUILD_DIR)" && \
	  "$(LIBOLX_SRC_DIR)/configure" \
	    --srcdir="$(LIBOLX_SRC_DIR)" \
	    --prefix="$(prefix)"
	$(AM_V_at) $(MAKE) -C "$(LIBOLX_BUILD_DIR)"
	$(AM_V_at) touch $@

# --- libpatch build ---

libpatch.stamp: $(LIBPATCH_LIB)
	$(AM_V_at) touch $@

$(LIBPATCH_LIB): libolx.stamp $(LIBPATCH_CONFIGURE)
	$(AM_V_at) $(MKDIR_P) "$(PKGCONFIG_DIR)"
	$(AM_V_at) cp "$(LIBOLX_BUILD_DIR)/etc/libolx.pc" "$(OLX_PC)"
	$(AM_V_at) $(SED) \
	  -e 's|^Cflags:.*|Cflags: -I$(LIBOLX_SRC_DIR)/include|' \
	  -e 's|^Libs:.*|Libs: -L$(LIBOLX_BUILD_DIR)/lib -lolx|' \
	  "$(OLX_PC)" > "$(OLX_PC).tmp" && mv "$(OLX_PC).tmp" "$(OLX_PC)"
	$(AM_V_at) $(MKDIR_P) "$(LIBPATCH_BUILD_DIR)"
	$(AM_V_at) cd "$(LIBPATCH_BUILD_DIR)" && \
	  PKG_CONFIG_PATH="$(PKGCONFIG_DIR):$$PKG_CONFIG_PATH" \
	  LD_LIBRARY_PATH="$(LIBOLX_BUILD_DIR)/lib:$$LD_LIBRARY_PATH" \
	  "$(LIBPATCH_SRC_DIR)/configure" \
	    --disable-ftrace-build \
	    --disable-patch-coverage-build \
	    --disable-patch-integrity-build \
	    --without-manpages \
	    --without-lttng \
	    --without-dyninst \
	    --without-liteinst \
	    --without-benchmarks \
	    --srcdir="$(LIBPATCH_SRC_DIR)" \
	    --prefix="$(prefix)"
	$(AM_V_at) guile_bin=$${GUILE:-$$(command -v guile || command -v guile3.0)}; \
	  test -n "$$guile_bin" || { echo "libpatch: missing guile executable"; exit 1; }; \
	  PKG_CONFIG_PATH="$(PKGCONFIG_DIR):$$PKG_CONFIG_PATH" \
	  LD_LIBRARY_PATH="$(LIBOLX_BUILD_DIR)/lib:$$LD_LIBRARY_PATH" \
	  $(MAKE) -C "$(LIBPATCH_BUILD_DIR)" \
	    PROJECT_REPL="$(LIBPATCH_PROJECT_REPL)"
	$(AM_V_at) test -f "$(LIBPATCH_LIB)" || { echo "libpatch: missing $(LIBPATCH_LIB) after build"; exit 1; }

# --- Install third party libraries ---
install-exec-local: install-third-party
install-third-party: libpatch.stamp
	@set -e; \
	$(MAKE) -C "$(LIBOLX_BUILD_DIR)" install; \
	if [ -d "$(prefix)" ]; then \
	  find "$(prefix)" \( -name '*libpatch*' -o -path '*libpatch*' -o -path '*/bin/patch*' \) \
	    -exec chmod u+w {} + 2>/dev/null || true; \
	fi; \
	guile_bin=$${GUILE:-$$(command -v guile || command -v guile3.0)}; \
	test -n "$$guile_bin" || { echo "libpatch: missing guile executable"; exit 1; }; \
	PKG_CONFIG_PATH="$(PKGCONFIG_DIR):$$PKG_CONFIG_PATH" \
	LD_LIBRARY_PATH="$(LIBOLX_BUILD_DIR)/lib:$$LD_LIBRARY_PATH" \
	$(MAKE) -C "$(LIBPATCH_BUILD_DIR)" install \
	  PROJECT_REPL="$(LIBPATCH_PROJECT_REPL)"

# --- Uninstall third party libraries ---
uninstall-local: uninstall-third-party
uninstall-third-party:
	@set -e; \
	echo "-----------------------------------------------------------------------------"; \
	echo "Bundled libraries, libolx and libpatch, do not provide an 'uninstall' target."; \
	echo "Therefore, you need to uninstall their artifacts manually :("; \
	echo "-----------------------------------------------------------------------------";

distclean-local: distclean-third-party
distclean-third-party:
	$(AM_V_at) rm -rf "$(abs_top_builddir)/third_party/" || true

endif  # BUNDLED_LIBPATCH

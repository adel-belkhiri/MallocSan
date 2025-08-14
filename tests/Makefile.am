# Test programs are built but not installed.

if BUILD_TESTS
noinst_PROGRAMS   = simple-dw
simple_dw_SOURCES = simple/simple.c
AM_CPPFLAGS        =
AM_CFLAGS = -Wall -g
else
	@echo "========================================="
	@echo "WARNING: Tests were disabled at configure"
	@echo "========================================="
endif


SUBDIRS =


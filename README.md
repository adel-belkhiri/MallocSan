
# MallocSan
A lightweight and efficient memory sanitizer that uses tainted pointers to
detect invalid accesses to memory allocated via malloc and related functions.

## Overview
MallocSan instruments heap allocations to help detect out-of-bounds accesses
with minimal runtime overhead. Based on some criteria (see the relevant
environment variables below), pointers returned by malloc are tainted, which
means MallocSan leverages the unused high bits of the pointer (the top 2 bytes)
to store metadata.

When a tainted pointer is derefernced:
1. A SIGSEGV is triggered.
2. The SIGSEGV handler then:
   - Untaint the offending register
   - Check the access against the object bounds
   - Execute the access, and
   - Retaint the offending register
3. Control is returned to the original execution flow.

**Note:** Getting back the control after the access, to retaint the register,
is the tricky part. The access instruction is executed out of line such that
the retainting code can be executed after. That's why MallocSan relies on the
libpatch library to dynamically patch code and reroute instruction execution.

## Build Requirements
MallocSan uses the GNU Autotools build system for portability. Here are a few
things you should have on your system in order to compile this source tree:

  - GNU Autotools  (recent automake recommended!)
  - GCC or Clang
  - GNU Make
  - pkg-config

## Runtime Requirements
- libpatch (dynamic instruction patching)
- capstone (disassembly)
- libdw (ELF/DWARF introspection)

## Building MallocSan
To build MallocSan from sources, you can run:

```sh
$ autoreconf -fi  # if building from a fresh git checkout
$ mkdir build && cd build
$ ./configure         # see options below
$ make
$ make install
```

### Configuration options
- ``` --with-bundled-libpatch```
Fetch and build libpatch as a bundled library. If this option is not specified, you need to have libpatch and libolx libraries installed on your system.

- ``` --enable-tests ```
Build the optional test programs in tests/. Tests are disabled by default.

## Environment variables

The following environment variables control pointer tainting and library's operations:

| Variable              | Description                                                                                        |
| --------------------- | -------------------------------------------------------------------------------------------------- |
| `DW_MIN_SIZE`         | Taint only allocations **≥** this size (bytes).                                                    |
| `DW_MAX_SIZE`         | Taint only allocations **≤** this size (bytes).                                                    |
| `DW_MAX_NB_PROTECTED` | Maximum number of allocations to taint.                                                            |
| `DW_FIRST_PROTECTED`  | Skip tainting for the first N allocations.                                                         |
| `DW_INSN_ENTRIES`     | Expected number of instructions to patch/trap. The internal table will be \~2× this size.          |
| `DW_LOG_LEVEL`        | Log verbosity: `0` = silent, `4` = debug (errors, warnings, info, debug).                          |
| `DW_STATS_FILE`       | Output file for patching statistics (default: `.taintstats.txt`).                                  |
| `DW_STRATEGY`         | Patching mode: `0` = TRAP, `1` = JUMP. (Currently focusing on TRAP due to `libpatch` limitations.) |
| `DW_CHECK_HANDLING`   | Enable extra consistency checks (`1` = on, default = `0`).                                         |
| `DW_HIDE_BANNER`      | Hide MallocSan banner printed at startup (`1` = hide, default = `0`).                              |


## Usage
A sample invocation of the test application "simple" can look like the following:

```bash
time LD_PRELOAD=./libmallocsan.so \
     DW_STATS_FILE=stats.txt \
     DW_STRATEGY=1 \
     DW_LOG_LEVEL=0 \
     ./simple 10 1000000 2>out.txt
```
## Debugging Tips
Debugging under GDB with LD_PRELOAD can be difficult due to frequent SIGSEGV
handling. A better approach is to link libmallocsan.so directly into the target
binary:

```bash
patchelf --add-needed <absolute path>/libmallocsan.so ./simple
```

While live debugging is still cumbersome, post-mortem analysis works well:
If the program crashes, you can inspect the generated core dump in GDB without
interference from trap handling.


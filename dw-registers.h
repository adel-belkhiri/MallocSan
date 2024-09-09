#ifndef DW_REGISTERS_H
#define DW_REGISTERS_H

#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>

// The register table contains all the information about the x86_64 registers.
// The register naming / index from libcapstone is taken since it is the more
// complete and also this is the source of our information. Each entry contains
// the register name, the index in different context structures where registers
// are saved (e.g. signal handler, libpatch handler...), and other information
// to help untaint and taint pointers in those registers.

struct reg_entry {
    int index;
    char *name;
    int size;
    int vector_size;
    int ucontext_index;
    int libpatch_index;
    int libolx_index;
    unsigned epilogue_size;
    uint8_t epilogue[17];
};

struct reg_entry *dw_get_reg_entry(unsigned reg);

extern unsigned dw_saved_registers[];
extern const unsigned dw_nb_saved_registers;
extern uintptr_t dw_save_regs[];

#define dw_get_register(base, index) *((uintptr_t *)((void *)(base) + (index)))
#define dw_set_register(base, index, value) *((uintptr_t *)((void *)(base) + (index))) = value

#endif /* DW_REGISTERS_H */

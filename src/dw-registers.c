#define _GNU_SOURCE 1

#include <capstone/capstone.h>
#include <libpatch/patch.h>
#include <stdbool.h>
#include <string.h>
#include <ucontext.h>

#include "dw-registers.h"

// Included information our table is based on:
//
// ucontext_t uc_mcontext gregs []
//     REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14,
//     REG_R15, REG_RDI, REG_RSI, REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX,
//     REG_RSP, REG_RIP, REG_EFL, REG_CSGSFS, REG_ERR, REG_TRAPNO,
//     REG_OLDMASK, REG_CR2
//
// ucontext_t uc_mcontext fpregs *_libc_fpstate
// ucontext_t __fpregs_mem _libc_fpstate
//     cwd, swd, ftw, fop, rip, rdp, mxcsr, mxcr_mask, _st[8] (each 16 bytes), _xmm[16] (each 4 x u32)
//
// patch_probe_context gregs[]
//     PATCH_X86_64_RAX, PATCH_X86_64_RBX, PATCH_X86_64_RCX, PATCH_X86_64_RDX, PATCH_X86_64_RSI,
//     PATCH_X86_64_RDI, PATCH_X86_64_RBP, PATCH_X86_64_R8, PATCH_X86_64_R9, PATCH_X86_64_R10,
//     PATCH_X86_64_R11, PATCH_X86_64_R12, PATCH_X86_64_R13, PATCH_X86_64_R14, PATCH_X86_64_R15
//
// patch_probe_context *extended_states

unsigned dw_saved_registers[] = {
	X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSI,
	X86_REG_RDI, X86_REG_RBP, X86_REG_R8, X86_REG_R9, X86_REG_R10,
	X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15};

const unsigned dw_nb_saved_registers = sizeof(dw_saved_registers) / sizeof(unsigned);

uintptr_t dw_save_regs[sizeof(dw_saved_registers) / sizeof(unsigned)];

struct reg_entry reg_table[] = {
	{ X86_REG_INVALID, NULL, false, X86_REG_INVALID, 0, 1, -1, -1, -1, 0, {} },
	{ X86_REG_AH, "ah", true, X86_REG_RAX, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX])+1, offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX])+1, -1, 0, {} },
	{ X86_REG_AL, "al", true, X86_REG_RAX, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX]), -1, 0, {} },
	{ X86_REG_AX, "ax", true, X86_REG_RAX, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX]), -1, 0, {} },
	{ X86_REG_BH, "bh", true, X86_REG_RBX, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX])+1, offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX])+1, -1, 0, {} },
	{ X86_REG_BL, "bl", true, X86_REG_RBX, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX]), -1, 0, {} },
	{ X86_REG_BP, "bp", true, X86_REG_RBP, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBP]), -1, 0, {} },
	{ X86_REG_BPL, "bpl", true, X86_REG_RBP, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBP]), -1, 0, {} },
	{ X86_REG_BX, "bx", true, X86_REG_RBX, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX]), -1, 0, {} },
	{ X86_REG_CH, "ch", true, X86_REG_RCX, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX])+1, offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX])+1, -1, 0, {} },
	{ X86_REG_CL, "cl", true, X86_REG_RCX, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX]), -1, 0, {} },
	{ X86_REG_CS, "cs", false, X86_REG_CS, 2, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CX, "cx", true, X86_REG_RCX, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX]), -1, 0, {} },
	{ X86_REG_DH, "dh", true, X86_REG_RDX, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX])+1, offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX])+1, -1, 0, {} },
	{ X86_REG_DI, "di", true, X86_REG_RDI, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDI]), -1, 0, {} },
	{ X86_REG_DIL, "dil", true, X86_REG_RDI, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDI]), -1, 0, {} },
	{ X86_REG_DL, "dl", true, X86_REG_RDX, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX]), -1, 0, {} },
	{ X86_REG_DS, "ds", false, X86_REG_DS, 2, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DX, "dx", true, X86_REG_RDX, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX]), -1, 0, {} },
	{ X86_REG_EAX, "eax", true, X86_REG_RAX, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX]), -1, 0, {} },
	{ X86_REG_EBP, "ebp", true, X86_REG_RBP, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBP]), -1, 0, {} },
	{ X86_REG_EBX, "ebx", true, X86_REG_RBX, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX]), -1, 0, {} },
	{ X86_REG_ECX, "ecx", true, X86_REG_RCX, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX]), -1, 0, {} },
	{ X86_REG_EDI, "edi", true, X86_REG_RDI, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDI]), -1, 0, {} },
	{ X86_REG_EDX, "edx", true, X86_REG_RDX, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX]), -1, 0, {} },
	{ X86_REG_EFLAGS, "flags", false, X86_REG_EFLAGS, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_EFL]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_EFL]) */, -1, 0, {} },
	{ X86_REG_EIP, "eip", false, X86_REG_EIP, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RIP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RIP]) */, -1, 0, {} },
	{ X86_REG_EIZ, "eiz", false, X86_REG_EIZ, 4, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ES, "es", false, X86_REG_ES, 2, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ESI, "esi", true, X86_REG_RSI, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
	{ X86_REG_ESP, "esp", false, X86_REG_RSP, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSP]) */, -1, 0, {} },
	{ X86_REG_FPSW, "fpsw", false, X86_REG_FPSW, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FS, "fs", false, X86_REG_FS, 2, 1, -1, -1, -1, 0, {} },
	{ X86_REG_GS, "gs", false, X86_REG_GS, 2, 1, -1, -1, -1, 0, {} },
	{ X86_REG_IP, "ip", false, X86_REG_IP, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RIP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RIP]) */, -1, 0, {} },
	{ X86_REG_RAX, "rax", true, X86_REG_RAX, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX]), -1, 0, {} },
	{ X86_REG_RBP, "rbp", true, X86_REG_RBP, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBP]), -1, 0, {} },
	{ X86_REG_RBX, "rbx", true, X86_REG_RBX, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX]), -1, 0, {} },
	{ X86_REG_RCX, "rcx", true, X86_REG_RCX, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX]), -1, 0, {} },
	{ X86_REG_RDI, "rdi", true, X86_REG_RDI, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDI]), -1, 0, {} },
	{ X86_REG_RDX, "rdx", true, X86_REG_RDX, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX]), -1, 0, {} },
	{ X86_REG_RIP, "rip", false, X86_REG_RIP, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RIP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RIP]) */, -1, 0, {} },
	{ X86_REG_RIZ, "riz", false, X86_REG_RIZ, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_RSI, "rsi", true, X86_REG_RSI, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
	{ X86_REG_RSP, "rsp", true, X86_REG_RSP, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSP]) */, -1, 0, {} },
	{ X86_REG_SI, "si", true, X86_REG_RSI, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
	{ X86_REG_SIL, "sil", true, X86_REG_RSI, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
	{ X86_REG_SP, "sp", false, X86_REG_RSP, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSP]) */, -1, 0, {} },
	{ X86_REG_SPL, "spl", false, X86_REG_RSP, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSP]) */, -1, 0, {} },
	{ X86_REG_SS, "ss", false, X86_REG_SS, 2, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR0, "cr0", false, X86_REG_CR0, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR1, "cr1", false, X86_REG_CR1, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR2, "cr2", false, X86_REG_CR2, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR3, "cr3", false, X86_REG_CR3, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR4, "cr4", false, X86_REG_CR4, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR5, "cr5", false, X86_REG_CR5, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR6, "cr6", false, X86_REG_CR6, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR7, "cr7", false, X86_REG_CR7, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR8, "cr8", false, X86_REG_CR8, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR9, "cr9", false, X86_REG_CR9, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR10, "cr10", false, X86_REG_CR10, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR11, "cr11", false, X86_REG_CR11, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR12, "cr12", false, X86_REG_CR12, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR13, "cr13", false, X86_REG_CR13, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR14, "cr14", false, X86_REG_CR14, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_CR15, "cr15", false, X86_REG_CR15, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR0, "dr0", false, X86_REG_DR0, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR1, "dr1", false, X86_REG_DR1, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR2, "dr2", false, X86_REG_DR2, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR3, "dr3", false, X86_REG_DR3, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR4, "dr4", false, X86_REG_DR4, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR5, "dr5", false, X86_REG_DR5, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR6, "dr6", false, X86_REG_DR6, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR7, "dr7", false, X86_REG_DR7, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR8, "dr8", false, X86_REG_DR8, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR9, "dr9", false, X86_REG_DR9, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR10, "dr10", false, X86_REG_DR10, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR11, "dr11", false, X86_REG_DR11, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR12, "dr12", false, X86_REG_DR12, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR13, "dr13", false, X86_REG_DR13, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR14, "dr14", false, X86_REG_DR14, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_DR15, "dr15", false, X86_REG_DR15, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FP0, "fp0", false, X86_REG_FP0, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FP1, "fp1", false, X86_REG_FP1, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FP2, "fp2", false, X86_REG_FP2, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FP3, "fp3", false, X86_REG_FP3, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FP4, "fp4", false, X86_REG_FP4, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FP5, "fp5", false, X86_REG_FP5, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FP6, "fp6", false, X86_REG_FP6, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_FP7, "fp7", false, X86_REG_FP7, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_K0, "k0", false, X86_REG_K0, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_K1, "k1", false, X86_REG_K1, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_K2, "k2", false, X86_REG_K2, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_K3, "k3", false, X86_REG_K3, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_K4, "k4", false, X86_REG_K4, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_K5, "k5", false, X86_REG_K5, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_K6, "k6", false, X86_REG_K6, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_K7, "k7", false, X86_REG_K7, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_MM0, "mm0", false, X86_REG_MM0, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_MM1, "mm1", false, X86_REG_MM1, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_MM2, "mm2", false, X86_REG_MM2, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_MM3, "mm3", false, X86_REG_MM3, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_MM4, "mm4", false, X86_REG_MM4, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_MM5, "mm5", false, X86_REG_MM5, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_MM6, "mm6", false, X86_REG_MM6, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_MM7, "mm7", false, X86_REG_MM7, 8, 1, -1, -1, -1, 0, {} },
	{ X86_REG_R8, "r8", true, X86_REG_R8, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R8]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R8]), -1, 0, {} },
	{ X86_REG_R9, "r9", true, X86_REG_R9, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R9]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R9]), -1, 0, {} },
	{ X86_REG_R10, "r10", true, X86_REG_R10, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R10]), -1, 0, {} },
	{ X86_REG_R11, "r11", true, X86_REG_R11, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R11]), -1, 0, {} },
	{ X86_REG_R12, "r12", true, X86_REG_R12, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R12]), -1, 0, {} },
	{ X86_REG_R13, "r13", true, X86_REG_R13, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R13]), -1, 0, {} },
	{ X86_REG_R14, "r14", true, X86_REG_R14, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R14]), -1, 0, {} },
	{ X86_REG_R15, "r15", true, X86_REG_R15, 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R15]), -1, 0, {} },
	{ X86_REG_ST0, "st0", false, X86_REG_ST0, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ST1, "st1", false, X86_REG_ST1, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ST2, "st2", false, X86_REG_ST2, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ST3, "st3", false, X86_REG_ST3, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ST4, "st4", false, X86_REG_ST4, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ST5, "st5", false, X86_REG_ST5, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ST6, "st6", false, X86_REG_ST6, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ST7, "st7", false, X86_REG_ST7, 10, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM0, "xmm0", false, X86_REG_XMM0, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM1, "xmm1", false, X86_REG_XMM1, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM2, "xmm2", false, X86_REG_XMM2, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM3, "xmm3", false, X86_REG_XMM3, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM4, "xmm4", false, X86_REG_XMM4, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM5, "xmm5", false, X86_REG_XMM5, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM6, "xmm6", false, X86_REG_XMM6, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM7, "xmm7", false, X86_REG_XMM7, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM8, "xmm8", false, X86_REG_XMM8, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM9, "xmm9", false, X86_REG_XMM9, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM10, "xmm10", false, X86_REG_XMM10, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM11, "xmm11", false, X86_REG_XMM11, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM12, "xmm12", false, X86_REG_XMM12, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM13, "xmm13", false, X86_REG_XMM13, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM14, "xmm14", false, X86_REG_XMM14, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM15, "xmm15", false, X86_REG_XMM15, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM16, "xmm16", false, X86_REG_XMM16, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM17, "xmm17", false, X86_REG_XMM17, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM18, "xmm18", false, X86_REG_XMM18, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM19, "xmm19", false, X86_REG_XMM19, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM20, "xmm20", false, X86_REG_XMM20, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM21, "xmm21", false, X86_REG_XMM21, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM22, "xmm22", false, X86_REG_XMM22, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM23, "xmm23", false, X86_REG_XMM23, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM24, "xmm24", false, X86_REG_XMM24, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM25, "xmm25", false, X86_REG_XMM25, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM26, "xmm26", false, X86_REG_XMM26, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM27, "xmm27", false, X86_REG_XMM27, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM28, "xmm28", false, X86_REG_XMM28, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM29, "xmm29", false, X86_REG_XMM29, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM30, "xmm30", false, X86_REG_XMM30, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_XMM31, "xmm31", false, X86_REG_XMM31, 16, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM0, "ymm0", false, X86_REG_YMM0, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM1, "ymm1", false, X86_REG_YMM1, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM2, "ymm2", false, X86_REG_YMM2, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM3, "ymm3", false, X86_REG_YMM3, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM4, "ymm4", false, X86_REG_YMM4, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM5, "ymm5", false, X86_REG_YMM5, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM6, "ymm6", false, X86_REG_YMM6, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM7, "ymm7", false, X86_REG_YMM7, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM8, "ymm8", false, X86_REG_YMM8, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM9, "ymm9", false, X86_REG_YMM9, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM10, "ymm10", false, X86_REG_YMM10, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM11, "ymm11", false, X86_REG_YMM11, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM12, "ymm12", false, X86_REG_YMM12, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM13, "ymm13", false, X86_REG_YMM13, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM14, "ymm14", false, X86_REG_YMM14, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM15, "ymm15", false, X86_REG_YMM15, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM16, "ymm16", false, X86_REG_YMM16, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM17, "ymm17", false, X86_REG_YMM17, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM18, "ymm18", false, X86_REG_YMM18, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM19, "ymm19", false, X86_REG_YMM19, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM20, "ymm20", false, X86_REG_YMM20, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM21, "ymm21", false, X86_REG_YMM21, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM22, "ymm22", false, X86_REG_YMM22, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM23, "ymm23", false, X86_REG_YMM23, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM24, "ymm24", false, X86_REG_YMM24, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM25, "ymm25", false, X86_REG_YMM25, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM26, "ymm26", false, X86_REG_YMM26, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM27, "ymm27", false, X86_REG_YMM27, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM28, "ymm28", false, X86_REG_YMM28, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM29, "ymm29", false, X86_REG_YMM29, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM30, "ymm30", false, X86_REG_YMM30, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_YMM31, "ymm31", false, X86_REG_YMM31, 32, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM0, "zmm0", false, X86_REG_ZMM0, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM1, "zmm1", false, X86_REG_ZMM1, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM2, "zmm2", false, X86_REG_ZMM2, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM3, "zmm3", false, X86_REG_ZMM3, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM4, "zmm4", false, X86_REG_ZMM4, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM5, "zmm5", false, X86_REG_ZMM5, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM6, "zmm6", false, X86_REG_ZMM6, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM7, "zmm7", false, X86_REG_ZMM7, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM8, "zmm8", false, X86_REG_ZMM8, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM9, "zmm9", false, X86_REG_ZMM9, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM10, "zmm10", false, X86_REG_ZMM10, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM11, "zmm11", false, X86_REG_ZMM11, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM12, "zmm12", false, X86_REG_ZMM12, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM13, "zmm13", false, X86_REG_ZMM13, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM14, "zmm14", false, X86_REG_ZMM14, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM15, "zmm15", false, X86_REG_ZMM15, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM16, "zmm16", false, X86_REG_ZMM16, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM17, "zmm17", false, X86_REG_ZMM17, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM18, "zmm18", false, X86_REG_ZMM18, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM19, "zmm19", false, X86_REG_ZMM19, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM20, "zmm20", false, X86_REG_ZMM20, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM21, "zmm21", false, X86_REG_ZMM21, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM22, "zmm22", false, X86_REG_ZMM22, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM23, "zmm23", false, X86_REG_ZMM23, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM24, "zmm24", false, X86_REG_ZMM24, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM25, "zmm25", false, X86_REG_ZMM25, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM26, "zmm26", false, X86_REG_ZMM26, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM27, "zmm27", false, X86_REG_ZMM27, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM28, "zmm28", false, X86_REG_ZMM28, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM29, "zmm29", false, X86_REG_ZMM29, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM30, "zmm30", false, X86_REG_ZMM30, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_ZMM31, "zmm31", false, X86_REG_ZMM31, 64, 1, -1, -1, -1, 0, {} },
	{ X86_REG_R8B, "r8b", true, X86_REG_R8, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R8]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R8]), -1, 0, {} },
	{ X86_REG_R9B, "r9b", true, X86_REG_R9, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R9]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R9]), -1, 0, {} },
	{ X86_REG_R10B, "r10b", true, X86_REG_R10, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R10]), -1, 0, {} },
	{ X86_REG_R11B, "r11b", true, X86_REG_R11, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R11]), -1, 0, {} },
	{ X86_REG_R12B, "r12b", true, X86_REG_R12, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R12]), -1, 0, {} },
	{ X86_REG_R13B, "r13b", true, X86_REG_R13, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R13]), -1, 0, {} },
	{ X86_REG_R14B, "r14b", true, X86_REG_R14, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R14]), -1, 0, {} },
	{ X86_REG_R15B, "r15b", true, X86_REG_R15, 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R15]), -1, 0, {} },
	{ X86_REG_R8D, "r8d", true, X86_REG_R8, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R8]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R8]), -1, 0, {} },
	{ X86_REG_R9D, "r9d", true, X86_REG_R9, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R9]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R9]), -1, 0, {} },
	{ X86_REG_R10D, "r10d", true, X86_REG_R10, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R10]), -1, 0, {} },
	{ X86_REG_R11D, "r11d", true, X86_REG_R11, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R11]), -1, 0, {} },
	{ X86_REG_R12D, "r12d", true, X86_REG_R12, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R12]), -1, 0, {} },
	{ X86_REG_R13D, "r13d", true, X86_REG_R13, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R13]), -1, 0, {} },
	{ X86_REG_R14D, "r14d", true, X86_REG_R14, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R14]), -1, 0, {} },
	{ X86_REG_R15D, "r15d", true, X86_REG_R15, 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R15]), -1, 0, {} },
	{ X86_REG_R8W, "r8w", true, X86_REG_R8, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R8]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R8]), -1, 0, {} },
	{ X86_REG_R9W, "r9w", true, X86_REG_R9, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R9]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R9]), -1, 0, {} },
	{ X86_REG_R10W, "r10w", true, X86_REG_R10, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R10]), -1, 0, {} },
	{ X86_REG_R11W, "r11w", true, X86_REG_R11, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R11]), -1, 0, {} },
	{ X86_REG_R12W, "r12w", true, X86_REG_R12, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R12]), -1, 0, {} },
	{ X86_REG_R13W, "r13w", true, X86_REG_R13, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R13]), -1, 0, {} },
	{ X86_REG_R14W, "r14w", true, X86_REG_R14, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R14]), -1, 0, {} },
	{ X86_REG_R15W, "r15w", true, X86_REG_R15, 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R15]), -1, 0, {} },
	// { X86_REG_BND0, "bnd0", 16, 1, -1, -1, -1, 0, {} },
	// { X86_REG_BND1, "bnd0", 16, 1, -1, -1, -1, 0, {} },
	// { X86_REG_BND2, "bnd0", 16, 1, -1, -1, -1, 0, {} },
	// { X86_REG_BND3, "bnd0", 16, 1, -1, -1, -1, 0, {} }
};

static unsigned reg_table_size = sizeof(reg_table) / sizeof(struct reg_entry);

inline struct reg_entry *dw_get_reg_entry(unsigned reg)
{
	if (reg >= reg_table_size)
		return NULL;
	return (reg_table + reg);
}

inline bool reg_is_gpr(unsigned reg)
{
	struct reg_entry *re = dw_get_reg_entry(reg);
	return re && re->is_gpr;
}

/*
 * Helper structure and function for decode_extended_states and save_extended_states,
 * whose role is to decode/encode AVX registers
 */
struct xstate_slice {
	uint8_t *ptr;
	size_t len;
};

static bool gather_xstate_slices(unsigned reg, void *fp, struct patch_x86_64_xsave_header *hdr,
						    struct xstate_slice *slices, size_t *slice_count, size_t *total_len)
{
	size_t count = 0;
	size_t total = 0;

	if (!fp || !hdr || !slices || !slice_count || !total_len)
		return false;

	if (reg_is_avx512(reg)) {
		if (reg <= X86_REG_ZMM15) {
			if (!(hdr->xstate_bv & (1ull << PATCH_X86_64_AVX512_ZMM_HI256_STATE)))
				return false;

			struct patch_x86_64_legacy *sse;
			struct patch_x86_64_avx *avx;
			struct patch_x86_64_avx512_zmm_hi256 *zmm_hi;

			if (patch_x86_sse_state(fp, &sse) != PATCH_OK ||
			    patch_x86_avx_state(fp, &avx) != PATCH_OK ||
			    patch_x86_avx512_zmm_hi256_state(fp, &zmm_hi) != PATCH_OK)
				return false;

			int reg_idx = reg - X86_REG_ZMM0;

			slices[count++] = (struct xstate_slice){ (uint8_t *)&sse->xmm0 + reg_idx * 16, 16 };
			slices[count++] = (struct xstate_slice){ (uint8_t *)&avx->ymm0 + reg_idx * 16, 16 };
			slices[count++] = (struct xstate_slice){ (uint8_t *)&zmm_hi->zmm0 + reg_idx * 32, 32 };
		} else {
			if (!(hdr->xstate_bv & (1ull << PATCH_X86_64_AVX512_HI16_ZMM_STATE)))
				return false;

			struct patch_x86_64_avx512_hi16_zmm *hi16_zmm;
			if (patch_x86_avx512_hi16_zmm_state(fp, &hi16_zmm) != PATCH_OK)
				return false;

			int reg_idx = reg - X86_REG_ZMM16;
			slices[count++] = (struct xstate_slice){ (uint8_t *)&hi16_zmm->zmm16 + reg_idx * 64, 64 };
		}
	} else if (reg_is_avx2(reg)) {
		if (!(hdr->xstate_bv & (1ull << PATCH_X86_64_AVX_STATE)))
			return false;

		if (reg <= X86_REG_YMM15) {
			struct patch_x86_64_legacy *sse;
			struct patch_x86_64_avx *avx;

			if (patch_x86_sse_state(fp, &sse) != PATCH_OK ||
			    patch_x86_avx_state(fp, &avx) != PATCH_OK)
				return false;

			int reg_idx = reg - X86_REG_YMM0;

			slices[count++] = (struct xstate_slice){ (uint8_t *)&sse->xmm0 + reg_idx * 16, 16 };
			slices[count++] = (struct xstate_slice){ (uint8_t *)&avx->ymm0 + reg_idx * 16, 16 };
		} else {
			struct patch_x86_64_avx512_hi16_zmm *hi16_zmm;

			if (patch_x86_avx512_hi16_zmm_state(fp, &hi16_zmm) != PATCH_OK)
				return false;

			int reg_idx = reg - X86_REG_YMM16;
			slices[count++] = (struct xstate_slice){ (uint8_t *)&hi16_zmm->zmm16 + reg_idx * 64, 32 };
		}
	} else if (reg_is_sse(reg)) {
		if (!(hdr->xstate_bv & (1ull << PATCH_X86_64_SSE_STATE)))
			return false;

		if (reg <= X86_REG_XMM15) {
			struct patch_x86_64_legacy *sse;

			if (patch_x86_sse_state(fp, &sse) != PATCH_OK)
				return false;

			int reg_idx = reg - X86_REG_XMM0;
			slices[count++] = (struct xstate_slice){ (uint8_t *)&sse->xmm0 + reg_idx * 16, 16 };
		} else {
			struct patch_x86_64_avx512_hi16_zmm *hi16_zmm;

			if (patch_x86_avx512_hi16_zmm_state(fp, &hi16_zmm) != PATCH_OK)
				return false;

			int reg_idx = reg - X86_REG_XMM16;
			slices[count++] = (struct xstate_slice){ (uint8_t *)&hi16_zmm->zmm16 + reg_idx * 64, 16 };
		}
	} else {
		return false;
	}

	for (size_t i = 0; i < count; ++i)
		total += slices[i].len;

	*slice_count = count;
	*total_len = total;
	return count > 0;
}

/*
 * Decode an AVX register from signal or libpatch ucontext.
 *
 * This function decodes XMM, YMM, and ZMM registers. It uses helper functions from libpatch
 * to locate the different state components (SSE, AVX, AVX-512) within the fpregs save area.
 *
 * The register value is reconstructed from different parts of the floating-point register save area
 * (fpregs) in the ucontext. The layout of this area is defined by the x86-64 XSAVE feature set.
 *
 * - XMM registers (128 bits) are the base
 * - YMM register (256 bits) is composed of an XMM register (lower 128 bits) and an upper 128 bits part
 * - ZMM register (512 bits) is composed of a YMM register (lower 256 bits) and an upper 256 bits part
 */
size_t decode_extended_states(unsigned reg, void *fp, uint8_t *out)
{
	if (!fp || !out)
		return 0;

	struct patch_x86_64_xsave_header *hdr = (void *)((char *)fp + sizeof(struct patch_x86_64_legacy));

	if (reg_is_avx512_opmask(reg)) {
		if (!(hdr->xstate_bv & (1ull << PATCH_X86_64_AVX512_OPMASK_STATE)))
			return 0;

		struct patch_x86_64_avx512_opmask *opmask;

		if (patch_x86_avx512_opmask_state(fp, &opmask) == PATCH_OK) {
			unsigned reg_idx = reg - X86_REG_K0;

			memcpy(out, (uint8_t *)&opmask->k0 + reg_idx * sizeof(opmask->k0), sizeof(opmask->k0));
			return sizeof(opmask->k0);
		}

		return 0;
	}

	struct xstate_slice slices[3];
	size_t slice_count = 0, total_len = 0;

	if (!gather_xstate_slices(reg, fp, hdr, slices, &slice_count, &total_len))
		return 0;

	for (size_t i = 0; i < slice_count; ++i) {
		memcpy(out, slices[i].ptr, slices[i].len);
		out += slices[i].len;
	}

	return total_len;
}

/*
 * Encode an AVX register value into a signal or libpatch ucontext.
 */
size_t save_extended_states(unsigned reg, void *fp, const uint8_t *in)
{
	if (!fp || !in) return 0;

	struct patch_x86_64_xsave_header *hdr = (void *)((char *)fp + sizeof(struct patch_x86_64_legacy));

	struct xstate_slice slices[3];
	size_t slice_count = 0;
	size_t total_len = 0;

	if (!gather_xstate_slices(reg, fp, hdr, slices, &slice_count, &total_len))
		return 0;

	for (size_t i = 0; i < slice_count; ++i) {
		memcpy(slices[i].ptr, in, slices[i].len);
		in += slices[i].len;
	}

	return total_len;
}

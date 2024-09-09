#define _GNU_SOURCE 1

#include "dw-registers.h"
#include <ucontext.h>
#include <libpatch/patch.h>
#include <capstone/capstone.h>

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
//
// Install new version of libolx, fill in the table in a separate file
// Make separate functions to untaint / taint called from hooks
// Have assertions in those functions
// Check on small program
// Print if xmm/ymm case
// Debug wrappers

unsigned dw_saved_registers[] = {
    X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, X86_REG_RSI, 
    X86_REG_RDI, X86_REG_RBP, X86_REG_R8, X86_REG_R9, X86_REG_R10,
    X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15};
    
const unsigned dw_nb_saved_registers = sizeof(dw_saved_registers) / sizeof(unsigned);

uintptr_t dw_save_regs[sizeof(dw_saved_registers) / sizeof(unsigned)];

struct reg_entry reg_table[] = {
    { X86_REG_INVALID, NULL, 0, 1, -1, -1, -1, 0, {} },
    { X86_REG_AH, "ah", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX])+1, offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX])+1, -1, 0, {} },
    { X86_REG_AL, "al", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX]), -1, 0, {} },
    { X86_REG_AX, "ax", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX]), -1, 0, {} },
    { X86_REG_BH, "bh", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX])+1, offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX])+1, -1, 0, {} },
    { X86_REG_BL, "bl", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX]), -1, 0, {} },
    { X86_REG_BP, "bp", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX]), -1, 0, {} },
    { X86_REG_BPL, "bpl", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBP]), -1, 0, {} },
    { X86_REG_BX, "bx", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBP]), -1, 0, {} },
    { X86_REG_CH, "ch", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX])+1, offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX])+1, -1, 0, {} },
    { X86_REG_CL, "cl", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX]), -1, 0, {} },
    { X86_REG_CS, "cs", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_CX, "cx", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX]), -1, 0, {} },
    { X86_REG_DH, "dh", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX])+1, offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX])+1, -1, 0, {} },
    { X86_REG_DI, "di", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDI]), -1, 0, {} },
    { X86_REG_DIL, "dil", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDI]), -1, 0, {} },
    { X86_REG_DL, "dl", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX]), -1, 0, {} },
    { X86_REG_DS, "ds", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_DX, "dx", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX]), -1, 0, {} },
    { X86_REG_EAX, "eax", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX]), -1, 0, {} },
    { X86_REG_EBP, "ebp", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBP]), -1, 0, {} },
    { X86_REG_EBX, "ebx", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX]), -1, 0, {} },
    { X86_REG_ECX, "ecx", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX]), -1, 0, {} },
    { X86_REG_EDI, "edi", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDI]), -1, 0, {} },
    { X86_REG_EDX, "edx", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX]), -1, 0, {} },
    { X86_REG_EFLAGS, "flags", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_EFL]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_EFL]) */, -1, 0, {} },
    { X86_REG_EIP, "eip", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RIP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RIP]) */, -1, 0, {} },
    { X86_REG_EIZ, "eiz", 4, 1, -1, -1, -1, 0, {} },
    { X86_REG_ES, "es", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
    { X86_REG_ESI, "esi", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
    { X86_REG_ESP, "esp", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSP]) */, -1, 0, {} },
    { X86_REG_FPSW, "fpsw", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_FS, "fs", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_GS, "gs", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_IP, "ip", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RIP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RIP]) */, -1, 0, {} },
    { X86_REG_RAX, "rax", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RAX]), -1, 0, {} },
    { X86_REG_RBP, "rbp", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBP]), -1, 0, {} },
    { X86_REG_RBX, "rbx", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RBX]), -1, 0, {} },
    { X86_REG_RCX, "rcx", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RCX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RCX]), -1, 0, {} },
    { X86_REG_RDI, "rdi", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDI]), -1, 0, {} },
    { X86_REG_RDX, "rdx", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RDX]), -1, 0, {} },
    { X86_REG_RIP, "rip", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RIP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RIP]) */, -1, 0, {} },
    { X86_REG_RIZ, "riz", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_RSI, "rsi", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
    { X86_REG_RSP, "rsp", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSP]) */, -1, 0, {} },
    { X86_REG_SI, "si", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
    { X86_REG_SIL, "sil", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSI]), -1, 0, {} },
    { X86_REG_SP, "sp", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSP]) */, -1, 0, {} },
    { X86_REG_SPL, "spl", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_RSP]), -1 /* offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_RSP]) */, -1, 0, {} },
    { X86_REG_SS, "ss", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR0, "cr0", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR1, "cr1", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR2, "cr2", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR3, "cr3", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR4, "cr4", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR5, "cr5", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR6, "cr6", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR7, "cr7", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR8, "cr8", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR9, "cr9", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR10, "cr10", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR11, "cr11", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR12, "cr12", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR13, "cr13", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR14, "cr14", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_CR15, "cr15", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR0, "dr0", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR1, "dr1", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR2, "dr2", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR3, "dr3", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR4, "dr4", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR5, "dr5", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR6, "dr6", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR7, "dr7", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR8, "dr8", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR9, "dr9", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR10, "dr10", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR11, "dr11", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR12, "dr12", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR13, "dr13", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR14, "dr14", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_DR15, "dr15", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_FP0, "fp0", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_FP1, "fp1", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_FP2, "fp2", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_FP3, "fp3", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_FP4, "fp4", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_FP5, "fp5", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_FP6, "fp6", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_FP7, "fp7", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_K0, "k0", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_K1, "k1", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_K2, "k2", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_K3, "k3", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_K4, "k4", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_K5, "k5", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_K6, "k6", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_K7, "k7", 2, 1, -1, -1, -1, 0, {} },
    { X86_REG_MM0, "mm0", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_MM1, "mm1", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_MM2, "mm2", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_MM3, "mm3", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_MM4, "mm4", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_MM5, "mm5", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_MM6, "mm6", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_MM7, "mm7", 8, 1, -1, -1, -1, 0, {} },
    { X86_REG_R8, "r8", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R8]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R8]), -1, 0, {} },
    { X86_REG_R9, "r9", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R9]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R9]), -1, 0, {} },
    { X86_REG_R10, "r10", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R10]), -1, 0, {} },
    { X86_REG_R11, "r11", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R11]), -1, 0, {} },
    { X86_REG_R12, "r12", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R12]), -1, 0, {} },
    { X86_REG_R13, "r13", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R13]), -1, 0, {} },
    { X86_REG_R14, "r14", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R14]), -1, 0, {} },
    { X86_REG_R15, "r15", 8, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R15]), -1, 0, {} },
    { X86_REG_ST0, "st0", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_ST1, "st1", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_ST2, "st2", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_ST3, "st3", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_ST4, "st4", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_ST5, "st5", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_ST6, "st6", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_ST7, "st7", 10, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM0, "xmm0", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM1, "xmm1", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM2, "xmm2", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM3, "xmm3", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM4, "xmm4", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM5, "xmm5", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM6, "xmm6", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM7, "xmm7", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM8, "xmm8", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM9, "xmm9", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM10, "xmm10", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM11, "xmm11", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM12, "xmm12", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM13, "xmm13", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM14, "xmm14", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM15, "xmm15", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM16, "xmm16", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM17, "xmm17", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM18, "xmm18", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM19, "xmm19", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM20, "xmm20", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM21, "xmm21", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM22, "xmm22", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM23, "xmm23", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM24, "xmm24", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM25, "xmm25", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM26, "xmm26", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM27, "xmm27", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM28, "xmm28", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM29, "xmm29", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM30, "xmm30", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_XMM31, "xmm31", 16, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM0, "ymm0", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM1, "ymm1", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM2, "ymm2", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM3, "ymm3", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM4, "ymm4", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM5, "ymm5", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM6, "ymm6", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM7, "ymm7", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM8, "ymm8", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM9, "ymm9", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM10, "ymm10", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM11, "ymm11", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM12, "ymm12", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM13, "ymm13", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM14, "ymm14", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM15, "ymm15", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM16, "ymm16", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM17, "ymm17", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM18, "ymm18", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM19, "ymm19", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM20, "ymm20", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM21, "ymm21", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM22, "ymm22", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM23, "ymm23", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM24, "ymm24", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM25, "ymm25", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM26, "ymm26", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM27, "ymm27", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM28, "ymm28", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM29, "ymm29", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM30, "ymm30", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_YMM31, "ymm31", 32, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM0, "zmm0", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM1, "zmm1", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM2, "zmm2", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM3, "zmm3", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM4, "zmm4", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM5, "zmm5", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM6, "zmm6", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM7, "zmm7", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM8, "zmm8", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM9, "zmm9", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM10, "zmm10", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM11, "zmm11", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM12, "zmm12", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM13, "zmm13", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM14, "zmm14", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM15, "zmm15", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM16, "zmm16", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM17, "zmm17", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM18, "zmm18", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM19, "zmm19", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM20, "zmm20", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM21, "zmm21", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM22, "zmm22", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM23, "zmm23", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM24, "zmm24", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM25, "zmm25", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM26, "zmm26", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM27, "zmm27", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM28, "zmm28", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM29, "zmm29", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM30, "zmm30", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_ZMM31, "zmm31", 64, 1, -1, -1, -1, 0, {} },
    { X86_REG_R8B, "r8b", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R8]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R8]), -1, 0, {} },
    { X86_REG_R9B, "r9b", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R9]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R9]), -1, 0, {} },
    { X86_REG_R10B, "r10b", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R10]), -1, 0, {} },
    { X86_REG_R11B, "r11b", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R11]), -1, 0, {} },
    { X86_REG_R12B, "r12b", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R12]), -1, 0, {} },
    { X86_REG_R13B, "r13b", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R13]), -1, 0, {} },
    { X86_REG_R14B, "r14b", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R14]), -1, 0, {} },
    { X86_REG_R15B, "r15b", 1, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R15]), -1, 0, {} },
    { X86_REG_R8D, "r8d", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R8]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R8]), -1, 0, {} },
    { X86_REG_R9D, "r9d", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R9]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R9]), -1, 0, {} },
    { X86_REG_R10D, "r10d", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R10]), -1, 0, {} },
    { X86_REG_R11D, "r11d", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R11]), -1, 0, {} },
    { X86_REG_R12D, "r12d", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R12]), -1, 0, {} },
    { X86_REG_R13D, "r13d", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R13]), -1, 0, {} },
    { X86_REG_R14D, "r14d", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R14]), -1, 0, {} },
    { X86_REG_R15D, "r15d", 4, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R15]), -1, 0, {} },
    { X86_REG_R8W, "r8w", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R8]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R8]), -1, 0, {} },
    { X86_REG_R9W, "r9w", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R9]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R9]), -1, 0, {} },
    { X86_REG_R10W, "r10w", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R10]), -1, 0, {} },
    { X86_REG_R11W, "r11w", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R11]), -1, 0, {} },
    { X86_REG_R12W, "r12w", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R12]), -1, 0, {} },
    { X86_REG_R13W, "r13w", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R13]), -1, 0, {} },
    { X86_REG_R14W, "r14w", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R14]), -1, 0, {} },
    { X86_REG_R15W, "r15w", 2, 1, offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]), offsetof(struct patch_exec_context, general_purpose_registers[PATCH_X86_64_R15]), -1, 0, {} },
//    { X86_REG_BND0, "bnd0", 16, 1, -1, -1, -1, 0, {} },
//    { X86_REG_BND1, "bnd0", 16, 1, -1, -1, -1, 0, {} },
//    { X86_REG_BND2, "bnd0", 16, 1, -1, -1, -1, 0, {} },
//    { X86_REG_BND3, "bnd0", 16, 1, -1, -1, -1, 0, {} }
};

static unsigned reg_table_size = sizeof(reg_table) / sizeof(struct reg_entry);

struct reg_entry *dw_get_reg_entry(unsigned reg)
{
    if(reg >= reg_table_size) return NULL;
    return (reg_table + reg);
}

#if 0
void dw_test_proc(void *arg)
{
  register void *tmp1 asm ("r12");
  register void *tmp2 asm ("r13");
  register void *tmp3 asm ("r14");
  register void *tmp4 asm ("r15");

  uintptr_t *ptr = (uintptr_t *)arg;
  uintptr_t var1 = ptr[0];
  uintptr_t var2 = ptr[1];
  uintptr_t var3 = ptr[2];
  uintptr_t var4 = ptr[3];
  uintptr_t var5 = ptr[4];
  uintptr_t var6 = ptr[5];
  uintptr_t var7 = ptr[6];
  uintptr_t var8 = ptr[7];

  var2 = var1 + var2;
  var3 = var2 + var3;
  var4 = var3 + var4;
  var5 = var4 + var5;
  var6 = var5 + var6;
  var7 = var6 + var7;
  var8 = var7 + var8;
  fprintf(stderr, "%lu %lu %lu %lu %lu %lu %lu %lu %p %p %p %p\n", var1, var2, var3, var4, var5, var6, var7, var8, tmp1, tmp2, tmp3, tmp4);
}

// The epilogue needs to retaint the pointer contained in the register.
// Here we have saved the register before it was untainted. We simply pop it back.
// The table contains for each register the code for popping it.
// We also have to replace the stack pointer, because we jumped over the red zone.
// The code is in epilogue_red_zone.
//
//    pop %r8
//    leaq 0x80(%rsp), %rsp

static uint8_t epilogue_red_zone[] = {0x48, 0x8d, 0xa4, 0x24, 0x80, 0x00, 0x00, 0x00};

struct register_entry olx_restore_taint_table[] = {
    {"r8", 1, {0x41, 0x58}},
    {"r9", 1, {0x41, 0x59}},
    {"r10", 1, {0x41, 0x5a}},
    {"r11", 1, {0x41, 0x5b}},
    {"r12", 1, {0x41, 0x5c}},
    {"r13", 1, {0x41, 0x5d}},
    {"r14", 1, {0x41, 0x5e}},
    {"r15", 1, {0x41, 0x5f}},
    {"rdi", 1, {0x5f, 0x00}},
    {"rsi", 1, {0x5e, 0x00}},
    {"rbp", 1, {0x5d, 0x00}},
    {"rbx", 1, {0x5b, 0x00}},
    {"rdx", 1, {0x5a, 0x00}},
    {"rax", 1, {0x58, 0x00}},
    {"rcx", 1, {0x59, 0x00}},
    {"rsp", 1, {0x5c, 0x00}}
};

// For this test, we just put back 0x0001 in the unused MS bytes.
// Ideally, the epilogue should not affect any flag or use other registers.
// Otherwise, it would have to save and restore them.
// The following sequence should do the trick to add 0x0001 (shown for r8)
//
//    rorxq   $48, %r8, %r8
//    leaq    0x1(%r8), %r8
//    rorxq   $16, %r8, %r8

struct register_entry olx_naive_table[] = {
    {"r8", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xc0, 0x30, 0x4d, 0x8d, 0x40, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xc0, 0x10, 0x00}},
    {"r9", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xc9, 0x30, 0x4d, 0x8d, 0x49, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xc9, 0x10, 0x00}},
    {"r10", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xd2, 0x30, 0x4d, 0x8d, 0x52, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xd2, 0x10, 0x00}},
    {"r11", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xdb, 0x30, 0x4d, 0x8d, 0x5b, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xdb, 0x10, 0x00}},
    {"r12", 17, {0xc4, 0x43, 0xfb, 0xf0, 0xe4, 0x30, 0x4d, 0x8d, 0x64, 0x24, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xe4, 0x10}},
    {"r13", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xed, 0x30, 0x4d, 0x8d, 0x6d, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xed, 0x10, 0x00}},
    {"r14", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xf6, 0x30, 0x4d, 0x8d, 0x76, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xf6, 0x10, 0x00}},
    {"r15", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xff, 0x30, 0x4d, 0x8d, 0x7f, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xff, 0x10, 0x00}},
    {"rdi", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xff, 0x30, 0x48, 0x8d, 0x7f, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xff, 0x10, 0x00}},
    {"rsi", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xf6, 0x30, 0x48, 0x8d, 0x76, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xf6, 0x10, 0x00}},
    {"rbp", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xed, 0x30, 0x48, 0x8d, 0x6d, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xed, 0x10, 0x00}},
    {"rbx", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xdb, 0x30, 0x48, 0x8d, 0x5b, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xdb, 0x10, 0x00}},
    {"rdx", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xd2, 0x30, 0x48, 0x8d, 0x52, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xd2, 0x10, 0x00}},
    {"rax", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xc0, 0x30, 0x48, 0x8d, 0x40, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xc0, 0x10, 0x00}},
    {"rcx", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xc9, 0x30, 0x48, 0x8d, 0x49, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xc9, 0x10, 0x00}},
    {"rsp", 17, {0xc4, 0xe3, 0xfb, 0xf0, 0xe4, 0x30, 0x48, 0x8d, 0x64, 0x24, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xe4, 0x10}}
};
#endif // 0

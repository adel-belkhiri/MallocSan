#ifndef DW_CPUID_H
#define DW_CPUID_H

#include <stdint.h>

/*
 * Check for CPU features such as XSAVE support (copied from libpatch).
 */
static inline void dw_cpuid(uint32_t in_eax, uint32_t in_ecx, uint32_t *out_eax, uint32_t *out_ebx,
							uint32_t *out_ecx, uint32_t *out_edx)
{
	register uint32_t eax asm ("eax") = in_eax;
	register uint32_t ebx asm ("ebx");
	register uint32_t ecx asm ("ecx") = in_ecx;
	register uint32_t edx asm ("edx");

	asm volatile("cpuid" : "+r"(eax), "=r"(ebx), "+r"(ecx), "=r"(edx) : :);

	if (out_eax)
		*out_eax = eax;
	if (out_ebx)
		*out_ebx = ebx;
	if (out_ecx)
		*out_ecx = ecx;
	if (out_edx)
		*out_edx = edx;
}

static inline uint32_t dw_cpuid_max_leaf(void)
{
	uint32_t eax = 0;
	dw_cpuid(0, 0, &eax, NULL, NULL, NULL);
	return eax;
}

static inline int dw_cpuid_has_leaf(uint32_t leaf)
{
	return dw_cpuid_max_leaf() >= leaf;
}

#endif

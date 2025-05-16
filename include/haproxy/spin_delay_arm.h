#ifndef _HAPROXY_SPIN_DELAY_ARM_H
#define _HAPROXY_SPIN_DELAY_ARM_H

#include "haproxy/compiler.h"

/* Global variable to track SB support */
extern int arm_has_sb_instruction;

#if defined(__aarch64__) || defined(__arm64__)

/* Use SB instruction if available, otherwise ISB */
static inline void spin_delay_arm(void) {
	if (__builtin_expect(arm_has_sb_instruction == 1, 1)) {
		asm volatile(".inst 0xd50330ff");   /* SB instruction encoding */
	} else {
		asm volatile("isb");
	}
}

#endif /* defined(__aarch64__) || defined(__arm64__) */
#endif /* _HAPROXY_SPIN_DELAY_ARM_H */

#include "haproxy/compiler.h"
#include "haproxy/spin_delay_arm.h"

/* Initialize to 0 (false) by default */
int arm_has_sb_instruction = 0;

#if defined(__linux__) && (defined(__aarch64__) || defined(__arm64__)) && \
	(defined(__GNUC__) || defined(__clang__))
#include <sys/auxv.h>

#ifndef HWCAP_SB
#define HWCAP_SB		(1 << 29)
#endif  // HWCAP_SB

__attribute__((constructor))
void detect_arm_sb_support(void) {
    arm_has_sb_instruction = (getauxval(AT_HWCAP) & HWCAP_SB) ? 1 : 0;
}

#endif

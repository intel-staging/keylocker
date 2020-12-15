/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_KEYLOCKER_H
#define _ASM_KEYLOCKER_H

#ifndef __ASSEMBLY__

#include <linux/bits.h>
#include <asm/fpu/types.h>

/**
 * struct iwkey - A temporary wrapping key storage.
 * @integrity_key:	A 128-bit key used to verify the integrity of
 *			key handles
 * @encryption_key:	A 256-bit encryption key used for wrapping and
 *			unwrapping clear text keys.
 *
 * This storage should be flushed immediately after being loaded.
 */
struct iwkey {
	struct reg_128_bit integrity_key;
	struct reg_128_bit encryption_key[2];
};

#define KEYLOCKER_CPUID			0x019
#define KEYLOCKER_CPUID_EAX_SUPERVISOR	BIT(0)
#define KEYLOCKER_CPUID_EBX_AESKLE	BIT(0)
#define KEYLOCKER_CPUID_EBX_WIDE	BIT(2)
#define KEYLOCKER_CPUID_EBX_BACKUP	BIT(4)

#ifdef CONFIG_X86_KEYLOCKER
void setup_keylocker(void);
void restore_keylocker(void);
extern bool valid_keylocker(void);
#else
static inline void setup_keylocker(void) { }
static inline void restore_keylocker(void) { }
static inline bool valid_keylocker(void) { return false; }
#endif

#endif /*__ASSEMBLY__ */
#endif /* _ASM_KEYLOCKER_H */

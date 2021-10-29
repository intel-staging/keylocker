/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_KEYLOCKER_H
#define _ASM_KEYLOCKER_H

#ifndef __ASSEMBLY__

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

#endif /*__ASSEMBLY__ */
#endif /* _ASM_KEYLOCKER_H */

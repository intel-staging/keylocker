/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _AESKL_INTEL_GLUE_H
#define _AESKL_INTEL_GLUE_H

#include <crypto/aes.h>
#include <linux/types.h>

#define AESKL_AAD_SIZE		16
#define AESKL_TAG_SIZE		16
#define AESKL_CIPHERTEXT_MAX	AES_KEYSIZE_256

/* The Key Locker handle is an encoded form of the AES key. */
struct aeskl_handle {
	u8 additional_authdata[AESKL_AAD_SIZE];
	u8 integrity_tag[AESKL_TAG_SIZE];
	u8 ciphre_text[AESKL_CIPHERTEXT_MAX];
};

/*
 * Key Locker does not support 192-bit key size. The driver needs to
 * retrieve the key size in the first place. The offset of the
 * 'key_length' field here should be compatible with struct
 * crypto_aes_ctx.
 */
#define AESKL_CTX_RESERVED (sizeof(struct crypto_aes_ctx) - sizeof(struct aeskl_handle) \
			    - sizeof(u32))

struct aeskl_ctx {
	struct aeskl_handle handle;
	u8 reserved[AESKL_CTX_RESERVED];
	u32 key_length;
};

#endif /* _AESKL_INTEL_GLUE_H */

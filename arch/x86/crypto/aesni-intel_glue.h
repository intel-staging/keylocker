/* SPDX-License-Identifier: GPL-2.0 */

/*
 * These are AES-NI functions that are used by the AES-KL code as a
 * fallback when it is given a 192-bit key. Key Locker does not support
 * 192-bit keys.
 */

#ifndef _AESNI_INTEL_GLUE_H
#define _AESNI_INTEL_GLUE_H

asmlinkage void aesni_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
			      unsigned int key_len);
asmlinkage void __aesni_enc(const void *ctx, u8 *out, const u8 *in);
asmlinkage void __aesni_xts_encrypt(const struct crypto_aes_ctx *ctx, u8 *out,
				    const u8 *in, unsigned int len, u8 *iv);
asmlinkage void __aesni_xts_decrypt(const struct crypto_aes_ctx *ctx, u8 *out,
				    const u8 *in, unsigned int len, u8 *iv);

static inline int aesni_enc(const void *ctx, u8 *out, const u8 *in)
{
	__aesni_enc(ctx, out, in);
	return 0;
}

static inline int aesni_xts_encrypt(const union x86_aes_ctx *ctx, u8 *out, const u8 *in,
				    unsigned int len, u8 *iv)
{
	__aesni_xts_encrypt(&ctx->aesni, out, in, len, iv);
	return 0;
}

static inline int aesni_xts_decrypt(const union x86_aes_ctx *ctx, u8 *out, const u8 *in,
				    unsigned int len, u8 *iv)
{
	__aesni_xts_decrypt(&ctx->aesni, out, in, len, iv);
	return 0;
}

#endif /* _AESNI_INTEL_GLUE_H */

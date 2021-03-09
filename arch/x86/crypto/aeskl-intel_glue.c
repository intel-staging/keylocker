// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Support for AES Key Locker instructions. This file contains glue
 * code and the real AES implementation is in aeskl-intel_asm.S.
 *
 * Most code is based on AES-NI glue code, aesni-intel_glue.c
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/err.h>
#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/xts.h>
#include <crypto/internal/skcipher.h>
#include <crypto/internal/simd.h>
#include <asm/simd.h>
#include <asm/cpu_device_id.h>
#include <asm/fpu/api.h>
#include <asm/keylocker.h>

#include "aes-helper_glue.h"
#include "aesni-intel_glue.h"

asmlinkage int aeskl_setkey(struct crypto_aes_ctx *ctx, const u8 *in_key, unsigned int keylen);

asmlinkage int __aeskl_enc(const void *ctx, u8 *out, const u8 *in);
asmlinkage int __aeskl_dec(const void *ctx, u8 *out, const u8 *in);

asmlinkage int __aeskl_xts_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in,
				   unsigned int len, u8 *iv);
asmlinkage int __aeskl_xts_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in,
				   unsigned int len, u8 *iv);

static int aeskl_setkey_common(struct crypto_tfm *tfm, void *raw_ctx, const u8 *in_key,
			       unsigned int keylen)
{
	/* raw_ctx is an aligned address via xts_setkey_common() */
	struct crypto_aes_ctx *ctx = (struct crypto_aes_ctx *)raw_ctx;
	int err;

	if (!crypto_simd_usable())
		return -EBUSY;

	if (keylen != AES_KEYSIZE_128 && keylen != AES_KEYSIZE_192 &&
	    keylen != AES_KEYSIZE_256)
		return -EINVAL;

	kernel_fpu_begin();
	if (unlikely(keylen == AES_KEYSIZE_192)) {
		pr_warn_once("AES-KL does not support 192-bit key. Use AES-NI.\n");
		err = aesni_set_key(ctx, in_key, keylen);
	} else {
		if (!valid_keylocker())
			err = -ENODEV;
		else
			err = aeskl_setkey(ctx, in_key, keylen);
	}
	kernel_fpu_end();

	return err;
}

/*
 * The below wrappers for the encryption/decryption functions
 * incorporate the feature availability check:
 *
 * In the rare event of hardware failure, the wrapping key can be lost
 * after wake-up from a deep sleep state. Then, this check helps to
 * avoid any subsequent misuse with populating a proper error code.
 */

static inline int aeskl_enc(const void *ctx, u8 *out, const u8 *in)
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_enc(ctx, out, in);
}

static inline int aeskl_dec(const void *ctx, u8 *out, const u8 *in)
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_dec(ctx, out, in);
}

static inline int aeskl_xts_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in,
				    unsigned int len, u8 *iv)
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_xts_encrypt(ctx, out, in, len, iv);
}

static inline int aeskl_xts_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in,
				    unsigned int len, u8 *iv)
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_xts_decrypt(ctx, out, in, len, iv);
}

static int aeskl_xts_setkey(struct crypto_skcipher *tfm, const u8 *key,
			    unsigned int keylen)
{
	return xts_setkey_common(tfm, key, keylen, aeskl_setkey_common);
}

static inline int xts_keylen(struct skcipher_request *req, u32 *keylen)
{
	struct aes_xts_ctx *ctx = aes_xts_ctx(crypto_skcipher_reqtfm(req));

	if (ctx->crypt_ctx.key_length != ctx->tweak_ctx.key_length)
		return -EINVAL;

	*keylen = ctx->crypt_ctx.key_length;
	return 0;
}

static int xts_encrypt(struct skcipher_request *req)
{
	u32 keylen;
	int err;

	err = xts_keylen(req, &keylen);
	if (err)
		return err;

	if (likely(keylen != AES_KEYSIZE_192))
		return xts_crypt_common(req, aeskl_xts_encrypt, aeskl_enc);
	else
		return xts_crypt_common(req, aesni_xts_encrypt, aesni_enc);
}

static int xts_decrypt(struct skcipher_request *req)
{
	u32 keylen;
	int rc;

	rc = xts_keylen(req, &keylen);
	if (rc)
		return rc;

	if (likely(keylen != AES_KEYSIZE_192))
		return xts_crypt_common(req, aeskl_xts_decrypt, aeskl_enc);
	else
		return xts_crypt_common(req, aesni_xts_decrypt, aesni_enc);
}

static struct skcipher_alg aeskl_skciphers[] = {
	{
		.base = {
			.cra_name		= "__xts(aes)",
			.cra_driver_name	= "__xts-aes-aeskl",
			.cra_priority		= 200,
			.cra_flags		= CRYPTO_ALG_INTERNAL,
			.cra_blocksize		= AES_BLOCK_SIZE,
			.cra_ctxsize		= XTS_AES_CTX_SIZE,
			.cra_module		= THIS_MODULE,
		},
		.min_keysize	= 2 * AES_MIN_KEY_SIZE,
		.max_keysize	= 2 * AES_MAX_KEY_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.walksize	= 2 * AES_BLOCK_SIZE,
		.setkey		= aeskl_xts_setkey,
		.encrypt	= xts_encrypt,
		.decrypt	= xts_decrypt,
	}
};

static struct simd_skcipher_alg *aeskl_simd_skciphers[ARRAY_SIZE(aeskl_skciphers)];

static int __init aeskl_init(void)
{
	u32 eax, ebx, ecx, edx;
	int err;

	if (!valid_keylocker())
		return -ENODEV;

	cpuid_count(KEYLOCKER_CPUID, 0, &eax, &ebx, &ecx, &edx);
	if (!(ebx & KEYLOCKER_CPUID_EBX_WIDE))
		return -ENODEV;

	/*
	 * AES-KL itself does not depend on AES-NI. But AES-KL does not
	 * support 192-bit keys. To make itself AES-compliant, it falls
	 * back to AES-NI.
	 */
	if (!boot_cpu_has(X86_FEATURE_AES))
		return -ENODEV;

	err = simd_register_skciphers_compat(aeskl_skciphers, ARRAY_SIZE(aeskl_skciphers),
					     aeskl_simd_skciphers);
	if (err)
		return err;

	return 0;
}

static void __exit aeskl_exit(void)
{
	simd_unregister_skciphers(aeskl_skciphers, ARRAY_SIZE(aeskl_skciphers),
				  aeskl_simd_skciphers);
}

late_initcall(aeskl_init);
module_exit(aeskl_exit);

MODULE_DESCRIPTION("Rijndael (AES) Cipher Algorithm, AES Key Locker implementation");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("aes");

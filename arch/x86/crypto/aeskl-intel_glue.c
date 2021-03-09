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

asmlinkage int __aeskl_setkey(struct crypto_aes_ctx *ctx, const u8 *in_key, unsigned int keylen);

asmlinkage int __aeskl_enc(const void *ctx, u8 *out, const u8 *in);

asmlinkage int __aeskl_xts_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in,
				   unsigned int len, u8 *iv);
asmlinkage int __aeskl_xts_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in,
				   unsigned int len, u8 *iv);

/*
 * In the event of hardware failure, the wrapping key can be lost
 * from a sleep state. Then, it is not usable anymore. The feature
 * state can be found via valid_keylocker().
 *
 * Such disabling can happen anywhere preemptible. So, to avoid the
 * race condition, check the availability on every use along with
 * kernel_fpu_begin().
 */

static int aeskl_setkey(struct crypto_tfm *tfm, void *raw_ctx, const u8 *in_key,
			unsigned int keylen)
{
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
			err = __aeskl_setkey(ctx, in_key, keylen);
	}
	kernel_fpu_end();

	return err;
}

static inline int aeskl_enc(const void *ctx, u8 *out, const u8 *in)
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_enc(ctx, out, in);
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

static int xts_setkey(struct crypto_skcipher *tfm, const u8 *key,
			    unsigned int keylen)
{
	return xts_setkey_common(tfm, key, keylen, aeskl_setkey);
}

static inline u32 xts_keylen(struct skcipher_request *req)
{
	struct aes_xts_ctx *ctx = aes_xts_ctx(crypto_skcipher_reqtfm(req));

	return ctx->crypt_ctx.key_length;
}

static int xts_encrypt(struct skcipher_request *req)
{
	u32 keylen = xts_keylen(req);

	if (likely(keylen != AES_KEYSIZE_192))
		return xts_crypt_common(req, aeskl_xts_encrypt, aeskl_enc);
	else
		return xts_crypt_common(req, aesni_xts_encrypt, aesni_enc);
}

static int xts_decrypt(struct skcipher_request *req)
{
	u32 keylen = xts_keylen(req);

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
		.setkey		= xts_setkey,
		.encrypt	= xts_encrypt,
		.decrypt	= xts_decrypt,
	}
};

static struct simd_skcipher_alg *aeskl_simd_skciphers[ARRAY_SIZE(aeskl_skciphers)];

static int __init aeskl_init(void)
{
	u32 eax, ebx, ecx, edx;

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

	return simd_register_skciphers_compat(aeskl_skciphers, ARRAY_SIZE(aeskl_skciphers),
					      aeskl_simd_skciphers);
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

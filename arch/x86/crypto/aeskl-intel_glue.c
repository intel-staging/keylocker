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

asmlinkage void __aeskl_setkey(struct aeskl_ctx *ctx, const u8 *in_key, unsigned int keylen);

asmlinkage int __aeskl_enc(const void *ctx, u8 *out, const u8 *in);

asmlinkage int __aeskl_xts_encrypt(const struct aeskl_ctx *ctx, u8 *out, const u8 *in,
				   unsigned int len, u8 *iv);
asmlinkage int __aeskl_xts_decrypt(const struct aeskl_ctx *ctx, u8 *out, const u8 *in,
				   unsigned int len, u8 *iv);

/*
 * If a hardware failure occurs, the wrapping key may be lost during
 * sleep states. The state of the feature can be retrieved via
 * valid_keylocker().
 *
 * Since disabling can occur preemptively, check for availability on
 * every use along with kernel_fpu_begin().
 */

static int aeskl_setkey(union x86_aes_ctx *ctx, const u8 *in_key, unsigned int keylen)
{
	int err;

	if (!crypto_simd_usable())
		return -EBUSY;

	err = aes_check_keylen(keylen);
	if (err)
		return err;

	if (unlikely(keylen == AES_KEYSIZE_192)) {
		pr_warn_once("AES-KL does not support 192-bit key. Use AES-NI.\n");
		kernel_fpu_begin();
		aesni_set_key(&ctx->aesni, in_key, keylen);
		kernel_fpu_end();
		return 0;
	}

	if (!valid_keylocker())
		return -ENODEV;

	kernel_fpu_begin();
	__aeskl_setkey(&ctx->aeskl, in_key, keylen);
	kernel_fpu_end();
	return 0;
}

static inline int aeskl_enc(const void *ctx, u8 *out, const u8 *in)
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_enc(ctx, out, in);
}

static inline int aeskl_xts_encrypt(const union x86_aes_ctx *ctx, u8 *out, const u8 *in,
				    unsigned int len, u8 *iv)
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_xts_encrypt(&ctx->aeskl, out, in, len, iv);
}

static inline int aeskl_xts_decrypt(const union x86_aes_ctx *ctx, u8 *out, const u8 *in,
				    unsigned int len, u8 *iv)
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_xts_decrypt(&ctx->aeskl, out, in, len, iv);
}

static int xts_setkey(struct crypto_skcipher *tfm, const u8 *key,
		      unsigned int keylen)
{
	return xts_setkey_common(tfm, key, keylen, aeskl_setkey);
}

static inline u32 xts_keylen(struct skcipher_request *req)
{
	struct aes_xts_ctx *ctx = aes_xts_ctx(crypto_skcipher_reqtfm(req));

	return ctx->crypt_ctx.aeskl.key_length;
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
	 * AES-KL itself does not rely on AES-NI. But, AES-KL does not
	 * support 192-bit keys. To ensure AES compliance, AES-KL falls
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

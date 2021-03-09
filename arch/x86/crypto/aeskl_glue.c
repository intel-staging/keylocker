// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Support for AES Key Locker instructions. This file contains glue
 * code and the real AES implementation is in aeskl-xts-x86_64.S.
 *
 * Most code is based on aesni-intel_glue.c
 */

#include <linux/err.h>
#include <linux/types.h>
#include <linux/module.h>

#include <crypto/aes.h>
#include <crypto/xts.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>

#include <asm/fpu/api.h>
#include <asm/keylocker.h>
#include <asm/simd.h>

#include "aesni-xts.h"

#define AES_ALIGN		16
#define AES_ALIGN_ATTR		__attribute__ ((__aligned__(AES_ALIGN)))
#define AES_ALIGN_EXTRA		((AES_ALIGN - 1) & ~(CRYPTO_MINALIGN - 1))

#define AESKL_AAD_SIZE		16
#define AESKL_TAG_SIZE		16
#define AESKL_CIPHERTEXT_MAX	AES_KEYSIZE_256

/* The Key Locker handle is an encoded form of the AES key. */
struct aeskl_handle {
	u8 additional_authdata[AESKL_AAD_SIZE];
	u8 integrity_tag[AESKL_TAG_SIZE];
	u8 cipher_text[AESKL_CIPHERTEXT_MAX];
};

/*
 * Key Locker does not support 192-bit key size. The driver needs to
 * retrieve the key size in the first place. The offset of the
 * 'key_length' field here must be compatible with struct
 * crypto_aes_ctx.
 */
#define AESKL_CTX_RESERVED (sizeof(struct crypto_aes_ctx) \
			    - sizeof(struct aeskl_handle) \
			    - sizeof(u32))

struct aeskl_ctx {
	struct aeskl_handle handle;
	u8 reserved[AESKL_CTX_RESERVED];
	u32 key_length;
};

/*
 * Unify the two context structures to represent the crypto context.
 * Depending on the key size, either AES-KL or AES-NI will be used.
 */
union x86_aes_ctx {
	struct aeskl_ctx      aeskl;
	struct crypto_aes_ctx aesni;
};

struct xts_aes_ctx {
	union x86_aes_ctx tweak_ctx AES_ALIGN_ATTR;
	union x86_aes_ctx crypt_ctx AES_ALIGN_ATTR;
};

static inline struct xts_aes_ctx *xts_aes_ctx(struct crypto_skcipher *tfm)
{
	void *addr = crypto_skcipher_ctx(tfm);

	if (crypto_tfm_ctx_alignment() >= AES_ALIGN)
		return addr;

	return PTR_ALIGN(addr, AES_ALIGN);
}

static inline u32 xts_keylen(struct skcipher_request *req)
{
	struct xts_aes_ctx *ctx = xts_aes_ctx(crypto_skcipher_reqtfm(req));

	BUILD_BUG_ON(offsetof(struct crypto_aes_ctx, key_length) !=
		     offsetof(struct aeskl_ctx, key_length));

	return ctx->crypt_ctx.aeskl.key_length;
}

asmlinkage void __aeskl_setkey(struct aeskl_ctx *handle, const u8 *key, unsigned int keylen);

asmlinkage int __aeskl_enc(const void *handle, u8 *dst, const u8 *src);

asmlinkage int __aeskl_xts_encrypt(const struct aeskl_ctx *handle, u8 *dst, const u8 *src,
				   unsigned int len, u8 *tweak);
asmlinkage int __aeskl_xts_decrypt(const struct aeskl_ctx *handle, u8 *dst, const u8 *src,
				   unsigned int len, u8 *tweak);

/*
 * If a hardware failure occurs, the wrapping key may be lost during
 * sleep states. The state of the feature can be retrieved via
 * valid_keylocker().
 *
 * Since disabling can occur preemptively, check for availability on
 * every use along with kernel_fpu_begin().
 */

static int aeskl_setkey(struct aeskl_ctx *ctx, const u8 *in_key, unsigned int keylen)
{
	if (!crypto_simd_usable())
		return -EBUSY;

	kernel_fpu_begin();
	if (!valid_keylocker()) {
		kernel_fpu_end();
		return -ENODEV;
	}

	__aeskl_setkey(ctx, in_key, keylen);
	kernel_fpu_end();
	return 0;
}

static int aeskl_xts_encrypt_iv(const struct aeskl_ctx *tweak_key,
				u8 iv[AES_BLOCK_SIZE])
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_enc(tweak_key, iv, iv);
}

static int aeskl_xts_encrypt(const struct aeskl_ctx *key,
			     const u8 *src, u8 *dst, unsigned int len,
			     u8 tweak[AES_BLOCK_SIZE])
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_xts_encrypt(key, dst, src, len, tweak);
}

static int aeskl_xts_decrypt(const struct aeskl_ctx *key,
			     const u8 *src, u8 *dst, unsigned int len,
			     u8 tweak[AES_BLOCK_SIZE])
{
	if (!valid_keylocker())
		return -ENODEV;

	return __aeskl_xts_decrypt(key, dst, src, len, tweak);
}

/*
 * The glue code in xts_crypt() and xts_crypt_slowpath() follows
 * aesni-intel_glue.c. While this code is shareable, the key
 * material format difference can cause more destructive code changes in
 * the AES-NI side.
 */

enum xts_ops {
	XTS_ENCRYPTION,
	XTS_DECRYPTION
};

/* This handles cases where the source and/or destination span pages. */
static noinline int xts_crypt_slowpath(struct skcipher_request *req, enum xts_ops ops)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct xts_aes_ctx *ctx = xts_aes_ctx(tfm);
	int tail = req->cryptlen % AES_BLOCK_SIZE;
	struct scatterlist sg_src[2], sg_dst[2];
	struct skcipher_request subreq;
	struct scatterlist *src, *dst;
	struct skcipher_walk walk;
	int err;

	/*
	 * If the message length isn't divisible by the AES block size, then
	 * separate off the last full block and the partial block.  This ensures
	 * that they are processed in the same call to the assembly function,
	 * which is required for ciphertext stealing.
	 */
	if (tail) {
		skcipher_request_set_tfm(&subreq, tfm);
		skcipher_request_set_callback(&subreq,
					      skcipher_request_flags(req),
					      NULL, NULL);
		skcipher_request_set_crypt(&subreq, req->src, req->dst,
					   req->cryptlen - tail - AES_BLOCK_SIZE,
					   req->iv);
		req = &subreq;
	}

	err = skcipher_walk_virt(&walk, req, false);

	while (walk.nbytes) {
		kernel_fpu_begin();
		if (ops == XTS_ENCRYPTION) {
			err |= aeskl_xts_encrypt(&ctx->crypt_ctx.aeskl, walk.src.virt.addr,
						 walk.dst.virt.addr,
						 walk.nbytes & ~(AES_BLOCK_SIZE - 1), req->iv);
		} else {
			err |= aeskl_xts_decrypt(&ctx->crypt_ctx.aeskl, walk.src.virt.addr,
						 walk.dst.virt.addr,
						 walk.nbytes & ~(AES_BLOCK_SIZE - 1), req->iv);
		}
		kernel_fpu_end();
		err |= skcipher_walk_done(&walk,
					  walk.nbytes & (AES_BLOCK_SIZE - 1));
	}

	if (err || !tail)
		return err;

	/* Do ciphertext stealing with the last full block and partial block. */

	dst = src = scatterwalk_ffwd(sg_src, req->src, req->cryptlen);
	if (req->dst != req->src)
		dst = scatterwalk_ffwd(sg_dst, req->dst, req->cryptlen);

	skcipher_request_set_crypt(req, src, dst, AES_BLOCK_SIZE + tail,
				   req->iv);

	err = skcipher_walk_virt(&walk, req, false);
	if (err)
		return err;

	kernel_fpu_begin();
	if (ops == XTS_ENCRYPTION) {
		err = aeskl_xts_encrypt(&ctx->crypt_ctx.aeskl, walk.src.virt.addr,
					walk.dst.virt.addr, walk.nbytes, req->iv);
	} else {
		err = aeskl_xts_decrypt(&ctx->crypt_ctx.aeskl, walk.src.virt.addr,
					walk.dst.virt.addr, walk.nbytes, req->iv);
	}
	kernel_fpu_end();
	if (err)
		return err;

	return skcipher_walk_done(&walk, 0);
}

/* __always_inline to avoid indirect call in fastpath */
static __always_inline int xts_crypt(struct skcipher_request *req, enum xts_ops ops)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct xts_aes_ctx *ctx = xts_aes_ctx(tfm);
	const unsigned int cryptlen = req->cryptlen;
	struct scatterlist *src = req->src;
	struct scatterlist *dst = req->dst;
	int err;

	if (unlikely(cryptlen < AES_BLOCK_SIZE))
		return -EINVAL;

	kernel_fpu_begin();
	err = aeskl_xts_encrypt_iv(&ctx->tweak_ctx.aeskl, req->iv);
	if (err)
		goto out;

	/*
	 * In practice, virtually all XTS plaintexts and ciphertexts are either
	 * 512 or 4096 bytes, aligned such that they don't span page boundaries.
	 * To optimize the performance of these cases, and also any other case
	 * where no page boundary is spanned, the below fast-path handles
	 * single-page sources and destinations as efficiently as possible.
	 */
	if (likely(src->length >= cryptlen && dst->length >= cryptlen &&
		   src->offset + cryptlen <= PAGE_SIZE &&
		   dst->offset + cryptlen <= PAGE_SIZE)) {
		struct page *src_page = sg_page(src);
		struct page *dst_page = sg_page(dst);
		void *src_virt = kmap_local_page(src_page) + src->offset;
		void *dst_virt = kmap_local_page(dst_page) + dst->offset;

		if (ops == XTS_ENCRYPTION) {
			err = aeskl_xts_encrypt(&ctx->crypt_ctx.aeskl, src_virt,
						dst_virt, cryptlen, req->iv);
		} else {
			err = aeskl_xts_decrypt(&ctx->crypt_ctx.aeskl, src_virt,
						dst_virt, cryptlen, req->iv);
		}
		if (err)
			goto out;
		kunmap_local(dst_virt);
		kunmap_local(src_virt);
		kernel_fpu_end();
		return 0;
	}
out:
	kernel_fpu_end();
	if (err)
		return err;
	return xts_crypt_slowpath(req, ops);
}

static int xts_setkey_aeskl(struct crypto_skcipher *tfm, const u8 *key, unsigned int keylen)
{
	struct xts_aes_ctx *ctx = xts_aes_ctx(tfm);
	unsigned int aes_keylen;
	int err;

	err = xts_verify_key(tfm, key, keylen);
	if (err)
		return err;

	aes_keylen = keylen / 2;
	err = aes_check_keylen(aes_keylen);
	if (err)
		return err;

	if (unlikely(aes_keylen == AES_KEYSIZE_192)) {
		pr_warn_once("AES-KL does not support 192-bit key. Use AES-NI.\n");
		return xts_setkey_aesni(tfm, key, keylen);
	}

	err = aeskl_setkey(&ctx->crypt_ctx.aeskl, key, aes_keylen);
	if (err)
		return err;

	return aeskl_setkey(&ctx->tweak_ctx.aeskl, key + aes_keylen, aes_keylen);
}

static int xts_encrypt_aeskl(struct skcipher_request *req)
{
	if (unlikely(xts_keylen(req) == AES_KEYSIZE_192))
		return xts_encrypt_aesni(req);

	return xts_crypt(req, XTS_ENCRYPTION);
}

static int xts_decrypt_aeskl(struct skcipher_request *req)
{
	if (unlikely(xts_keylen(req) == AES_KEYSIZE_192))
		return xts_decrypt_aesni(req);

	return xts_crypt(req, XTS_DECRYPTION);
}

#define XTS_AES_CTX_SIZE (sizeof(struct xts_aes_ctx) + AES_ALIGN_EXTRA)

/*
 * The 'cra_priority' value is intentionally set lower than
 * xts-aes-aesni.
 */
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
		.setkey		= xts_setkey_aeskl,
		.encrypt	= xts_encrypt_aeskl,
		.decrypt	= xts_decrypt_aeskl,
	}
};

static struct simd_skcipher_alg *aeskl_simd_skciphers[ARRAY_SIZE(aeskl_skciphers)];

static int __init aeskl_init(void)
{
	u32 eax, ebx, ecx, edx;

	if (!valid_keylocker())
		return -ENODEV;

	/*
	 * For performance, use the Key Locker AES wide and AVX
	 * instructions.
	 */
	cpuid_count(KEYLOCKER_CPUID, 0, &eax, &ebx, &ecx, &edx);
	if (!(ebx & KEYLOCKER_CPUID_EBX_WIDE))
		return -ENODEV;
	if (!boot_cpu_has(X86_FEATURE_AVX))
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

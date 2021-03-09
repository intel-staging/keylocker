/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _AESNI_XTS_H
#define _AESNI_XTS_H

/*
 * These AES-NI functions are used by the AES-KL code as a fallback when
 * a 192-bit key is provided. Key Locker does not support 192-bit keys.
 */

int xts_setkey_aesni(struct crypto_skcipher *tfm, const u8 *key, unsigned int keylen);
int xts_encrypt_aesni(struct skcipher_request *req);
int xts_decrypt_aesni(struct skcipher_request *req);

#endif /* _AESNI_XTS_H */

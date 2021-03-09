/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Implement AES algorithm using AES Key Locker instructions.
 *
 * Most code is primarily derived from aesni-intel_asm.S and
 * stylistically aligned with aes-xts-avx-x86_64.S.
 */

#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/inst.h>

.section .rodata
.p2align 4
.Lgf_poly:
	/*
	 * Represents the polynomial x^7 + x^2 + x + 1, where the low 64
	 * bits are XOR'd into the tweak's low 64 bits when a carry
	 * occurs from the high 64 bits.
	 */
	.quad	0x87, 1

	/*
	 * Table of constants for variable byte shifts and blending
	 * during ciphertext stealing operations.
	 */
.Lcts_permute_table:
	.byte	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
	.byte	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
	.byte	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	.byte	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	.byte	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
	.byte	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80

.text

.set	TWEAK_NEXT1,	%xmm8
.set	TWEAK_NEXT2,	%xmm9
.set	TWEAK_NEXT3,	%xmm10
.set	TWEAK_NEXT4,	%xmm11
.set	TWEAK_NEXT5,	%xmm12
.set	TWEAK_NEXT6,	%xmm13
.set	TWEAK_NEXT7,	%xmm14
.set	GF_POLY,	%xmm15
.set	TWEAK_TMP,	TWEAK_NEXT1
.set	TWEAK_NEXT,	TWEAK_NEXT2
.set	TMP,		%r10
.set	KLEN,		%r9d

/*
 * void __aeskl_setkey(struct crypto_aes_ctx *handle, const u8 *key,
 *		       unsigned int keylen)
 */
SYM_FUNC_START(__aeskl_setkey)
	.set	HANDLE,	%rdi	/* Pointer to struct aeskl_ctx */
	.set	KEY,	%rsi	/* Pointer to the original key */
	.set	KEYLEN,	%edx	/* AES key length in bytes */
	movl		KEYLEN, 480(HANDLE)
	vmovdqu		(KEY), %xmm0
	mov		$1, %eax
	cmp		$16, %dl
	je		.Lsetkey_128

	vmovdqu		0x10(KEY), %xmm1
	encodekey256	%eax, %eax
	vmovdqu		%xmm3, 0x30(HANDLE)
	jmp		.Lsetkey_end
.Lsetkey_128:
	encodekey128	%eax, %eax

.Lsetkey_end:
	vmovdqu		%xmm0, 0x00(HANDLE)
	vmovdqu		%xmm1, 0x10(HANDLE)
	vmovdqu		%xmm2, 0x20(HANDLE)
	RET
SYM_FUNC_END(__aeskl_setkey)

.macro _aeskl		operation
	cmp		$16, KLEN
	je		.Laes_128\@
.ifc \operation, dec
	aesdec256kl	(HANDLE), %xmm0
.else
	aesenc256kl	(HANDLE), %xmm0
.endif
	jmp		.Laes_end\@
.Laes_128\@:
.ifc \operation, dec
	aesdec128kl	(HANDLE), %xmm0
.else
	aesenc128kl	(HANDLE), %xmm0
.endif
.Laes_end\@:
.endm

.macro _aesklwide	operation
	cmp		$16, KLEN
	je		.Laesw_128\@
.ifc \operation, dec
	aesdecwide256kl	(HANDLE)
.else
	aesencwide256kl	(HANDLE)
.endif
	jmp		.Laesw_end\@
.Laesw_128\@:
.ifc \operation, dec
	aesdecwide128kl	(HANDLE)
.else
	aesencwide128kl	(HANDLE)
.endif
.Laesw_end\@:
.endm

/* int __aeskl_enc(const void *handle, u8 *dst, const u8 *src) */
SYM_FUNC_START(__aeskl_enc)
	.set	HANDLE,	%rdi	/* Pointer to struct aeskl_ctx */
	.set	DST,	%rsi	/* Pointer to next destination data */
	.set	SRC,	%rdx	/* Pointer to next source data */
	vmovdqu		(SRC), %xmm0
	movl		480(HANDLE), KLEN

	_aeskl		enc
	jz		.Lerror
	xor		%rax, %rax
	vmovdqu		%xmm0, (DST)
	RET
.Lerror:
	mov		$(-EINVAL), %eax
	RET
SYM_FUNC_END(__aeskl_enc)

/*
 * Calculate the next 128-bit XTS tweak by multiplying the polynomial 'x'
 * with the current tweak stored in the register \src, and store the
 * result in the \dst register.
 */
.macro _next_tweak	src, tmp, dst
	vpshufd		$0x13, \src, \tmp
	vpaddq		\src, \src, \dst
	vpsrad		$31, \tmp, \tmp
	vpand		GF_POLY, \tmp, \tmp
	vpxor		\tmp, \dst, \dst
.endm

.macro _aeskl_xts_crypt operation
	vmovdqa		.Lgf_poly(%rip), GF_POLY
	vmovups		(TWEAK), TWEAK_NEXT
	mov		480(HANDLE), KLEN

.ifc \operation, dec
	/*
	 * During decryption, if the message length is not a multiple of
	 * the AES block length, exclude the last complete block from the
	 * decryption loop by subtracting 16 from LEN. This adjustment is
	 * necessary because ciphertext stealing decryption uses the last
	 * two tweaks in reverse order. Special handling is required for
	 * the last complete block and any remaining partial block at the
	 * end.
	 */
	test		$15, LEN
	jz		.L8block_at_a_time\@
	sub		$16, LEN
.endif

.L8block_at_a_time\@:
	sub		$128, LEN
	jl		.Lhandle_remainder\@

	vpxor		(SRC), TWEAK_NEXT, %xmm0
	vmovups		TWEAK_NEXT, (DST)

	/*
	 * Calculate and cache tweak values. Note that the tweak
	 * computation cannot be interleaved with AES rounds here using
	 * Key Locker instructions.
	 */
	_next_tweak	TWEAK_NEXT,  %xmm1, TWEAK_NEXT1
	_next_tweak	TWEAK_NEXT1, %xmm1, TWEAK_NEXT2
	_next_tweak	TWEAK_NEXT2, %xmm1, TWEAK_NEXT3
	_next_tweak	TWEAK_NEXT3, %xmm1, TWEAK_NEXT4
	_next_tweak	TWEAK_NEXT4, %xmm1, TWEAK_NEXT5
	_next_tweak	TWEAK_NEXT5, %xmm1, TWEAK_NEXT6
	_next_tweak	TWEAK_NEXT6, %xmm1, TWEAK_NEXT7

	/* XOR each source block with its tweak. */
	vpxor		0x10(SRC), TWEAK_NEXT1, %xmm1
	vpxor		0x20(SRC), TWEAK_NEXT2, %xmm2
	vpxor		0x30(SRC), TWEAK_NEXT3, %xmm3
	vpxor		0x40(SRC), TWEAK_NEXT4, %xmm4
	vpxor		0x50(SRC), TWEAK_NEXT5, %xmm5
	vpxor		0x60(SRC), TWEAK_NEXT6, %xmm6
	vpxor		0x70(SRC), TWEAK_NEXT7, %xmm7

	/* Encrypt or decrypt 8 blocks per iteration. */
	_aesklwide	\operation
	jz		.Lerror\@

	/* XOR tweaks again. */
	vpxor		(DST), %xmm0, %xmm0
	vpxor		TWEAK_NEXT1, %xmm1, %xmm1
	vpxor		TWEAK_NEXT2, %xmm2, %xmm2
	vpxor		TWEAK_NEXT3, %xmm3, %xmm3
	vpxor		TWEAK_NEXT4, %xmm4, %xmm4
	vpxor		TWEAK_NEXT5, %xmm5, %xmm5
	vpxor		TWEAK_NEXT6, %xmm6, %xmm6
	vpxor		TWEAK_NEXT7, %xmm7, %xmm7

	/* Store destination blocks. */
	vmovdqu		%xmm0, 0x00(DST)
	vmovdqu		%xmm1, 0x10(DST)
	vmovdqu		%xmm2, 0x20(DST)
	vmovdqu		%xmm3, 0x30(DST)
	vmovdqu		%xmm4, 0x40(DST)
	vmovdqu		%xmm5, 0x50(DST)
	vmovdqu		%xmm6, 0x60(DST)
	vmovdqu		%xmm7, 0x70(DST)

	_next_tweak	TWEAK_NEXT7, TWEAK_TMP, TWEAK_NEXT
	add		$128, SRC
	add		$128, DST
	test		LEN, LEN
	jz		.Lend\@
	jmp		.L8block_at_a_time\@

.Lhandle_remainder\@:
	add		$128, LEN
	jz		.Lend\@
.ifc \operation, enc
	vmovdqu		%xmm7, %xmm0
.endif
	sub		$16, LEN
	jl		.Lcts\@

	/* Encrypt or decrypt one block per iteration */
.Lblock_at_a_time\@:
	vpxor		(SRC), TWEAK_NEXT, %xmm0
	_aeskl		\operation
	jz		.Lerror\@
	vpxor		TWEAK_NEXT, %xmm0, %xmm0
	_next_tweak	TWEAK_NEXT, TWEAK_TMP, TWEAK_NEXT
	test		LEN, LEN
	jz		.Lout\@

	add		$16, SRC
	vmovdqu		%xmm0, (DST)
	add		$16, DST
	sub		$16, LEN
	jge		.Lblock_at_a_time\@

.Lcts\@:
.ifc \operation, dec
	/*
	 * If decrypting, the last block was not decrypted because CTS
	 * decryption uses the last two tweaks in reverse order. This is
	 * done by advancing the tweak and decrypting the last block.
	 */
	_next_tweak	TWEAK_NEXT, TWEAK_TMP, %xmm4
	vpxor		(SRC), %xmm4, %xmm0
	_aeskl		\operation
	jz		.Lerror\@
	vpxor		%xmm4, %xmm0, %xmm0
	add		$16, SRC
.else
	/*
	 * If encrypting, the last block was already encrypted in %xmm0.
	 * Prepare the CTS encryption by rewinding the pointer.
	 */
	sub		$16, DST
.endif
	lea		.Lcts_permute_table(%rip), TMP

	/* Load the source partial block */
	vmovdqu		(SRC, LEN, 1), %xmm3

	/*
	 * Shift the first LEN bytes of the encryption and decryption of
	 * the last block to the end of a register, then store it to
	 * DST+LEN.
	 */
	add		$16, LEN
	vpshufb		(TMP, LEN, 1), %xmm0, %xmm2
	vmovdqu		%xmm2, (DST, LEN, 1)

	/* Shift the source partial block to the beginning */
	sub		LEN, TMP
	vmovdqu		32(TMP), %xmm2
	vpshufb		%xmm2, %xmm3, %xmm3

	/* Blend to generate the source partial block */
	vpblendvb	%xmm2, %xmm0, %xmm3, %xmm3

	/* Encrypt or decrypt again and store the last block. */
	vpxor		TWEAK_NEXT, %xmm3, %xmm0
	_aeskl		\operation
	jz		.Lerror\@
	vpxor		TWEAK_NEXT, %xmm0, %xmm0
	vmovdqu		%xmm0, (DST)

	xor		%rax, %rax
	RET
.Lout\@:
	vmovdqu		%xmm0, (DST)
.Lend\@:
	vmovups		TWEAK_NEXT, (TWEAK)
	xor		%rax, %rax
	RET
.Lerror\@:
	mov		$(-EINVAL), %eax
	RET
.endm

/*
 * int __aeskl_xts_encrypt(const struct aeskl_ctx *handle, u8 *dst,
 *			   const u8 *src, unsigned int len, u8 *tweak)
 */
SYM_FUNC_START(__aeskl_xts_encrypt)
	.set	HANDLE,	%rdi	/* Pointer to struct aeskl_ctx */
	.set	DST,	%rsi	/* Pointer to next destination data */
	.set	SRC,	%rdx	/* Pointer to next source data */
	.set	LEN,	%rcx	/* Remaining length in bytes */
	.set	TWEAK,	%r8	/* Pointer to next tweak */
	_aeskl_xts_crypt	enc
SYM_FUNC_END(__aeskl_xts_encrypt)

/*
 * int __aeskl_xts_decrypt(const struct crypto_aes_ctx *handle, u8 *dst,
 *			   const u8 *src, unsigned int len, u8 *tweak)
 */
SYM_FUNC_START(__aeskl_xts_decrypt)
	.set	HANDLE,	%rdi	/* Pointer to struct aeskl_ctx */
	.set	DST,	%rsi	/* Pointer to next destination data */
	.set	SRC,	%rdx	/* Pointer to next source data */
	.set	LEN,	%rcx	/* Remaining length in bytes */
	.set	TWEAK,	%r8	/* Pointer to next tweak */
	_aeskl_xts_crypt	dec
SYM_FUNC_END(__aeskl_xts_decrypt)


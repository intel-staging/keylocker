/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Implement AES algorithm using AES Key Locker instructions.
 *
 * Most code is primarily derived from aesni-intel_asm.S and
 * stylistically aligned with aes-xts-avx-x86_64.S.
 */

#include <linux/linkage.h>
#include <linux/cfi_types.h>
#include <asm/errno.h>
#include <asm/inst.h>
#include <asm/frame.h>

/* Constant values shared between AES implementations: */

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

.set	V0,		%xmm0
.set	V1,		%xmm1
.set	V2,		%xmm2
.set	V3,		%xmm3
.set	V4,		%xmm4
.set	V5,		%xmm5
.set	V6,		%xmm6
.set	V7,		%xmm7
.set	V8,		%xmm8
.set	V9,		%xmm9
.set	V10,		%xmm10
.set	V11,		%xmm11
.set	V12,		%xmm12
.set	V13,		%xmm13
.set	V14,		%xmm14
.set	V15,		%xmm15

.set	TWEAK_XMM1,	V8
.set	TWEAK_XMM2,	V9
.set	TWEAK_XMM3,	V10
.set	TWEAK_XMM4,	V11
.set	TWEAK_XMM5,	V12
.set	TWEAK_XMM6,	V13
.set	TWEAK_XMM7,	V14
.set	GF_POLY_XMM,	V15
.set	TWEAK_TMP,	TWEAK_XMM1
.set	TWEAK_XMM,	TWEAK_XMM2
.set	TMP,		%r10

/* Function parameters */
.set	HANDLEP,	%rdi	/* Pointer to struct aeskl_ctx */
.set	DST,		%rsi	/* Pointer to next destination data */
.set	UKEYP,		DST	/* Pointer to the original key */
.set	KLEN,		%r9d	/* AES key length in bytes */
.set	SRC,		%rdx	/* Pointer to next source data */
.set	LEN,		%rcx	/* Remaining length in bytes */
.set	TWEAK,		%r8	/* Pointer to next tweak */

/*
 * void __aeskl_setkey(struct crypto_aes_ctx *handlep, const u8 *ukeyp,
 *		       unsigned int key_len)
 */
SYM_FUNC_START(__aeskl_setkey)
	FRAME_BEGIN
	movl		%edx, 480(HANDLEP)
	vmovdqu		(UKEYP), V0
	mov		$1, %eax
	cmp		$16, %dl
	je		.Lsetkey_128

	vmovdqu		0x10(UKEYP), V1
	encodekey256	%eax, %eax
	vmovdqu		V3, 0x30(HANDLEP)
	jmp		.Lsetkey_end
.Lsetkey_128:
	encodekey128	%eax, %eax

.Lsetkey_end:
	vmovdqu		V0, 0x00(HANDLEP)
	vmovdqu		V1, 0x10(HANDLEP)
	vmovdqu		V2, 0x20(HANDLEP)

	FRAME_END
	RET
SYM_FUNC_END(__aeskl_setkey)

.macro _aeskl		width, operation
	cmp		$16, KLEN
	je		.Laeskl128\@
.ifc \width, wide
 .ifc \operation, dec
	aesdecwide256kl	(HANDLEP)
 .else
	aesencwide256kl	(HANDLEP)
 .endif
.else
 .ifc \operation, dec
	aesdec256kl	(HANDLEP), V0
 .else
	aesenc256kl	(HANDLEP), V0
 .endif
.endif
	jmp		.Laesklend\@
.Laeskl128\@:
.ifc \width, wide
 .ifc \operation, dec
	aesdecwide128kl	(HANDLEP)
 .else
	aesencwide128kl	(HANDLEP)
 .endif
.else
 .ifc \operation, dec
	aesdec128kl	(HANDLEP), V0
 .else
	aesenc128kl	(HANDLEP), V0
 .endif
.endif
.Laesklend\@:
.endm

/* int __aeskl_enc(const void *handlep, u8 *dst, const u8 *src) */
SYM_FUNC_START(__aeskl_enc)
	FRAME_BEGIN
	vmovdqu		(SRC), V0
	movl		480(HANDLEP), KLEN

	_aeskl		oneblock, enc
	jz		.Lerror
	xor		%rax, %rax
	vmovdqu		V0, (DST)
	FRAME_END
	RET
.Lerror:
	mov		$(-EINVAL), %rax
	FRAME_END
	RET
SYM_FUNC_END(__aeskl_enc)

/*
 * Calculate the next 128-bit XTS tweak by multiplying the polynomial 'x'
 * with the current tweak stored in the xmm register \src, and store the
 * result in \dst.
 */
.macro _next_tweak	src, tmp, dst
	vpshufd		$0x13, \src, \tmp
	vpaddq		\src, \src, \dst
	vpsrad		$31, \tmp, \tmp
	vpand		GF_POLY_XMM, \tmp, \tmp
	vpxor		\tmp, \dst, \dst
.endm

.macro _aeskl_xts_crypt operation
	FRAME_BEGIN
	vmovdqa		.Lgf_poly(%rip), GF_POLY_XMM
	vmovups		(TWEAK), TWEAK_XMM
	mov		480(HANDLEP), KLEN

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

	vpxor		(SRC), TWEAK_XMM, V0
	vmovups		TWEAK_XMM, (DST)

	/*
	 * Calculate and cache tweak values. Note that the tweak
	 * computation cannot be interleaved with AES rounds here using
	 * Key Locker instructions.
	 */
	_next_tweak	TWEAK_XMM,  V1, TWEAK_XMM1
	_next_tweak	TWEAK_XMM1, V1, TWEAK_XMM2
	_next_tweak	TWEAK_XMM2, V1, TWEAK_XMM3
	_next_tweak	TWEAK_XMM3, V1, TWEAK_XMM4
	_next_tweak	TWEAK_XMM4, V1, TWEAK_XMM5
	_next_tweak	TWEAK_XMM5, V1, TWEAK_XMM6
	_next_tweak	TWEAK_XMM6, V1, TWEAK_XMM7

	/* XOR each source block with its tweak. */
	vpxor		0x10(SRC), TWEAK_XMM1, V1
	vpxor		0x20(SRC), TWEAK_XMM2, V2
	vpxor		0x30(SRC), TWEAK_XMM3, V3
	vpxor		0x40(SRC), TWEAK_XMM4, V4
	vpxor		0x50(SRC), TWEAK_XMM5, V5
	vpxor		0x60(SRC), TWEAK_XMM6, V6
	vpxor		0x70(SRC), TWEAK_XMM7, V7

	/* Encrypt or decrypt 8 blocks per iteration. */
	_aeskl		wide, \operation
	jz		.Lerror\@

	/* XOR tweaks again. */
	vpxor		(DST), V0, V0
	vpxor		TWEAK_XMM1, V1, V1
	vpxor		TWEAK_XMM2, V2, V2
	vpxor		TWEAK_XMM3, V3, V3
	vpxor		TWEAK_XMM4, V4, V4
	vpxor		TWEAK_XMM5, V5, V5
	vpxor		TWEAK_XMM6, V6, V6
	vpxor		TWEAK_XMM7, V7, V7

	/* Store destination blocks. */
	vmovdqu		V0, 0x00(DST)
	vmovdqu		V1, 0x10(DST)
	vmovdqu		V2, 0x20(DST)
	vmovdqu		V3, 0x30(DST)
	vmovdqu		V4, 0x40(DST)
	vmovdqu		V5, 0x50(DST)
	vmovdqu		V6, 0x60(DST)
	vmovdqu		V7, 0x70(DST)

	_next_tweak	TWEAK_XMM7, TWEAK_TMP, TWEAK_XMM
	add		$128, SRC
	add		$128, DST
	test		LEN, LEN
	jz		.Lend\@
	jmp		.L8block_at_a_time\@

.Lhandle_remainder\@:
	add		$128, LEN
	jz		.Lend\@
.ifc \operation, enc
	vmovdqu		V7, V0
.endif
	sub		$16, LEN
	jl		.Lcts\@

	/* Encrypt or decrypt one block per iteration */
.Lblock_at_a_time\@:
	vpxor		(SRC), TWEAK_XMM, V0
	_aeskl		oneblock, \operation
	jz		.Lerror\@
	vpxor		TWEAK_XMM, V0, V0
	_next_tweak	TWEAK_XMM, TWEAK_TMP, TWEAK_XMM
	test		LEN, LEN
	jz		.Lout\@

	add		$16, SRC
	vmovdqu		V0, (DST)
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
	_next_tweak	TWEAK_XMM, TWEAK_TMP, V4
	vpxor		(SRC), V4, V0
	_aeskl		oneblock, \operation
	jz		.Lerror\@
	vpxor		V4, V0, V0
	add		$16, SRC
.else
	/*
	 * If encrypting, the last block was already encrypted in V0.
	 * Prepare the CTS encryption by rewinding the pointer.
	 */
	sub		$16, DST
.endif
	lea		.Lcts_permute_table(%rip), TMP

	/* Load the source partial block */
	vmovdqu		(SRC, LEN, 1), V3

	/*
	 * Shift the first LEN bytes of the encryption and decryption of
	 * the last block to the end of a register, then store it to
	 * DST+LEN.
	 */
	add		$16, LEN
	vpshufb		(TMP, LEN, 1), V0, V2
	vmovdqu		V2, (DST, LEN, 1)

	/* Shift the source partial block to the beginning */
	sub		LEN, TMP
	vmovdqu		32(TMP), V2
	vpshufb		V2, V3, V3

	/* Blend to generate the source partial block */
	vpblendvb	V2, V0, V3, V3

	/* Encrypt or decrypt again and store the last block. */
	vpxor		TWEAK_XMM, V3, V0
	_aeskl		oneblock, \operation
	jz		.Lerror\@
	vpxor		TWEAK_XMM, V0, V0
	vmovdqu		V0, (DST)

	xor		%rax, %rax
	FRAME_END
	RET
.Lout\@:
	vmovdqu		V0, (DST)
.Lend\@:
	vmovups		TWEAK_XMM, (TWEAK)
	xor		%rax, %rax
	FRAME_END
	RET
.Lerror\@:
	mov		$(-EINVAL), %rax
	FRAME_END
	RET
.endm

/*
 * int __aeskl_xts_encrypt(const struct aeskl_ctx *handlep, u8 *dst,
 *			   const u8 *src, unsigned int klen, le128 *tweak)
 */
SYM_FUNC_START(__aeskl_xts_encrypt)
	_aeskl_xts_crypt	enc
SYM_FUNC_END(__aeskl_xts_encrypt)

/*
 * int __aeskl_xts_decrypt(const struct crypto_aes_ctx *handlep, u8 *dst,
 *			   const u8 *src, unsigned int klen, le128 *twek)
 */
SYM_FUNC_START(__aeskl_xts_decrypt)
	_aeskl_xts_crypt	dec
SYM_FUNC_END(__aeskl_xts_decrypt)


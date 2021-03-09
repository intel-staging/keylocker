/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Implement AES algorithm using AES Key Locker instructions.
 *
 * Most code is based from the AES-NI implementation, aesni-intel_asm.S
 *
 */

#include <linux/linkage.h>
#include <linux/cfi_types.h>
#include <asm/errno.h>
#include <asm/inst.h>
#include <asm/frame.h>
#include "aes-helper_asm.S"

.text

#define STATE1	%xmm0
#define STATE2	%xmm1
#define STATE3	%xmm2
#define STATE4	%xmm3
#define STATE5	%xmm4
#define STATE6	%xmm5
#define STATE7	%xmm6
#define STATE8	%xmm7
#define STATE	STATE1

#define IV	%xmm9
#define KEY	%xmm10
#define INC	%xmm13

#define IN	%xmm8

#define HANDLEP	%rdi
#define OUTP	%rsi
#define KLEN	%r9d
#define INP	%rdx
#define T1	%r10
#define LEN	%rcx
#define IVP	%r8

#define UKEYP	OUTP
#define GF128MUL_MASK %xmm11

/*
 * void __aeskl_setkey(struct crypto_aes_ctx *handlep, const u8 *ukeyp,
 *		       unsigned int key_len)
 */
SYM_FUNC_START(__aeskl_setkey)
	FRAME_BEGIN
	movl %edx, 480(HANDLEP)
	movdqu (UKEYP), STATE1
	mov $1, %eax
	cmp $16, %dl
	je .Lsetkey_128

	movdqu 0x10(UKEYP), STATE2
	encodekey256 %eax, %eax
	movdqu STATE4, 0x30(HANDLEP)
	jmp .Lsetkey_end
.Lsetkey_128:
	encodekey128 %eax, %eax

.Lsetkey_end:
	movdqu STATE1, (HANDLEP)
	movdqu STATE2, 0x10(HANDLEP)
	movdqu STATE3, 0x20(HANDLEP)

	FRAME_END
	RET
SYM_FUNC_END(__aeskl_setkey)

/*
 * int __aeskl_enc(const void *handlep, u8 *outp, const u8 *inp)
 */
SYM_FUNC_START(__aeskl_enc)
	FRAME_BEGIN
	movdqu (INP), STATE
	movl 480(HANDLEP), KLEN

	cmp $16, KLEN
	je .Lenc_128
	aesenc256kl (HANDLEP), STATE
	jz .Lenc_err
	xor %rax, %rax
	jmp .Lenc_end
.Lenc_128:
	aesenc128kl (HANDLEP), STATE
	jz .Lenc_err
	xor %rax, %rax
	jmp .Lenc_end

.Lenc_err:
	mov $(-EINVAL), %rax
.Lenc_end:
	movdqu STATE, (OUTP)
	FRAME_END
	RET
SYM_FUNC_END(__aeskl_enc)

/*
 * XTS implementation
 */

/*
 * _aeskl_gf128mul_x_ble: 	internal ABI
 *	Multiply in GF(2^128) for XTS IVs
 * input:
 *	IV:	current IV
 *	GF128MUL_MASK == mask with 0x87 and 0x01
 * output:
 *	IV:	next IV
 * changed:
 *	CTR:	== temporary value
 *
 * While based on the AES-NI code, this macro is separated here due to
 * the register constraint. E.g., aesencwide256kl has implicit
 * operands: XMM0-7.
 */
#define _aeskl_gf128mul_x_ble() \
	pshufd $0x13, IV, KEY; \
	paddq IV, IV; \
	psrad $31, KEY; \
	pand GF128MUL_MASK, KEY; \
	pxor KEY, IV;

.macro XTS_ENC_DEC operation
	FRAME_BEGIN
	movdqa .Lgf128mul_x_ble_mask(%rip), GF128MUL_MASK
	movups (IVP), IV

	mov 480(HANDLEP), KLEN

.ifc \operation, dec
	test $15, LEN
	jz .Lxts_op8_\@
	sub $16, LEN
.endif

.Lxts_op8_\@:
	sub $128, LEN
	jl .Lxts_op1_pre_\@

	movdqa IV, STATE1
	movdqu (INP), INC
	pxor INC, STATE1
	movdqu IV, (OUTP)

	_aeskl_gf128mul_x_ble()
	movdqa IV, STATE2
	movdqu 0x10(INP), INC
	pxor INC, STATE2
	movdqu IV, 0x10(OUTP)

	_aeskl_gf128mul_x_ble()
	movdqa IV, STATE3
	movdqu 0x20(INP), INC
	pxor INC, STATE3
	movdqu IV, 0x20(OUTP)

	_aeskl_gf128mul_x_ble()
	movdqa IV, STATE4
	movdqu 0x30(INP), INC
	pxor INC, STATE4
	movdqu IV, 0x30(OUTP)

	_aeskl_gf128mul_x_ble()
	movdqa IV, STATE5
	movdqu 0x40(INP), INC
	pxor INC, STATE5
	movdqu IV, 0x40(OUTP)

	_aeskl_gf128mul_x_ble()
	movdqa IV, STATE6
	movdqu 0x50(INP), INC
	pxor INC, STATE6
	movdqu IV, 0x50(OUTP)

	_aeskl_gf128mul_x_ble()
	movdqa IV, STATE7
	movdqu 0x60(INP), INC
	pxor INC, STATE7
	movdqu IV, 0x60(OUTP)

	_aeskl_gf128mul_x_ble()
	movdqa IV, STATE8
	movdqu 0x70(INP), INC
	pxor INC, STATE8
	movdqu IV, 0x70(OUTP)

	cmp $16, KLEN
	je .Lxts_op8_128_\@
.ifc \operation, dec
	aesdecwide256kl (%rdi)
.else
	aesencwide256kl (%rdi)
.endif
	jz .Lxts_op_err_\@
	jmp .Lxts_op8_end_\@
.Lxts_op8_128_\@:
.ifc \operation, dec
	aesdecwide128kl (%rdi)
.else
	aesencwide128kl (%rdi)
.endif
	jz .Lxts_op_err_\@

.Lxts_op8_end_\@:
	movdqu 0x00(OUTP), INC
	pxor INC, STATE1
	movdqu STATE1, 0x00(OUTP)

	movdqu 0x10(OUTP), INC
	pxor INC, STATE2
	movdqu STATE2, 0x10(OUTP)

	movdqu 0x20(OUTP), INC
	pxor INC, STATE3
	movdqu STATE3, 0x20(OUTP)

	movdqu 0x30(OUTP), INC
	pxor INC, STATE4
	movdqu STATE4, 0x30(OUTP)

	movdqu 0x40(OUTP), INC
	pxor INC, STATE5
	movdqu STATE5, 0x40(OUTP)

	movdqu 0x50(OUTP), INC
	pxor INC, STATE6
	movdqu STATE6, 0x50(OUTP)

	movdqu 0x60(OUTP), INC
	pxor INC, STATE7
	movdqu STATE7, 0x60(OUTP)

	movdqu 0x70(OUTP), INC
	pxor INC, STATE8
	movdqu STATE8, 0x70(OUTP)

	_aeskl_gf128mul_x_ble()

	add $128, INP
	add $128, OUTP
	test LEN, LEN
	jnz .Lxts_op8_\@

.Lxts_op_ret_\@:
	movups IV, (IVP)
	xor %rax, %rax
	FRAME_END
	RET

.Lxts_op1_pre_\@:
	add $128, LEN
	jz .Lxts_op_ret_\@
.ifc \operation, enc
	sub $16, LEN
	jl .Lxts_op_cts4_\@
.endif

.Lxts_op1_\@:
	movdqu (INP), STATE1

.ifc \operation, dec
	add $16, INP
	sub $16, LEN
	jl .Lxts_op_cts1_\@
.endif

	pxor IV, STATE1

	cmp $16, KLEN
	je .Lxts_op1_128_\@
.ifc \operation, dec
	aesdec256kl (HANDLEP), STATE1
.else
	aesenc256kl (HANDLEP), STATE1
.endif
	jz .Lxts_op_err_\@
	jmp .Lxts_op1_end_\@
.Lxts_op1_128_\@:
.ifc \operation, dec
	aesdec128kl (HANDLEP), STATE1
.else
	aesenc128kl (HANDLEP), STATE1
.endif
	jz .Lxts_op_err_\@

.Lxts_op1_end_\@:
	pxor IV, STATE1
	_aeskl_gf128mul_x_ble()

	test LEN, LEN
	jz .Lxts_op1_out_\@

.ifc \operation, enc
	add $16, INP
	sub $16, LEN
	jl .Lxts_op_cts1_\@
.endif

	movdqu STATE1, (OUTP)
	add $16, OUTP
	jmp .Lxts_op1_\@

.Lxts_op1_out_\@:
	movdqu STATE1, (OUTP)
	jmp .Lxts_op_ret_\@

.Lxts_op_cts4_\@:
.ifc \operation, enc
	movdqu STATE8, STATE1
	sub $16, OUTP
.endif

.Lxts_op_cts1_\@:
.ifc \operation, dec
	movdqa IV, STATE5
	_aeskl_gf128mul_x_ble()

	pxor IV, STATE1

	cmp $16, KLEN
	je .Lxts_dec1_cts_pre_128_\@
	aesdec256kl (HANDLEP), STATE1
	jz .Lxts_op_err_\@
	jmp .Lxts_dec1_cts_pre_end_\@
.Lxts_dec1_cts_pre_128_\@:
	aesdec128kl (HANDLEP), STATE1
	jz .Lxts_op_err_\@
.Lxts_dec1_cts_pre_end_\@:
	pxor IV, STATE1
.endif

	lea .Lcts_permute_table(%rip), T1
	add LEN, INP		/* rewind input pointer */
	add $16, LEN		/* # bytes in final block */
	movups (INP), IN

	mov T1, IVP
	add $32, IVP
	add LEN, T1
	sub LEN, IVP
	add OUTP, LEN

	movups (T1), STATE2
	movaps STATE1, STATE3
	pshufb STATE2, STATE1
	movups STATE1, (LEN)

	movups (IVP), STATE1
	pshufb STATE1, IN
	pblendvb STATE3, IN
	movaps IN, STATE1

.ifc \operation, dec
	pxor STATE5, STATE1
.else
	pxor IV, STATE1
.endif

	cmp $16, KLEN
	je .Lxts_op1_cts_128_\@
.ifc \operation, dec
	aesdec256kl (HANDLEP), STATE1
.else
	aesenc256kl (HANDLEP), STATE1
.endif
	jz .Lxts_op_err_\@
	jmp .Lxts_op1_cts_end_\@
.Lxts_op1_cts_128_\@:
.ifc \operation, dec
	aesdec128kl (HANDLEP), STATE1
.else
	aesenc128kl (HANDLEP), STATE1
.endif
	jz .Lxts_op_err_\@

.Lxts_op1_cts_end_\@:
.ifc \operation, dec
	pxor STATE5, STATE1
.else
	pxor IV, STATE1
.endif
	movups STATE1, (OUTP)
	xor %rax, %rax
	FRAME_END
	RET

.Lxts_op_err_\@:
	mov $(-EINVAL), %rax
	FRAME_END
	RET
.endm

/*
 * int __aeskl_xts_encrypt(const struct aeskl_ctx *handlep, u8 *outp,
 *			   const u8 *inp, unsigned int klen, le128 *ivp)
 */
SYM_FUNC_START(__aeskl_xts_encrypt)
	XTS_ENC_DEC enc
SYM_FUNC_END(__aeskl_xts_encrypt)

/*
 * int __aeskl_xts_decrypt(const struct crypto_aes_ctx *handlep, u8 *outp,
 *			   const u8 *inp, unsigned int klen, le128 *ivp)
 */
SYM_FUNC_START(__aeskl_xts_decrypt)
	XTS_ENC_DEC dec
SYM_FUNC_END(__aeskl_xts_decrypt)


/*
 *   Copyright (c) 2015, Andrew Romanenko <melanhit@gmail.com>
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice, this
 *      list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright notice,
 *      this list of conditions and the following disclaimer in the documentation
 *      and/or other materials provided with the distribution.
 *   3. Neither the name of the project nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 *   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

.text
.file   "threefish_512.s"
.globl  akmos_threefish_512_setkey
.type   akmos_threefish_512_setkey, @function
akmos_threefish_512_setkey:
    pushq   %rbp
    movq    %rsp, %rbp

    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12

    movq      (%rsi), %r15
    movq     8(%rsi), %r14
    movq    16(%rsi), %r13
    movq    24(%rsi), %r12
    movq    32(%rsi), %r11
    movq    40(%rsi), %r10
    movq    48(%rsi), %r9
    movq    56(%rsi), %r8

    movabsq $0x1bd11bdaa9fc1a22, %rax

    xorq    %r15, %rax
    xorq    %r14, %rax
    xorq    %r13, %rax
    xorq    %r12, %rax
    xorq    %r11, %rax
    xorq    %r10, %rax
    xorq    %r9,  %rax
    xorq    %r8,  %rax

    movq    $0, %rcx
.L01:
    movq    %r15,  (%rdi)
    movq    %r14, 8(%rdi)
    movq    %r13,16(%rdi)
    movq    %r12,24(%rdi)
    movq    %r11,32(%rdi)
    movq    %r10,40(%rdi)
    movq    %r9, 48(%rdi)
    movq    %r8, 56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    movq    %r14,  (%rdi)
    movq    %r13, 8(%rdi)
    movq    %r12,16(%rdi)
    movq    %r11,24(%rdi)
    movq    %r10,32(%rdi)
    movq    %r9, 40(%rdi)
    movq    %r8, 48(%rdi)
    movq    %rax,56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    movq    %r13,  (%rdi)
    movq    %r12, 8(%rdi)
    movq    %r11,16(%rdi)
    movq    %r10,24(%rdi)
    movq    %r9, 32(%rdi)
    movq    %r8, 40(%rdi)
    movq    %rax,48(%rdi)
    movq    %r15,56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    movq    %r12,  (%rdi)
    movq    %r11, 8(%rdi)
    movq    %r10,16(%rdi)
    movq    %r9, 24(%rdi)
    movq    %r8, 32(%rdi)
    movq    %rax,40(%rdi)
    movq    %r15,48(%rdi)
    movq    %r14,56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    movq    %r11,  (%rdi)
    movq    %r10, 8(%rdi)
    movq    %r9, 16(%rdi)
    movq    %r8, 24(%rdi)
    movq    %rax,32(%rdi)
    movq    %r15,40(%rdi)
    movq    %r14,48(%rdi)
    movq    %r13,56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    movq    %r10,  (%rdi)
    movq    %r9,  8(%rdi)
    movq    %r8, 16(%rdi)
    movq    %rax,24(%rdi)
    movq    %r15,32(%rdi)
    movq    %r14,40(%rdi)
    movq    %r13,48(%rdi)
    movq    %r12,56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    movq    %r9,   (%rdi)
    movq    %r8,  8(%rdi)
    movq    %rax,16(%rdi)
    movq    %r15,24(%rdi)
    movq    %r14,32(%rdi)
    movq    %r13,40(%rdi)
    movq    %r12,48(%rdi)
    movq    %r11,56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    movq    %r8,   (%rdi)
    movq    %rax, 8(%rdi)
    movq    %r15,16(%rdi)
    movq    %r14,24(%rdi)
    movq    %r13,32(%rdi)
    movq    %r12,40(%rdi)
    movq    %r11,48(%rdi)
    movq    %r10,56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    movq    %rax,  (%rdi)
    movq    %r15, 8(%rdi)
    movq    %r14,16(%rdi)
    movq    %r13,24(%rdi)
    movq    %r12,32(%rdi)
    movq    %r11,40(%rdi)
    movq    %r10,48(%rdi)
    movq    %r9, 56(%rdi)
    addq    %rcx,56(%rdi)
    incq    %rcx
    addq    $64, %rdi

    cmp     $9, %rcx
    je      .L01

    /* end */
    movq    %r15,  (%rdi)
    movq    %r14, 8(%rdi)
    movq    %r13,16(%rdi)
    movq    %r12,24(%rdi)
    movq    %r11,32(%rdi)
    movq    %r10,40(%rdi)
    movq    %r9, 48(%rdi)
    movq    %r8, 56(%rdi)
    addq    %rcx,56(%rdi)

    popq    %r12
    popq    %r13
    popq    %r14
    popq    %r15

    popq    %rbp

    ret
.size   akmos_threefish_512_setkey, .-akmos_threefish_512_setkey

.globl  akmos_threefish_512_encrypt
.type   akmos_threefish_512_encrypt, @function
akmos_threefish_512_encrypt:
    push    %rbp
    movq    %rsp, %rbp

    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12

    movq      (%rsi), %r15
    movq     8(%rsi), %r14
    movq    16(%rsi), %r13
    movq    24(%rsi), %r12
    movq    32(%rsi), %r11
    movq    40(%rsi), %r10
    movq    48(%rsi), %r9
    movq    56(%rsi), %r8

    mov     $0, %rcx
.L11:
    addq      (%rdi), %r15
    addq     8(%rdi), %r14
    addq    16(%rdi), %r13
    addq    24(%rdi), %r12
    addq    32(%rdi), %r11
    addq    40(%rdi), %r10
    addq    48(%rdi), %r9
    addq    56(%rdi), %r8
    addq    $64, %rdi

    addq    %r14, %r15
    addq    %r12, %r13
    addq    %r10, %r11
    addq    %r8,  %r9
    rolq    $46,  %r14
    rolq    $36,  %r12
    rolq    $19,  %r10
    rolq    $37,  %r8
    xorq    %r15, %r14
    xorq    %r13, %r12
    xorq    %r11, %r10
    xorq    %r9,  %r8

    addq    %r14, %r13
    addq    %r8,  %r11
    addq    %r10, %r9
    addq    %r12, %r15
    rolq    $33,  %r14
    rolq    $27,  %r8
    rolq    $14,  %r10
    rolq    $42,  %r12
    xorq    %r13, %r14
    xorq    %r11, %r8
    xorq    %r9,  %r10
    xorq    %r15, %r12

    addq    %r14, %r11
    addq    %r12, %r9
    addq    %r10, %r15
    addq    %r8,  %r13
    rolq    $17,  %r14
    rolq    $49,  %r12
    rolq    $36,  %r10
    rolq    $39,  %r8
    xorq    %r11, %r14
    xorq    %r9,  %r12
    xorq    %r15, %r10
    xorq    %r13, %r8

    addq    %r14, %r9
    addq    %r8,  %r15
    addq    %r10, %r13
    addq    %r12, %r11
    rolq    $44,  %r14
    rolq    $9,   %r8
    rolq    $54,  %r10
    rolq    $56,  %r12
    xorq    %r9,  %r14
    xorq    %r15, %r8
    xorq    %r13, %r10
    xorq    %r11, %r12

    addq      (%rdi), %r15
    addq     8(%rdi), %r14
    addq    16(%rdi), %r13
    addq    24(%rdi), %r12
    addq    32(%rdi), %r11
    addq    40(%rdi), %r10
    addq    48(%rdi), %r9
    addq    56(%rdi), %r8
    addq    $64, %rdi

    addq    %r14, %r15
    addq    %r12, %r13
    addq    %r10, %r11
    addq    %r8,  %r9
    rolq    $39,  %r14
    rolq    $30,  %r12
    rolq    $34,  %r10
    rolq    $24,  %r8
    xorq    %r15, %r14
    xorq    %r13, %r12
    xorq    %r11, %r10
    xorq    %r9,  %r8

    addq    %r14, %r13
    addq    %r8,  %r11
    addq    %r10, %r9
    addq    %r12, %r15
    rolq    $13,  %r14
    rolq    $50,  %r8
    rolq    $10,  %r10
    rolq    $17,  %r12
    xorq    %r13, %r14
    xorq    %r11, %r8
    xorq    %r9,  %r10
    xorq    %r15, %r12

    addq    %r14, %r11
    addq    %r12, %r9
    addq    %r10, %r15
    addq    %r8,  %r13
    rolq    $25,  %r14
    rolq    $29,  %r12
    rolq    $39,  %r10
    rolq    $43,  %r8
    xorq    %r11, %r14
    xorq    %r9,  %r12
    xorq    %r15, %r10
    xorq    %r13, %r8

    addq    %r14, %r9
    addq    %r8,  %r15
    addq    %r10, %r13
    addq    %r12, %r11
    rolq    $8,   %r14
    rolq    $35,  %r8
    rolq    $56,  %r10
    rolq    $22,  %r12
    xorq    %r9,  %r14
    xorq    %r15, %r8
    xorq    %r13, %r10
    xorq    %r11, %r12

    inc     %rcx
    cmp     $9, %rcx
    jne     .L11

    /* end */
    addq      (%rdi), %r15
    addq     8(%rdi), %r14
    addq    16(%rdi), %r13
    addq    24(%rdi), %r12
    addq    32(%rdi), %r11
    addq    40(%rdi), %r10
    addq    48(%rdi), %r9
    addq    56(%rdi), %r8

    movq    %r15,   (%rdx)
    movq    %r14,  8(%rdx)
    movq    %r13, 16(%rdx)
    movq    %r12, 24(%rdx)
    movq    %r11, 32(%rdx)
    movq    %r10, 40(%rdx)
    movq    %r9,  48(%rdx)
    movq    %r8,  56(%rdx)

    popq    %r12
    popq    %r13
    popq    %r14
    popq    %r15

    popq    %rbp

    ret
.size   akmos_threefish_512_encrypt, .-akmos_threefish_512_encrypt

.globl  akmos_threefish_512_decrypt
.type   akmos_threefish_512_decrypt, @function
akmos_threefish_512_decrypt:
    push    %rbp
    movq    %rsp, %rbp

    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12

    movq      (%rsi), %r15
    movq     8(%rsi), %r14
    movq    16(%rsi), %r13
    movq    24(%rsi), %r12
    movq    32(%rsi), %r11
    movq    40(%rsi), %r10
    movq    48(%rsi), %r9
    movq    56(%rsi), %r8

    addq    $1152, %rdi
    subq      (%rdi), %r15
    subq     8(%rdi), %r14
    subq    16(%rdi), %r13
    subq    24(%rdi), %r12
    subq    32(%rdi), %r11
    subq    40(%rdi), %r10
    subq    48(%rdi), %r9
    subq    56(%rdi), %r8

    mov     $0, %rcx
.L21:
    xorq    %r11, %r12
    xorq    %r13, %r10
    xorq    %r15, %r8
    xorq    %r9,  %r14
    rolq    $42,  %r12
    rolq    $8,   %r10
    rolq    $29,  %r8
    rolq    $56,  %r14
    subq    %r12, %r11
    subq    %r10, %r13
    subq    %r8,  %r15
    subq    %r14, %r9

    xorq    %r13, %r8
    xorq    %r15, %r10
    xorq    %r9,  %r12
    xorq    %r11, %r14
    rolq    $21,  %r8
    rolq    $25,  %r10
    rolq    $35,  %r12
    rolq    $39,  %r14
    subq    %r8,  %r13
    subq    %r10, %r15
    subq    %r12, %r9
    subq    %r14, %r11

    xorq    %r15, %r12
    xorq    %r9,  %r10
    xorq    %r11, %r8
    xorq    %r13, %r14
    rolq    $47,  %r12
    rolq    $54,  %r10
    rolq    $14,  %r8
    rolq    $51,  %r14
    subq    %r12, %r15
    subq    %r10, %r9
    subq    %r8,  %r11
    subq    %r14, %r13

    xorq    %r9,  %r8
    xorq    %r11, %r10
    xorq    %r13, %r12
    xorq    %r15, %r14
    rolq    $40,  %r8
    rolq    $30,  %r10
    rolq    $34,  %r12
    rolq    $25,  %r14
    subq    %r8,  %r9
    subq    %r10, %r11
    subq    %r12, %r13
    subq    %r14, %r15

    subq    $64, %rdi
    subq      (%rdi), %r15
    subq     8(%rdi), %r14
    subq    16(%rdi), %r13
    subq    24(%rdi), %r12
    subq    32(%rdi), %r11
    subq    40(%rdi), %r10
    subq    48(%rdi), %r9
    subq    56(%rdi), %r8

    xorq    %r11, %r12
    xorq    %r13, %r10
    xorq    %r15, %r8
    xorq    %r9,  %r14
    rolq    $8,   %r12
    rolq    $10,  %r10
    rolq    $55,  %r8
    rolq    $20,  %r14
    subq    %r12, %r11
    subq    %r10, %r13
    subq    %r8,  %r15
    subq    %r14, %r9

    xorq    %r13, %r8
    xorq    %r15, %r10
    xorq    %r9,  %r12
    xorq    %r11, %r14
    rolq    $25,  %r8
    rolq    $28,  %r10
    rolq    $15,  %r12
    rolq    $47,  %r14
    subq    %r8,  %r13
    subq    %r10, %r15
    subq    %r12, %r9
    subq    %r14, %r11

    xorq    %r15, %r12
    xorq    %r9,  %r10
    xorq    %r11, %r8
    xorq    %r13, %r14
    rolq    $22,  %r12
    rolq    $50,  %r10
    rolq    $37,  %r8
    rolq    $31,  %r14
    subq    %r12, %r15
    subq    %r10, %r9
    subq    %r8,  %r11
    subq    %r14, %r13

    xorq    %r9,  %r8
    xorq    %r11, %r10
    xorq    %r13, %r12
    xorq    %r15, %r14
    rolq    $27,  %r8
    rolq    $45,  %r10
    rolq    $28,  %r12
    rolq    $18,  %r14
    subq    %r8,  %r9
    subq    %r10, %r11
    subq    %r12, %r13
    subq    %r14, %r15

    subq    $64, %rdi
    subq      (%rdi), %r15
    subq     8(%rdi), %r14
    subq    16(%rdi), %r13
    subq    24(%rdi), %r12
    subq    32(%rdi), %r11
    subq    40(%rdi), %r10
    subq    48(%rdi), %r9
    subq    56(%rdi), %r8

    inc     %rcx
    cmp     $9, %rcx
    jne     .L21

    /* end */
    movq    %r15,   (%rdx)
    movq    %r14,  8(%rdx)
    movq    %r13, 16(%rdx)
    movq    %r12, 24(%rdx)
    movq    %r11, 32(%rdx)
    movq    %r10, 40(%rdx)
    movq    %r9,  48(%rdx)
    movq    %r8,  56(%rdx)

    popq    %r12
    popq    %r13
    popq    %r14
    popq    %r15

    popq    %rbp

    ret
.size   akmos_threefish_512_decrypt, .-akmos_threefish_512_decrypt

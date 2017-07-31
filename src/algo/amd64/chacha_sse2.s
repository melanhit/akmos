/*
 *   Copyright (c) 2017, Andrew Romanenko <melanhit@gmail.com>
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
.file   "chacha_sse2.s"
.globl  akmos_chacha_setiv
.type   akmos_chacha_setiv, @function
akmos_chacha_setiv:
    movl    (%rsi), %r8d
    movl   4(%rsi), %r9d
    movl   8(%rsi), %r10d

    movl     %r8d, 52(%rdi)
    movl     %r9d, 56(%rdi)
    movl    %r10d, 60(%rdi)

    ret
.size   akmos_chacha_setiv, .-akmos_chacha_setiv

.globl  akmos_chacha_setcnt
.type   akmos_chacha_setcnt, @function
akmos_chacha_setcnt:
    movl    (%rsi), %eax
    movl    %eax, 48(%rdi)

    ret
.size   akmos_chacha_setcnt, .-akmos_chacha_setcnt

.globl  akmos_chacha_setkey
.type   akmos_chacha_setkey, @function
akmos_chacha_setkey:
    pushq   %rbp
    movq    %rsp, %rbp

    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12

    movl     $0x61707865,   (%rdi)
    movl     $0x3320646e,  4(%rdi)
    movl     $0x79622d32,  8(%rdi)
    movl     $0x6b206574, 12(%rdi)

    movl       (%rsi), %r8d
    movl      4(%rsi), %r9d
    movl      8(%rsi), %r10d
    movl     12(%rsi), %r11d
    movl     16(%rsi), %r12d
    movl     20(%rsi), %r13d
    movl     24(%rsi), %r14d
    movl     28(%rsi), %r15d

    movl      %r8d, 16(%rdi)
    movl      %r9d, 20(%rdi)
    movl     %r10d, 24(%rdi)
    movl     %r11d, 28(%rdi)
    movl     %r12d, 32(%rdi)
    movl     %r13d, 36(%rdi)
    movl     %r14d, 40(%rdi)
    movl     %r15d, 44(%rdi)

    popq    %r12
    popq    %r13
    popq    %r14
    popq    %r15

    popq    %rbp

    ret
.size   akmos_chacha_setkey, .-akmos_chacha_setkey

.globl  akmos_chacha_stream
.type   akmos_chacha_stream, @function
akmos_chacha_stream:
    movdqa    (%rdi), %xmm0
    movdqa  16(%rdi), %xmm1
    movdqa  32(%rdi), %xmm2
    movdqa  48(%rdi), %xmm3

    movdqa  %xmm0, %xmm10
    movdqa  %xmm1, %xmm11
    movdqa  %xmm2, %xmm12
    movdqa  %xmm3, %xmm13

    movq    $0, %rcx

.L10:
    cmpq    $10, %rcx
    je      .L11

    paddd   %xmm1, %xmm0

    pxor    %xmm0, %xmm3
    movdqa  %xmm3, %xmm4
    pslld   $16,   %xmm4
    psrld   $16,   %xmm3
    por     %xmm4, %xmm3

    paddd   %xmm3, %xmm2

    pxor    %xmm2, %xmm1
    movdqa  %xmm1, %xmm4
    pslld   $12,   %xmm4
    psrld   $20,   %xmm1
    por     %xmm4, %xmm1

    paddd   %xmm1, %xmm0

    pxor    %xmm0, %xmm3
    movdqa  %xmm3, %xmm4
    pslld   $8,    %xmm4
    psrld   $24,   %xmm3
    por     %xmm4, %xmm3

    paddd   %xmm3, %xmm2

    pxor    %xmm2, %xmm1
    movdqa  %xmm1, %xmm4
    pslld   $7,    %xmm4
    psrld   $25,   %xmm1
    por     %xmm4, %xmm1

    shufps  $0x39, %xmm1, %xmm1
    shufps  $0x4e, %xmm2, %xmm2
    shufps  $0x93, %xmm3, %xmm3

    paddd   %xmm1, %xmm0

    pxor    %xmm0, %xmm3
    movdqa  %xmm3, %xmm4
    pslld   $16,   %xmm4
    psrld   $16,   %xmm3
    por     %xmm4, %xmm3

    paddd   %xmm3, %xmm2

    pxor    %xmm2, %xmm1
    movdqa  %xmm1, %xmm4
    pslld   $12,   %xmm4
    psrld   $20,   %xmm1
    por     %xmm4, %xmm1

    paddd   %xmm1, %xmm0

    pxor    %xmm0, %xmm3
    movdqa  %xmm3, %xmm4
    pslld   $8,    %xmm4
    psrld   $24,   %xmm3
    por     %xmm4, %xmm3

    paddd   %xmm3, %xmm2

    pxor    %xmm2, %xmm1
    movdqa  %xmm1, %xmm4
    pslld   $7,    %xmm4
    psrld   $25,   %xmm1
    por     %xmm4, %xmm1

    shufps  $0x93, %xmm1, %xmm1
    shufps  $0x4e, %xmm2, %xmm2
    shufps  $0x39, %xmm3, %xmm3

    incq    %rcx
    jmp     .L10

.L11:
    paddd   %xmm10, %xmm0
    paddd   %xmm11, %xmm1
    paddd   %xmm12, %xmm2
    paddd   %xmm13, %xmm3

    movl    48(%rdi), %eax
    inc     %eax
    movl    %eax, 48(%rdi)

    movdqu  %xmm0,   (%rsi)
    movdqu  %xmm1, 16(%rsi)
    movdqu  %xmm2, 32(%rsi)
    movdqu  %xmm3, 48(%rsi)

    ret
.size   akmos_chacha_stream, .-akmos_chacha_stream

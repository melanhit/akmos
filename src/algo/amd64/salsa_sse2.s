/*
 *   Copyright (c) 2016-2018, Andrew Romanenko <melanhit@gmail.com>
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
.file   "salsa_sse2.s"
.globl  akmos_salsa_setiv
.type   akmos_salsa_setiv, @function
akmos_salsa_setiv:
    movl    (%rsi), %eax
    movl   4(%rsi), %ecx

    movl    %eax, 40(%rdi)
    movl    %ecx, 60(%rdi)

    ret
.size   akmos_salsa_setiv, .-akmos_salsa_setiv

.globl  akmos_salsa_setcnt
.type   akmos_salsa_setcnt, @function
akmos_salsa_setcnt:
    movl    (%rsi), %eax
    movl   4(%rsi), %ecx

    movl    %eax, 48(%rdi)
    movl    %ecx, 4(%rdi)

    ret
.size   akmos_salsa_setcnt, .-akmos_salsa_setcnt

.globl  akmos_salsa_setkey
.type   akmos_salsa_setkey, @function
akmos_salsa_setkey:

    cmp     $16, %rdx
    je      .L01

    cmp     $32, %rdx
    je      .L02

    jmp     .L03

.L01:
    movl       (%rsi), %eax
    movl      4(%rsi), %ecx
    movl      8(%rsi), %r8d
    movl     12(%rsi), %r9d

    movl     %eax, 36(%rdi)
    movl     %eax, 44(%rdi)
    movl     %ecx, 56(%rdi)
    movl     %ecx, 32(%rdi)
    movl     %r8d, 12(%rdi)
    movl     %r8d, 52(%rdi)
    movl     %r9d,   (%rdi)
    movl     %r9d,  8(%rdi)

    movl     $0x61707865, 16(%rdi)
    movl     $0x3120646E, 20(%rdi)
    movl     $0x79622D36, 24(%rdi)
    movl     $0x6B206574, 28(%rdi)

    jmp     .L03

.L02:
    movl       (%rsi), %eax
    movl      4(%rsi), %ecx
    movl      8(%rsi), %r8d
    movl     12(%rsi), %r9d

    movl     %eax, 36(%rdi)
    movl     %ecx, 56(%rdi)
    movl     %r8d, 12(%rdi)
    movl     %r9d,   (%rdi)

    movl     16(%rsi), %eax
    movl     20(%rsi), %ecx
    movl     24(%rsi), %r8d
    movl     28(%rsi), %r9d

    movl     %eax, 44(%rdi)
    movl     %ecx, 32(%rdi)
    movl     %r8d, 52(%rdi)
    movl     %r9d,  8(%rdi)

    movl     $0x61707865, 16(%rdi)
    movl     $0x3320646E, 20(%rdi)
    movl     $0x79622D32, 24(%rdi)
    movl     $0x6B206574, 28(%rdi)

    jmp     .L03

.L03:
    ret
.size   akmos_salsa_setkey, .-akmos_salsa_setkey


.globl  akmos_salsa_stream
.type   akmos_salsa_stream, @function
akmos_salsa_stream:

    movdqu    (%rdi), %xmm12
    movdqu  16(%rdi), %xmm13
    movdqu  32(%rdi), %xmm14
    movdqu  48(%rdi), %xmm15

    movdqa  %xmm12, %xmm0
    movdqa  %xmm13, %xmm1
    movdqa  %xmm14, %xmm2
    movdqa  %xmm15, %xmm3

    movq    $0, %rcx

.L10:
    cmpq    $10, %rcx
    je      .L11

    movdqa  %xmm1, %xmm4
    paddd   %xmm2, %xmm4
    movdqa  %xmm4, %xmm5
    pslld   $7, %xmm5
    psrld   $25, %xmm4
    por     %xmm5, %xmm4
    pxor    %xmm4, %xmm0

    movdqa  %xmm0, %xmm4
    paddd   %xmm1, %xmm4
    movdqa  %xmm4, %xmm5
    pslld   $9, %xmm5
    psrld   $23, %xmm4
    por     %xmm5, %xmm4
    pxor    %xmm4, %xmm3

    movdqa  %xmm3, %xmm4
    paddd   %xmm0, %xmm4
    movdqa  %xmm4, %xmm5
    pslld   $13, %xmm5
    psrld   $19, %xmm4
    por     %xmm5, %xmm4
    pxor    %xmm4, %xmm2

    movdqa  %xmm2, %xmm4
    paddd   %xmm3, %xmm4
    movdqa  %xmm4, %xmm5
    pslld   $18, %xmm5
    psrld   $14, %xmm4
    por     %xmm5, %xmm4
    pxor    %xmm4, %xmm1

    shufps  $0x93, %xmm0, %xmm0
    shufps  $0x39, %xmm2, %xmm2
    shufps  $0x4E, %xmm3, %xmm3

    movdqa  %xmm1, %xmm4
    paddd   %xmm0, %xmm4
    movdqa  %xmm4, %xmm5
    pslld   $7, %xmm5
    psrld   $25, %xmm4
    por     %xmm5, %xmm4
    pxor    %xmm4, %xmm2

    movdqa  %xmm2, %xmm4
    paddd   %xmm1, %xmm4
    movdqa  %xmm4, %xmm5
    pslld   $9, %xmm5
    psrld   $23, %xmm4
    por     %xmm5, %xmm4
    pxor    %xmm4, %xmm3

    movdqa  %xmm3, %xmm4
    paddd   %xmm2, %xmm4
    movdqa  %xmm4, %xmm5
    pslld   $13, %xmm5
    psrld   $19, %xmm4
    por     %xmm5, %xmm4
    pxor    %xmm4, %xmm0

    movdqa  %xmm0, %xmm4
    paddd   %xmm3, %xmm4
    movdqa  %xmm4, %xmm5
    pslld   $18, %xmm5
    psrld   $14, %xmm4
    por     %xmm5, %xmm4
    pxor    %xmm4, %xmm1

    shufps  $0x39, %xmm0, %xmm0
    shufps  $0x93, %xmm2, %xmm2
    shufps  $0x4E, %xmm3, %xmm3

    incq    %rcx
    jmp     .L10

.L11:
    paddd   %xmm12, %xmm0
    paddd   %xmm13, %xmm1
    paddd   %xmm14, %xmm2
    paddd   %xmm15, %xmm3

    movl    4(%rdi), %eax
    shrq    $32, %rax
    movl    48(%rdi), %eax
    incq    %rax
    movl    %eax, 48(%rdi)
    shlq    $32, %rax
    movl    %eax, 4(%rdi)

    movdqu  %xmm0,   (%rsi)
    movdqu  %xmm1, 16(%rsi)
    movdqu  %xmm2, 32(%rsi)
    movdqu  %xmm3, 48(%rsi)

    movl      (%rsi), %eax
    movl    16(%rsi), %ecx
    movl    %eax, 16(%rsi)
    movl    %ecx,   (%rsi)

    movl     4(%rsi), %eax
    movl    36(%rsi), %ecx
    movl    %eax, 36(%rsi)
    movl    %ecx,  4(%rsi)

    movl     8(%rsi), %eax
    movl    56(%rsi), %ecx
    movl    %eax, 56(%rsi)
    movl    %ecx,  8(%rsi)

    movl    24(%rsi), %eax
    movl    40(%rsi), %ecx
    movl    %eax, 40(%rsi)
    movl    %ecx, 24(%rsi)

    movl    28(%rsi), %eax
    movl    60(%rsi), %ecx
    movl    %eax, 60(%rsi)
    movl    %ecx, 28(%rsi)

    movl    32(%rsi), %eax
    movl    48(%rsi), %ecx
    movl    %eax, 48(%rsi)
    movl    %ecx, 32(%rsi)

    ret
.size   akmos_salsa_stream, .-akmos_salsa_stream

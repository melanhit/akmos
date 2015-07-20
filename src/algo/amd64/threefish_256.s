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
.file   "threefish_256.s"
.globl  akmos_threefish_256_setkey
.type   akmos_threefish_256_setkey, @function
akmos_threefish_256_setkey:
    movq      (%rsi), %r10
    movq     8(%rsi), %r11
    movq    16(%rsi), %r8
    movq    24(%rsi), %r9

    movabsq $0x1bd11bdaa9fc1a22, %rax

    xorq    %r10, %rax
    xorq    %r11, %rax
    xorq    %r8,  %rax
    xorq    %r9,  %rax

    movq    $0, %rcx
.L01:
    movq    %r10,  (%rdi)
    movq    %r11, 8(%rdi)
    movq    %r8, 16(%rdi)
    movq    %r9, 24(%rdi)
    addq    %rcx,24(%rdi)
    incq    %rcx
    addq    $32, %rdi

    movq    %r11,  (%rdi)
    movq    %r8,  8(%rdi)
    movq    %r9, 16(%rdi)
    movq    %rax,24(%rdi)
    addq    %rcx,24(%rdi)
    incq    %rcx
    addq    $32, %rdi

    movq    %r8,   (%rdi)
    movq    %r9,  8(%rdi)
    movq    %rax,16(%rdi)
    movq    %r10,24(%rdi)
    addq    %rcx,24(%rdi)
    incq    %rcx
    addq    $32, %rdi

    movq    %r9,   (%rdi)
    movq    %rax, 8(%rdi)
    movq    %r10,16(%rdi)
    movq    %r11,24(%rdi)
    addq    %rcx,24(%rdi)
    incq    %rcx
    addq    $32, %rdi

    movq    %rax,  (%rdi)
    movq    %r10, 8(%rdi)
    movq    %r11,16(%rdi)
    movq    %r8, 24(%rdi)
    addq    %rcx,24(%rdi)
    incq    %rcx
    addq    $32, %rdi

    cmp     $15, %rcx
    jne     .L01

    movq    %r10,  (%rdi)
    movq    %r11, 8(%rdi)
    movq    %r8, 16(%rdi)
    movq    %r9, 24(%rdi)
    addq    %rcx,24(%rdi)
    incq    %rcx
    addq    $32, %rdi

    movq    %r11,  (%rdi)
    movq    %r8,  8(%rdi)
    movq    %r9, 16(%rdi)
    movq    %rax,24(%rdi)
    addq    %rcx,24(%rdi)
    incq    %rcx
    addq    $32, %rdi

    movq    %r8,   (%rdi)
    movq    %r9,  8(%rdi)
    movq    %rax,16(%rdi)
    movq    %r10,24(%rdi)
    addq    %rcx,24(%rdi)
    incq    %rcx
    addq    $32, %rdi

    movq    %r9,   (%rdi)
    movq    %rax, 8(%rdi)
    movq    %r10,16(%rdi)
    movq    %r11,24(%rdi)
    addq    %rcx,24(%rdi)

    ret
.size   akmos_threefish_256_setkey, .-akmos_threefish_256_setkey

.globl  akmos_threefish_256_encrypt
.type   akmos_threefish_256_encrypt, @function
akmos_threefish_256_encrypt:
    movq      (%rsi), %r10
    movq     8(%rsi), %r11
    movq    16(%rsi), %r8
    movq    24(%rsi), %r9

    mov     $0, %rcx
.L11:
    addq      (%rdi), %r10
    addq     8(%rdi), %r11
    addq    16(%rdi), %r8
    addq    24(%rdi), %r9
    addq    $32, %rdi

    addq    %r11, %r10
    addq    %r9, %r8
    rolq    $14, %r11
    rolq    $16, %r9
    xorq    %r10, %r11
    xorq    %r8, %r9

    addq    %r9, %r10
    addq    %r11, %r8
    rolq    $52, %r9
    rolq    $57, %r11
    xorq    %r10, %r9
    xorq    %r8, %r11

    addq    %r11, %r10
    addq    %r9, %r8
    rolq    $23, %r11
    rolq    $40, %r9
    xorq    %r10, %r11
    xorq    %r8, %r9

    addq    %r9, %r10
    addq    %r11, %r8
    rolq    $5, %r9
    rolq    $37, %r11
    xorq    %r10, %r9
    xorq    %r8, %r11

    addq      (%rdi), %r10
    addq     8(%rdi), %r11
    addq    16(%rdi), %r8
    addq    24(%rdi), %r9
    addq    $32, %rdi

    addq    %r11, %r10
    addq    %r9, %r8
    rolq    $25, %r11
    rolq    $33, %r9
    xorq    %r10, %r11
    xorq    %r8, %r9

    addq    %r9, %r10
    addq    %r11, %r8
    rolq    $46, %r9
    rolq    $12, %r11
    xorq    %r10, %r9
    xorq    %r8, %r11

    addq    %r11, %r10
    addq    %r9, %r8
    rolq    $58, %r11
    rolq    $22, %r9
    xorq    %r10, %r11
    xorq    %r8, %r9

    addq    %r9, %r10
    addq    %r11, %r8
    rolq    $32, %r9
    rolq    $32, %r11
    xorq    %r10, %r9
    xorq    %r8, %r11

    inc     %rcx
    cmp     $9, %rcx
    jne     .L11

    /* end */
    addq      (%rdi), %r10
    addq     8(%rdi), %r11
    addq    16(%rdi), %r8
    addq    24(%rdi), %r9

    movq    %r10,  (%rdx)
    movq    %r11, 8(%rdx)
    movq    %r8, 16(%rdx)
    movq    %r9, 24(%rdx)

    ret
.size   akmos_threefish_256_encrypt, .-akmos_threefish_256_encrypt

.globl  akmos_threefish_256_decrypt
.type   akmos_threefish_256_decrypt, @function
akmos_threefish_256_decrypt:
    movq      (%rsi), %r8
    movq     8(%rsi), %r9
    movq    16(%rsi), %r10
    movq    24(%rsi), %r11

    movq    $0, %rcx

    addq    $576, %rdi

    subq      (%rdi), %r8
    subq     8(%rdi), %r9
    subq    16(%rdi), %r10
    subq    24(%rdi), %r11

.L21:
    xorq    %r8, %r11
    xorq    %r10, %r9
    rorq    $32, %r11
    rorq    $32, %r9
    subq    %r11, %r8
    subq    %r9, %r10

    xorq    %r8, %r9
    xorq    %r10, %r11
    rorq    $58, %r9
    rorq    $22, %r11
    subq    %r9, %r8
    subq    %r11, %r10

    xorq    %r8, %r11
    xorq    %r10, %r9
    rorq    $46, %r11
    rorq    $12, %r9
    subq    %r11, %r8
    subq    %r9, %r10

    xorq    %r8, %r9
    xorq    %r10, %r11
    rorq    $25, %r9
    rorq    $33, %r11
    subq    %r9, %r8
    subq    %r11, %r10

    subq    $32, %rdi
    subq      (%rdi), %r8
    subq     8(%rdi), %r9
    subq    16(%rdi), %r10
    subq    24(%rdi), %r11

    xorq    %r8, %r11
    xorq    %r10, %r9
    rorq    $5, %r11
    rorq    $37, %r9
    subq    %r11, %r8
    subq    %r9, %r10

    xorq    %r8, %r9
    xorq    %r10, %r11
    rorq    $23, %r9
    rorq    $40, %r11
    subq    %r9, %r8
    subq    %r11, %r10

    xorq    %r8, %r11
    xorq    %r10, %r9
    rorq    $52, %r11
    rorq    $57, %r9
    subq    %r11, %r8
    subq    %r9, %r10

    xorq    %r8, %r9
    xorq    %r10, %r11
    rorq    $14, %r9
    rorq    $16, %r11
    subq    %r9, %r8
    subq    %r11, %r10

    subq    $32, %rdi
    subq      (%rdi), %r8
    subq     8(%rdi), %r9
    subq    16(%rdi), %r10
    subq    24(%rdi), %r11

    inc     %rcx
    cmp     $9, %rcx
    jne     .L21

    /* end */
    movq    %r8,   (%rdx)
    movq    %r9,   8(%rdx)
    movq    %r10, 16(%rdx)
    movq    %r11, 24(%rdx)

    ret
.size   akmos_threefish_256_decrypt, .-akmos_threefish_256_decrypt

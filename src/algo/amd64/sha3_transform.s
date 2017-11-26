/*
 *   Copyright (c) 2015-2017, Andrew Romanenko <melanhit@gmail.com>
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
.file   "sha3_transform.s"
.align 16
.globl  akmos_sha3_transform
.type   akmos_sha3_transform, @function
akmos_sha3_transform:
    pushq   %rbp
    movq    %rsp, %rbp

    pushq   %rbx
    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12

.L4:
    cmp     $0, %rcx
    je      .L1

    pushq   %rcx
    pushq   %rdx

    movq      (%rsi), %r15
    movq     8(%rsi), %r14
    movq    16(%rsi), %r13
    movq    24(%rsi), %r12
    movq    32(%rsi), %r11
    movq    40(%rsi), %r10
    movq    48(%rsi), %r9
    movq    56(%rsi), %r8
    movq    64(%rsi), %rax

    xorq    %r15,   (%rdi)
    xorq    %r14,  8(%rdi)
    xorq    %r13, 16(%rdi)
    xorq    %r12, 24(%rdi)
    xorq    %r11, 32(%rdi)
    xorq    %r10, 40(%rdi)
    xorq    %r9,  48(%rdi)
    xorq    %r8,  56(%rdi)
    xorq    %rax, 64(%rdi)

    movq    %rdi, %r8
    addq    $72, %r8
    addq    $72, %rsi

    subq    $9, %rdx

.L2:
    cmp     $0, %rdx
    je      .L31

    movq    (%rsi), %r15
    xorq    %r15,   (%r8)

    addq    $8, %r8
    addq    $8, %rsi

    subq    $1, %rdx
    jmp     .L2

.L31:
    movq    $0, %rax

    leaq    RC(%rip), %r10

.L3:
    cmp     $24, %rax
    je      .L5

    pushq   %rax
    pushq   %r10

.L0:
    movq      (%rdi), %r15
    movq     8(%rdi), %r14
    movq    16(%rdi), %r13
    movq    24(%rdi), %r12
    movq    32(%rdi), %r11

    xorq    40(%rdi), %r15
    xorq    48(%rdi), %r14
    xorq    56(%rdi), %r13
    xorq    64(%rdi), %r12
    xorq    72(%rdi), %r11

    xorq     80(%rdi), %r15
    xorq     88(%rdi), %r14
    xorq     96(%rdi), %r13
    xorq    104(%rdi), %r12
    xorq    112(%rdi), %r11

    xorq    120(%rdi), %r15
    xorq    128(%rdi), %r14
    xorq    136(%rdi), %r13
    xorq    144(%rdi), %r12
    xorq    152(%rdi), %r11

    xorq    160(%rdi), %r15
    xorq    168(%rdi), %r14
    xorq    176(%rdi), %r13
    xorq    184(%rdi), %r12
    xorq    192(%rdi), %r11

    movq    %r15, %r10
    movq    %r14, %r9
    movq    %r13, %r8
    movq    %r12, %rax
    movq    %r11, %rcx

    rolq    $1, %r14
    rolq    $1, %r13
    rolq    $1, %r12
    rolq    $1, %r11
    rolq    $1, %r15

    xorq    %r14, %rcx
    xorq    %r13, %r10
    xorq    %r12, %r9
    xorq    %r11, %r8
    xorq    %r15, %rax

    /* b 17-20-21-22-23 */
    movq    %r10, %r11
    movq    %r9,  %r12
    movq    %r8,  %r13
    movq    %rax, %r14
    movq    %rcx, %r15
    xorq     88(%rdi), %r11
    xorq     16(%rdi), %r12
    xorq     64(%rdi), %r13
    xorq    112(%rdi), %r14
    xorq    120(%rdi), %r15
    rolq    $10, %r11
    rolq    $62, %r12
    rolq    $55, %r13
    rolq    $39, %r14
    rolq    $41, %r15
    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12
    pushq   %r11

    /* b 5-10-11-15-16 */
    movq    %r8,  %r11
    movq    %r10, %r12
    movq    %r9,  %r13
    movq    %rax, %r14
    movq    %rcx, %r15
    xorq    24(%rdi), %r11
    xorq     8(%rdi), %r12
    xorq    56(%rdi), %r13
    xorq    32(%rdi), %r14
    xorq    40(%rdi), %r15
    rolq    $28, %r11
    rolq    $1,  %r12
    rolq    $6,  %r13
    rolq    $27, %r14
    rolq    $36, %r15
    pushq   %r15
    pushq   %r14
    pushq   %r13
    pushq   %r12
    pushq   %r11

    /* b 0-1-2-3-4 */
    movq    %rcx, %r11
    movq    %r10, %r12
    movq    %r9,  %r13
    movq    %r8, %r14
    movq    %rax, %r15
    xorq    (%rdi), %r11
    xorq    48(%rdi), %r12
    xorq    96(%rdi), %r13
    xorq    144(%rdi), %r14
    xorq    192(%rdi), %r15
    rolq    $44, %r12
    rolq    $43, %r13
    rolq    $21, %r14
    rolq    $14, %r15

    /* s0 */
    movq    %r12, %rdx
    notq    %rdx
    andq    %r13, %rdx
    xorq    %r11, %rdx
    movq    %rdx, (%rdi)

    /* s1 */
    movq    %r13, %rdx
    notq    %rdx
    andq    %r14, %rdx
    xorq    %r12, %rdx
    movq    %rdx, 8(%rdi)

    /* s2 */
    movq    %r14, %rdx
    notq    %rdx
    andq    %r15, %rdx
    xorq    %r13, %rdx
    movq    %rdx, 16(%rdi)

    /* s3 */
    movq    %r15, %rdx
    notq    %rdx
    andq    %r11, %rdx
    xorq    %r14, %rdx
    movq    %rdx, 24(%rdi)

    /* s4 */
    notq    %r11
    andq    %r12, %r11
    xorq    %r15, %r11
    movq    %r11, 32(%rdi)

    /* b 5-6-7-8-9 */
    popq    %r11
    movq    %rax, %r12
    movq    %rcx, %r13
    movq    %r10, %r14
    movq    %r9, %r15
    xorq    72(%rdi), %r12
    xorq    80(%rdi), %r13
    xorq    128(%rdi), %r14
    xorq    176(%rdi), %r15
    rolq    $20, %r12
    rolq    $3, %r13
    rolq    $45, %r14
    rolq    $61, %r15

    /* s5 */
    movq    %r12, %rdx
    notq    %rdx
    andq    %r13, %rdx
    xorq    %r11, %rdx
    movq    %rdx, 40(%rdi)

    /* s6 */
    movq    %r13, %rdx
    notq    %rdx
    andq    %r14, %rdx
    xorq    %r12, %rdx
    movq    %rdx, 48(%rdi)

    /* s7 */
    movq    %r14, %rdx
    notq    %rdx
    andq    %r15, %rdx
    xorq    %r13, %rdx
    movq    %rdx, 56(%rdi)

    /* s8 */
    movq    %r15, %rdx
    notq    %rdx
    andq    %r11, %rdx
    xorq    %r14, %rdx
    movq    %rdx, 64(%rdi)

    /* s9 */
    notq    %r11
    andq    %r12, %r11
    xorq    %r15, %r11
    movq    %r11, 72(%rdi)

    /* b 10-11-12-13-14 */
    popq    %r11
    popq    %r12
    movq    %r8, %r13
    movq    %rax, %r14
    movq    %rcx, %r15
    xorq    104(%rdi), %r13
    xorq    152(%rdi), %r14
    xorq    160(%rdi), %r15
    rolq    $25, %r13
    rolq    $8,  %r14
    rolq    $18, %r15

    /* s10 */
    movq    %r12, %rdx
    notq    %rdx
    andq    %r13, %rdx
    xorq    %r11, %rdx
    movq    %rdx, 80(%rdi)

    /* s11 */
    movq    %r13, %rdx
    notq    %rdx
    andq    %r14, %rdx
    xorq    %r12, %rdx
    movq    %rdx, 88(%rdi)

    /* s12 */
    movq    %r14, %rdx
    notq    %rdx
    andq    %r15, %rdx
    xorq    %r13, %rdx
    movq    %rdx, 96(%rdi)

    /* s13 */
    movq    %r15, %rdx
    notq    %rdx
    andq    %r11, %rdx
    xorq    %r14, %rdx
    movq    %rdx, 104(%rdi)

    /* s14 */
    notq    %r11
    andq    %r12, %r11
    xorq    %r15, %r11
    movq    %r11, 112(%rdi)

    /* b 15-16-17-18-19 */
    popq    %r11
    popq    %r12
    popq    %r13
    movq    %r9, %r14
    movq    %r8, %r15
    xorq    136(%rdi), %r14
    xorq    184(%rdi), %r15
    rolq    $15, %r14
    rolq    $56, %r15

    /* s15 */
    movq    %r12, %rdx
    notq    %rdx
    andq    %r13, %rdx
    xorq    %r11, %rdx
    movq    %rdx, 120(%rdi)

    /* s16 */
    movq    %r13, %rdx
    notq    %rdx
    andq    %r14, %rdx
    xorq    %r12, %rdx
    movq    %rdx, 128(%rdi)

    /* s17 */
    movq    %r14, %rdx
    notq    %rdx
    andq    %r15, %rdx
    xorq    %r13, %rdx
    movq    %rdx, 136(%rdi)

    /* s18 */
    movq    %r15, %rdx
    notq    %rdx
    andq    %r11, %rdx
    xorq    %r14, %rdx
    movq    %rdx, 144(%rdi)

    /* s19 */
    notq    %r11
    andq    %r12, %r11
    xorq    %r15, %r11
    movq    %r11, 152(%rdi)

    /* b 20-21-22-23-24 */
    popq    %r11
    popq    %r12
    popq    %r13
    popq    %r14
    xorq    168(%rdi), %r10
    rolq    $2, %r10

    /* s20 */
    movq    %r12, %rdx
    notq    %rdx
    andq    %r13, %rdx
    xorq    %r11, %rdx
    movq    %rdx, 160(%rdi)

    /* s21 */
    movq    %r13, %rdx
    notq    %rdx
    andq    %r14, %rdx
    xorq    %r12, %rdx
    movq    %rdx, 168(%rdi)

    /* s22 */
    movq    %r14, %rdx
    notq    %rdx
    andq    %r10, %rdx
    xorq    %r13, %rdx
    movq    %rdx, 176(%rdi)

    /* s23 */
    movq    %r10, %rdx
    notq    %rdx
    andq    %r11, %rdx
    xorq    %r14, %rdx
    movq    %rdx, 184(%rdi)

    /* s24 */
    notq    %r11
    andq    %r12, %r11
    xorq    %r10, %r11
    movq    %r11, 192(%rdi)

    /* xor RC with S[0] */
    popq    %r10
    movq    (%r10), %r11
    xorq    %r11, (%rdi)
    addq    $8, %r10

    popq    %rax
    addq    $1, %rax
    jmp     .L3

.L5:
    popq    %rdx
    popq    %rcx
    subq    $1, %rcx
    jmp     .L4

.L1:
    /* clear stack */
    pushq   $0
    pushq   $0
    pushq   $0
    pushq   $0
    pushq   $0
    pushq   $0
    pushq   $0
    pushq   $0
    pushq   $0
    pushq   $0
    popq    %rax
    popq    %rax
    popq    %rax
    popq    %rax
    popq    %rax
    popq    %rax
    popq    %rax
    popq    %rax
    popq    %rax
    popq    %rax

    popq    %r12
    popq    %r13
    popq    %r14
    popq    %r15
    popq    %rbx

    popq    %rbp

    ret
.size   akmos_sha3_transform, .-akmos_sha3_transform

.type   RC,@object
.data
.align  16
RC:
    .quad   0x0000000000000001
    .quad   0x0000000000008082
    .quad   0x800000000000808a
    .quad   0x8000000080008000
    .quad   0x000000000000808b
    .quad   0x0000000080000001
    .quad   0x8000000080008081
    .quad   0x8000000000008009
    .quad   0x000000000000008a
    .quad   0x0000000000000088
    .quad   0x0000000080008009
    .quad   0x000000008000000a
    .quad   0x000000008000808b
    .quad   0x800000000000008b
    .quad   0x8000000000008089
    .quad   0x8000000000008003
    .quad   0x8000000000008002
    .quad   0x8000000000000080
    .quad   0x000000000000800a
    .quad   0x800000008000000a
    .quad   0x8000000080008081
    .quad   0x8000000000008080
    .quad   0x0000000080000001
    .quad   0x8000000080008008
.size   RC, 192

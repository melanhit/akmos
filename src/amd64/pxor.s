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
.file   "pxor.s"
.globl  akmos_pxor8
.type   akmos_pxor8, @function
akmos_pxor8:
    movq    (%rdi), %r8
    xorq    (%rsi), %r8
    movq    %r8,  (%rdx)

    ret
.size   akmos_pxor8, .-akmos_pxor8

.globl  akmos_pxor16
.type   akmos_pxor16, @function
akmos_pxor16:
    movq     (%rdi), %r8
    movq    8(%rdi), %r9

    xorq     (%rsi), %r8
    xorq    8(%rsi), %r9

    movq    %r8,  (%rdx)
    movq    %r9, 8(%rdx)

    ret
.size   akmos_pxor16, .-akmos_pxor16

.globl  akmos_pxor32
.type   akmos_pxor32, @function
akmos_pxor32:
    movq      (%rdi), %r8
    movq     8(%rdi), %r9
    movq    16(%rdi), %r10
    movq    24(%rdi), %r11

    xorq      (%rsi), %r8
    xorq     8(%rsi), %r9
    xorq    16(%rsi), %r10
    xorq    24(%rsi), %r11

    movq    %r8,    (%rdx)
    movq    %r9,   8(%rdx)
    movq    %r10, 16(%rdx)
    movq    %r11, 24(%rdx)

    ret
.size   akmos_pxor32, .-akmos_pxor32

.globl  akmos_pxor64
.type   akmos_pxor64, @function
akmos_pxor64:
    movq      (%rdi), %r8
    movq     8(%rdi), %r9
    movq    16(%rdi), %r10
    movq    24(%rdi), %r11

    xorq      (%rsi), %r8
    xorq     8(%rsi), %r9
    xorq    16(%rsi), %r10
    xorq    24(%rsi), %r11

    movq    %r8,    (%rdx)
    movq    %r9,   8(%rdx)
    movq    %r10, 16(%rdx)
    movq    %r11, 24(%rdx)

    movq    32(%rdi), %r8
    movq    40(%rdi), %r9
    movq    48(%rdi), %r10
    movq    56(%rdi), %r11

    xorq    32(%rsi), %r8
    xorq    40(%rsi), %r9
    xorq    48(%rsi), %r10
    xorq    56(%rsi), %r11

    movq    %r8,  32(%rdx)
    movq    %r9,  40(%rdx)
    movq    %r10, 48(%rdx)
    movq    %r11, 56(%rdx)

    ret
.size   akmos_pxor64, .-akmos_pxor64

.globl  akmos_pxor128
.type   akmos_pxor128, @function
akmos_pxor128:
    movq      (%rdi), %r8
    movq     8(%rdi), %r9
    movq    16(%rdi), %r10
    movq    24(%rdi), %r11

    xorq      (%rsi), %r8
    xorq     8(%rsi), %r9
    xorq    16(%rsi), %r10
    xorq    24(%rsi), %r11

    movq    %r8,    (%rdx)
    movq    %r9,   8(%rdx)
    movq    %r10, 16(%rdx)
    movq    %r11, 24(%rdx)

    movq    32(%rdi), %r8
    movq    40(%rdi), %r9
    movq    48(%rdi), %r10
    movq    56(%rdi), %r11

    xorq    32(%rsi), %r8
    xorq    40(%rsi), %r9
    xorq    48(%rsi), %r10
    xorq    56(%rsi), %r11

    movq    %r8,  32(%rdx)
    movq    %r9,  40(%rdx)
    movq    %r10, 48(%rdx)
    movq    %r11, 56(%rdx)

    movq    64(%rdi), %r8
    movq    72(%rdi), %r9
    movq    80(%rdi), %r10
    movq    88(%rdi), %r11

    xorq    64(%rsi), %r8
    xorq    72(%rsi), %r9
    xorq    80(%rsi), %r10
    xorq    88(%rsi), %r11

    movq    %r8,  64(%rdx)
    movq    %r9,  72(%rdx)
    movq    %r10, 80(%rdx)
    movq    %r11, 88(%rdx)

    movq     96(%rdi), %r8
    movq    104(%rdi), %r9
    movq    112(%rdi), %r10
    movq    120(%rdi), %r11

    xorq     96(%rsi), %r8
    xorq    104(%rsi), %r9
    xorq    112(%rsi), %r10
    xorq    120(%rsi), %r11

    movq    %r8,   96(%rdx)
    movq    %r9,  104(%rdx)
    movq    %r10, 112(%rdx)
    movq    %r11, 120(%rdx)

    ret
.size   akmos_pxor128, .-akmos_pxor128

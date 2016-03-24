/*
 *   Copyright (c) 2015-2016, Andrew Romanenko <melanhit@gmail.com>
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

#include <stdint.h>
#include <string.h>
#include <limits.h>

#include <config.h>

#include "pxor.h"

#define P8      (  8 & SIZE_T_MAX)
#define P16     ( 16 & SIZE_T_MAX)
#define P32     ( 32 & SIZE_T_MAX)
#define P64     ( 64 & SIZE_T_MAX)
#define P128    (128 & SIZE_T_MAX)

void akmos_pxor8(const uint8_t *in_blk1, const uint8_t *in_blk2, uint8_t *out_blk)
{
    uint64_t a, b;

    memcpy(&a, in_blk1, P8);
    memcpy(&b, in_blk2, P8);

    b ^= a;

    memcpy(out_blk, &b, P8);
}

void akmos_pxor16(const uint8_t *in_blk1, const uint8_t *in_blk2, uint8_t *out_blk)
{
    uint64_t a[2], b[2];

    memcpy(a, in_blk1, P16);
    memcpy(b, in_blk2, P16);

    b[0] ^= a[0]; b[1] ^= a[1];

    memcpy(out_blk, b, P16);
}

void akmos_pxor32(const uint8_t *in_blk1, const uint8_t *in_blk2, uint8_t *out_blk)
{
    uint64_t a[4], b[4];

    memcpy(a, in_blk1, P32);
    memcpy(b, in_blk2, P32);

    b[0] ^= a[0]; b[1] ^= a[1];
    b[2] ^= a[2]; b[3] ^= a[3];

    memcpy(out_blk, b, P32);
}

void akmos_pxor64(const uint8_t *in_blk1, const uint8_t *in_blk2, uint8_t *out_blk)
{
    uint64_t a[8], b[8];

    memcpy(a, in_blk1, P64);
    memcpy(b, in_blk2, P64);

    b[0] ^= a[0]; b[1] ^= a[1];
    b[2] ^= a[2]; b[3] ^= a[3];
    b[4] ^= a[4]; b[5] ^= a[5];
    b[6] ^= a[6]; b[7] ^= a[7];

    memcpy(out_blk, b, P64);
}

void akmos_pxor128(const uint8_t *in_blk1, const uint8_t *in_blk2, uint8_t *out_blk)
{
    uint64_t a[16], b[16];

    memcpy(a, in_blk1, P128);
    memcpy(b, in_blk2, P128);

    b[ 0] ^= a[ 0]; b[ 1] ^= a[ 1];
    b[ 2] ^= a[ 2]; b[ 3] ^= a[ 3];
    b[ 4] ^= a[ 4]; b[ 5] ^= a[ 5];
    b[ 6] ^= a[ 6]; b[ 7] ^= a[ 7];
    b[ 8] ^= a[ 8]; b[ 9] ^= a[ 9];
    b[10] ^= a[10]; b[11] ^= a[11];
    b[12] ^= a[12]; b[13] ^= a[13];
    b[14] ^= a[14]; b[15] ^= a[15];

    memcpy(out_blk, b, P128);
}

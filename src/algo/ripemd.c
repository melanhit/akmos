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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include <config.h>

#include "../akmos.h"
#include "../bits.h"

#include "ripemd.h"

#define H0  0x67452301
#define H1  0xEFCDAB89
#define H2  0x98BADCFE
#define H3  0x10325476
#define H4  0xC3D2E1F0
#define H5  0x76543210
#define H6  0xFEDCBA98
#define H7  0x89ABCDEF
#define H8  0x01234567
#define H9  0x3C2D1E0F

#define K0  0x00000000
#define K1  0x5A827999
#define K2  0x6ED9EBA1
#define K3  0x8F1BBCDC
#define K4  0xA953FD4E

#define KK0 0x50A28BE6
#define KK1 0x5C4DD124
#define KK2 0x6D703EF3
#define KK3 0x7A6D76E9
#define KK4 0x00000000

#define F0(x, y, z) ((x) ^ (y) ^ (z))
#define F1(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define F2(x, y, z) (((x) | (~y)) ^ (z))
#define F3(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define F4(x, y, z) ((x) ^ ((y) | (~z)))

#define R0(a, b, c, d, Fj, Kj, sj, rj)                  \
{                                                       \
        a = ROTL32(a + Fj(b,c,d) + X(rj) + Kj, sj);     \
}

#define R1(a, b, c, d, e, Fj, Kj, sj, rj)               \
{                                                       \
        a = ROTL32(a + Fj(b,c,d) + X(rj) + Kj, sj) + e; \
        c = ROTL32(c, 10);                              \
}

#define X(i)    x[i]

static uint8_t PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void ripemd_160_transform(akmos_ripemd_t *ctx, const uint8_t *block)
{
    uint32_t a, b, c, d, e, aa, bb, cc, dd, ee, t, *x, *state;
    size_t i;

    state = ctx->state;
    x = ctx->x;

    for(i = 0; i < (AKMOS_RIPEMD_160_BLKLEN / 4); i++, block += 4)
        x[i] = PACK32BE(block);

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* Round 1 */
    R1(a, b, c, d, e, F0, K0, 11,  0);
    R1(e, a, b, c, d, F0, K0, 14,  1);
    R1(d, e, a, b, c, F0, K0, 15,  2);
    R1(c, d, e, a, b, F0, K0, 12,  3);
    R1(b, c, d, e, a, F0, K0,  5,  4);
    R1(a, b, c, d, e, F0, K0,  8,  5);
    R1(e, a, b, c, d, F0, K0,  7,  6);
    R1(d, e, a, b, c, F0, K0,  9,  7);
    R1(c, d, e, a, b, F0, K0, 11,  8);
    R1(b, c, d, e, a, F0, K0, 13,  9);
    R1(a, b, c, d, e, F0, K0, 14, 10);
    R1(e, a, b, c, d, F0, K0, 15, 11);
    R1(d, e, a, b, c, F0, K0,  6, 12);
    R1(c, d, e, a, b, F0, K0,  7, 13);
    R1(b, c, d, e, a, F0, K0,  9, 14);
    R1(a, b, c, d, e, F0, K0,  8, 15); /* #15 */
    /* Round 2 */
    R1(e, a, b, c, d, F1, K1,  7,  7);
    R1(d, e, a, b, c, F1, K1,  6,  4);
    R1(c, d, e, a, b, F1, K1,  8, 13);
    R1(b, c, d, e, a, F1, K1, 13,  1);
    R1(a, b, c, d, e, F1, K1, 11, 10);
    R1(e, a, b, c, d, F1, K1,  9,  6);
    R1(d, e, a, b, c, F1, K1,  7, 15);
    R1(c, d, e, a, b, F1, K1, 15,  3);
    R1(b, c, d, e, a, F1, K1,  7, 12);
    R1(a, b, c, d, e, F1, K1, 12,  0);
    R1(e, a, b, c, d, F1, K1, 15,  9);
    R1(d, e, a, b, c, F1, K1,  9,  5);
    R1(c, d, e, a, b, F1, K1, 11,  2);
    R1(b, c, d, e, a, F1, K1,  7, 14);
    R1(a, b, c, d, e, F1, K1, 13, 11);
    R1(e, a, b, c, d, F1, K1, 12,  8); /* #31 */
    /* Round 3 */
    R1(d, e, a, b, c, F2, K2, 11,  3);
    R1(c, d, e, a, b, F2, K2, 13, 10);
    R1(b, c, d, e, a, F2, K2,  6, 14);
    R1(a, b, c, d, e, F2, K2,  7,  4);
    R1(e, a, b, c, d, F2, K2, 14,  9);
    R1(d, e, a, b, c, F2, K2,  9, 15);
    R1(c, d, e, a, b, F2, K2, 13,  8);
    R1(b, c, d, e, a, F2, K2, 15,  1);
    R1(a, b, c, d, e, F2, K2, 14,  2);
    R1(e, a, b, c, d, F2, K2,  8,  7);
    R1(d, e, a, b, c, F2, K2, 13,  0);
    R1(c, d, e, a, b, F2, K2,  6,  6);
    R1(b, c, d, e, a, F2, K2,  5, 13);
    R1(a, b, c, d, e, F2, K2, 12, 11);
    R1(e, a, b, c, d, F2, K2,  7,  5);
    R1(d, e, a, b, c, F2, K2,  5, 12); /* #47 */
    /* Round 4 */
    R1(c, d, e, a, b, F3, K3, 11,  1);
    R1(b, c, d, e, a, F3, K3, 12,  9);
    R1(a, b, c, d, e, F3, K3, 14, 11);
    R1(e, a, b, c, d, F3, K3, 15, 10);
    R1(d, e, a, b, c, F3, K3, 14,  0);
    R1(c, d, e, a, b, F3, K3, 15,  8);
    R1(b, c, d, e, a, F3, K3,  9, 12);
    R1(a, b, c, d, e, F3, K3,  8,  4);
    R1(e, a, b, c, d, F3, K3,  9, 13);
    R1(d, e, a, b, c, F3, K3, 14,  3);
    R1(c, d, e, a, b, F3, K3,  5,  7);
    R1(b, c, d, e, a, F3, K3,  6, 15);
    R1(a, b, c, d, e, F3, K3,  8, 14);
    R1(e, a, b, c, d, F3, K3,  6,  5);
    R1(d, e, a, b, c, F3, K3,  5,  6);
    R1(c, d, e, a, b, F3, K3, 12,  2); /* #63 */
    /* Round 5 */
    R1(b, c, d, e, a, F4, K4,  9,  4);
    R1(a, b, c, d, e, F4, K4, 15,  0);
    R1(e, a, b, c, d, F4, K4,  5,  5);
    R1(d, e, a, b, c, F4, K4, 11,  9);
    R1(c, d, e, a, b, F4, K4,  6,  7);
    R1(b, c, d, e, a, F4, K4,  8, 12);
    R1(a, b, c, d, e, F4, K4, 13,  2);
    R1(e, a, b, c, d, F4, K4, 12, 10);
    R1(d, e, a, b, c, F4, K4,  5, 14);
    R1(c, d, e, a, b, F4, K4, 12,  1);
    R1(b, c, d, e, a, F4, K4, 13,  3);
    R1(a, b, c, d, e, F4, K4, 14,  8);
    R1(e, a, b, c, d, F4, K4, 11, 11);
    R1(d, e, a, b, c, F4, K4,  8,  6);
    R1(c, d, e, a, b, F4, K4,  5, 15);
    R1(b, c, d, e, a, F4, K4,  6, 13); /* #79 */

    aa = a ; bb = b; cc = c; dd = d; ee = e;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* Parallel round 1 */
    R1(a, b, c, d, e, F4, KK0,  8,  5);
    R1(e, a, b, c, d, F4, KK0,  9, 14);
    R1(d, e, a, b, c, F4, KK0,  9,  7);
    R1(c, d, e, a, b, F4, KK0, 11,  0);
    R1(b, c, d, e, a, F4, KK0, 13,  9);
    R1(a, b, c, d, e, F4, KK0, 15,  2);
    R1(e, a, b, c, d, F4, KK0, 15, 11);
    R1(d, e, a, b, c, F4, KK0,  5,  4);
    R1(c, d, e, a, b, F4, KK0,  7, 13);
    R1(b, c, d, e, a, F4, KK0,  7,  6);
    R1(a, b, c, d, e, F4, KK0,  8, 15);
    R1(e, a, b, c, d, F4, KK0, 11,  8);
    R1(d, e, a, b, c, F4, KK0, 14,  1);
    R1(c, d, e, a, b, F4, KK0, 14, 10);
    R1(b, c, d, e, a, F4, KK0, 12,  3);
    R1(a, b, c, d, e, F4, KK0,  6, 12); /* #15 */
    /* Parallel round 2 */
    R1(e, a, b, c, d, F3, KK1,  9,  6);
    R1(d, e, a, b, c, F3, KK1, 13, 11);
    R1(c, d, e, a, b, F3, KK1, 15,  3);
    R1(b, c, d, e, a, F3, KK1,  7,  7);
    R1(a, b, c, d, e, F3, KK1, 12,  0);
    R1(e, a, b, c, d, F3, KK1,  8, 13);
    R1(d, e, a, b, c, F3, KK1,  9,  5);
    R1(c, d, e, a, b, F3, KK1, 11, 10);
    R1(b, c, d, e, a, F3, KK1,  7, 14);
    R1(a, b, c, d, e, F3, KK1,  7, 15);
    R1(e, a, b, c, d, F3, KK1, 12,  8);
    R1(d, e, a, b, c, F3, KK1,  7, 12);
    R1(c, d, e, a, b, F3, KK1,  6,  4);
    R1(b, c, d, e, a, F3, KK1, 15,  9);
    R1(a, b, c, d, e, F3, KK1, 13,  1);
    R1(e, a, b, c, d, F3, KK1, 11,  2); /* #31 */
    /* Parallel round 3 */
    R1(d, e, a, b, c, F2, KK2,  9, 15);
    R1(c, d, e, a, b, F2, KK2,  7,  5);
    R1(b, c, d, e, a, F2, KK2, 15,  1);
    R1(a, b, c, d, e, F2, KK2, 11,  3);
    R1(e, a, b, c, d, F2, KK2,  8,  7);
    R1(d, e, a, b, c, F2, KK2,  6, 14);
    R1(c, d, e, a, b, F2, KK2,  6,  6);
    R1(b, c, d, e, a, F2, KK2, 14,  9);
    R1(a, b, c, d, e, F2, KK2, 12, 11);
    R1(e, a, b, c, d, F2, KK2, 13,  8);
    R1(d, e, a, b, c, F2, KK2,  5, 12);
    R1(c, d, e, a, b, F2, KK2, 14,  2);
    R1(b, c, d, e, a, F2, KK2, 13, 10);
    R1(a, b, c, d, e, F2, KK2, 13,  0);
    R1(e, a, b, c, d, F2, KK2,  7,  4);
    R1(d, e, a, b, c, F2, KK2,  5, 13); /* #47 */
    /* Parallel round 4 */
    R1(c, d, e, a, b, F1, KK3, 15,  8);
    R1(b, c, d, e, a, F1, KK3,  5,  6);
    R1(a, b, c, d, e, F1, KK3,  8,  4);
    R1(e, a, b, c, d, F1, KK3, 11,  1);
    R1(d, e, a, b, c, F1, KK3, 14,  3);
    R1(c, d, e, a, b, F1, KK3, 14, 11);
    R1(b, c, d, e, a, F1, KK3,  6, 15);
    R1(a, b, c, d, e, F1, KK3, 14,  0);
    R1(e, a, b, c, d, F1, KK3,  6,  5);
    R1(d, e, a, b, c, F1, KK3,  9, 12);
    R1(c, d, e, a, b, F1, KK3, 12,  2);
    R1(b, c, d, e, a, F1, KK3,  9, 13);
    R1(a, b, c, d, e, F1, KK3, 12,  9);
    R1(e, a, b, c, d, F1, KK3,  5,  7);
    R1(d, e, a, b, c, F1, KK3, 15, 10);
    R1(c, d, e, a, b, F1, KK3,  8, 14); /* #63 */
    /* Parallel round 5 */
    R1(b, c, d, e, a, F0, KK4,  8, 12);
    R1(a, b, c, d, e, F0, KK4,  5, 15);
    R1(e, a, b, c, d, F0, KK4, 12, 10);
    R1(d, e, a, b, c, F0, KK4,  9,  4);
    R1(c, d, e, a, b, F0, KK4, 12,  1);
    R1(b, c, d, e, a, F0, KK4,  5,  5);
    R1(a, b, c, d, e, F0, KK4, 14,  8);
    R1(e, a, b, c, d, F0, KK4,  6,  7);
    R1(d, e, a, b, c, F0, KK4,  8,  6);
    R1(c, d, e, a, b, F0, KK4, 13,  2);
    R1(b, c, d, e, a, F0, KK4,  6, 13);
    R1(a, b, c, d, e, F0, KK4,  5, 14);
    R1(e, a, b, c, d, F0, KK4, 15,  0);
    R1(d, e, a, b, c, F0, KK4, 13,  3);
    R1(c, d, e, a, b, F0, KK4, 11,  9);
    R1(b, c, d, e, a, F0, KK4, 11, 11); /* #79 */

    t =        state[1] + cc + d;
    state[1] = state[2] + dd + e;
    state[2] = state[3] + ee + a;
    state[3] = state[4] + aa + b;
    state[4] = state[0] + bb + c;
    state[0] = t;
}

static void ripemd_256_transform(akmos_ripemd_t *ctx, const uint8_t *block)
{
    uint32_t a, b, c, d, aa, bb, cc, dd, t, *x, *state;
    size_t i;

    state = ctx->state;
    x = ctx->x;

    for(i = 0; i < (AKMOS_RIPEMD_256_BLKLEN / 4); i++, block += 4)
        x[i] = PACK32BE(block);

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    aa = state[4];
    bb = state[5];
    cc = state[6];
    dd = state[7];

    /* Round 1 */
    R0(a, b, c, d, F0, K0, 11,  0);
    R0(d, a, b, c, F0, K0, 14,  1);
    R0(c, d, a, b, F0, K0, 15,  2);
    R0(b, c, d, a, F0, K0, 12,  3);
    R0(a, b, c, d, F0, K0,  5,  4);
    R0(d, a, b, c, F0, K0,  8,  5);
    R0(c, d, a, b, F0, K0,  7,  6);
    R0(b, c, d, a, F0, K0,  9,  7);
    R0(a, b, c, d, F0, K0, 11,  8);
    R0(d, a, b, c, F0, K0, 13,  9);
    R0(c, d, a, b, F0, K0, 14, 10);
    R0(b, c, d, a, F0, K0, 15, 11);
    R0(a, b, c, d, F0, K0,  6, 12);
    R0(d, a, b, c, F0, K0,  7, 13);
    R0(c, d, a, b, F0, K0,  9, 14);
    R0(b, c, d, a, F0, K0,  8, 15);

    R0(aa, bb, cc, dd, F3, KK0,  8,  5);
    R0(dd, aa, bb, cc, F3, KK0,  9, 14);
    R0(cc, dd, aa, bb, F3, KK0,  9,  7);
    R0(bb, cc, dd, aa, F3, KK0, 11,  0);
    R0(aa, bb, cc, dd, F3, KK0, 13,  9);
    R0(dd, aa, bb, cc, F3, KK0, 15,  2);
    R0(cc, dd, aa, bb, F3, KK0, 15, 11);
    R0(bb, cc, dd, aa, F3, KK0,  5,  4);
    R0(aa, bb, cc, dd, F3, KK0,  7, 13);
    R0(dd, aa, bb, cc, F3, KK0,  7,  6);
    R0(cc, dd, aa, bb, F3, KK0,  8, 15);
    R0(bb, cc, dd, aa, F3, KK0, 11,  8);
    R0(aa, bb, cc, dd, F3, KK0, 14,  1);
    R0(dd, aa, bb, cc, F3, KK0, 14, 10);
    R0(cc, dd, aa, bb, F3, KK0, 12,  3);
    R0(bb, cc, dd, aa, F3, KK0,  6, 12); /* #15 */

    t = a; a = aa; aa = t;

    /* Round 2 */
    R0(a, b, c, d, F1, K1,  7,  7);
    R0(d, a, b, c, F1, K1,  6,  4);
    R0(c, d, a, b, F1, K1,  8, 13);
    R0(b, c, d, a, F1, K1, 13,  1);
    R0(a, b, c, d, F1, K1, 11, 10);
    R0(d, a, b, c, F1, K1,  9,  6);
    R0(c, d, a, b, F1, K1,  7, 15);
    R0(b, c, d, a, F1, K1, 15,  3);
    R0(a, b, c, d, F1, K1,  7, 12);
    R0(d, a, b, c, F1, K1, 12,  0);
    R0(c, d, a, b, F1, K1, 15,  9);
    R0(b, c, d, a, F1, K1,  9,  5);
    R0(a, b, c, d, F1, K1, 11,  2);
    R0(d, a, b, c, F1, K1,  7, 14);
    R0(c, d, a, b, F1, K1, 13, 11);
    R0(b, c, d, a, F1, K1, 12,  8);

    R0(aa, bb, cc, dd, F2, KK1,  9,  6);
    R0(dd, aa, bb, cc, F2, KK1, 13, 11);
    R0(cc, dd, aa, bb, F2, KK1, 15,  3);
    R0(bb, cc, dd, aa, F2, KK1,  7,  7);
    R0(aa, bb, cc, dd, F2, KK1, 12,  0);
    R0(dd, aa, bb, cc, F2, KK1,  8, 13);
    R0(cc, dd, aa, bb, F2, KK1,  9,  5);
    R0(bb, cc, dd, aa, F2, KK1, 11, 10);
    R0(aa, bb, cc, dd, F2, KK1,  7, 14);
    R0(dd, aa, bb, cc, F2, KK1,  7, 15);
    R0(cc, dd, aa, bb, F2, KK1, 12,  8);
    R0(bb, cc, dd, aa, F2, KK1,  7, 12);
    R0(aa, bb, cc, dd, F2, KK1,  6,  4);
    R0(dd, aa, bb, cc, F2, KK1, 15,  9);
    R0(cc, dd, aa, bb, F2, KK1, 13,  1);
    R0(bb, cc, dd, aa, F2, KK1, 11,  2); /* #31 */

    t = b; b = bb; bb = t;

    /* Round 3 */
    R0(a, b, c, d, F2, K2, 11,  3);
    R0(d, a, b, c, F2, K2, 13, 10);
    R0(c, d, a, b, F2, K2,  6, 14);
    R0(b, c, d, a, F2, K2,  7,  4);
    R0(a, b, c, d, F2, K2, 14,  9);
    R0(d, a, b, c, F2, K2,  9, 15);
    R0(c, d, a, b, F2, K2, 13,  8);
    R0(b, c, d, a, F2, K2, 15,  1);
    R0(a, b, c, d, F2, K2, 14,  2);
    R0(d, a, b, c, F2, K2,  8,  7);
    R0(c, d, a, b, F2, K2, 13,  0);
    R0(b, c, d, a, F2, K2,  6,  6);
    R0(a, b, c, d, F2, K2,  5, 13);
    R0(d, a, b, c, F2, K2, 12, 11);
    R0(c, d, a, b, F2, K2,  7,  5);
    R0(b, c, d, a, F2, K2,  5, 12);

    R0(aa, bb, cc, dd, F1, KK2,  9, 15);
    R0(dd, aa, bb, cc, F1, KK2,  7,  5);
    R0(cc, dd, aa, bb, F1, KK2, 15,  1);
    R0(bb, cc, dd, aa, F1, KK2, 11,  3);
    R0(aa, bb, cc, dd, F1, KK2,  8,  7);
    R0(dd, aa, bb, cc, F1, KK2,  6, 14);
    R0(cc, dd, aa, bb, F1, KK2,  6,  6);
    R0(bb, cc, dd, aa, F1, KK2, 14,  9);
    R0(aa, bb, cc, dd, F1, KK2, 12, 11);
    R0(dd, aa, bb, cc, F1, KK2, 13,  8);
    R0(cc, dd, aa, bb, F1, KK2,  5, 12);
    R0(bb, cc, dd, aa, F1, KK2, 14,  2);
    R0(aa, bb, cc, dd, F1, KK2, 13, 10);
    R0(dd, aa, bb, cc, F1, KK2, 13,  0);
    R0(cc, dd, aa, bb, F1, KK2,  7,  4);
    R0(bb, cc, dd, aa, F1, KK2,  5, 13); /* #47 */

    t = c; c = cc; cc = t;

    /* Round 4 */
    R0(a, b, c, d, F3, K3, 11,  1);
    R0(d, a, b, c, F3, K3, 12,  9);
    R0(c, d, a, b, F3, K3, 14, 11);
    R0(b, c, d, a, F3, K3, 15, 10);
    R0(a, b, c, d, F3, K3, 14,  0);
    R0(d, a, b, c, F3, K3, 15,  8);
    R0(c, d, a, b, F3, K3,  9, 12);
    R0(b, c, d, a, F3, K3,  8,  4);
    R0(a, b, c, d, F3, K3,  9, 13);
    R0(d, a, b, c, F3, K3, 14,  3);
    R0(c, d, a, b, F3, K3,  5,  7);
    R0(b, c, d, a, F3, K3,  6, 15);
    R0(a, b, c, d, F3, K3,  8, 14);
    R0(d, a, b, c, F3, K3,  6,  5);
    R0(c, d, a, b, F3, K3,  5,  6);
    R0(b, c, d, a, F3, K3, 12,  2);

    R0(aa, bb, cc, dd, F0, KK4, 15,  8);
    R0(dd, aa, bb, cc, F0, KK4,  5,  6);
    R0(cc, dd, aa, bb, F0, KK4,  8,  4);
    R0(bb, cc, dd, aa, F0, KK4, 11,  1);
    R0(aa, bb, cc, dd, F0, KK4, 14,  3);
    R0(dd, aa, bb, cc, F0, KK4, 14, 11);
    R0(cc, dd, aa, bb, F0, KK4,  6, 15);
    R0(bb, cc, dd, aa, F0, KK4, 14,  0);
    R0(aa, bb, cc, dd, F0, KK4,  6,  5);
    R0(dd, aa, bb, cc, F0, KK4,  9, 12);
    R0(cc, dd, aa, bb, F0, KK4, 12,  2);
    R0(bb, cc, dd, aa, F0, KK4,  9, 13);
    R0(aa, bb, cc, dd, F0, KK4, 12,  9);
    R0(dd, aa, bb, cc, F0, KK4,  5,  7);
    R0(cc, dd, aa, bb, F0, KK4, 15, 10);
    R0(bb, cc, dd, aa, F0, KK4,  8, 14); /* #63 */

    t = d; d = dd; dd = t;

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += aa;
    state[5] += bb;
    state[6] += cc;
    state[7] += dd;
}

static void ripemd_320_transform(akmos_ripemd_t *ctx, const uint8_t *block)
{
    uint32_t a, b, c, d, e, aa, bb, cc, dd, ee, t, *x, *state;
    size_t i;

    state = ctx->state;
    x = ctx->x;

    for(i = 0; i < (AKMOS_RIPEMD_320_BLKLEN / 4); i++, block += 4)
        x[i] = PACK32BE(block);

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    aa = state[5];
    bb = state[6];
    cc = state[7];
    dd = state[8];
    ee = state[9];

    /* Round 1 */
    R1(a, b, c, d, e, F0, K0, 11,  0);
    R1(e, a, b, c, d, F0, K0, 14,  1);
    R1(d, e, a, b, c, F0, K0, 15,  2);
    R1(c, d, e, a, b, F0, K0, 12,  3);
    R1(b, c, d, e, a, F0, K0,  5,  4);
    R1(a, b, c, d, e, F0, K0,  8,  5);
    R1(e, a, b, c, d, F0, K0,  7,  6);
    R1(d, e, a, b, c, F0, K0,  9,  7);
    R1(c, d, e, a, b, F0, K0, 11,  8);
    R1(b, c, d, e, a, F0, K0, 13,  9);
    R1(a, b, c, d, e, F0, K0, 14, 10);
    R1(e, a, b, c, d, F0, K0, 15, 11);
    R1(d, e, a, b, c, F0, K0,  6, 12);
    R1(c, d, e, a, b, F0, K0,  7, 13);
    R1(b, c, d, e, a, F0, K0,  9, 14);
    R1(a, b, c, d, e, F0, K0,  8, 15);

    R1(aa, bb, cc, dd, ee, F4, KK0,  8,  5);
    R1(ee, aa, bb, cc, dd, F4, KK0,  9, 14);
    R1(dd, ee, aa, bb, cc, F4, KK0,  9,  7);
    R1(cc, dd, ee, aa, bb, F4, KK0, 11,  0);
    R1(bb, cc, dd, ee, aa, F4, KK0, 13,  9);
    R1(aa, bb, cc, dd, ee, F4, KK0, 15,  2);
    R1(ee, aa, bb, cc, dd, F4, KK0, 15, 11);
    R1(dd, ee, aa, bb, cc, F4, KK0,  5,  4);
    R1(cc, dd, ee, aa, bb, F4, KK0,  7, 13);
    R1(bb, cc, dd, ee, aa, F4, KK0,  7,  6);
    R1(aa, bb, cc, dd, ee, F4, KK0,  8, 15);
    R1(ee, aa, bb, cc, dd, F4, KK0, 11,  8);
    R1(dd, ee, aa, bb, cc, F4, KK0, 14,  1);
    R1(cc, dd, ee, aa, bb, F4, KK0, 14, 10);
    R1(bb, cc, dd, ee, aa, F4, KK0, 12,  3);
    R1(aa, bb, cc, dd, ee, F4, KK0,  6, 12); /* #15 */

    t = a; a = aa; aa = t;

    /* Round 2 */
    R1(e, a, b, c, d, F1, K1,  7,  7);
    R1(d, e, a, b, c, F1, K1,  6,  4);
    R1(c, d, e, a, b, F1, K1,  8, 13);
    R1(b, c, d, e, a, F1, K1, 13,  1);
    R1(a, b, c, d, e, F1, K1, 11, 10);
    R1(e, a, b, c, d, F1, K1,  9,  6);
    R1(d, e, a, b, c, F1, K1,  7, 15);
    R1(c, d, e, a, b, F1, K1, 15,  3);
    R1(b, c, d, e, a, F1, K1,  7, 12);
    R1(a, b, c, d, e, F1, K1, 12,  0);
    R1(e, a, b, c, d, F1, K1, 15,  9);
    R1(d, e, a, b, c, F1, K1,  9,  5);
    R1(c, d, e, a, b, F1, K1, 11,  2);
    R1(b, c, d, e, a, F1, K1,  7, 14);
    R1(a, b, c, d, e, F1, K1, 13, 11);
    R1(e, a, b, c, d, F1, K1, 12,  8);

    R1(ee, aa, bb, cc, dd, F3, KK1,  9,  6);
    R1(dd, ee, aa, bb, cc, F3, KK1, 13, 11);
    R1(cc, dd, ee, aa, bb, F3, KK1, 15,  3);
    R1(bb, cc, dd, ee, aa, F3, KK1,  7,  7);
    R1(aa, bb, cc, dd, ee, F3, KK1, 12,  0);
    R1(ee, aa, bb, cc, dd, F3, KK1,  8, 13);
    R1(dd, ee, aa, bb, cc, F3, KK1,  9,  5);
    R1(cc, dd, ee, aa, bb, F3, KK1, 11, 10);
    R1(bb, cc, dd, ee, aa, F3, KK1,  7, 14);
    R1(aa, bb, cc, dd, ee, F3, KK1,  7, 15);
    R1(ee, aa, bb, cc, dd, F3, KK1, 12,  8);
    R1(dd, ee, aa, bb, cc, F3, KK1,  7, 12);
    R1(cc, dd, ee, aa, bb, F3, KK1,  6,  4);
    R1(bb, cc, dd, ee, aa, F3, KK1, 15,  9);
    R1(aa, bb, cc, dd, ee, F3, KK1, 13,  1);
    R1(ee, aa, bb, cc, dd, F3, KK1, 11,  2); /* #31 */

    t = b; b = bb; bb = t;

    /* Round 3 */
    R1(d, e, a, b, c, F2, K2, 11,  3);
    R1(c, d, e, a, b, F2, K2, 13, 10);
    R1(b, c, d, e, a, F2, K2,  6, 14);
    R1(a, b, c, d, e, F2, K2,  7,  4);
    R1(e, a, b, c, d, F2, K2, 14,  9);
    R1(d, e, a, b, c, F2, K2,  9, 15);
    R1(c, d, e, a, b, F2, K2, 13,  8);
    R1(b, c, d, e, a, F2, K2, 15,  1);
    R1(a, b, c, d, e, F2, K2, 14,  2);
    R1(e, a, b, c, d, F2, K2,  8,  7);
    R1(d, e, a, b, c, F2, K2, 13,  0);
    R1(c, d, e, a, b, F2, K2,  6,  6);
    R1(b, c, d, e, a, F2, K2,  5, 13);
    R1(a, b, c, d, e, F2, K2, 12, 11);
    R1(e, a, b, c, d, F2, K2,  7,  5);
    R1(d, e, a, b, c, F2, K2,  5, 12);

    R1(dd, ee, aa, bb, cc, F2, KK2,  9, 15);
    R1(cc, dd, ee, aa, bb, F2, KK2,  7,  5);
    R1(bb, cc, dd, ee, aa, F2, KK2, 15,  1);
    R1(aa, bb, cc, dd, ee, F2, KK2, 11,  3);
    R1(ee, aa, bb, cc, dd, F2, KK2,  8,  7);
    R1(dd, ee, aa, bb, cc, F2, KK2,  6, 14);
    R1(cc, dd, ee, aa, bb, F2, KK2,  6,  6);
    R1(bb, cc, dd, ee, aa, F2, KK2, 14,  9);
    R1(aa, bb, cc, dd, ee, F2, KK2, 12, 11);
    R1(ee, aa, bb, cc, dd, F2, KK2, 13,  8);
    R1(dd, ee, aa, bb, cc, F2, KK2,  5, 12);
    R1(cc, dd, ee, aa, bb, F2, KK2, 14,  2);
    R1(bb, cc, dd, ee, aa, F2, KK2, 13, 10);
    R1(aa, bb, cc, dd, ee, F2, KK2, 13,  0);
    R1(ee, aa, bb, cc, dd, F2, KK2,  7,  4);
    R1(dd, ee, aa, bb, cc, F2, KK2,  5, 13); /* #47 */

    t = c; c = cc; cc = t;

    /* Round 4 */
    R1(c, d, e, a, b, F3, K3, 11,  1);
    R1(b, c, d, e, a, F3, K3, 12,  9);
    R1(a, b, c, d, e, F3, K3, 14, 11);
    R1(e, a, b, c, d, F3, K3, 15, 10);
    R1(d, e, a, b, c, F3, K3, 14,  0);
    R1(c, d, e, a, b, F3, K3, 15,  8);
    R1(b, c, d, e, a, F3, K3,  9, 12);
    R1(a, b, c, d, e, F3, K3,  8,  4);
    R1(e, a, b, c, d, F3, K3,  9, 13);
    R1(d, e, a, b, c, F3, K3, 14,  3);
    R1(c, d, e, a, b, F3, K3,  5,  7);
    R1(b, c, d, e, a, F3, K3,  6, 15);
    R1(a, b, c, d, e, F3, K3,  8, 14);
    R1(e, a, b, c, d, F3, K3,  6,  5);
    R1(d, e, a, b, c, F3, K3,  5,  6);
    R1(c, d, e, a, b, F3, K3, 12,  2);

    R1(cc, dd, ee, aa, bb, F1, KK3, 15,  8);
    R1(bb, cc, dd, ee, aa, F1, KK3,  5,  6);
    R1(aa, bb, cc, dd, ee, F1, KK3,  8,  4);
    R1(ee, aa, bb, cc, dd, F1, KK3, 11,  1);
    R1(dd, ee, aa, bb, cc, F1, KK3, 14,  3);
    R1(cc, dd, ee, aa, bb, F1, KK3, 14, 11);
    R1(bb, cc, dd, ee, aa, F1, KK3,  6, 15);
    R1(aa, bb, cc, dd, ee, F1, KK3, 14,  0);
    R1(ee, aa, bb, cc, dd, F1, KK3,  6,  5);
    R1(dd, ee, aa, bb, cc, F1, KK3,  9, 12);
    R1(cc, dd, ee, aa, bb, F1, KK3, 12,  2);
    R1(bb, cc, dd, ee, aa, F1, KK3,  9, 13);
    R1(aa, bb, cc, dd, ee, F1, KK3, 12,  9);
    R1(ee, aa, bb, cc, dd, F1, KK3,  5,  7);
    R1(dd, ee, aa, bb, cc, F1, KK3, 15, 10);
    R1(cc, dd, ee, aa, bb, F1, KK3,  8, 14); /* #63 */

    t = d; d = dd; dd = t;

    /* Round 5 */
    R1(b, c, d, e, a, F4, K4,  9,  4);
    R1(a, b, c, d, e, F4, K4, 15,  0);
    R1(e, a, b, c, d, F4, K4,  5,  5);
    R1(d, e, a, b, c, F4, K4, 11,  9);
    R1(c, d, e, a, b, F4, K4,  6,  7);
    R1(b, c, d, e, a, F4, K4,  8, 12);
    R1(a, b, c, d, e, F4, K4, 13,  2);
    R1(e, a, b, c, d, F4, K4, 12, 10);
    R1(d, e, a, b, c, F4, K4,  5, 14);
    R1(c, d, e, a, b, F4, K4, 12,  1);
    R1(b, c, d, e, a, F4, K4, 13,  3);
    R1(a, b, c, d, e, F4, K4, 14,  8);
    R1(e, a, b, c, d, F4, K4, 11, 11);
    R1(d, e, a, b, c, F4, K4,  8,  6);
    R1(c, d, e, a, b, F4, K4,  5, 15);
    R1(b, c, d, e, a, F4, K4,  6, 13);

    R1(bb, cc, dd, ee, aa, F0, KK4,  8, 12);
    R1(aa, bb, cc, dd, ee, F0, KK4,  5, 15);
    R1(ee, aa, bb, cc, dd, F0, KK4, 12, 10);
    R1(dd, ee, aa, bb, cc, F0, KK4,  9,  4);
    R1(cc, dd, ee, aa, bb, F0, KK4, 12,  1);
    R1(bb, cc, dd, ee, aa, F0, KK4,  5,  5);
    R1(aa, bb, cc, dd, ee, F0, KK4, 14,  8);
    R1(ee, aa, bb, cc, dd, F0, KK4,  6,  7);
    R1(dd, ee, aa, bb, cc, F0, KK4,  8,  6);
    R1(cc, dd, ee, aa, bb, F0, KK4, 13,  2);
    R1(bb, cc, dd, ee, aa, F0, KK4,  6, 13);
    R1(aa, bb, cc, dd, ee, F0, KK4,  5, 14);
    R1(ee, aa, bb, cc, dd, F0, KK4, 15,  0);
    R1(dd, ee, aa, bb, cc, F0, KK4, 13,  3);
    R1(cc, dd, ee, aa, bb, F0, KK4, 11,  9);
    R1(bb, cc, dd, ee, aa, F0, KK4, 11, 11); /* #79 */

    t = e; e = ee; ee = t;

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += aa;
    state[6] += bb;
    state[7] += cc;
    state[8] += dd;
    state[9] += ee;
}

void akmos_ripemd_160_init(akmos_ripemd_t *ctx)
{
    ctx->count = 0;
    ctx->state[0] = H0;
    ctx->state[1] = H1;
    ctx->state[2] = H2;
    ctx->state[3] = H3;
    ctx->state[4] = H4;

    ctx->diglen = AKMOS_RIPEMD_160_DIGLEN;
}

void akmos_ripemd_256_init(akmos_ripemd_t *ctx)
{
    ctx->count = 0;
    ctx->state[0] = H0;
    ctx->state[1] = H1;
    ctx->state[2] = H2;
    ctx->state[3] = H3;
    ctx->state[4] = H5;
    ctx->state[5] = H6;
    ctx->state[6] = H7;
    ctx->state[7] = H8;

    ctx->diglen = AKMOS_RIPEMD_256_DIGLEN;
}

void akmos_ripemd_320_init(akmos_ripemd_t *ctx)
{
    ctx->count = 0;
    ctx->state[0] = H0;
    ctx->state[1] = H1;
    ctx->state[2] = H2;
    ctx->state[3] = H3;
    ctx->state[4] = H4;
    ctx->state[5] = H5;
    ctx->state[6] = H6;
    ctx->state[7] = H7;
    ctx->state[8] = H8;
    ctx->state[9] = H9;

    ctx->diglen = AKMOS_RIPEMD_320_DIGLEN;
}

void akmos_ripemd_update(akmos_ripemd_t *ctx, const uint8_t *input, size_t len)
{
    size_t have, off, need;

    have = (ctx->count / 8) % 64;
    need = 64 - have;
    ctx->count += 8 * len;
    off = 0;

    if(len >= need) {
        if(have) {
            memcpy(ctx->buffer + have, input, need);

            switch(ctx->diglen) {
                case AKMOS_RIPEMD_160_DIGLEN:
                    ripemd_160_transform(ctx, ctx->buffer);
                    break;

                case AKMOS_RIPEMD_256_DIGLEN:
                    ripemd_256_transform(ctx, ctx->buffer);
                    break;

                case AKMOS_RIPEMD_320_DIGLEN:
                    ripemd_320_transform(ctx, ctx->buffer);
                    break;
            }

            off = need;
            have = 0;
        }
        /* now the buffer is empty */
        while(off + 64 <= len) {
            switch(ctx->diglen) {
                case AKMOS_RIPEMD_160_DIGLEN:
                    ripemd_160_transform(ctx, input + off);
                    break;

                case AKMOS_RIPEMD_256_DIGLEN:
                    ripemd_256_transform(ctx, input + off);
                    break;

                case AKMOS_RIPEMD_320_DIGLEN:
                    ripemd_320_transform(ctx, input + off);
                    break;
            }
            off += 64;
        }
    }

    if(off < len)
        memcpy(ctx->buffer + have, input+off, len-off);
}

void akmos_ripemd_done(akmos_ripemd_t *ctx, uint8_t *digest)
{
    uint8_t size[8];
    size_t i, padlen;

    UNPACK64BE(size, ctx->count);

    padlen = (64 - ((ctx->count / 8) % 64)) & SIZE_T_MAX;
    if(padlen < 1 + 8)
        padlen += 64;

    akmos_ripemd_update(ctx, PADDING, padlen - 8);
    akmos_ripemd_update(ctx, size, sizeof(size));

    if(digest != NULL) {
        for(i = 0; i < (ctx->diglen / 4); i++)
            UNPACK32BE(digest + (i * 4), ctx->state[i]);
    }
}

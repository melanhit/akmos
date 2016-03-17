/*
 *   Copyright (c) 2014-2016, Andrew Romanenko <melanhit@gmail.com>
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

#include "../akmos.h"
#include "../bits.h"

#include "sha1.h"

#define F0(x, y, z)  ((x & y) ^ (~x & z))
#define F1(x, y, z)  (x ^ y ^ z)
#define F2(x, y, z)  ((x & y) ^ (x & z) ^ (y & z))
#define F3(x, y, z)  (x ^ y ^ z)

#define E(x, i) (x[i & 15] =                        \
        ROTL32(                                     \
            x[i & 15] ^                             \
            x[(i - 14) & 15]  ^                     \
            x[(i - 8) & 15]  ^                      \
            x[(i - 3) & 15], 1))

#define R(a, b, c, d, e, f, k, data)                \
        (e += ROTL32(a, 5) + f(b, c, d) + k + data, b = ROTL32(b, 30))

#define K0  0x5a827999
#define K1  0x6ed9eba1
#define K2  0x8f1bbcdc
#define K3  0xca62c1d6

#define H0  0x67452301
#define H1  0xefcdab89
#define H2  0x98badcfe
#define H3  0x10325476
#define H4  0xc3d2e1f0

static void sha1_transform(akmos_sha1_t *ctx, const uint8_t *block, size_t nb)
{
    uint32_t A, B, C, D, E, i;
    uint32_t *w;
    const uint8_t *sub;

    w = ctx->w;

    for(i = 0; i < nb; i++) {
        A = ctx->h[0]; B = ctx->h[1];
        C = ctx->h[2]; D = ctx->h[3];
        E = ctx->h[4];

        sub = block + (i << 6);

        w[ 0] = PACK32LE(sub     ); w[ 1] = PACK32LE(sub +  4);
        w[ 2] = PACK32LE(sub +  8); w[ 3] = PACK32LE(sub + 12);
        w[ 4] = PACK32LE(sub + 16); w[ 5] = PACK32LE(sub + 20);
        w[ 6] = PACK32LE(sub + 24); w[ 7] = PACK32LE(sub + 28);
        w[ 8] = PACK32LE(sub + 32); w[ 9] = PACK32LE(sub + 36);
        w[10] = PACK32LE(sub + 40); w[11] = PACK32LE(sub + 44);
        w[12] = PACK32LE(sub + 48); w[13] = PACK32LE(sub + 52);
        w[14] = PACK32LE(sub + 56); w[15] = PACK32LE(sub + 60);

        R(A, B, C, D, E, F0, K0, w[ 0]);
        R(E, A, B, C, D, F0, K0, w[ 1]);
        R(D, E, A, B, C, F0, K0, w[ 2]);
        R(C, D, E, A, B, F0, K0, w[ 3]);
        R(B, C, D, E, A, F0, K0, w[ 4]);
        R(A, B, C, D, E, F0, K0, w[ 5]);
        R(E, A, B, C, D, F0, K0, w[ 6]);
        R(D, E, A, B, C, F0, K0, w[ 7]);
        R(C, D, E, A, B, F0, K0, w[ 8]);
        R(B, C, D, E, A, F0, K0, w[ 9]);
        R(A, B, C, D, E, F0, K0, w[10]);
        R(E, A, B, C, D, F0, K0, w[11]);
        R(D, E, A, B, C, F0, K0, w[12]);
        R(C, D, E, A, B, F0, K0, w[13]);
        R(B, C, D, E, A, F0, K0, w[14]);
        R(A, B, C, D, E, F0, K0, w[15]);
        R(E, A, B, C, D, F0, K0, E(w, 16));
        R(D, E, A, B, C, F0, K0, E(w, 17));
        R(C, D, E, A, B, F0, K0, E(w, 18));
        R(B, C, D, E, A, F0, K0, E(w, 19));

        R(A, B, C, D, E, F1, K1, E(w, 20));
        R(E, A, B, C, D, F1, K1, E(w, 21));
        R(D, E, A, B, C, F1, K1, E(w, 22));
        R(C, D, E, A, B, F1, K1, E(w, 23));
        R(B, C, D, E, A, F1, K1, E(w, 24));
        R(A, B, C, D, E, F1, K1, E(w, 25));
        R(E, A, B, C, D, F1, K1, E(w, 26));
        R(D, E, A, B, C, F1, K1, E(w, 27));
        R(C, D, E, A, B, F1, K1, E(w, 28));
        R(B, C, D, E, A, F1, K1, E(w, 29));
        R(A, B, C, D, E, F1, K1, E(w, 30));
        R(E, A, B, C, D, F1, K1, E(w, 31));
        R(D, E, A, B, C, F1, K1, E(w, 32));
        R(C, D, E, A, B, F1, K1, E(w, 33));
        R(B, C, D, E, A, F1, K1, E(w, 34));
        R(A, B, C, D, E, F1, K1, E(w, 35));
        R(E, A, B, C, D, F1, K1, E(w, 36));
        R(D, E, A, B, C, F1, K1, E(w, 37));
        R(C, D, E, A, B, F1, K1, E(w, 38));
        R(B, C, D, E, A, F1, K1, E(w, 39));

        R(A, B, C, D, E, F2, K2, E(w, 40));
        R(E, A, B, C, D, F2, K2, E(w, 41));
        R(D, E, A, B, C, F2, K2, E(w, 42));
        R(C, D, E, A, B, F2, K2, E(w, 43));
        R(B, C, D, E, A, F2, K2, E(w, 44));
        R(A, B, C, D, E, F2, K2, E(w, 45));
        R(E, A, B, C, D, F2, K2, E(w, 46));
        R(D, E, A, B, C, F2, K2, E(w, 47));
        R(C, D, E, A, B, F2, K2, E(w, 48));
        R(B, C, D, E, A, F2, K2, E(w, 49));
        R(A, B, C, D, E, F2, K2, E(w, 50));
        R(E, A, B, C, D, F2, K2, E(w, 51));
        R(D, E, A, B, C, F2, K2, E(w, 52));
        R(C, D, E, A, B, F2, K2, E(w, 53));
        R(B, C, D, E, A, F2, K2, E(w, 54));
        R(A, B, C, D, E, F2, K2, E(w, 55));
        R(E, A, B, C, D, F2, K2, E(w, 56));
        R(D, E, A, B, C, F2, K2, E(w, 57));
        R(C, D, E, A, B, F2, K2, E(w, 58));
        R(B, C, D, E, A, F2, K2, E(w, 59));

        R(A, B, C, D, E, F3, K3, E(w, 60));
        R(E, A, B, C, D, F3, K3, E(w, 61));
        R(D, E, A, B, C, F3, K3, E(w, 62));
        R(C, D, E, A, B, F3, K3, E(w, 63));
        R(B, C, D, E, A, F3, K3, E(w, 64));
        R(A, B, C, D, E, F3, K3, E(w, 65));
        R(E, A, B, C, D, F3, K3, E(w, 66));
        R(D, E, A, B, C, F3, K3, E(w, 67));
        R(C, D, E, A, B, F3, K3, E(w, 68));
        R(B, C, D, E, A, F3, K3, E(w, 69));
        R(A, B, C, D, E, F3, K3, E(w, 70));
        R(E, A, B, C, D, F3, K3, E(w, 71));
        R(D, E, A, B, C, F3, K3, E(w, 72));
        R(C, D, E, A, B, F3, K3, E(w, 73));
        R(B, C, D, E, A, F3, K3, E(w, 74));
        R(A, B, C, D, E, F3, K3, E(w, 75));
        R(E, A, B, C, D, F3, K3, E(w, 76));
        R(D, E, A, B, C, F3, K3, E(w, 77));
        R(C, D, E, A, B, F3, K3, E(w, 78));
        R(B, C, D, E, A, F3, K3, E(w, 79));

        ctx->h[0] += A;
        ctx->h[1] += B;
        ctx->h[2] += C;
        ctx->h[3] += D;
        ctx->h[4] += E;
    }
}

void akmos_sha1_init(akmos_sha1_t *ctx)
{
    ctx->h[0] = H0;
    ctx->h[1] = H1;
    ctx->h[2] = H2;
    ctx->h[3] = H3;
    ctx->h[4] = H4;

    ctx->total = ctx->len = 0;
}

void akmos_sha1_update(akmos_sha1_t *ctx, const uint8_t *input, size_t len)
{
    size_t nb, new_len, rem_len, tmp_len;
    const uint8_t *sfi;

    tmp_len = AKMOS_SHA1_BLKLEN - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(ctx->block + ctx->len, input, rem_len);

    if((ctx->len + len) < AKMOS_SHA1_BLKLEN) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    nb = new_len / AKMOS_SHA1_BLKLEN;

    sfi = input + rem_len;

    sha1_transform(ctx, ctx->block, 1);
    sha1_transform(ctx, sfi, nb);

    rem_len = new_len % AKMOS_SHA1_BLKLEN;

    if(rem_len > 0)
        memcpy(ctx->block, sfi + (nb << 6), rem_len);

    ctx->len = rem_len;
    ctx->total += (nb + 1) << 6;
}

void akmos_sha1_done(akmos_sha1_t *ctx, uint8_t *digest)
{
    uint32_t nb, pm_len;
    uint64_t len_bit;

    nb = (1 + ((AKMOS_SHA1_BLKLEN - 9) < (ctx->len % AKMOS_SHA1_BLKLEN)));

    len_bit = (ctx->total + ctx->len) << 3;
    pm_len = nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;

    UNPACK64LE(ctx->block + (pm_len - 8), len_bit);

    sha1_transform(ctx, ctx->block, nb);

    UNPACK32LE(digest     , ctx->h[0]);
    UNPACK32LE(digest +  4, ctx->h[1]);
    UNPACK32LE(digest +  8, ctx->h[2]);
    UNPACK32LE(digest + 12, ctx->h[3]);
    UNPACK32LE(digest + 16, ctx->h[4]);
}

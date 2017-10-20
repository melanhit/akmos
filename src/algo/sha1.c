/*
 *   Copyright (c) 2014-2017, Andrew Romanenko <melanhit@gmail.com>
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

#include <config.h>

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

static void sha1_transform(uint32_t *h, const uint8_t *blk, size_t nb)
{
    uint32_t A, B, C, D, E, *w;
    size_t i;

    w = h + 5;

    for(i = 0; i < nb; i++, blk += AKMOS_SHA1_BLKLEN) {
        A = h[0]; B = h[1];
        C = h[2]; D = h[3];
        E = h[4];

        w[ 0] = PACK32LE(blk     ); w[ 1] = PACK32LE(blk +  4);
        w[ 2] = PACK32LE(blk +  8); w[ 3] = PACK32LE(blk + 12);
        w[ 4] = PACK32LE(blk + 16); w[ 5] = PACK32LE(blk + 20);
        w[ 6] = PACK32LE(blk + 24); w[ 7] = PACK32LE(blk + 28);
        w[ 8] = PACK32LE(blk + 32); w[ 9] = PACK32LE(blk + 36);
        w[10] = PACK32LE(blk + 40); w[11] = PACK32LE(blk + 44);
        w[12] = PACK32LE(blk + 48); w[13] = PACK32LE(blk + 52);
        w[14] = PACK32LE(blk + 56); w[15] = PACK32LE(blk + 60);

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

        h[0] += A; h[1] += B;
        h[2] += C; h[3] += D;
        h[4] += E;
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
    size_t nb, tmp_len;

    tmp_len = len + ctx->len;

    if(tmp_len < AKMOS_SHA1_BLKLEN) {
        memcpy(ctx->block + ctx->len, input, len);
        ctx->len += len;
        return;
    }

    if(ctx->len) {
        tmp_len = AKMOS_SHA1_BLKLEN - ctx->len;
        memcpy(ctx->block + ctx->len, input, tmp_len);

        sha1_transform(ctx->h, ctx->block, 1 & SIZE_T_MAX);

        ctx->len = 0;
        ctx->total++;

        len -= tmp_len;
        input += tmp_len;
    }

    nb = len / AKMOS_SHA1_BLKLEN;
    if(nb)
        sha1_transform(ctx->h, input, nb);

    tmp_len = len % AKMOS_SHA1_BLKLEN;
    if(tmp_len) {
        memcpy(ctx->block, input + (len - tmp_len), tmp_len);
        ctx->len = tmp_len;
    }

    ctx->total += nb;
}

void akmos_sha1_done(akmos_sha1_t *ctx, uint8_t *digest)
{
    uint64_t len_b;
    size_t i;

    len_b = ((ctx->total * AKMOS_SHA1_BLKLEN) + ctx->len) * 8;
    ctx->block[ctx->len] = 0x80;
    ctx->len++;

    if(ctx->len > (AKMOS_SHA1_BLKLEN - sizeof(uint64_t))) {
        memset(ctx->block + ctx->len, 0, AKMOS_SHA1_BLKLEN - ctx->len);
        sha1_transform(ctx->h, ctx->block, 1);
        ctx->len = 0;
    }

    memset(ctx->block + ctx->len, 0, AKMOS_SHA1_BLKLEN - ctx->len);
    UNPACK64LE(ctx->block + (AKMOS_SHA1_BLKLEN - sizeof(uint64_t)), len_b);
    sha1_transform(ctx->h, ctx->block, 1);

    for(i = 0; i < AKMOS_SHA1_DIGLEN / (sizeof(uint32_t)); i++, digest += sizeof(uint32_t))
        UNPACK32LE(digest, ctx->h[i]);
}

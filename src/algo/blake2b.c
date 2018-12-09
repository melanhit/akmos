/*
 *   Copyright (c) 2018, Andrew Romanenko <melanhit@gmail.com>
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
#include "../digest.h"

#include "blake2b.h"

#define BLAKE2B_WORDS   16
#define BLAKE2B_ROUNDS  12

#define BLAKE2B_FINAL   UINT64_C(0xffffffffffffffff)

static const uint64_t H[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

static const uint8_t P[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#define W(i, j) (w[P[i][j]])

#define G_fun(a, b, c, d, p0, p1)   \
{                                   \
    a += b + W(j, p0);              \
    d = ROTR64(d ^ a, 32);          \
    c += d;                         \
    b = ROTR64(b ^ c, 24);          \
    a += b + W(j, p1);              \
    d = ROTR64(d ^ a, 16);          \
    c += d;                         \
    b = ROTR64(b ^ c, 63);          \
}

#define INC128(x, n)                \
{                                   \
    x[0] += n;                      \
    if(x[0] < n)                    \
        x[1]++;                     \
}

static void blake2b_transform(akmos_blake2b_t *ctx, const uint8_t *blk, size_t nb)
{
    uint64_t v[BLAKE2B_WORDS], w[BLAKE2B_WORDS];
    size_t i, j;

    for(i = 0; i < nb; i++, blk += AKMOS_BLAKE2B_BLKLEN) {
        memcpy(w, blk, AKMOS_BLAKE2B_BLKLEN);

        for(j = 0; j < 8; j++)
            v[j] = ctx->h[j];

        for(j = 8; j < BLAKE2B_WORDS; j++)
            v[j] = H[j - 8];

        INC128(ctx->cnt, ctx->tlen);
        v[12] ^= ctx->cnt[0];
        v[13] ^= ctx->cnt[1];

        v[14] ^= ctx->final;

        for(j = 0; j < BLAKE2B_ROUNDS; j++) {
            G_fun(v[0], v[4], v[ 8], v[12],  0,  1);
            G_fun(v[1], v[5], v[ 9], v[13],  2,  3);
            G_fun(v[2], v[6], v[10], v[14],  4,  5);
            G_fun(v[3], v[7], v[11], v[15],  6,  7);
            G_fun(v[0], v[5], v[10], v[15],  8,  9);
            G_fun(v[1], v[6], v[11], v[12], 10, 11);
            G_fun(v[2], v[7], v[ 8], v[13], 12, 13);
            G_fun(v[3], v[4], v[ 9], v[14], 14, 15);
        }

        for(j = 0; j < 8; j++)
            ctx->h[j] ^= v[j] ^ v[j + 8];
    }
}

void akmos_blake2b_init(akmos_digest_algo_t *uctx)
{
    akmos_blake2b_t *ctx;
    uint8_t *p, buf[64] = { 0 };
    size_t i;

    ctx = &uctx->blake2b;

    buf[0] = AKMOS_BLAKE2B_DIGLEN;    /* Digest length */
    buf[2] = 1;                       /* Fanout */
    buf[3] = 1;                       /* Depth */

    ctx->final = 0;
    ctx->tlen = AKMOS_BLAKE2B_BLKLEN;

    p = buf;
    for(i = 0; i < 8; i++, p += sizeof(uint64_t))
        ctx->h[i] = H[i] ^ PACK64BE(p);
}

void akmos_blake2b_update(akmos_digest_algo_t *uctx, const uint8_t *input, size_t len)
{
    akmos_blake2b_t *ctx;
    size_t tmp_len, rem_len, nb;

    ctx = &uctx->blake2b;

    tmp_len = ctx->len + len;
    if(tmp_len <= AKMOS_BLAKE2B_BLKLEN) {
        memcpy(ctx->buf + ctx->len, input, len);
        ctx->len += len;
        return;
    }

    tmp_len = AKMOS_BLAKE2B_BLKLEN - ctx->len;

    if(ctx->len < AKMOS_BLAKE2B_BLKLEN) {
        memcpy(ctx->buf + ctx->len, input, tmp_len);
        input += tmp_len;
        len -= tmp_len;
    }

    blake2b_transform(ctx, ctx->buf, 1);

    rem_len = len % AKMOS_BLAKE2B_BLKLEN;

    if(rem_len) {
        memcpy(ctx->buf, input + (len - rem_len), rem_len);
        ctx->len = rem_len;
    } else {
        memcpy(ctx->buf, input + (len - AKMOS_BLAKE2B_BLKLEN), AKMOS_BLAKE2B_BLKLEN);
        ctx->len = AKMOS_BLAKE2B_BLKLEN;
        len -= AKMOS_BLAKE2B_BLKLEN;
    }

    nb = len / AKMOS_BLAKE2B_BLKLEN;
    if(nb)
        blake2b_transform(ctx, input, nb);
}

void akmos_blake2b_done(akmos_digest_algo_t *uctx, uint8_t *digest)
{
    akmos_blake2b_t *ctx;

    ctx = &uctx->blake2b;

    if(ctx->len < AKMOS_BLAKE2B_BLKLEN) {
        memset(ctx->buf + ctx->len, 0, AKMOS_BLAKE2B_BLKLEN - ctx->len);
        ctx->tlen = ctx->len;
    }

    ctx->final = BLAKE2B_FINAL;
    blake2b_transform(ctx, ctx->buf, 1);

    memcpy(digest, ctx->h, AKMOS_BLAKE2B_DIGLEN);
}

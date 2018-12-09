/*
 *   Copyright (c) 2015-2018, Andrew Romanenko <melanhit@gmail.com>
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

#include "tiger.h"

#define S0(x)   (akmos_tiger_sbox[0][x])
#define S1(x)   (akmos_tiger_sbox[1][x])
#define S2(x)   (akmos_tiger_sbox[2][x])
#define S3(x)   (akmos_tiger_sbox[3][x])

#define tiger_round(a, b, c, x, mul)                    \
{                                                       \
    c ^= x;                                             \
    UNPACK64BE(t, c);                                   \
    a -= S0(t[0]) ^ S1(t[2]) ^ S2(t[4]) ^ S3(t[6]);     \
    b += S3(t[1]) ^ S2(t[3]) ^ S1(t[5]) ^ S0(t[7]);     \
    b *= mul;                                           \
}

#define tiger_sched(w)                                  \
{                                                       \
    w[0] -= w[7] ^ UINT64_C(0xa5a5a5a5a5a5a5a5);        \
    w[1] ^= w[0];                                       \
    w[2] += w[1];                                       \
    w[3] -= w[2] ^ ((~w[1]) << 19);                     \
    w[4] ^= w[3];                                       \
    w[5] += w[4];                                       \
    w[6] -= w[5] ^ ((~w[4]) >> 23);                     \
    w[7] ^= w[6];                                       \
    w[0] += w[7];                                       \
    w[1] -= w[0] ^ ((~w[7]) << 19);                     \
    w[2] ^= w[1];                                       \
    w[3] += w[2];                                       \
    w[4] -= w[3] ^ ((~w[2]) >> 23);                     \
    w[5] ^= w[4];                                       \
    w[6] += w[5];                                       \
    w[7] -= w[6] ^ UINT64_C(0x0123456789abcdef);        \
}

#define H0  UINT64_C(0x0123456789abcdef)
#define H1  UINT64_C(0xfedcba9876543210)
#define H2  UINT64_C(0xf096a5b4c3b2e187)

static void tiger_transform(uint64_t *h, const uint8_t *blk, size_t nb)
{
    uint64_t a, b, c, aa, bb, cc, *w;
    uint8_t t[8];
    size_t i;

    w = h + 3;

    a = aa = h[0];
    b = bb = h[1];
    c = cc = h[2];

    for(i = 0; i < nb; i++, blk += AKMOS_TIGER_BLKLEN) {
        memcpy(w, blk, AKMOS_TIGER_BLKLEN);

        aa = a; bb = b; cc = c;

        tiger_round(a, b, c, w[0], 5);
        tiger_round(b, c, a, w[1], 5);
        tiger_round(c, a, b, w[2], 5);
        tiger_round(a, b, c, w[3], 5);
        tiger_round(b, c, a, w[4], 5);
        tiger_round(c, a, b, w[5], 5);
        tiger_round(a, b, c, w[6], 5);
        tiger_round(b, c, a, w[7], 5);

        tiger_sched(w);

        tiger_round(c, a, b, w[0], 7);
        tiger_round(a, b, c, w[1], 7);
        tiger_round(b, c, a, w[2], 7);
        tiger_round(c, a, b, w[3], 7);
        tiger_round(a, b, c, w[4], 7);
        tiger_round(b, c, a, w[5], 7);
        tiger_round(c, a, b, w[6], 7);
        tiger_round(a, b, c, w[7], 7);

        tiger_sched(w);

        tiger_round(b, c, a, w[0], 9);
        tiger_round(c, a, b, w[1], 9);
        tiger_round(a, b, c, w[2], 9);
        tiger_round(b, c, a, w[3], 9);
        tiger_round(c, a, b, w[4], 9);
        tiger_round(a, b, c, w[5], 9);
        tiger_round(b, c, a, w[6], 9);
        tiger_round(c, a, b, w[7], 9);

        a ^= aa; b -= bb; c += cc;
    }

    h[0] = a; h[1] = b; h[2] = c;
}

void akmos_tiger_init(akmos_digest_algo_t *uctx)
{
    akmos_tiger_t *ctx;

    ctx = &uctx->tiger;

    ctx->h[0] = H0;
    ctx->h[1] = H1;
    ctx->h[2] = H2;

    ctx->total = ctx->len = 0;
}

void akmos_tiger_update(akmos_digest_algo_t *uctx, const uint8_t *input, size_t len)
{
    akmos_tiger_t *ctx;
    size_t nb, tmp_len;

    ctx = &uctx->tiger;

    tmp_len = len + ctx->len;

    if(tmp_len < AKMOS_TIGER_BLKLEN) {
        memcpy(ctx->block + ctx->len, input, len);
        ctx->len += len;
        return;
    }

    if(ctx->len) {
        tmp_len = AKMOS_TIGER_BLKLEN - ctx->len;
        memcpy(ctx->block + ctx->len, input, tmp_len);

        tiger_transform(ctx->h, ctx->block, 1 & SIZE_T_MAX);

        ctx->len = 0;
        ctx->total++;

        len -= tmp_len;
        input += tmp_len;
    }

    nb = len / AKMOS_TIGER_BLKLEN;
    if(nb)
        tiger_transform(ctx->h, input, nb);

    tmp_len = len % AKMOS_TIGER_BLKLEN;
    if(tmp_len) {
        memcpy(ctx->block, input + (len - tmp_len), tmp_len);
        ctx->len = tmp_len;
    }

    ctx->total += nb;
}

void akmos_tiger_done(akmos_digest_algo_t *uctx, uint8_t *digest)
{
    akmos_tiger_t *ctx;
    uint64_t len_b;

    ctx = &uctx->tiger;

    len_b = ((ctx->total * AKMOS_TIGER_BLKLEN) + ctx->len) * 8;
    ctx->block[ctx->len] = 0x01;
    ctx->len++;

    if(ctx->len > (AKMOS_TIGER_BLKLEN - sizeof(uint64_t))) {
        memset(ctx->block + ctx->len, 0, AKMOS_TIGER_BLKLEN - ctx->len);
        tiger_transform(ctx->h, ctx->block, 1);
        ctx->len = 0;
    }

    memset(ctx->block + ctx->len, 0, AKMOS_TIGER_BLKLEN - ctx->len);
    UNPACK64BE(ctx->block + (AKMOS_TIGER_BLKLEN - sizeof(uint64_t)), len_b);
    tiger_transform(ctx->h, ctx->block, 1);

    memcpy(digest, ctx->h, AKMOS_TIGER_DIGLEN);
}

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

#include "../akmos.h"
#include "../bits.h"

#include "tiger.h"
#include "tiger_sb64.h"

#define tiger_round(a, b, c, x, mul)                    \
{                                                       \
    c ^= x;                                             \
    UNPACK64BE(t, c);                                    \
    a -= SB0[t[0]] ^ SB1[t[2]] ^ SB2[t[4]] ^ SB3[t[6]]; \
    b += SB3[t[1]] ^ SB2[t[3]] ^ SB1[t[5]] ^ SB0[t[7]]; \
    b *= mul;                                           \
}

#define tiger_sched(w)                  \
{                                       \
    w[0] -= w[7] ^ 0xa5a5a5a5a5a5a5a5;  \
    w[1] ^= w[0];                       \
    w[2] += w[1];                       \
    w[3] -= w[2] ^ ((~w[1]) << 19);     \
    w[4] ^= w[3];                       \
    w[5] += w[4];                       \
    w[6] -= w[5] ^ ((~w[4]) >> 23);     \
    w[7] ^= w[6];                       \
    w[0] += w[7];                       \
    w[1] -= w[0] ^ ((~w[7]) << 19);     \
    w[2] ^= w[1];                       \
    w[3] += w[2];                       \
    w[4] -= w[3] ^ ((~w[2]) >> 23);     \
    w[5] ^= w[4];                       \
    w[6] += w[5];                       \
    w[7] -= w[6] ^ 0x0123456789abcdef;  \
}

#define H0  0x0123456789abcdef
#define H1  0xfedcba9876543210
#define H2  0xf096a5b4c3b2e187

static void tiger_transform(akmos_tiger_t *ctx, const uint8_t *block, uint32_t nb)
{
    uint64_t a, b, c, aa, bb, cc, *w;
    uint8_t *t;
    const uint8_t *sub;
    size_t i;

    w = ctx->w;
    t = ctx->t;

    a = aa = ctx->h[0];
    b = bb = ctx->h[1];
    c = cc = ctx->h[2];

    for(i = 0; i < nb; i++) {
        sub = block + (i * 64);

        w[0] = PACK64BE(sub     ); w[1] = PACK64BE(sub +  8);
        w[2] = PACK64BE(sub + 16); w[3] = PACK64BE(sub + 24);
        w[4] = PACK64BE(sub + 32); w[5] = PACK64BE(sub + 40);
        w[6] = PACK64BE(sub + 48); w[7] = PACK64BE(sub + 56);

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

        a ^= aa;
        b -= bb;
        c += cc;
    }

    ctx->h[0] = a;
    ctx->h[1] = b;
    ctx->h[2] = c;
}

void akmos_tiger_init(akmos_tiger_t *ctx)
{
    ctx->h[0] = H0;
    ctx->h[1] = H1;
    ctx->h[2] = H2;
}

void akmos_tiger_update(akmos_tiger_t *ctx, const uint8_t *input, size_t len)
{
    uint32_t nb, new_len, rem_len, tmp_len;
    const uint8_t *sfi;

    tmp_len = AKMOS_TIGER_BLKLEN - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(ctx->block + ctx->len, input, rem_len);

    if((ctx->len + len) < AKMOS_TIGER_BLKLEN) {
        ctx->len += len;
        return;
    }
    new_len = len - rem_len;
    nb = new_len / AKMOS_TIGER_BLKLEN;

    sfi = input + rem_len;

    tiger_transform(ctx, ctx->block, 1);
    tiger_transform(ctx, sfi, nb);

    rem_len = new_len % AKMOS_TIGER_BLKLEN;

    if(rem_len > 0)
        memcpy(ctx->block, sfi + (nb * 64), rem_len);

    ctx->len = rem_len;
    ctx->total += ((nb + 1) * 64);
}

void akmos_tiger_done(akmos_tiger_t *ctx, uint8_t *digest)
{
    uint32_t nb, pm_len;
    uint64_t len_bit;

    nb = (1 + ((AKMOS_TIGER_BLKLEN - 9) < (ctx->len % AKMOS_TIGER_BLKLEN)));

    len_bit = (ctx->total + ctx->len) * 8;
    pm_len = nb * 64;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x01;

    UNPACK64BE(ctx->block + (pm_len - 8), len_bit);

    tiger_transform(ctx, ctx->block, nb);

    UNPACK64LE(digest     , ctx->h[0]);
    UNPACK64LE(digest +  8, ctx->h[1]);
    UNPACK64LE(digest + 16, ctx->h[2]);
}

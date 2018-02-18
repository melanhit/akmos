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

#include "whirlpool.h"

#define S0(x)   (akmos_whirlpool_sbox[0][x])
#define S1(x)   (akmos_whirlpool_sbox[1][x])
#define S2(x)   (akmos_whirlpool_sbox[2][x])
#define S3(x)   (akmos_whirlpool_sbox[3][x])
#define S4(x)   (akmos_whirlpool_sbox[4][x])
#define S5(x)   (akmos_whirlpool_sbox[5][x])
#define S6(x)   (akmos_whirlpool_sbox[6][x])
#define S7(x)   (akmos_whirlpool_sbox[7][x])

static const uint64_t RC[10] = {
    UINT64_C(0x1823c6e887b8014f), UINT64_C(0x36a6d2f5796f9152),
    UINT64_C(0x60bc9b8ea30c7b35), UINT64_C(0x1de0d7c22e4bfe57),
    UINT64_C(0x157737e59ff04ada), UINT64_C(0x58c9290ab1a06b85),
    UINT64_C(0xbd5d10f4cb3e0567), UINT64_C(0xe427418ba77d95d8),
    UINT64_C(0xfbee7c66dd17479e), UINT64_C(0xca2dbf07ad5a8333)
};

static void whirlpool_transform(uint64_t *h, const uint8_t *blk, size_t nb)
{
    uint64_t *w, *s, *k;
    size_t i, j;

    w = h + 8;
    s = w + 8;
    k = w + 16;

    for(i = 0; i < nb; i++, blk += AKMOS_WHIRLPOOL_BLKLEN) {
        w[0] = PACK64LE(blk     ); w[1] = PACK64LE(blk +  8);
        w[2] = PACK64LE(blk + 16); w[3] = PACK64LE(blk + 24);
        w[4] = PACK64LE(blk + 32); w[5] = PACK64LE(blk + 40);
        w[6] = PACK64LE(blk + 48); w[7] = PACK64LE(blk + 56);

        k[0] = h[0]; k[1] = h[1];
        k[2] = h[2]; k[3] = h[3];
        k[4] = h[4]; k[5] = h[5];
        k[6] = h[6]; k[7] = h[7];

        h[0] ^= w[0]; h[1] ^= w[1];
        h[2] ^= w[2]; h[3] ^= w[3];
        h[4] ^= w[4]; h[5] ^= w[5];
        h[6] ^= w[6]; h[7] ^= w[7];

        w[0] ^= k[0]; w[1] ^= k[1];
        w[2] ^= k[2]; w[3] ^= k[3];
        w[4] ^= k[4]; w[5] ^= k[5];
        w[6] ^= k[6]; w[7] ^= k[7];

        for(j = 0; j < AKMOS_WHIRLPOOL_ROUNDS; j++) {
            /* compute key */
            s[0] = S0((k[0] >> 56) & 0xff) ^ S1((k[7] >> 48) & 0xff) ^
                   S2((k[6] >> 40) & 0xff) ^ S3((k[5] >> 32) & 0xff) ^
                   S4((k[4] >> 24) & 0xff) ^ S5((k[3] >> 16) & 0xff) ^
                   S6((k[2] >>  8) & 0xff) ^ S7((k[1] >>  0) & 0xff) ^ RC[j];

            s[1] = S0((k[1] >> 56) & 0xff) ^ S1((k[0] >> 48) & 0xff) ^
                   S2((k[7] >> 40) & 0xff) ^ S3((k[6] >> 32) & 0xff) ^
                   S4((k[5] >> 24) & 0xff) ^ S5((k[4] >> 16) & 0xff) ^
                   S6((k[3] >>  8) & 0xff) ^ S7((k[2] >>  0) & 0xff);

            s[2] = S0((k[2] >> 56) & 0xff) ^ S1((k[1] >> 48) & 0xff) ^
                   S2((k[0] >> 40) & 0xff) ^ S3((k[7] >> 32) & 0xff) ^
                   S4((k[6] >> 24) & 0xff) ^ S5((k[5] >> 16) & 0xff) ^
                   S6((k[4] >>  8) & 0xff) ^ S7((k[3] >>  0) & 0xff);

            s[3] = S0((k[3] >> 56) & 0xff) ^ S1((k[2] >> 48) & 0xff) ^
                   S2((k[1] >> 40) & 0xff) ^ S3((k[0] >> 32) & 0xff) ^
                   S4((k[7] >> 24) & 0xff) ^ S5((k[6] >> 16) & 0xff) ^
                   S6((k[5] >>  8) & 0xff) ^ S7((k[4] >>  0) & 0xff);

            s[4] = S0((k[4] >> 56) & 0xff) ^ S1((k[3] >> 48) & 0xff) ^
                   S2((k[2] >> 40) & 0xff) ^ S3((k[1] >> 32) & 0xff) ^
                   S4((k[0] >> 24) & 0xff) ^ S5((k[7] >> 16) & 0xff) ^
                   S6((k[6] >>  8) & 0xff) ^ S7((k[5] >>  0) & 0xff);

            s[5] = S0((k[5] >> 56) & 0xff) ^ S1((k[4] >> 48) & 0xff) ^
                   S2((k[3] >> 40) & 0xff) ^ S3((k[2] >> 32) & 0xff) ^
                   S4((k[1] >> 24) & 0xff) ^ S5((k[0] >> 16) & 0xff) ^
                   S6((k[7] >>  8) & 0xff) ^ S7((k[6] >>  0) & 0xff);

            s[6] = S0((k[6] >> 56) & 0xff) ^ S1((k[5] >> 48) & 0xff) ^
                   S2((k[4] >> 40) & 0xff) ^ S3((k[3] >> 32) & 0xff) ^
                   S4((k[2] >> 24) & 0xff) ^ S5((k[1] >> 16) & 0xff) ^
                   S6((k[0] >>  8) & 0xff) ^ S7((k[7] >>  0) & 0xff);

            s[7] = S0((k[7] >> 56) & 0xff) ^ S1((k[6] >> 48) & 0xff) ^
                   S2((k[5] >> 40) & 0xff) ^ S3((k[4] >> 32) & 0xff) ^
                   S4((k[3] >> 24) & 0xff) ^ S5((k[2] >> 16) & 0xff) ^
                   S6((k[1] >>  8) & 0xff) ^ S7((k[0] >>  0) & 0xff);

            k[0] = s[0]; k[1] = s[1]; k[2] = s[2]; k[3] = s[3];
            k[4] = s[4]; k[5] = s[5]; k[6] = s[6]; k[7] = s[7];

            /* transformation */
            s[0] ^= S0((w[0] >> 56) & 0xff) ^ S1((w[7] >> 48) & 0xff) ^
                    S2((w[6] >> 40) & 0xff) ^ S3((w[5] >> 32) & 0xff) ^
                    S4((w[4] >> 24) & 0xff) ^ S5((w[3] >> 16) & 0xff) ^
                    S6((w[2] >>  8) & 0xff) ^ S7((w[1] >>  0) & 0xff);

            s[1] ^= S0((w[1] >> 56) & 0xff) ^ S1((w[0] >> 48) & 0xff) ^
                    S2((w[7] >> 40) & 0xff) ^ S3((w[6] >> 32) & 0xff) ^
                    S4((w[5] >> 24) & 0xff) ^ S5((w[4] >> 16) & 0xff) ^
                    S6((w[3] >>  8) & 0xff) ^ S7((w[2] >>  0) & 0xff);

            s[2] ^= S0((w[2] >> 56) & 0xff) ^ S1((w[1] >> 48) & 0xff) ^
                    S2((w[0] >> 40) & 0xff) ^ S3((w[7] >> 32) & 0xff) ^
                    S4((w[6] >> 24) & 0xff) ^ S5((w[5] >> 16) & 0xff) ^
                    S6((w[4] >>  8) & 0xff) ^ S7((w[3] >>  0) & 0xff);

            s[3] ^= S0((w[3] >> 56) & 0xff) ^ S1((w[2] >> 48) & 0xff) ^
                    S2((w[1] >> 40) & 0xff) ^ S3((w[0] >> 32) & 0xff) ^
                    S4((w[7] >> 24) & 0xff) ^ S5((w[6] >> 16) & 0xff) ^
                    S6((w[5] >>  8) & 0xff) ^ S7((w[4] >>  0) & 0xff);

            s[4] ^= S0((w[4] >> 56) & 0xff) ^ S1((w[3] >> 48) & 0xff) ^
                    S2((w[2] >> 40) & 0xff) ^ S3((w[1] >> 32) & 0xff) ^
                    S4((w[0] >> 24) & 0xff) ^ S5((w[7] >> 16) & 0xff) ^
                    S6((w[6] >>  8) & 0xff) ^ S7((w[5] >>  0) & 0xff);

            s[5] ^= S0((w[5] >> 56) & 0xff) ^ S1((w[4] >> 48) & 0xff) ^
                    S2((w[3] >> 40) & 0xff) ^ S3((w[2] >> 32) & 0xff) ^
                    S4((w[1] >> 24) & 0xff) ^ S5((w[0] >> 16) & 0xff) ^
                    S6((w[7] >>  8) & 0xff) ^ S7((w[6] >>  0) & 0xff);

            s[6] ^= S0((w[6] >> 56) & 0xff) ^ S1((w[5] >> 48) & 0xff) ^
                    S2((w[4] >> 40) & 0xff) ^ S3((w[3] >> 32) & 0xff) ^
                    S4((w[2] >> 24) & 0xff) ^ S5((w[1] >> 16) & 0xff) ^
                    S6((w[0] >>  8) & 0xff) ^ S7((w[7] >>  0) & 0xff);

            s[7] ^= S0((w[7] >> 56) & 0xff) ^ S1((w[6] >> 48) & 0xff) ^
                    S2((w[5] >> 40) & 0xff) ^ S3((w[4] >> 32) & 0xff) ^
                    S4((w[3] >> 24) & 0xff) ^ S5((w[2] >> 16) & 0xff) ^
                    S6((w[1] >>  8) & 0xff) ^ S7((w[0] >>  0) & 0xff);

            w[0] = s[0]; w[1] = s[1]; w[2] = s[2]; w[3] = s[3];
            w[4] = s[4]; w[5] = s[5]; w[6] = s[6]; w[7] = s[7];
        }

        h[0] ^= w[0]; h[1] ^= w[1]; h[2] ^= w[2]; h[3] ^= w[3];
        h[4] ^= w[4]; h[5] ^= w[5]; h[6] ^= w[6]; h[7] ^= w[7];
    }
}

void akmos_whirlpool_init(akmos_digest_algo_t *uctx)
{
    akmos_whirlpool_t *ctx;

    ctx = &uctx->whirlpool;

    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = 0;
    ctx->h[4] = ctx->h[5] = ctx->h[6] = ctx->h[7] = 0;

    ctx->len = ctx->total = 0;
}

void akmos_whirlpool_update(akmos_digest_algo_t *uctx, const uint8_t *input, size_t len)
{
    akmos_whirlpool_t *ctx;
    size_t nb, tmp_len;

    ctx = &uctx->whirlpool;

    tmp_len = len + ctx->len;

    if(tmp_len < AKMOS_WHIRLPOOL_BLKLEN) {
        memcpy(ctx->block + ctx->len, input, len);
        ctx->len += len;
        return;
    }

    if(ctx->len) {
        tmp_len = AKMOS_WHIRLPOOL_BLKLEN - ctx->len;
        memcpy(ctx->block + ctx->len, input, tmp_len);

        whirlpool_transform(ctx->h, ctx->block, 1 & SIZE_T_MAX);

        ctx->len = 0;
        ctx->total++;

        len -= tmp_len;
        input += tmp_len;
    }

    nb = len / AKMOS_WHIRLPOOL_BLKLEN;
    if(nb)
        whirlpool_transform(ctx->h, input, nb);

    tmp_len = len % AKMOS_WHIRLPOOL_BLKLEN;
    if(tmp_len) {
        memcpy(ctx->block, input + (len - tmp_len), tmp_len);
        ctx->len = tmp_len;
    }

    ctx->total += nb;
}

void akmos_whirlpool_done(akmos_digest_algo_t *uctx, uint8_t *digest)
{
    akmos_whirlpool_t *ctx;
    uint64_t len_b;
    size_t i;

    ctx = &uctx->whirlpool;

    len_b = ((ctx->total * AKMOS_WHIRLPOOL_BLKLEN) + ctx->len) * 8;
    ctx->block[ctx->len] = 0x80;
    ctx->len++;

    if(ctx->len > (AKMOS_WHIRLPOOL_BLKLEN - 32)) {
        memset(ctx->block + ctx->len, 0, AKMOS_WHIRLPOOL_BLKLEN - ctx->len);
        whirlpool_transform(ctx->h, ctx->block, 1);
        ctx->len = 0;
    }

    memset(ctx->block + ctx->len, 0, AKMOS_WHIRLPOOL_BLKLEN - ctx->len);
    UNPACK64LE(ctx->block + (AKMOS_WHIRLPOOL_BLKLEN - 8), len_b);
    whirlpool_transform(ctx->h, ctx->block, 1);

    for(i = 0; i < AKMOS_WHIRLPOOL_DIGLEN / (sizeof(uint64_t)); i++, digest += sizeof(uint64_t))
        UNPACK64LE(digest, ctx->h[i]);
}

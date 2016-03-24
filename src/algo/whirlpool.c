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

#include "whirlpool.h"
#include "whirlpool_sb64.h"

static const uint64_t RC[10] = {
    UINT64_C(0x1823c6e887b8014f), UINT64_C(0x36a6d2f5796f9152),
    UINT64_C(0x60bc9b8ea30c7b35), UINT64_C(0x1de0d7c22e4bfe57),
    UINT64_C(0x157737e59ff04ada), UINT64_C(0x58c9290ab1a06b85),
    UINT64_C(0xbd5d10f4cb3e0567), UINT64_C(0xe427418ba77d95d8),
    UINT64_C(0xfbee7c66dd17479e), UINT64_C(0xca2dbf07ad5a8333)
};

static void whirlpool_transform(akmos_whirlpool_t *ctx, const uint8_t *block, size_t nb)
{
    uint64_t *w, *s, *k, *h;
    const uint8_t *sub;
    size_t i, j;

    w = ctx->w;
    s = w + 8;
    k = w + 16;

    h = ctx->h;

    for(i = 0; i < nb; i++) {
        sub = block + (i * 64);

        w[0] = PACK64LE(sub     ); w[1] = PACK64LE(sub +  8);
        w[2] = PACK64LE(sub + 16); w[3] = PACK64LE(sub + 24);
        w[4] = PACK64LE(sub + 32); w[5] = PACK64LE(sub + 40);
        w[6] = PACK64LE(sub + 48); w[7] = PACK64LE(sub + 56);

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
            s[0] = SB0[(k[0] >> 56) & 0xff] ^ SB1[(k[7] >> 48) & 0xff] ^
                   SB2[(k[6] >> 40) & 0xff] ^ SB3[(k[5] >> 32) & 0xff] ^
                   SB4[(k[4] >> 24) & 0xff] ^ SB5[(k[3] >> 16) & 0xff] ^
                   SB6[(k[2] >>  8) & 0xff] ^ SB7[(k[1] >>  0) & 0xff] ^ RC[j];

            s[1] = SB0[(k[1] >> 56) & 0xff] ^ SB1[(k[0] >> 48) & 0xff] ^
                   SB2[(k[7] >> 40) & 0xff] ^ SB3[(k[6] >> 32) & 0xff] ^
                   SB4[(k[5] >> 24) & 0xff] ^ SB5[(k[4] >> 16) & 0xff] ^
                   SB6[(k[3] >>  8) & 0xff] ^ SB7[(k[2] >>  0) & 0xff];

            s[2] = SB0[(k[2] >> 56) & 0xff] ^ SB1[(k[1] >> 48) & 0xff] ^
                   SB2[(k[0] >> 40) & 0xff] ^ SB3[(k[7] >> 32) & 0xff] ^
                   SB4[(k[6] >> 24) & 0xff] ^ SB5[(k[5] >> 16) & 0xff] ^
                   SB6[(k[4] >>  8) & 0xff] ^ SB7[(k[3] >>  0) & 0xff];

            s[3] = SB0[(k[3] >> 56) & 0xff] ^ SB1[(k[2] >> 48) & 0xff] ^
                   SB2[(k[1] >> 40) & 0xff] ^ SB3[(k[0] >> 32) & 0xff] ^
                   SB4[(k[7] >> 24) & 0xff] ^ SB5[(k[6] >> 16) & 0xff] ^
                   SB6[(k[5] >>  8) & 0xff] ^ SB7[(k[4] >>  0) & 0xff];

            s[4] = SB0[(k[4] >> 56) & 0xff] ^ SB1[(k[3] >> 48) & 0xff] ^
                   SB2[(k[2] >> 40) & 0xff] ^ SB3[(k[1] >> 32) & 0xff] ^
                   SB4[(k[0] >> 24) & 0xff] ^ SB5[(k[7] >> 16) & 0xff] ^
                   SB6[(k[6] >>  8) & 0xff] ^ SB7[(k[5] >>  0) & 0xff];

            s[5] = SB0[(k[5] >> 56) & 0xff] ^ SB1[(k[4] >> 48) & 0xff] ^
                   SB2[(k[3] >> 40) & 0xff] ^ SB3[(k[2] >> 32) & 0xff] ^
                   SB4[(k[1] >> 24) & 0xff] ^ SB5[(k[0] >> 16) & 0xff] ^
                   SB6[(k[7] >>  8) & 0xff] ^ SB7[(k[6] >>  0) & 0xff];

            s[6] = SB0[(k[6] >> 56) & 0xff] ^ SB1[(k[5] >> 48) & 0xff] ^
                   SB2[(k[4] >> 40) & 0xff] ^ SB3[(k[3] >> 32) & 0xff] ^
                   SB4[(k[2] >> 24) & 0xff] ^ SB5[(k[1] >> 16) & 0xff] ^
                   SB6[(k[0] >>  8) & 0xff] ^ SB7[(k[7] >>  0) & 0xff];

            s[7] = SB0[(k[7] >> 56) & 0xff] ^ SB1[(k[6] >> 48) & 0xff] ^
                   SB2[(k[5] >> 40) & 0xff] ^ SB3[(k[4] >> 32) & 0xff] ^
                   SB4[(k[3] >> 24) & 0xff] ^ SB5[(k[2] >> 16) & 0xff] ^
                   SB6[(k[1] >>  8) & 0xff] ^ SB7[(k[0] >>  0) & 0xff];

            k[0] = s[0]; k[1] = s[1]; k[2] = s[2]; k[3] = s[3];
            k[4] = s[4]; k[5] = s[5]; k[6] = s[6]; k[7] = s[7];

            /* transformation */
            s[0] ^= SB0[(w[0] >> 56) & 0xff] ^ SB1[(w[7] >> 48) & 0xff] ^
                    SB2[(w[6] >> 40) & 0xff] ^ SB3[(w[5] >> 32) & 0xff] ^
                    SB4[(w[4] >> 24) & 0xff] ^ SB5[(w[3] >> 16) & 0xff] ^
                    SB6[(w[2] >>  8) & 0xff] ^ SB7[(w[1] >>  0) & 0xff];

            s[1] ^= SB0[(w[1] >> 56) & 0xff] ^ SB1[(w[0] >> 48) & 0xff] ^
                    SB2[(w[7] >> 40) & 0xff] ^ SB3[(w[6] >> 32) & 0xff] ^
                    SB4[(w[5] >> 24) & 0xff] ^ SB5[(w[4] >> 16) & 0xff] ^
                    SB6[(w[3] >>  8) & 0xff] ^ SB7[(w[2] >>  0) & 0xff];

            s[2] ^= SB0[(w[2] >> 56) & 0xff] ^ SB1[(w[1] >> 48) & 0xff] ^
                    SB2[(w[0] >> 40) & 0xff] ^ SB3[(w[7] >> 32) & 0xff] ^
                    SB4[(w[6] >> 24) & 0xff] ^ SB5[(w[5] >> 16) & 0xff] ^
                    SB6[(w[4] >>  8) & 0xff] ^ SB7[(w[3] >>  0) & 0xff];

            s[3] ^= SB0[(w[3] >> 56) & 0xff] ^ SB1[(w[2] >> 48) & 0xff] ^
                    SB2[(w[1] >> 40) & 0xff] ^ SB3[(w[0] >> 32) & 0xff] ^
                    SB4[(w[7] >> 24) & 0xff] ^ SB5[(w[6] >> 16) & 0xff] ^
                    SB6[(w[5] >>  8) & 0xff] ^ SB7[(w[4] >>  0) & 0xff];

            s[4] ^= SB0[(w[4] >> 56) & 0xff] ^ SB1[(w[3] >> 48) & 0xff] ^
                    SB2[(w[2] >> 40) & 0xff] ^ SB3[(w[1] >> 32) & 0xff] ^
                    SB4[(w[0] >> 24) & 0xff] ^ SB5[(w[7] >> 16) & 0xff] ^
                    SB6[(w[6] >>  8) & 0xff] ^ SB7[(w[5] >>  0) & 0xff];

            s[5] ^= SB0[(w[5] >> 56) & 0xff] ^ SB1[(w[4] >> 48) & 0xff] ^
                    SB2[(w[3] >> 40) & 0xff] ^ SB3[(w[2] >> 32) & 0xff] ^
                    SB4[(w[1] >> 24) & 0xff] ^ SB5[(w[0] >> 16) & 0xff] ^
                    SB6[(w[7] >>  8) & 0xff] ^ SB7[(w[6] >>  0) & 0xff];

            s[6] ^= SB0[(w[6] >> 56) & 0xff] ^ SB1[(w[5] >> 48) & 0xff] ^
                    SB2[(w[4] >> 40) & 0xff] ^ SB3[(w[3] >> 32) & 0xff] ^
                    SB4[(w[2] >> 24) & 0xff] ^ SB5[(w[1] >> 16) & 0xff] ^
                    SB6[(w[0] >>  8) & 0xff] ^ SB7[(w[7] >>  0) & 0xff];

            s[7] ^= SB0[(w[7] >> 56) & 0xff] ^ SB1[(w[6] >> 48) & 0xff] ^
                    SB2[(w[5] >> 40) & 0xff] ^ SB3[(w[4] >> 32) & 0xff] ^
                    SB4[(w[3] >> 24) & 0xff] ^ SB5[(w[2] >> 16) & 0xff] ^
                    SB6[(w[1] >>  8) & 0xff] ^ SB7[(w[0] >>  0) & 0xff];

            w[0] = s[0]; w[1] = s[1]; w[2] = s[2]; w[3] = s[3];
            w[4] = s[4]; w[5] = s[5]; w[6] = s[6]; w[7] = s[7];
        }

        h[0] ^= w[0]; h[1] ^= w[1]; h[2] ^= w[2]; h[3] ^= w[3];
        h[4] ^= w[4]; h[5] ^= w[5]; h[6] ^= w[6]; h[7] ^= w[7];
    }
}

void akmos_whirlpool_init(akmos_whirlpool_t *ctx)
{
    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = 0;
    ctx->h[4] = ctx->h[5] = ctx->h[6] = ctx->h[7] = 0;

    ctx->len=0;
}

void akmos_whirlpool_update(akmos_whirlpool_t *ctx, const uint8_t *input, size_t len)
{
    size_t nb, new_len, rem_len, tmp_len;
    const uint8_t *sfi;

    tmp_len = AKMOS_WHIRLPOOL_BLKLEN - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(ctx->block + ctx->len, input, rem_len);

    if((ctx->len + len) < AKMOS_WHIRLPOOL_BLKLEN) {
        ctx->len += len;
        return;
    }
    new_len = len - rem_len;
    nb = new_len / AKMOS_WHIRLPOOL_BLKLEN;

    sfi = input + rem_len;

    whirlpool_transform(ctx, ctx->block, 1 & SIZE_T_MAX);
    whirlpool_transform(ctx, sfi, nb);

    rem_len = new_len % AKMOS_WHIRLPOOL_BLKLEN;

    if(rem_len > 0)
        memcpy(ctx->block, sfi + (nb * 64), rem_len);

    ctx->len = rem_len;
    ctx->total += ((nb + 1) * 64);
}

void akmos_whirlpool_done(akmos_whirlpool_t *ctx, uint8_t *digest)
{
    size_t nb, pm_len;
    uint64_t len_bit;

    nb = (1 + ((AKMOS_WHIRLPOOL_BLKLEN - 33) < (ctx->len % AKMOS_WHIRLPOOL_BLKLEN)));

    len_bit = (ctx->total + ctx->len) * 8;
    pm_len = nb * 64;

    memset(ctx->block + ctx->len, 0, pm_len);
    ctx->block[ctx->len] = 0x80;

    /* decrease original bitcount from 256 to 64 (for speed) */
    UNPACK64LE(ctx->block + (pm_len - 8), len_bit);

    whirlpool_transform(ctx, ctx->block, nb);

    UNPACK64LE(digest     , ctx->h[0]);
    UNPACK64LE(digest +  8, ctx->h[1]);
    UNPACK64LE(digest + 16, ctx->h[2]);
    UNPACK64LE(digest + 24, ctx->h[3]);
    UNPACK64LE(digest + 32, ctx->h[4]);
    UNPACK64LE(digest + 40, ctx->h[5]);
    UNPACK64LE(digest + 48, ctx->h[6]);
    UNPACK64LE(digest + 56, ctx->h[7]);
}

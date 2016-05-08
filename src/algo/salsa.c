/*
 *   Copyright (c) 2016, Andrew Romanenko <melanhit@gmail.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../akmos.h"
#include "../bits.h"

#include "salsa.h"

#define C0  0x61707865
#define C1  0x3320646e
#define C2  0x79622d32
#define C3  0x6b206574

#define C4  0x3120646e
#define C5  0x79622d36

void akmos_salsa_setiv(akmos_salsa_t *ctx, const uint8_t *iv)
{
    ctx->s[6] = PACK32BE(iv    );
    ctx->s[7] = PACK32BE(iv + 4);
}

void akmos_salsa_setcnt(akmos_salsa_t *ctx, const uint8_t *cnt)
{
    ctx->s[8] = PACK32BE(cnt    );
    ctx->s[9] = PACK32BE(cnt + 4);
}

void akmos_salsa_setkey(akmos_salsa_t *ctx, const uint8_t *in_key, size_t len)
{
    switch(len) {
        case 16:
            ctx->s[ 1] = PACK32BE(in_key     );
            ctx->s[ 2] = PACK32BE(in_key +  4);
            ctx->s[ 3] = PACK32BE(in_key +  8);
            ctx->s[ 4] = PACK32BE(in_key + 12);

            ctx->s[11] = ctx->s[1];
            ctx->s[12] = ctx->s[2];
            ctx->s[13] = ctx->s[3];
            ctx->s[14] = ctx->s[4];

            ctx->s[ 0] = C0;
            ctx->s[ 5] = C4;
            ctx->s[10] = C5;
            ctx->s[15] = C3;
            break;

        case 32:
            ctx->s[ 1] = PACK32BE(in_key     );
            ctx->s[ 2] = PACK32BE(in_key +  4);
            ctx->s[ 3] = PACK32BE(in_key +  8);
            ctx->s[ 4] = PACK32BE(in_key + 12);
            ctx->s[11] = PACK32BE(in_key + 16);
            ctx->s[12] = PACK32BE(in_key + 20);
            ctx->s[13] = PACK32BE(in_key + 24);
            ctx->s[14] = PACK32BE(in_key + 28);

            ctx->s[ 0] = C0;
            ctx->s[ 5] = C1;
            ctx->s[10] = C2;
            ctx->s[15] = C3;
            break;

        default:
            return;
    }


}

void akmos_salsa_stream20(akmos_salsa_t *ctx, uint8_t *out_blk)
{
    size_t i;
    uint32_t s[16];

    for(i = 0; i < 16; i++)
        s[i] = ctx->s[i];

    for(i = 0; i < AKMOS_SALSA20_ROUNDS / 2; i++) {
        s[ 4] ^= ROTL32((s[ 0] + s[12]),  7); s[ 9] ^= ROTL32((s[ 5] + s[ 1]),  7);
        s[14] ^= ROTL32((s[10] + s[ 6]),  7); s[ 3] ^= ROTL32((s[15] + s[11]),  7);
        s[ 8] ^= ROTL32((s[ 4] + s[ 0]),  9); s[13] ^= ROTL32((s[ 9] + s[ 5]),  9);
        s[ 2] ^= ROTL32((s[14] + s[10]),  9); s[ 7] ^= ROTL32((s[ 3] + s[15]),  9);
        s[12] ^= ROTL32((s[ 8] + s[ 4]), 13); s[ 1] ^= ROTL32((s[13] + s[ 9]), 13);
        s[ 6] ^= ROTL32((s[ 2] + s[14]), 13); s[11] ^= ROTL32((s[ 7] + s[ 3]), 13);
        s[ 0] ^= ROTL32((s[12] + s[ 8]), 18); s[ 5] ^= ROTL32((s[ 1] + s[13]), 18);
        s[10] ^= ROTL32((s[ 6] + s[ 2]), 18); s[15] ^= ROTL32((s[11] + s[ 7]), 18);

        s[ 1] ^= ROTL32((s[ 0] + s[ 3]),  7); s[ 6] ^= ROTL32((s[ 5] + s[ 4]),  7);
        s[11] ^= ROTL32((s[10] + s[ 9]),  7); s[12] ^= ROTL32((s[15] + s[14]),  7);
        s[ 2] ^= ROTL32((s[ 1] + s[ 0]),  9); s[ 7] ^= ROTL32((s[ 6] + s[ 5]),  9);
        s[ 8] ^= ROTL32((s[11] + s[10]),  9); s[13] ^= ROTL32((s[12] + s[15]),  9);
        s[ 3] ^= ROTL32((s[ 2] + s[ 1]), 13); s[ 4] ^= ROTL32((s[ 7] + s[ 6]), 13);
        s[ 9] ^= ROTL32((s[ 8] + s[11]), 13); s[14] ^= ROTL32((s[13] + s[12]), 13);
        s[ 0] ^= ROTL32((s[ 3] + s[ 2]), 18); s[ 5] ^= ROTL32((s[ 4] + s[ 7]), 18);
        s[10] ^= ROTL32((s[ 9] + s[ 8]), 18); s[15] ^= ROTL32((s[14] + s[13]), 18);
    }

    for(i = 0; i < 16; i++)
        s[i] += ctx->s[i];

    ctx->s[8]++;
    if(!ctx->s[8])
        ctx->s[9]++;

    for(i = 0; i < AKMOS_SALSA_BLKLEN / 4; i++, out_blk += 4)
        UNPACK32BE(out_blk, s[i]);
}

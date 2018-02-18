/*
 *   Copyright (c) 2016-2018, Andrew Romanenko <melanhit@gmail.com>
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

#include "../akmos.h"
#include "../bits.h"
#include "../cipher.h"

#include "salsa.h"

#define C0  0x61707865
#define C1  0x3320646e
#define C2  0x79622d32
#define C3  0x6b206574

#define C4  0x3120646e
#define C5  0x79622d36

#define QROUND(a, b, c, n)             \
    s[a] ^= ROTL32((s[b] + s[c]), n);

void akmos_salsa_setiv(akmos_cipher_algo_t *uctx, const uint8_t *iv)
{
    akmos_salsa_t *ctx;

    ctx = &uctx->salsa;

    ctx->s[6] = PACK32BE(iv    );
    ctx->s[7] = PACK32BE(iv + 4);
}

void akmos_salsa_setcnt(akmos_cipher_algo_t *uctx, const uint8_t *cnt)
{
    akmos_salsa_t *ctx;

    ctx = &uctx->salsa;

    ctx->s[8] = PACK32BE(cnt    );
    ctx->s[9] = PACK32BE(cnt + 4);
}

void akmos_salsa_setkey(akmos_cipher_algo_t *uctx, const uint8_t *in_key, size_t len)
{
    akmos_salsa_t *ctx;

    ctx = &uctx->salsa;

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

void akmos_salsa_stream(akmos_cipher_algo_t *uctx, uint8_t *out_blk)
{
    akmos_salsa_t *ctx;
    size_t i;
    uint32_t s[16];

    ctx = &uctx->salsa;

    for(i = 0; i < 16; i++)
        s[i] = ctx->s[i];

    for(i = 0; i < AKMOS_SALSA_ROUNDS / 2; i++) {
        QROUND( 4,  0, 12,  7); QROUND( 9,  5,  1,  7);
        QROUND(14, 10,  6,  7); QROUND( 3, 15, 11,  7);
        QROUND( 8,  4,  0,  9); QROUND(13,  9,  5,  9);
        QROUND( 2, 14, 10,  9); QROUND( 7,  3, 15,  9);
        QROUND(12,  8,  4, 13); QROUND( 1, 13,  9, 13);
        QROUND( 6,  2, 14, 13); QROUND(11,  7,  3, 13);
        QROUND( 0, 12,  8, 18); QROUND( 5,  1, 13, 18);
        QROUND(10,  6,  2, 18); QROUND(15, 11,  7, 18);

        QROUND( 1,  0,  3,  7); QROUND( 6,  5,  4,  7);
        QROUND(11, 10,  9,  7); QROUND(12, 15, 14,  7);
        QROUND( 2,  1,  0,  9); QROUND( 7,  6,  5,  9);
        QROUND( 8, 11, 10,  9); QROUND(13, 12, 15,  9);
        QROUND( 3,  2,  1, 13); QROUND( 4,  7,  6, 13);
        QROUND( 9,  8, 11, 13); QROUND(14, 13, 12, 13);
        QROUND( 0,  3,  2, 18); QROUND( 5,  4,  7, 18);
        QROUND(10,  9,  8, 18); QROUND(15, 14, 13, 18);
    }

    for(i = 0; i < 16; i++)
        s[i] += ctx->s[i];

    ctx->s[8]++;
    if(!ctx->s[8])
        ctx->s[9]++;

    for(i = 0; i < AKMOS_SALSA_BLKLEN / 4; i++, out_blk += 4)
        UNPACK32BE(out_blk, s[i]);
}

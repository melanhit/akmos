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
#include <string.h>

#include "../akmos.h"
#include "../bits.h"

#include "chacha.h"

#define C0  0x61707865
#define C1  0x3320646e
#define C2  0x79622d32
#define C3  0x6b206574

#define QROUND(a, b, c, d)                          \
{                                                   \
    s[a] += s[b]; s[d] = ROTL32((s[d] ^ s[a]), 16); \
    s[c] += s[d]; s[b] = ROTL32((s[b] ^ s[c]), 12); \
    s[a] += s[b]; s[d] = ROTL32((s[d] ^ s[a]),  8); \
    s[c] += s[d]; s[b] = ROTL32((s[b] ^ s[c]),  7); \
}

void akmos_chacha_setiv(akmos_chacha_t *ctx, const uint8_t *iv)
{
    memcpy(ctx->s + 13, iv, 12);
}

void akmos_chacha_setcnt(akmos_chacha_t *ctx, const uint8_t *cnt)
{
    ctx->s[12] = PACK32BE(cnt);
}

void akmos_chacha_setkey(akmos_chacha_t *ctx, const uint8_t *in_key, size_t __attribute__((unused)) len)
{
    ctx->s[0] = C0;
    ctx->s[1] = C1;
    ctx->s[2] = C2;
    ctx->s[3] = C3;

    memcpy(ctx->s + 4, in_key, AKMOS_CHACHA_KEYMAX);
}

void akmos_chacha_stream(akmos_chacha_t *ctx, uint8_t *out_blk)
{
    size_t i;
    uint32_t s[16];

    for(i = 0; i < 16; i++)
        s[i] = ctx->s[i];

    for(i = 0; i < AKMOS_CHACHA_ROUNDS / 2; i++) {
        QROUND( 0,  4,  8, 12); QROUND( 1,  5,  9, 13);
        QROUND( 2,  6, 10, 14); QROUND( 3,  7, 11, 15);
        QROUND( 0,  5, 10, 15); QROUND( 1,  6, 11, 12);
        QROUND( 2,  7,  8, 13); QROUND( 3,  4,  9, 14);
    }

    for(i = 0; i < 16; i++)
        s[i] += ctx->s[i];

    ctx->s[12]++;

    memcpy(out_blk, s, AKMOS_CHACHA_BLKLEN);
}

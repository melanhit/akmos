/*
 *   Copyright (c) 2015-2017, Andrew Romanenko <melanhit@gmail.com>
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

#include "threefish.h"
#include "threefish_mix.h"

#define WORDS_256   AKMOS_THREEFISH_WORDS_256
#define ROUNDS_256  (72 / 8)
#define SKEYS_256   ((ROUNDS_256 * 2) + 1)

void akmos_threefish_256_setkey(akmos_threefish_256_t *ctx,
                                const uint8_t *key,
                                size_t __attribute__((unused)) len)
{
    uint64_t *k, *S;
    size_t i, j;

    k = ctx->k;

    for(i = 0; i < WORDS_256; i++, key += 8)
        k[i] = PACK64BE(key);

    k[WORDS_256] = AKMOS_THREEFISH_C240;

    for(i = 0; i < WORDS_256; i++)
        k[WORDS_256] ^= k[i];

    for(i = 0, S = ctx->S; i < SKEYS_256; i++, S += WORDS_256) {
        for(j = 0; j < WORDS_256; j++)
            S[j] = k[(i+j)%(WORDS_256+1)];

        S[WORDS_256-1] += i;
    }
}

void akmos_threefish_256_encrypt(akmos_threefish_256_t *ctx,
                                 const uint8_t *in_blk,
                                 uint8_t *out_blk)
{
    uint64_t s[WORDS_256], *S;
    int i, j;

    for(i = 0; i < WORDS_256; i++, in_blk += 8)
        s[i] = PACK64BE(in_blk);

    for(i = 0, S = ctx->S; i < ROUNDS_256; i++, S += WORDS_256) {
        for(j = 0; j < WORDS_256; j++)
            s[j] += S[j];

        threefish_256_emix(s, 14, 16, 52, 57);
        threefish_256_emix(s, 23, 40,  5, 37);

        for(j = 0, S += WORDS_256; j < WORDS_256; j++)
            s[j] += S[j];

        threefish_256_emix(s, 25, 33, 46, 12);
        threefish_256_emix(s, 58, 22, 32, 32);
    }

    for(i = 0; i < WORDS_256; i++, out_blk += 8)
        UNPACK64BE(out_blk, s[i] + S[i]);
}

void akmos_threefish_256_decrypt(akmos_threefish_256_t *ctx,
                                 const uint8_t *in_blk,
                                 uint8_t *out_blk)
{
    uint64_t s[WORDS_256], *S;
    int i, j;

    for(i = 0; i < WORDS_256; i++, in_blk += 8)
        s[i] = PACK64BE(in_blk);

    S = ctx->S + (WORDS_256 * (SKEYS_256 - 1));
    for(i = 0; i < WORDS_256; i++)
        s[i] -= S[i];

    for(i = ROUNDS_256; i > 0; i--) {
        threefish_256_dmix(s, 32, 32, 58, 22);
        threefish_256_dmix(s, 46, 12, 25, 33);

        for(j = 0, S -= WORDS_256; j < WORDS_256; j++)
            s[j] -= S[j];

        threefish_256_dmix(s,  5, 37, 23, 40);
        threefish_256_dmix(s, 52, 57, 14, 16);

        for(j = 0, S -= WORDS_256; j < WORDS_256; j++)
            s[j] -= S[j];
    }

    for(i = 0; i < WORDS_256; i++, out_blk += 8)
        UNPACK64BE(out_blk, s[i]);
}

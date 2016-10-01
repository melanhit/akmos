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

#include "../akmos.h"
#include "../bits.h"

#include "threefish.h"
#include "threefish_mix.h"

#define WORDS_1024  AKMOS_THREEFISH_WORDS_1024
#define ROUNDS_1024 (80 / 8)
#define SKEYS_1024  ((ROUNDS_1024 * 2) + 1)

#define CONST_240   UINT64_C(0x1bd11bdaa9fc1a22)

void akmos_threefish_1024_setkey(akmos_threefish_1024_t *ctx,
                                 const uint8_t *key,
                                 size_t __attribute__((unused)) len)
{
    uint64_t *k, *S;
    size_t i, j;

    k = ctx->k;

    for(i = 0; i < WORDS_1024; i++, key +=8)
        k[i] = PACK64BE(key);

    k[WORDS_1024] = CONST_240;
    for(i = 0; i < WORDS_1024; i++)
        k[WORDS_1024] ^= k[i];

    for(i = 0, S = ctx->S; i < SKEYS_1024; i++, S += WORDS_1024) {
        for(j = 0; j < WORDS_1024; j++)
            S[j] = k[(i+j)%(WORDS_1024+1)];

        S[WORDS_1024-1] += i;
    }
}

void akmos_threefish_1024_encrypt(akmos_threefish_1024_t *ctx,
                                  const uint8_t *in_blk,
                                  uint8_t *out_blk)
{
    uint64_t s[WORDS_1024], *S;
    int i, j;

    for(i = 0; i < WORDS_1024; i++, in_blk += 8)
        s[i] = PACK64BE(in_blk);

    for(i = 0, S = ctx->S; i < ROUNDS_1024; i++, S += WORDS_1024) {
        for(j = 0; j < WORDS_1024; j++)
            s[j] += S[j];

        threefish_1024_emix1(s, 24, 13,  8, 47,  8, 17, 22, 37);
        threefish_1024_emix2(s, 38, 19, 10, 55, 49, 18, 23, 52);
        threefish_1024_emix3(s, 33,  4, 51, 13, 34, 41, 59, 17);
        threefish_1024_emix4(s,  5, 20, 48, 41, 47, 28, 16, 25);

        for(j = 0, S += WORDS_1024; j < WORDS_1024; j++)
            s[j] += S[j];

        threefish_1024_emix1(s, 41,  9, 37, 31, 12, 47, 44, 30);
        threefish_1024_emix2(s, 16, 34, 56, 51,  4, 53, 42, 41);
        threefish_1024_emix3(s, 31, 44, 47, 46, 19, 42, 44, 25);
        threefish_1024_emix4(s,  9, 48, 35, 52, 23, 31, 37, 20);
    }

    for(i = 0; i < WORDS_1024; i++, out_blk += 8)
        UNPACK64BE(out_blk, s[i] + S[i]);
}

void akmos_threefish_1024_decrypt(akmos_threefish_1024_t *ctx,
                                  const uint8_t *in_blk,
                                  uint8_t *out_blk)
{
    uint64_t s[WORDS_1024], *S;
    int i, j;

    for(i = 0; i < WORDS_1024; i++, in_blk += 8)
        s[i] = PACK64BE(in_blk);

    S = ctx->S + (WORDS_1024 * (SKEYS_1024 - 1));
    for(i = 0; i < WORDS_1024; i++)
        s[i] -= S[i];

    for(i = ROUNDS_1024; i > 0; i--) {
        threefish_1024_dmix1(s, 20, 37, 31, 23, 52, 35, 48,  9);
        threefish_1024_dmix2(s, 25, 44, 42, 19, 46, 47, 44, 31);
        threefish_1024_dmix3(s, 41, 42, 53,  4, 51, 56, 34, 16);
        threefish_1024_dmix4(s, 30, 44, 47, 12, 31, 37,  9, 41);

        for(j = 0, S -= WORDS_1024; j < WORDS_1024; j++)
            s[j] -= S[j];

        threefish_1024_dmix1(s, 25, 16, 28, 47, 41, 48, 20,  5);
        threefish_1024_dmix2(s, 17, 59, 41, 34, 13, 51,  4, 33);
        threefish_1024_dmix3(s, 52, 23, 18, 49, 55, 10, 19, 38);
        threefish_1024_dmix4(s, 37, 22, 17,  8, 47,  8, 13, 24);

        for(j = 0, S -= WORDS_1024; j < WORDS_1024; j++)
            s[j] -= S[j];
    }

    for(i = 0; i < WORDS_1024; i++, out_blk += 8)
        UNPACK64BE(out_blk, s[i]);
}

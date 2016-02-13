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

#define WORDS_512   8
#define ROUNDS_512  72
#define SKEYS_512   ((ROUNDS_512 / 4) + 1)

#define CONST_240   0x1bd11bdaa9fc1a22

#define SZ_U64      sizeof(uint64_t)

void akmos_threefish_512_setkey(akmos_threefish_512_t *ctx,
                                const uint8_t *key,
                                size_t len)
{
    uint64_t k[WORDS_512 + 1], *S;
    int i, y;

    for(i = 0; i < WORDS_512; i++)
        k[i] = PACK64BE(key + (i * SZ_U64));

    k[WORDS_512] = CONST_240;

    for(i = 0; i < WORDS_512; i++)
         k[WORDS_512] ^= k[i];

    for(i = 0; i < SKEYS_512; i++) {
        S = ctx->S + (WORDS_512 * i);

        for(y = 0; y < WORDS_512; y++)
            S[y] = k[(i+y)%(WORDS_512+1)];

        S[WORDS_512-1] += i;
    }

    akmos_memzero(k, sizeof(k));
}

void akmos_threefish_512_encrypt(akmos_threefish_512_t *ctx,
                                 const uint8_t *in_blk,
                                 uint8_t *out_blk)
{
    uint64_t s[WORDS_512], *S;
    int i, y;

    for(i = 0; i < WORDS_512; i++)
        s[i] = PACK64BE(in_blk + (i * SZ_U64));

    for(i = 0, S = ctx->S; i < ROUNDS_512 / 8; i++, S += WORDS_512) {
        for(y = 0; y < WORDS_512; y++)
            s[y] += S[y];

        threefish_512_emix1(s, 46, 36, 19, 37);
        threefish_512_emix2(s, 33, 27, 14, 42);
        threefish_512_emix3(s, 17, 49, 36, 39);
        threefish_512_emix4(s, 44,  9, 54, 56);

        for(y = 0, S += WORDS_512; y < WORDS_512; y++)
            s[y] += S[y];

        threefish_512_emix1(s, 39, 30, 34, 24);
        threefish_512_emix2(s, 13, 50, 10, 17);
        threefish_512_emix3(s, 25, 29, 39, 43);
        threefish_512_emix4(s,  8, 35, 56, 22);
    }

    for(i = 0; i < WORDS_512; i++)
        UNPACK64BE(out_blk + (i * SZ_U64), s[i] + S[i]);
}

void akmos_threefish_512_decrypt(akmos_threefish_512_t *ctx,
                                 const uint8_t *in_blk,
                                 uint8_t *out_blk)
{
    uint64_t s[WORDS_512], *S;
    int i, y;

    for(i = 0; i < WORDS_512; i++)
        s[i] = PACK64BE(in_blk + (i * SZ_U64));

    S = ctx->S + (WORDS_512 * (SKEYS_512 - 1));
    for(i = 0; i < WORDS_512; i++)
        s[i] -= S[i];

    for(i = ROUNDS_512 / 8; i > 0; i--) {
        threefish_512_dmix1(s, 22, 56, 35,  8);
        threefish_512_dmix2(s, 43, 39, 29, 25);
        threefish_512_dmix3(s, 17, 10, 50, 13);
        threefish_512_dmix4(s, 24, 34, 30, 39);

        for(y = 0, S -= WORDS_512; y < WORDS_512; y++)
            s[y] -= S[y];

        threefish_512_dmix1(s, 56, 54,  9, 44);
        threefish_512_dmix2(s, 39, 36, 49, 17);
        threefish_512_dmix3(s, 42, 14, 27, 33);
        threefish_512_dmix4(s, 37, 19, 36, 46);

        for(y = 0, S -= WORDS_512; y < WORDS_512; y++)
            s[y] -= S[y];
    }

    for(i = 0; i < WORDS_512; i++)
        UNPACK64BE(out_blk + (i * SZ_U64), s[i]);
}

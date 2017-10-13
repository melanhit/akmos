/*
 *   Copyright (c) 2017, Andrew Romanenko <melanhit@gmail.com>
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

#include <stdint.h>
#include <string.h>

#include "../bits.h"

#include "skein.h"
#include "skein_transform.h"
#include "threefish_mix.h"

#define SKEIN_ROUNDS    AKMOS_SKEIN_1024_ROUNDS
#define SKEIN_SKEYS     AKMOS_SKEIN_1024_SKEYS
#define SKEIN_WORDS     AKMOS_SKEIN_1024_WORDS

void akmos_skein_1024_transform(akmos_skein_t *ctx, const uint8_t *blk, size_t nb, size_t len)
{
    uint64_t k[SKEIN_WORDS+1], s[SKEIN_WORDS], w[SKEIN_WORDS], *skey;
    size_t i, j, y;

    for(i = 0; i < nb; i++) {
        /* set skey */
        ctx->tw[0] += len;
        ctx->tw[2] = ctx->tw[0] ^ ctx->tw[1];

        k[SKEIN_WORDS] = AKMOS_SKEIN_C240;
        for(j = 0; j < SKEIN_WORDS; j++) {
            k[j] = ctx->key[j];
            k[SKEIN_WORDS] ^= ctx->key[j];
        }

        for(j = 0, skey = ctx->skey; j < SKEIN_SKEYS; j++, skey += SKEIN_WORDS) {
            for(y = 0; y < SKEIN_WORDS; y++)
                skey[y] = k[(j+y)%(SKEIN_WORDS+1)];

            skey[SKEIN_WORDS - 3] += ctx->tw[j%3];
            skey[SKEIN_WORDS - 2] += ctx->tw[(j+1)%3];
            skey[SKEIN_WORDS - 1] += j;
        }

        /* encrypt */
        for(j = 0; j < SKEIN_WORDS; j++, blk += 8)
            s[j] = w[j] =  PACK64BE(blk);

        for(j = 0, skey = ctx->skey; j < SKEIN_ROUNDS; j++, skey += SKEIN_WORDS) {
            for(y = 0; y < SKEIN_WORDS; y++)
                s[y] += skey[y];

            threefish_1024_emix1(s, 24, 13,  8, 47,  8, 17, 22, 37);
            threefish_1024_emix2(s, 38, 19, 10, 55, 49, 18, 23, 52);
            threefish_1024_emix3(s, 33,  4, 51, 13, 34, 41, 59, 17);
            threefish_1024_emix4(s,  5, 20, 48, 41, 47, 28, 16, 25);

            for(y = 0, skey += SKEIN_WORDS; y < SKEIN_WORDS; y++)
                s[y] += skey[y];

            threefish_1024_emix1(s, 41,  9, 37, 31, 12, 47, 44, 30);
            threefish_1024_emix2(s, 16, 34, 56, 51,  4, 53, 42, 41);
            threefish_1024_emix3(s, 31, 44, 47, 46, 19, 42, 44, 25);
            threefish_1024_emix4(s,  9, 48, 35, 52, 23, 31, 37, 20);
        }

        for(j = 0; j < SKEIN_WORDS; j++)
            s[j] += skey[j];

        for(j = 0; j < SKEIN_WORDS; j++)
            ctx->key[j] = s[j] ^ w[j];

        ctx->tw[1] &= ~AKMOS_SKEIN_FLAG_FIRST;
    }
}

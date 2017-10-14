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
#include "skein_skey.h"
#include "threefish_mix.h"

#define SKEIN_ROUNDS    AKMOS_SKEIN_512_ROUNDS
#define SKEIN_SKEYS     AKMOS_SKEIN_512_SKEYS
#define SKEIN_WORDS     AKMOS_SKEIN_512_WORDS

void akmos_skein_512_transform(akmos_skein_t *ctx, const uint8_t *blk, size_t nb, size_t len)
{
    uint64_t s[SKEIN_WORDS], w[SKEIN_WORDS], *k, *skey;
    size_t i, j, y;

    for(i = 0; i < nb; i++) {
        /* set skey */
        ctx->tw[0] += len;
        ctx->tw[2] = ctx->tw[0] ^ ctx->tw[1];

        k = ctx->key;
        k[SKEIN_WORDS] = AKMOS_SKEIN_C240;
        for(j = 0; j < SKEIN_WORDS; j++)
            k[SKEIN_WORDS] ^= k[j];

        SKEIN_SKEY_512(ctx->skey, k, ctx->tw);

        /* encrypt */
        for(j = 0; j < SKEIN_WORDS; j++, blk += 8)
            s[j] = w[j] =  PACK64BE(blk);

        for(j = 0, skey = ctx->skey; j < SKEIN_ROUNDS; j++, skey += SKEIN_WORDS) {
            for(y = 0; y < SKEIN_WORDS; y++)
                s[y] += skey[y];

            threefish_512_emix1(s, 46, 36, 19, 37);
            threefish_512_emix2(s, 33, 27, 14, 42);
            threefish_512_emix3(s, 17, 49, 36, 39);
            threefish_512_emix4(s, 44,  9, 54, 56);

            for(y = 0, skey += SKEIN_WORDS; y < SKEIN_WORDS; y++)
                s[y] += skey[y];

            threefish_512_emix1(s, 39, 30, 34, 24);
            threefish_512_emix2(s, 13, 50, 10, 17);
            threefish_512_emix3(s, 25, 29, 39, 43);
            threefish_512_emix4(s,  8, 35, 56, 22);
        }

        for(j = 0; j < SKEIN_WORDS; j++)
            s[j] += skey[j];

        for(j = 0; j < SKEIN_WORDS; j++)
            ctx->key[j] = s[j] ^ w[j];

        ctx->tw[1] &= ~AKMOS_SKEIN_FLAG_FIRST;
    }
}

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

#include "../akmos.h"
#include "../bits.h"
#include "../cipher.h"

#include "threefish.h"
#include "threefish_mix.h"

#define WORDS_512   AKMOS_THREEFISH_WORDS_512
#define ROUNDS_512  (72 / 8)
#define SKEYS_512   ((ROUNDS_512 * 2) + 1)

void akmos_threefish_512_setkey(akmos_cipher_algo_t *uctx,
                                const uint8_t *key,
                                size_t __attribute__((unused)) len)
{
    akmos_threefish_512_t *ctx;
    uint64_t *k, *S;
    size_t i, j;

    ctx = &uctx->tf_512;

    k = ctx->k;

    for(i = 0; i < WORDS_512; i++, key += 8)
        k[i] = PACK64BE(key);

    k[WORDS_512] = AKMOS_THREEFISH_C240;

    for(i = 0; i < WORDS_512; i++)
         k[WORDS_512] ^= k[i];

    for(i = 0, S = ctx->S; i < SKEYS_512; i++, S += WORDS_512) {
        for(j = 0; j < WORDS_512; j++)
            S[j] = k[(i+j)%(WORDS_512+1)];

        S[WORDS_512-1] += i;
    }
}

void akmos_threefish_512_encrypt(akmos_cipher_algo_t *uctx,
                                 const uint8_t *in_blk,
                                 uint8_t *out_blk)
{
    akmos_threefish_512_t *ctx;
    uint64_t s[WORDS_512], *S;
    int i, j;

    ctx = &uctx->tf_512;

    for(i = 0; i < WORDS_512; i++, in_blk += 8)
        s[i] = PACK64BE(in_blk);

    for(i = 0, S = ctx->S; i < ROUNDS_512; i++, S += WORDS_512) {
        for(j = 0; j < WORDS_512; j++)
            s[j] += S[j];

        threefish_512_emix1(s, 46, 36, 19, 37);
        threefish_512_emix2(s, 33, 27, 14, 42);
        threefish_512_emix3(s, 17, 49, 36, 39);
        threefish_512_emix4(s, 44,  9, 54, 56);

        for(j = 0, S += WORDS_512; j < WORDS_512; j++)
            s[j] += S[j];

        threefish_512_emix1(s, 39, 30, 34, 24);
        threefish_512_emix2(s, 13, 50, 10, 17);
        threefish_512_emix3(s, 25, 29, 39, 43);
        threefish_512_emix4(s,  8, 35, 56, 22);
    }

    for(i = 0; i < WORDS_512; i++, out_blk += 8)
        UNPACK64BE(out_blk, s[i] + S[i]);
}

void akmos_threefish_512_decrypt(akmos_cipher_algo_t *uctx,
                                 const uint8_t *in_blk,
                                 uint8_t *out_blk)
{
    akmos_threefish_512_t *ctx;
    uint64_t s[WORDS_512], *S;
    int i, j;

    ctx = &uctx->tf_512;

    for(i = 0; i < WORDS_512; i++, in_blk += 8)
        s[i] = PACK64BE(in_blk);

    S = ctx->S + (WORDS_512 * (SKEYS_512 - 1));
    for(i = 0; i < WORDS_512; i++)
        s[i] -= S[i];

    for(i = ROUNDS_512; i > 0; i--) {
        threefish_512_dmix1(s, 22, 56, 35,  8);
        threefish_512_dmix2(s, 43, 39, 29, 25);
        threefish_512_dmix3(s, 17, 10, 50, 13);
        threefish_512_dmix4(s, 24, 34, 30, 39);

        for(j = 0, S -= WORDS_512; j < WORDS_512; j++)
            s[j] -= S[j];

        threefish_512_dmix1(s, 56, 54,  9, 44);
        threefish_512_dmix2(s, 39, 36, 49, 17);
        threefish_512_dmix3(s, 42, 14, 27, 33);
        threefish_512_dmix4(s, 37, 19, 36, 46);

        for(j = 0, S -= WORDS_512; j < WORDS_512; j++)
            s[j] -= S[j];
    }

    for(i = 0; i < WORDS_512; i++, out_blk += 8)
        UNPACK64BE(out_blk, s[i]);
}

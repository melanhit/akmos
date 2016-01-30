/*
 *   Copyright (c) 2014-2016, Andrew Romanenko <melanhit@gmail.com>
 *   Copyright (c) 1999 Dr Brian Gladman (gladman@seven77.demon.co.uk)
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
#include "../macro.h"

#include "cast6.h"
#include "cast6_sb32.h"

#define U0(t)  (S0[EXTBYTE(t,3)])
#define U1(t)  (S1[EXTBYTE(t,2)])
#define U2(t)  (S2[EXTBYTE(t,1)])
#define U3(t)  (S3[EXTBYTE(t,0)])

#define f1(y, x, kr, km)                    \
    t  = ROTL32(km + x, kr);                \
    y ^= ((U0(t) ^ U1(t)) - U2(t) + U3(t))

#define f2(y, x, kr, km)                    \
    t  = ROTL32(km ^ x, kr);                \
    y ^= ((U0(t) - U1(t) + U2(t)) ^ U3(t))

#define f3(y, x, kr, km)                    \
    t  = ROTL32(km - x, kr);                \
    y ^= (((U0(t) + U1(t)) ^ U2(t)) - U3(t))\

#define f_rnd(a, b, c, d, n)                \
    f1(c, d, l_key[n],     l_key[n + 4]);   \
    f2(b, c, l_key[n + 1], l_key[n + 5]);   \
    f3(a, b, l_key[n + 2], l_key[n + 6]);   \
    f1(d, a, l_key[n + 3], l_key[n + 7])

#define i_rnd(a, b, c, d, n)                \
    f1(d, a, l_key[n + 3], l_key[n + 7]);   \
    f3(a, b, l_key[n + 2], l_key[n + 6]);   \
    f2(b, c, l_key[n + 1], l_key[n + 5]);   \
    f1(c, d, l_key[n],     l_key[n + 4])

#define k_rnd(k, tr, tm)                    \
    f1(k[6], k[7], tr[0], tm[0]);           \
    f2(k[5], k[6], tr[1], tm[1]);           \
    f3(k[4], k[5], tr[2], tm[2]);           \
    f1(k[3], k[4], tr[3], tm[3]);           \
    f2(k[2], k[3], tr[4], tm[4]);           \
    f3(k[1], k[2], tr[5], tm[5]);           \
    f1(k[0], k[1], tr[6], tm[6]);           \
    f2(k[7], k[0], tr[7], tm[7])

void akmos_cast6_setkey(akmos_cast6_t *ctx, const uint8_t *key, size_t len)
{
    uint32_t *l_key, i, j, t, cm, cr, lk[8], tm[8], tr[8];

    l_key = ctx->l_key;

    for(i = 0; i < (len / 4); key += 4, i++)
        lk[i] = PACK32LE(key);

    for(; i < 8; ++i)
        lk[i] = 0;

    cm = 0x5a827999; cr = 19;

    for(i = 0; i < 96; i += 8) {
        for(j = 0; j < 8; ++j) {
            tm[j] = cm; cm += 0x6ed9eba1;
            tr[j] = cr; cr += 17;
        }

        k_rnd(lk, tr, tm);

        for(j = 0; j < 8; ++j) {
            tm[j] = cm; cm += 0x6ed9eba1;
            tr[j] = cr; cr += 17;
        }

        k_rnd(lk, tr, tm);

        l_key[i + 0] = lk[0]; l_key[i + 1] = lk[2];
        l_key[i + 2] = lk[4]; l_key[i + 3] = lk[6];
        l_key[i + 4] = lk[7]; l_key[i + 5] = lk[5];
        l_key[i + 6] = lk[3]; l_key[i + 7] = lk[1];
    }
}

void akmos_cast6_encrypt(akmos_cast6_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint32_t *l_key, t;
    uint32_t a, b, c, d;

    l_key = ctx->l_key;

    a = PACK32LE(in_blk    ); b = PACK32LE(in_blk +  4);
    c = PACK32LE(in_blk + 8); d = PACK32LE(in_blk + 12);

    f_rnd(a, b, c, d,  0); f_rnd(a, b, c, d,  8);
    f_rnd(a, b, c, d, 16); f_rnd(a, b, c, d, 24);
    f_rnd(a, b, c, d, 32); f_rnd(a, b, c, d, 40);
    i_rnd(a, b, c, d, 48); i_rnd(a, b, c, d, 56);
    i_rnd(a, b, c, d, 64); i_rnd(a, b, c, d, 72);
    i_rnd(a, b, c, d, 80); i_rnd(a, b, c, d, 88);

    UNPACK32LE(out_blk,     a); UNPACK32LE(out_blk +  4, b);
    UNPACK32LE(out_blk + 8, c); UNPACK32LE(out_blk + 12, d);
}

void akmos_cast6_decrypt(akmos_cast6_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint32_t *l_key, t;
    uint32_t a, b, c, d;

    l_key = ctx->l_key;

    a = PACK32LE(in_blk    ); b = PACK32LE(in_blk +  4);
    c = PACK32LE(in_blk + 8); d = PACK32LE(in_blk + 12);

    f_rnd(a, b, c, d, 88); f_rnd(a, b, c, d, 80);
    f_rnd(a, b, c, d, 72); f_rnd(a, b, c, d, 64);
    f_rnd(a, b, c, d, 56); f_rnd(a, b, c, d, 48);
    i_rnd(a, b, c, d, 40); i_rnd(a, b, c, d, 32);
    i_rnd(a, b, c, d, 24); i_rnd(a, b, c, d, 16);
    i_rnd(a, b, c, d,  8); i_rnd(a, b, c, d,  0);

    UNPACK32LE(out_blk,     a); UNPACK32LE(out_blk +  4, b);
    UNPACK32LE(out_blk + 8, c); UNPACK32LE(out_blk + 12, d);
}

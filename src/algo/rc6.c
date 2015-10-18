/*
 *   Copyright (c) 2014, Andrew Romanenko <melanhit@gmail.com>
 *   Copyright (c) 1999, Dr Brian Gladman (gladman@seven77.demon.co.uk)
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

#include "rc6.h"

#define f_rnd(i,a,b,c,d)                    \
        u = ROTL32(d * (d + d + 1), 5);     \
        t = ROTL32(b * (b + b + 1), 5);     \
        a = ROTL32(a ^ t, u) + l_key[i];    \
        c = ROTL32(c ^ u, t) + l_key[i + 1]

#define i_rnd(i,a,b,c,d)                    \
        u = ROTL32(d * (d + d + 1), 5);     \
        t = ROTL32(b * (b + b + 1), 5);     \
        c = ROTR32(c - l_key[i + 1], t) ^ u;\
        a = ROTR32(a - l_key[i], u) ^ t

void akmos_rc6_setkey(akmos_rc6_t *ctx, const uint8_t *key, size_t len)
{
    uint32_t i, j, k, a, b, l[8], t;
    uint32_t in_key[8], *l_key;

    l_key = ctx->l_key;

    for(i = 0; i < (len / 4); i++)
        in_key[i] = PACK32BE(key + (i * 4));

    l_key[0] = 0xb7e15163;

    for(k = 1; k < 44; ++k)
        l_key[k] = l_key[k - 1] + 0x9e3779b9;

    for(k = 0; k < len / 4; ++k)
        l[k] = in_key[k];

    t = (len / 4) - 1;

    a = b = i = j = 0;

    for(k = 0; k < 132; ++k) {
        a = ROTL32(l_key[i] + a + b, 3); b += a;
        b = ROTL32(l[j] + b, b);
        l_key[i] = a; l[j] = b;
        i = (i == 43 ? 0 : i + 1);
        j = (j == t ? 0 : j + 1);
    }
}

void akmos_rc6_encrypt(akmos_rc6_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint32_t a, b, c, d, t, u;
    uint32_t *l_key;

    l_key = ctx->l_key;

    a = PACK32BE(in_blk     );
    b = PACK32BE(in_blk +  4) + l_key[0];
    c = PACK32BE(in_blk +  8);
    d = PACK32BE(in_blk + 12) + l_key[1];

    f_rnd( 2,a,b,c,d); f_rnd( 4,b,c,d,a);
    f_rnd( 6,c,d,a,b); f_rnd( 8,d,a,b,c);
    f_rnd(10,a,b,c,d); f_rnd(12,b,c,d,a);
    f_rnd(14,c,d,a,b); f_rnd(16,d,a,b,c);
    f_rnd(18,a,b,c,d); f_rnd(20,b,c,d,a);
    f_rnd(22,c,d,a,b); f_rnd(24,d,a,b,c);
    f_rnd(26,a,b,c,d); f_rnd(28,b,c,d,a);
    f_rnd(30,c,d,a,b); f_rnd(32,d,a,b,c);
    f_rnd(34,a,b,c,d); f_rnd(36,b,c,d,a);
    f_rnd(38,c,d,a,b); f_rnd(40,d,a,b,c);

    UNPACK32BE(out_blk,      (a + l_key[42]));
    UNPACK32BE(out_blk +  4, b);
    UNPACK32BE(out_blk +  8, (c + l_key[43]));
    UNPACK32BE(out_blk + 12, d);
}

void akmos_rc6_decrypt(akmos_rc6_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint32_t a, b, c, d, t, u;
    uint32_t *l_key;

    l_key = ctx->l_key;

    a = PACK32BE(in_blk     ) - l_key[42];
    b = PACK32BE(in_blk +  4);
    c = PACK32BE(in_blk +  8) - l_key[43];
    d = PACK32BE(in_blk + 12);

    i_rnd(40,d,a,b,c); i_rnd(38,c,d,a,b);
    i_rnd(36,b,c,d,a); i_rnd(34,a,b,c,d);
    i_rnd(32,d,a,b,c); i_rnd(30,c,d,a,b);
    i_rnd(28,b,c,d,a); i_rnd(26,a,b,c,d);
    i_rnd(24,d,a,b,c); i_rnd(22,c,d,a,b);
    i_rnd(20,b,c,d,a); i_rnd(18,a,b,c,d);
    i_rnd(16,d,a,b,c); i_rnd(14,c,d,a,b);
    i_rnd(12,b,c,d,a); i_rnd(10,a,b,c,d);
    i_rnd( 8,d,a,b,c); i_rnd( 6,c,d,a,b);
    i_rnd( 4,b,c,d,a); i_rnd( 2,a,b,c,d);

    UNPACK32BE(out_blk,      a);
    UNPACK32BE(out_blk +  4, (b - l_key[0]));
    UNPACK32BE(out_blk +  8, c);
    UNPACK32BE(out_blk + 12, (d - l_key[1]));
}

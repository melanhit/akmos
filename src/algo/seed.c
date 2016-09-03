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

#include "seed.h"

#define PROTR8(a, b)            \
{                               \
    t = a;                      \
    a = (a >> 8) ^ (b << 24);   \
    b = (b >> 8) ^ (t << 24);   \
}

#define PROTL8(a, b)            \
{                               \
    t = a;                      \
    a = (a << 8) ^ (b >> 24);   \
    b = (b << 8) ^ (t >> 24);   \
}

#define U0(x)   ((uint8_t)((x)      ))
#define U1(x)   ((uint8_t)((x) >>  8))
#define U2(x)   ((uint8_t)((x) >> 16))
#define U3(x)   ((uint8_t)((x) >> 24))

#define S0(x)   (akmos_seed_sbox[0][x])
#define S1(x)   (akmos_seed_sbox[1][x])
#define S2(x)   (akmos_seed_sbox[2][x])
#define S3(x)   (akmos_seed_sbox[3][x])

#define KC(x)   (akmos_seed_kc[x])

#define G(x)    (S0(U0(x)) ^ S1(U1(x)) ^ S2(U2(x)) ^ S3(U3(x)))

#define F(x, k0, k1, t, c, d)   \
{                               \
    c  = (uint32_t)(x >> 32);   \
    d  = (uint32_t)(x);         \
    c ^= k0;                    \
    d ^= k1 ^ c;                \
    d  = G(d);                  \
    c += d;                     \
    c  = G(c);                  \
    d += c;                     \
    d  = G(d);                  \
    c += d;                     \
    t  = (uint64_t)(c) << 32;   \
    t ^= (uint64_t)(d);         \
}

void akmos_seed_setkey(akmos_seed_t *ctx, const uint8_t *in_key, size_t len)
{
    uint32_t k0, k1, k2, k3, t;
    size_t i, y;

    k0 = PACK32LE(in_key    ); k1 = PACK32LE(in_key +  4);
    k2 = PACK32LE(in_key + 8); k3 = PACK32LE(in_key + 12);

    for(i = 0, y = 0; i < len; i++, y += 2) {
        ctx->key[y] = k0 + k2 - KC(i);
        ctx->key[y] = G(ctx->key[y]);

        ctx->key[y + 1] = k1 - k3 + KC(i);
        ctx->key[y + 1] = G(ctx->key[y + 1]);

        if((i % 2) == 0) {
            PROTR8(k0, k1);
        } else {
            PROTL8(k2, k3);
        }
    }
}

void akmos_seed_encrypt(akmos_seed_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint64_t l, r, t;
    uint32_t c, d;
    size_t i, y;

    l = PACK64LE(in_blk); r = PACK64LE(in_blk + 8);

    for(i = 0, y = 0; i < 15; i++, y += 2) {
        F(r, ctx->key[y], ctx->key[y + 1], t, c, d);
        l ^= t;
        t = l; l = r; r = t;
    }

    F(r, ctx->key[30], ctx->key[31], t, c, d);
    l ^= t;

    UNPACK64LE(out_blk, l); UNPACK64LE(out_blk + 8, r);
}

void akmos_seed_decrypt(akmos_seed_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint64_t l, r, t;
    uint32_t c, d;
    size_t i, y;

    l = PACK64LE(in_blk); r = PACK64LE(in_blk + 8);


    for(i = 0, y = 30; i < 15; i++, y -= 2) {
        F(r, ctx->key[y], ctx->key[y + 1], t, c, d);
        l ^= t;
        t = l; l = r; r = t;
    }
    F(r, ctx->key[0], ctx->key[1], t, c, d);
    l ^= t;


    UNPACK64LE(out_blk, l); UNPACK64LE(out_blk + 8, r);
}

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

#include "rijndael.h"

#define RIJNDAEL_R128   10
#define RIJNDAEL_R192   12
#define RIJNDAEL_R256   14

#define RIJNDAEL_K128   4
#define RIJNDAEL_K192   6
#define RIJNDAEL_K256   8

#define S(x)    (akmos_rijndael_s[x])

#define S0(x)   (akmos_rijndael_sbox[0][x])
#define S1(x)   (akmos_rijndael_sbox[1][x])
#define S2(x)   (akmos_rijndael_sbox[2][x])
#define S3(x)   (akmos_rijndael_sbox[3][x])
#define S4(x)   (akmos_rijndael_sbox[4][x])

#define SI0(x)  (akmos_rijndael_si[0][x])
#define SI1(x)  (akmos_rijndael_si[1][x])
#define SI2(x)  (akmos_rijndael_si[2][x])
#define SI3(x)  (akmos_rijndael_si[3][x])
#define SI4(x)  (akmos_rijndael_si[4][x])

#define KeySubByte(x)                                   \
(                                                       \
    (((S((((x) >> 16) & 0xff))) << 24) & 0xff000000) |  \
    (((S((((x) >>  8) & 0xff))) << 16) & 0x00ff0000) |  \
    (((S((((x)      ) & 0xff))) <<  8) & 0x0000ff00) |  \
    (((S((((x) >> 24) & 0xff)))      ) & 0x000000ff)    \
)

#define AddRoundKey(k, w, s)                \
{                                           \
    s[0] = w[0] ^ k[0]; s[1] = w[1] ^ k[1]; \
    s[2] = w[2] ^ k[2]; s[3] = w[3] ^ k[3]; \
}

static const uint32_t R[11] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
    0x36000000
};

static void rijndael_setkey128(uint32_t *k)
{
    uint32_t i, t;

    for(i = RIJNDAEL_K128; i < 4 * (RIJNDAEL_R128 + 1); i++) {
        t = k[i - 1];
        if((i % RIJNDAEL_K128) == 0)
            t = KeySubByte(t) ^ R[i / RIJNDAEL_K128];
        k[i] = k[i - RIJNDAEL_K128] ^ t;
    }
}

static void rijndael_setkey192(uint32_t *k)
{
    uint32_t i, t;

    for(i = RIJNDAEL_K192; i < 4 * (RIJNDAEL_R192 + 1); i++) {
        t = k[i - 1];
        if((i % RIJNDAEL_K192) == 0)
            t = KeySubByte(t) ^ R[i / RIJNDAEL_K192];
        k[i] = k[i - RIJNDAEL_K192] ^ t;
    }
}

static void rijndael_setkey256(uint32_t *k)
{
    uint32_t i, t;

    for(i = RIJNDAEL_K256; i < 4 * (RIJNDAEL_R256 + 1); i++) {
        t = k[i - 1];
        if((i % RIJNDAEL_K256) == 0)
            t = KeySubByte(t) ^ R[i / RIJNDAEL_K256];
        else if((i % RIJNDAEL_K256) == 4)
            t = KeySubByte(ROTR32(t, 8));

        k[i] = k[i - RIJNDAEL_K256] ^ t;
    }
}

void akmos_rijndael_setkey(akmos_cipher_algo_t *uctx, const uint8_t *key, size_t len)
{
    akmos_rijndael_t *ctx;
    uint32_t *k;
    size_t i, j;

    ctx = &uctx->rijndael;

    for(i = 0; i < len / 4; i++)
        ctx->ke[i] = PACK32LE(key + (i * 4));

    switch(len) {
        case 16:
            rijndael_setkey128(ctx->ke);
            ctx->r = RIJNDAEL_R128;
            break;

        case 24:
            rijndael_setkey192(ctx->ke);
            ctx->r = RIJNDAEL_R192;
            break;

        case 32:
            rijndael_setkey256(ctx->ke);
            ctx->r = RIJNDAEL_R256;
            break;

        default:
            return;
    }

    for(i = 0, j = ctx->r*4; i <= ctx->r*4; i += 4, j -= 4) {
        ctx->kd[i    ] = ctx->ke[j    ];
        ctx->kd[i + 1] = ctx->ke[j + 1];
        ctx->kd[i + 2] = ctx->ke[j + 2];
        ctx->kd[i + 3] = ctx->ke[j + 3];
    }

    k = ctx->kd + 4;
    for(i = 1; i < ctx->r; i++, k += 4) {
        k[0] =  SI0(S4((k[0] >> 24)       ) & 0xff) ^
                SI1(S4((k[0] >> 16) & 0xff) & 0xff) ^
                SI2(S4((k[0] >>  8) & 0xff) & 0xff) ^
                SI3(S4((k[0]      ) & 0xff) & 0xff);
        k[1] =  SI0(S4((k[1] >> 24)       ) & 0xff) ^
                SI1(S4((k[1] >> 16) & 0xff) & 0xff) ^
                SI2(S4((k[1] >>  8) & 0xff) & 0xff) ^
                SI3(S4((k[1]      ) & 0xff) & 0xff);
        k[2] =  SI0(S4((k[2] >> 24)       ) & 0xff) ^
                SI1(S4((k[2] >> 16) & 0xff) & 0xff) ^
                SI2(S4((k[2] >>  8) & 0xff) & 0xff) ^
                SI3(S4((k[2]      ) & 0xff) & 0xff);
        k[3] =  SI0(S4((k[3] >> 24)       ) & 0xff) ^
                SI1(S4((k[3] >> 16) & 0xff) & 0xff) ^
                SI2(S4((k[3] >>  8) & 0xff) & 0xff) ^
                SI3(S4((k[3]      ) & 0xff) & 0xff);
    }

}

void akmos_rijndael_encrypt(akmos_cipher_algo_t *uctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    akmos_rijndael_t *ctx;
    uint32_t s[4], *w, *k, i;

    ctx = &uctx->rijndael;

    w = ctx->w;
    k = ctx->ke;

    w[0] = PACK32LE(in_blk    ); w[1] = PACK32LE(in_blk +  4);
    w[2] = PACK32LE(in_blk + 8); w[3] = PACK32LE(in_blk + 12);

    AddRoundKey(k, w, s);
    k += 4;

    for(i = 1; i < ctx->r; i++, k += 4) {
        w[0] = S0(s[0] >> 24) ^ S1((s[1] >> 16) & 0xff) ^ S2((s[2] >> 8) & 0xff) ^ S3(s[3] & 0xff);
        w[1] = S0(s[1] >> 24) ^ S1((s[2] >> 16) & 0xff) ^ S2((s[3] >> 8) & 0xff) ^ S3(s[0] & 0xff);
        w[2] = S0(s[2] >> 24) ^ S1((s[3] >> 16) & 0xff) ^ S2((s[0] >> 8) & 0xff) ^ S3(s[1] & 0xff);
        w[3] = S0(s[3] >> 24) ^ S1((s[0] >> 16) & 0xff) ^ S2((s[1] >> 8) & 0xff) ^ S3(s[2] & 0xff);
        AddRoundKey(k, w, s);
    }

    w[0] = (S4((s[0] >> 24)       ) & 0xff000000) ^
           (S4((s[1] >> 16) & 0xff) & 0x00ff0000) ^
           (S4((s[2] >>  8) & 0xff) & 0x0000ff00) ^
           (S4((s[3]      ) & 0xff) & 0x000000ff);
    w[1] = (S4((s[1] >> 24)       ) & 0xff000000) ^
           (S4((s[2] >> 16) & 0xff) & 0x00ff0000) ^
           (S4((s[3] >>  8) & 0xff) & 0x0000ff00) ^
           (S4((s[0]      ) & 0xff) & 0x000000ff);
    w[2] = (S4((s[2] >> 24)       ) & 0xff000000) ^
           (S4((s[3] >> 16) & 0xff) & 0x00ff0000) ^
           (S4((s[0] >>  8) & 0xff) & 0x0000ff00) ^
           (S4((s[1]      ) & 0xff) & 0x000000ff);
    w[3] = (S4((s[3] >> 24)       ) & 0xff000000) ^
           (S4((s[0] >> 16) & 0xff) & 0x00ff0000) ^
           (S4((s[1] >>  8) & 0xff) & 0x0000ff00) ^
           (S4((s[2]      ) & 0xff) & 0x000000ff);

    AddRoundKey(k, w, s);

    UNPACK32LE(out_blk    , s[0]); UNPACK32LE(out_blk +  4, s[1]);
    UNPACK32LE(out_blk + 8, s[2]); UNPACK32LE(out_blk + 12, s[3]);
}

void akmos_rijndael_decrypt(akmos_cipher_algo_t *uctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    akmos_rijndael_t *ctx;
    uint32_t s[4], *w, *k, i;

    ctx = &uctx->rijndael;

    w = ctx->w;
    k = ctx->kd;

    w[0] = PACK32LE(in_blk    ); w[1] = PACK32LE(in_blk +  4);
    w[2] = PACK32LE(in_blk + 8); w[3] = PACK32LE(in_blk + 12);

    AddRoundKey(k, w, s);
    k += 4;

    for(i = 1; i < ctx->r; i++, k += 4) {
        w[0] = SI0(s[0] >> 24) ^ SI1((s[3] >> 16) & 0xff) ^ SI2((s[2] >> 8) & 0xff) ^ SI3(s[1] & 0xff);
        w[1] = SI0(s[1] >> 24) ^ SI1((s[0] >> 16) & 0xff) ^ SI2((s[3] >> 8) & 0xff) ^ SI3(s[2] & 0xff);
        w[2] = SI0(s[2] >> 24) ^ SI1((s[1] >> 16) & 0xff) ^ SI2((s[0] >> 8) & 0xff) ^ SI3(s[3] & 0xff);
        w[3] = SI0(s[3] >> 24) ^ SI1((s[2] >> 16) & 0xff) ^ SI2((s[1] >> 8) & 0xff) ^ SI3(s[0] & 0xff);

        AddRoundKey(k, w, s);
    }

    w[0] = (SI4((s[0] >> 24)       ) & 0xff000000) ^
           (SI4((s[3] >> 16) & 0xff) & 0x00ff0000) ^
           (SI4((s[2] >>  8) & 0xff) & 0x0000ff00) ^
           (SI4((s[1]      ) & 0xff) & 0x000000ff);
    w[1] = (SI4((s[1] >> 24)       ) & 0xff000000) ^
           (SI4((s[0] >> 16) & 0xff) & 0x00ff0000) ^
           (SI4((s[3] >>  8) & 0xff) & 0x0000ff00) ^
           (SI4((s[2]      ) & 0xff) & 0x000000ff);
    w[2] = (SI4((s[2] >> 24)       ) & 0xff000000) ^
           (SI4((s[1] >> 16) & 0xff) & 0x00ff0000) ^
           (SI4((s[0] >>  8) & 0xff) & 0x0000ff00) ^
           (SI4((s[3]      ) & 0xff) & 0x000000ff);
    w[3] = (SI4((s[3] >> 24)       ) & 0xff000000) ^
           (SI4((s[2] >> 16) & 0xff) & 0x00ff0000) ^
           (SI4((s[1] >>  8) & 0xff) & 0x0000ff00) ^
           (SI4((s[0]      ) & 0xff) & 0x000000ff);

    AddRoundKey(k, w, s);

    UNPACK32LE(out_blk    , s[0]); UNPACK32LE(out_blk +  4, s[1]);
    UNPACK32LE(out_blk + 8, s[2]); UNPACK32LE(out_blk + 12, s[3]);
}

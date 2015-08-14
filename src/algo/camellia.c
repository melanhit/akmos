/*
 *   Copyright (c) 2015, Andrew Romanenko <melanhit@gmail.com>
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

#include "camellia.h"
#include "camellia_sb64.h"

#define C0  0xa09e667f3bcc908b
#define C1  0xb67ae8584caa73b2
#define C2  0xc6ef372fe94f82be
#define C3  0x54ff53a5f1d36f1c
#define C4  0x10e527fade682d1d
#define C5  0xb05688c2b3e6c1fd

/* rotate 128bit via 2x64bit */
/*  1..n..63 */
#define Q1ROTL(x1, x2, n) (((x1) << (n)) | ((x2) >> (64 - (n))))
/* 65..n..127 */
#define Q2ROTL(x1, x2, n) (((x2) << ((n) - 64)) | ((x1) >> (128 - (n))))

#define U0(x)   ((uint8_t)((x) >> 56))
#define U1(x)   ((uint8_t)((x) >> 48))
#define U2(x)   ((uint8_t)((x) >> 40))
#define U3(x)   ((uint8_t)((x) >> 32))
#define U4(x)   ((uint8_t)((x) >> 24))
#define U5(x)   ((uint8_t)((x) >> 16))
#define U6(x)   ((uint8_t)((x) >>  8))
#define U7(x)   ((uint8_t)((x)      ))

#define F(x) (SB0[U0(x)] ^ SB1[U1(x)] ^ SB2[U2(x)] ^ SB3[U3(x)] ^ SB4[U4(x)] ^ SB5[U5(x)] ^ SB6[U6(x)] ^ SB7[U7(x)])

#define KEY_KA_SCHED(d1, d2, k, ka) \
{                                   \
    t   = d1 ^ C0;                  \
    d2 ^= F(t);                     \
    t   = d2 ^ C1;                  \
    d1 ^= F(t);                     \
    d1 ^= k[0];                     \
    d2 ^= k[1];                     \
    t   = d1 ^ C2;                  \
    d2 ^= F(t);                     \
    t   = d2 ^ C3;                  \
    d1 ^= F(t);                     \
    ka[0] = d1; ka[1] = d2;         \
}

static uint64_t fl(uint64_t in, uint64_t k)
{
    uint32_t k1, k2, x1, x2;

    x1 = in >> 32;
    x2 = in & 0xffffffff;

    k1 = k >> 32;
    k2 = k & 0xffffffff;

    x2 ^= ROTL((x1 & k1), 1);
    x1 ^= (x2 | k2);

    return (((uint64_t)x1 << 32) | x2);
}

static uint64_t flinv(uint64_t in, uint64_t k)
{
    uint32_t k1, k2, x1, x2;

    x1 = in >> 32;
    x2 = in & 0xffffffff;

    k1 = k >> 32;
    k2 = k & 0xffffffff;

    x1 ^= (x2 | k2);
    x2 ^= ROTL((x1 & k1), 1);

    return (((uint64_t)x1 << 32) | x2);
}

static void camellia_setkey128(akmos_camellia_t *ctx, const uint8_t *key)
{
    uint64_t d1, d2, t;
    uint64_t ka[2], k[2];

    k[0] = PACK64(key); k[1] = PACK64(key + 8);

    d1 = k[0]; d2 = k[1];
    KEY_KA_SCHED(d1, d2, k, ka);

    ctx->kw[0] = k[0];
    ctx->kw[1] = k[1];
    ctx->kw[2] = Q2ROTL(ka[0], ka[1], 111);
    ctx->kw[3] = Q2ROTL(ka[1], ka[0], 111);

    ctx->ke[0] = Q1ROTL(ka[0], ka[1],  30);
    ctx->ke[1] = Q1ROTL(ka[1], ka[0],  30);
    ctx->ke[2] = Q2ROTL(k [0], k [1],  77);
    ctx->ke[3] = Q2ROTL(k [1], k [0],  77);
    ctx->ke[4] = ctx->k[0];
    ctx->ke[5] = ctx->k[1];

    ctx->k[ 0] = ka[0];
    ctx->k[ 1] = ka[1];
    ctx->k[ 2] = Q1ROTL(k [0], k [1],  15);
    ctx->k[ 3] = Q1ROTL(k [1], k [0],  15);
    ctx->k[ 4] = Q1ROTL(ka[0], ka[1],  15);
    ctx->k[ 5] = Q1ROTL(ka[1], ka[0],  15);
    ctx->k[ 6] = Q1ROTL(k [0], k [1],  45);
    ctx->k[ 7] = Q1ROTL(k [1], k [0],  45);
    ctx->k[ 8] = Q1ROTL(ka[0], ka[1],  45);
    ctx->k[ 9] = Q1ROTL(k [1], k [0],  60);
    ctx->k[10] = Q1ROTL(ka[0], ka[1],  60);
    ctx->k[11] = Q1ROTL(ka[1], ka[0],  60);
    ctx->k[12] = Q2ROTL(k [0], k [1],  94);
    ctx->k[13] = Q2ROTL(k [1], k [0],  94);
    ctx->k[14] = Q2ROTL(ka[0], ka[1],  94);
    ctx->k[15] = Q2ROTL(ka[1], ka[0],  94);
    ctx->k[16] = Q2ROTL(k [0], k [1], 111);
    ctx->k[17] = Q2ROTL(k [1], k [0], 111);
}

static void camellia_setkey256(akmos_camellia_t *ctx, const uint8_t *key, size_t len)
{
    uint64_t d1, d2, t;
    uint64_t ka[2], kb[2], k[4];

    k[0] = PACK64(key     );
    k[1] = PACK64(key +  8);
    k[2] = PACK64(key + 16);
    if(len == 32)
        k[3] = PACK64(key + 24);
    else
        k[3] = ~k[2];

    d1 = k[0] ^ k[2]; d2 = k[1] ^ k[3];
    KEY_KA_SCHED(d1, d2, k, ka);

    d1 ^= k[2]; d2 ^= k[3];
    t   = d1 ^ C4;
    d2 ^= F(t);
    t   = d2 ^ C5;
    d1 ^= F(t);
    kb[0] = d1; kb[1] = d2;

    ctx->kw[0] = k[0];
    ctx->kw[1] = k[1];
    ctx->kw[2] = Q2ROTL(kb[0], kb[1], 111);
    ctx->kw[3] = Q2ROTL(kb[1], kb[0], 111);

    ctx->ke[0] = Q1ROTL(k [2], k [3],  30);
    ctx->ke[1] = Q1ROTL(k [3], k [2],  30);
    ctx->ke[2] = Q1ROTL(k [0], k [1],  60);
    ctx->ke[3] = Q1ROTL(k [1], k [0],  60);
    ctx->ke[4] = Q2ROTL(ka[0], ka[1],  77);
    ctx->ke[5] = Q2ROTL(ka[1], ka[0],  77);

    ctx->k[ 0] = kb[0];
    ctx->k[ 1] = kb[1];
    ctx->k[ 2] = Q1ROTL(k [2], k [3],  15);
    ctx->k[ 3] = Q1ROTL(k [3], k [2],  15);
    ctx->k[ 4] = Q1ROTL(ka[0], ka[1],  15);
    ctx->k[ 5] = Q1ROTL(ka[1], ka[0],  15);
    ctx->k[ 6] = Q1ROTL(kb[0], kb[1],  30);
    ctx->k[ 7] = Q1ROTL(kb[1], kb[0],  30);
    ctx->k[ 8] = Q1ROTL(k [0], k [1],  45);
    ctx->k[ 9] = Q1ROTL(k [1], k [0],  45);
    ctx->k[10] = Q1ROTL(ka[0], ka[1],  45);
    ctx->k[11] = Q1ROTL(ka[1], ka[0],  45);
    ctx->k[12] = Q1ROTL(k [2], k [3],  60);
    ctx->k[13] = Q1ROTL(k [3], k [2],  60);
    ctx->k[14] = Q1ROTL(kb[0], kb[1],  60);
    ctx->k[15] = Q1ROTL(kb[1], kb[0],  60);
    ctx->k[16] = Q2ROTL(k [0], k [1],  77);
    ctx->k[17] = Q2ROTL(k [1], k [0],  77);
    ctx->k[18] = Q2ROTL(k [2], k [3],  94);
    ctx->k[19] = Q2ROTL(k [3], k [2],  94);
    ctx->k[20] = Q2ROTL(ka[0], ka[1],  94);
    ctx->k[21] = Q2ROTL(ka[1], ka[0],  94);
    ctx->k[22] = Q2ROTL(k [0], k [1], 111);
    ctx->k[23] = Q2ROTL(k [1], k [0], 111);
}

void akmos_camellia_setkey(akmos_camellia_t *ctx, const uint8_t *key, size_t len)
{
    ctx->bits = len * 8;
    switch(len) {
        case 16:
            camellia_setkey128(ctx, key);
            break;

        case 24:
        case 32:
            camellia_setkey256(ctx, key, len);
            break;

        default:
            break;
    }
}

void akmos_camellia_encrypt(akmos_camellia_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint64_t pt[2], ct[2], t;

    pt[0] = PACK64(in_blk); pt[1] = PACK64(in_blk + 8);

    ct[0] = pt[0] ^ ctx->kw[0];
    ct[1] = pt[1] ^ ctx->kw[1];

    t = ct[0] ^ ctx->k[ 0]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[ 1]; ct[0] ^= F(t);
    t = ct[0] ^ ctx->k[ 2]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[ 3]; ct[0] ^= F(t);
    t = ct[0] ^ ctx->k[ 4]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[ 5]; ct[0] ^= F(t);

    ct[0] = fl(ct[0], ctx->ke[0]);
    ct[1] = flinv(ct[1], ctx->ke[1]);
    
    t = ct[0] ^ ctx->k[ 6]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[ 7]; ct[0] ^= F(t);
    t = ct[0] ^ ctx->k[ 8]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[ 9]; ct[0] ^= F(t);
    t = ct[0] ^ ctx->k[10]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[11]; ct[0] ^= F(t);

    ct[0] = fl(ct[0], ctx->ke[2]);
    ct[1] = flinv(ct[1], ctx->ke[3]);
    
    t = ct[0] ^ ctx->k[12]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[13]; ct[0] ^= F(t);
    t = ct[0] ^ ctx->k[14]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[15]; ct[0] ^= F(t);
    t = ct[0] ^ ctx->k[16]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[17]; ct[0] ^= F(t);

    if(ctx->bits == 128)
        goto out;

    ct[0] = fl(ct[0], ctx->ke[4]);
    ct[1] = flinv(ct[1], ctx->ke[5]);
    
    t = ct[0] ^ ctx->k[18]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[19]; ct[0] ^= F(t);
    t = ct[0] ^ ctx->k[20]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[21]; ct[0] ^= F(t);
    t = ct[0] ^ ctx->k[22]; ct[1] ^= F(t);
    t = ct[1] ^ ctx->k[23]; ct[0] ^= F(t);

out:
    ct[1] ^= ctx->kw[2];
    ct[0] ^= ctx->kw[3];

    UNPACK64(out_blk, ct[1]); UNPACK64(out_blk + 8, ct[0]);
}

void akmos_camellia_decrypt(akmos_camellia_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint64_t pt[2], ct[2], t;

    ct[0] = PACK64(in_blk); ct[1] = PACK64(in_blk + 8);

    pt[0] = ct[0] ^ ctx->kw[2];
    pt[1] = ct[1] ^ ctx->kw[3];

    if(ctx->bits != 128) {
        t = pt[0] ^ ctx->k[23]; pt[1] ^= F(t);
        t = pt[1] ^ ctx->k[22]; pt[0] ^= F(t);
        t = pt[0] ^ ctx->k[21]; pt[1] ^= F(t);
        t = pt[1] ^ ctx->k[20]; pt[0] ^= F(t);
        t = pt[0] ^ ctx->k[19]; pt[1] ^= F(t);
        t = pt[1] ^ ctx->k[18]; pt[0] ^= F(t);

        pt[0] = fl(pt[0], ctx->ke[5]);
        pt[1] = flinv(pt[1], ctx->ke[4]);
    }
        
    t = pt[0] ^ ctx->k[17]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[16]; pt[0] ^= F(t);
    t = pt[0] ^ ctx->k[15]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[14]; pt[0] ^= F(t);
    t = pt[0] ^ ctx->k[13]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[12]; pt[0] ^= F(t);

    pt[0] = fl(pt[0], ctx->ke[3]);
    pt[1] = flinv(pt[1], ctx->ke[2]);
    
    t = pt[0] ^ ctx->k[11]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[10]; pt[0] ^= F(t);
    t = pt[0] ^ ctx->k[ 9]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[ 8]; pt[0] ^= F(t);
    t = pt[0] ^ ctx->k[ 7]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[ 6]; pt[0] ^= F(t);

    pt[0] = fl(pt[0], ctx->ke[1]);
    pt[1] = flinv(pt[1], ctx->ke[0]);
    
    t = pt[0] ^ ctx->k[ 5]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[ 4]; pt[0] ^= F(t);
    t = pt[0] ^ ctx->k[ 3]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[ 2]; pt[0] ^= F(t);
    t = pt[0] ^ ctx->k[ 1]; pt[1] ^= F(t);
    t = pt[1] ^ ctx->k[ 0]; pt[0] ^= F(t);

    pt[1] ^= ctx->kw[0];
    pt[0] ^= ctx->kw[1];

    UNPACK64(out_blk, pt[1]); UNPACK64(out_blk + 8, pt[0]);
}

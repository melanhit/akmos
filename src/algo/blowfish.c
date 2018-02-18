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
#include <unistd.h>

#include "../akmos.h"
#include "../bits.h"
#include "../cipher.h"

#include "blowfish.h"

#define U0(x)       ((uint8_t)((x) >> 24))
#define U1(x)       ((uint8_t)((x) >> 16))
#define U2(x)       ((uint8_t)((x) >>  8))
#define U3(x)       ((uint8_t)((x)      ))

#define S0(x)       (ctx->s0[x])
#define S1(x)       (ctx->s1[x])
#define S2(x)       (ctx->s2[x])
#define S3(x)       (ctx->s3[x])

#define F(x)        (((S0(U0(x)) + S1(U1(x))) ^ S2(U2(x))) + S3(U3(x)))

void akmos_blowfish_setkey(akmos_cipher_algo_t *uctx, const uint8_t *in_key, size_t len)
{
    akmos_blowfish_t *ctx;
    const uint8_t *key;
    uint8_t *buf;
    size_t i, j;

    ctx = &uctx->blowfish;

    buf = ctx->b;

    j = len / 4;
    for(i = 0, key = in_key; i < 18; i++, key += 4) {
        if((i % j) == 0) {
            key = in_key;
        }
        ctx->p[i] = PACK32LE(key) ^ akmos_blowfish_p[i];
    }

    /* copy sbox */
    for(i = 0; i < 256; i++) {
        S0(i) = akmos_blowfish_sbox[0][i];
        S1(i) = akmos_blowfish_sbox[1][i];
        S2(i) = akmos_blowfish_sbox[2][i];
        S3(i) = akmos_blowfish_sbox[3][i];
    }

    for(i = 0; i < AKMOS_BLOWFISH_BLKLEN; i++)
        buf[i] = 0;

    for(i = 0; i < 18; i += 2) {
        akmos_blowfish_encrypt(uctx, buf, buf);
        ctx->p[i] = PACK32LE(buf);
        ctx->p[i+1] = PACK32LE(buf + 4);
    }

    for(i = 0; i < 256; i += 2) {
        akmos_blowfish_encrypt(uctx, buf, buf);
        ctx->s0[i] = PACK32LE(buf);
        ctx->s0[i+1] = PACK32LE(buf + 4);
    }
    for(i = 0; i < 256; i += 2) {
        akmos_blowfish_encrypt(uctx, buf, buf);
        ctx->s1[i] = PACK32LE(buf);
        ctx->s1[i+1] = PACK32LE(buf + 4);
    }
    for(i = 0; i < 256; i += 2) {
        akmos_blowfish_encrypt(uctx, buf, buf);
        ctx->s2[i] = PACK32LE(buf);
        ctx->s2[i+1] = PACK32LE(buf + 4);
    }
    for(i = 0; i < 256; i += 2) {
        akmos_blowfish_encrypt(uctx, buf, buf);
        ctx->s3[i] = PACK32LE(buf);
        ctx->s3[i+1] = PACK32LE(buf + 4);
    }
}

void akmos_blowfish_encrypt(akmos_cipher_algo_t *uctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    akmos_blowfish_t *ctx;
    uint32_t l, r;
    size_t i;

    ctx = &uctx->blowfish;

    l = PACK32LE(in_blk); r = PACK32LE(in_blk + 4);

    for(i = 0; i < 16; i += 2) {
        l ^= ctx->p[i];
        r ^= F(l);

        r ^= ctx->p[i+1];
        l ^= F(r);
    }

    l ^= ctx->p[16];
    r ^= ctx->p[17];

    UNPACK32LE(out_blk, r); UNPACK32LE(out_blk + 4, l);
}

void akmos_blowfish_decrypt(akmos_cipher_algo_t *uctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    akmos_blowfish_t *ctx;
    uint32_t l, r;
    ssize_t i;

    ctx = &uctx->blowfish;

    r = PACK32LE(in_blk); l = PACK32LE(in_blk + 4);

    l ^= ctx->p[16];
    r ^= ctx->p[17];

    for(i = 15; i > 0; i -= 2) {
        l ^= F(r);
        r ^= ctx->p[i];

        r ^= F(l);
        l ^= ctx->p[i-1];
    }

    UNPACK32LE(out_blk, l); UNPACK32LE(out_blk + 4, r);
}

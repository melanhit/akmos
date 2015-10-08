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
#include <unistd.h>

#include "../akmos.h"
#include "../macro.h"

#include "blowfish.h"
#include "blowfish_sb32.h"

#define U0(x)       ((uint8_t)((x) >> 24))
#define U1(x)       ((uint8_t)((x) >> 16))
#define U2(x)       ((uint8_t)((x) >>  8))
#define U3(x)       ((uint8_t)((x)      ))

#define F(in, S)    (((S[U0(in)] + S[U1(in) + 256]) ^ S[U2(in) + 512]) + S[U3(in) + 768])

void akmos_blowfish_setkey(akmos_blowfish_t *ctx, const uint8_t *in_key, size_t len)
{
    const uint8_t *key;
    uint8_t buf[AKMOS_BLOWFISH_BLKLEN] = { 0 };
    size_t i, j;

    j = len / 4;
    for(i = 0, key = in_key; i < 18; i++, key += 4) {
        if((i % j) == 0) {
            key = in_key;
        }
        ctx->p[i] = PACK32LE(key) ^ P[i];
    }

    /* copy sbox */
    for(i = 0; i < 4*256; i++) {
        ctx->s[i] = S[i];
    }

    for(i = 0; i < 18; i += 2) {
        akmos_blowfish_encrypt(ctx, buf, buf);
        ctx->p[i] = PACK32LE(buf);
        ctx->p[i+1] = PACK32LE(buf + 4);
    }

    for(i = 0; i < 4*256; i += 2) {
        akmos_blowfish_encrypt(ctx, buf, buf);
        ctx->s[i] = PACK32LE(buf);
        ctx->s[i+1] = PACK32LE(buf + 4);
    }
}

void akmos_blowfish_encrypt(akmos_blowfish_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint32_t l, r;
    size_t i;

    l = PACK32LE(in_blk); r = PACK32LE(in_blk + 4);

    for(i = 0; i < 16; i += 2) {
        l ^= ctx->p[i];
        r ^= F(l, ctx->s);

        r ^= ctx->p[i+1];
        l ^= F(r, ctx->s);
    }

    l ^= ctx->p[16];
    r ^= ctx->p[17];

    UNPACK32LE(out_blk, r); UNPACK32LE(out_blk + 4, l);
}

void akmos_blowfish_decrypt(akmos_blowfish_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint32_t l, r;
    ssize_t i;

    r = PACK32LE(in_blk); l = PACK32LE(in_blk + 4);

    l ^= ctx->p[16];
    r ^= ctx->p[17];

    for(i = 15; i > 0; i -= 2) {
        l ^= F(r, ctx->s);
        r ^= ctx->p[i];

        r ^= F(l, ctx->s);
        l ^= ctx->p[i-1];
    }

    UNPACK32LE(out_blk, l); UNPACK32LE(out_blk + 4, r);
}

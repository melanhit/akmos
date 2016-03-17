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
#include <string.h>
#include <limits.h>

#include "../akmos.h"
#include "../bits.h"

#include "sha3.h"

#ifdef AKMOS_ASM
#define sha3_transform(ctx, blk, nb)            \
{                                               \
    akmos_sha3_transform(ctx, blk, ctx->r, nb); \
}
#else
#define sha3_transform(ctx, blk, nb)            \
{                                               \
    akmos_sha3_transform(ctx, blk, nb);         \
}
#endif

void akmos_sha3_224_init(akmos_sha3_t *ctx)
{
    memset(ctx, 0, sizeof(akmos_sha3_t));
    ctx->blklen = AKMOS_SHA3_224_BLKLEN;
    ctx->diglen = AKMOS_SHA3_224_DIGLEN;
    ctx->r = AKMOS_SHA3_224_BLKLEN / sizeof(uint64_t);
}

void akmos_sha3_256_init(akmos_sha3_t *ctx)
{
    memset(ctx, 0, sizeof(akmos_sha3_t));
    ctx->blklen = AKMOS_SHA3_256_BLKLEN;
    ctx->diglen = AKMOS_SHA3_256_DIGLEN;
    ctx->r = AKMOS_SHA3_256_BLKLEN / sizeof(uint64_t);
}

void akmos_sha3_384_init(akmos_sha3_t *ctx)
{
    memset(ctx, 0, sizeof(akmos_sha3_t));
    ctx->blklen = AKMOS_SHA3_384_BLKLEN;
    ctx->diglen = AKMOS_SHA3_384_DIGLEN;
    ctx->r = AKMOS_SHA3_384_BLKLEN / sizeof(uint64_t);
}

void akmos_sha3_512_init(akmos_sha3_t *ctx)
{
    memset(ctx, 0, sizeof(akmos_sha3_t));
    ctx->blklen = AKMOS_SHA3_512_BLKLEN;
    ctx->diglen = AKMOS_SHA3_512_DIGLEN;
    ctx->r = AKMOS_SHA3_512_BLKLEN / sizeof(uint64_t);
}

void akmos_sha3_update(akmos_sha3_t *ctx, const uint8_t *input, size_t len)
{
    size_t nb, new_len, rem_len, tmp_len;
    const uint8_t *blk;

    tmp_len = ctx->blklen - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->b[ctx->len], input, rem_len);

    if((ctx->len + len) < ctx->blklen) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    nb = new_len / ctx->blklen;

    blk = input + rem_len;

    sha3_transform(ctx, ctx->b, 1 & SIZE_T_MAX);
    sha3_transform(ctx, blk, nb);

    rem_len = new_len % ctx->blklen;

    memcpy(ctx->b, &blk[nb * ctx->blklen], rem_len);
    ctx->len = rem_len;
}

void akmos_sha3_done(akmos_sha3_t *ctx, uint8_t *digest)
{
    uint32_t *p;
    size_t i, nb, pm_len;

    nb = (1 + ((ctx->blklen - 1) < (ctx->len % ctx->blklen)));
    pm_len = nb * ctx->blklen;

    memset(ctx->b + ctx->len, 0, pm_len - ctx->len);

    ctx->b[ctx->len] = 0x06;
    ctx->b[ctx->blklen - 1] |= 0x80;

    if(nb > 0)
        sha3_transform(ctx, ctx->b, nb);

    /* because 224 not multiple 64, use 32 */
    p = (uint32_t *)ctx->S;
    for(i = 0; i < ctx->diglen / sizeof(uint32_t); i++)
        UNPACK32BE(digest + (i * sizeof(uint32_t)), p[i]);
}


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
#include <string.h>

#include <config.h>

#include "../akmos.h"
#include "../bits.h"
#include "../digest.h"

#include "sha3.h"
#include "sha3_transform.h"

#define sha3_transform(ctx, blk, nb)                \
{                                                   \
    akmos_sha3_transform(ctx->S, blk, ctx->r, nb);  \
}

static void sha3_224_out(akmos_sha3_t *ctx, uint8_t *digest)
{
    uint32_t *p;
    size_t i;

    p = (uint32_t *)ctx->S;
    for(i = 0; i < ctx->diglen / sizeof(uint32_t); i++, digest += sizeof(uint32_t))
        UNPACK32BE(digest, p[i]);
}

static void sha3_out(akmos_sha3_t *ctx, uint8_t *digest)
{
    size_t i;

    for(i = 0; i < ctx->diglen / sizeof(uint64_t); i++, digest += sizeof(uint64_t))
        UNPACK64BE(digest, ctx->S[i]);
}

void akmos_sha3_224_init(akmos_digest_algo_t *uctx)
{
    akmos_sha3_t *ctx;

    ctx = &uctx->sha3;

    ctx->blklen = AKMOS_SHA3_224_BLKLEN;
    ctx->diglen = AKMOS_SHA3_224_DIGLEN;

    ctx->r = AKMOS_SHA3_224_BLKLEN / sizeof(uint64_t);

    ctx->out = sha3_224_out;
}

void akmos_sha3_256_init(akmos_digest_algo_t *uctx)
{
    akmos_sha3_t *ctx;

    ctx = &uctx->sha3;

    ctx->blklen = AKMOS_SHA3_256_BLKLEN;
    ctx->diglen = AKMOS_SHA3_256_DIGLEN;

    ctx->r = AKMOS_SHA3_256_BLKLEN / sizeof(uint64_t);

    ctx->out = sha3_out;
}

void akmos_sha3_384_init(akmos_digest_algo_t *uctx)
{
    akmos_sha3_t *ctx;

    ctx = &uctx->sha3;

    ctx->blklen = AKMOS_SHA3_384_BLKLEN;
    ctx->diglen = AKMOS_SHA3_384_DIGLEN;

    ctx->r = AKMOS_SHA3_384_BLKLEN / sizeof(uint64_t);

    ctx->out = sha3_out;
}

void akmos_sha3_512_init(akmos_digest_algo_t *uctx)
{
    akmos_sha3_t *ctx;

    ctx = &uctx->sha3;

    ctx->blklen = AKMOS_SHA3_512_BLKLEN;
    ctx->diglen = AKMOS_SHA3_512_DIGLEN;

    ctx->r = AKMOS_SHA3_512_BLKLEN / sizeof(uint64_t);

    ctx->out = sha3_out;
}

void akmos_sha3_update(akmos_digest_algo_t *uctx, const uint8_t *input, size_t len)
{
    akmos_sha3_t *ctx;
    size_t nb, tmp_len;

    ctx = &uctx->sha3;

    tmp_len = len + ctx->len;

    if(tmp_len < ctx->blklen) {
        memcpy(ctx->block + ctx->len, input, len);
        ctx->len += len;
        return;
    }

    if(ctx->len) {
        tmp_len = ctx->blklen - ctx->len;
        memcpy(ctx->block + ctx->len, input, tmp_len);

        sha3_transform(ctx, ctx->block, 1 & SIZE_T_MAX);

        ctx->len = 0;

        len -= tmp_len;
        input += tmp_len;
    }

    nb = len / ctx->blklen;
    if(nb)
        sha3_transform(ctx, input, nb);

    tmp_len = len % ctx->blklen;
    if(tmp_len) {
        memcpy(ctx->block, input + (len - tmp_len), tmp_len);
        ctx->len = tmp_len;
    }
}

void akmos_sha3_done(akmos_digest_algo_t *uctx, uint8_t *digest)
{
    akmos_sha3_t *ctx;

    ctx = &uctx->sha3;

    memset(ctx->block + ctx->len, 0, ctx->blklen - ctx->len);

    ctx->block[ctx->len] = 0x06;
    ctx->block[ctx->blklen - 1] |= 0x80;

    sha3_transform(ctx, ctx->block, 1 & SIZE_T_MAX);

    ctx->out(ctx, digest);
}

/*
 *   Copyright (c) 2017-2018, Andrew Romanenko <melanhit@gmail.com>
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

#include "skein.h"
#include "skein_transform.h"

#define SKEIN_INIT_FLAG     \
(                           \
    AKMOS_SKEIN_FLAG_FIRST |\
    AKMOS_SKEIN_FLAG_FINAL |\
    AKMOS_SKEIN_TYPE_CFG    \
)

#define SKEIN_DONE_FLAG     \
(                           \
    AKMOS_SKEIN_FLAG_FIRST |\
    AKMOS_SKEIN_FLAG_FINAL |\
    AKMOS_SKEIN_TYPE_OUT    \
)

#define SKEIN_MSG_FLAG      \
(                           \
    AKMOS_SKEIN_FLAG_FIRST |\
    AKMOS_SKEIN_TYPE_MSG    \
)

static void skein_init(akmos_skein_t *ctx)
{
    uint64_t bits;

    bits = ctx->blklen * 8;

    UNPACK64BE(ctx->buf    , AKMOS_SKEIN_SCHEMA);
    UNPACK64BE(ctx->buf + 8, bits);

    ctx->tw[1] = SKEIN_INIT_FLAG;

    ctx->transform(ctx, ctx->buf, 1, AKMOS_SKEIN_CFG_LEN);

    ctx->tw[0] = 0;
    ctx->tw[1] = SKEIN_MSG_FLAG;
}

void akmos_skein_256_init(akmos_digest_algo_t *uctx)
{
    akmos_skein_t *ctx;

    ctx = &uctx->skein;

    memset(ctx, 0, sizeof(akmos_skein_t));

    ctx->blklen = AKMOS_SKEIN_256_BLKLEN;
    ctx->transform = akmos_skein_256_transform;

    skein_init(ctx);
}

void akmos_skein_512_init(akmos_digest_algo_t *uctx)
{
    akmos_skein_t *ctx;

    ctx = &uctx->skein;

    memset(ctx, 0, sizeof(akmos_skein_t));

    ctx->blklen = AKMOS_SKEIN_512_BLKLEN;
    ctx->transform = akmos_skein_512_transform;

    skein_init(ctx);
}

void akmos_skein_1024_init(akmos_digest_algo_t *uctx)
{
    akmos_skein_t *ctx;

    ctx = &uctx->skein;

    memset(ctx, 0, sizeof(akmos_skein_t));

    ctx->blklen = AKMOS_SKEIN_1024_BLKLEN;
    ctx->transform = akmos_skein_1024_transform;

    skein_init(ctx);
}

void akmos_skein_update(akmos_digest_algo_t *uctx, const uint8_t *input, size_t len)
{
    akmos_skein_t *ctx;
    size_t tmp_len, rem_len, nb;

    ctx = &uctx->skein;

    tmp_len = ctx->len + len;

    if(tmp_len <= ctx->blklen) {
        memcpy(ctx->buf + ctx->len, input, len);
        ctx->len += len;
        return;
    }

    tmp_len = ctx->blklen - ctx->len;

    if(ctx->len < ctx->blklen) {
        memcpy(ctx->buf + ctx->len, input, tmp_len);
        input += tmp_len;
        len -= tmp_len;
    }

    ctx->transform(ctx, ctx->buf, 1 & SIZE_T_MAX, ctx->blklen);

    rem_len = len % ctx->blklen;

    if(rem_len) {
        memcpy(ctx->buf, input + (len - rem_len), rem_len);
        ctx->len = rem_len;
    } else {
        memcpy(ctx->buf, input + (len - ctx->blklen), ctx->blklen);
        ctx->len = ctx->blklen;
        len -= ctx->blklen;
    }

    nb = len / ctx->blklen;
    if(nb)
        ctx->transform(ctx, input, nb, ctx->blklen);
}

void akmos_skein_done(akmos_digest_algo_t *uctx, uint8_t *digest)
{
    akmos_skein_t *ctx;
    size_t i;

    ctx = &uctx->skein;

    if(ctx->len < ctx->blklen)
        memset(ctx->buf + ctx->len, 0, ctx->blklen - ctx->len);

    ctx->tw[1] |= AKMOS_SKEIN_FLAG_FINAL;
    ctx->transform(ctx, ctx->buf, 1 & SIZE_T_MAX, ctx->len);

    ctx->tw[0] = 0;
    ctx->tw[1] = SKEIN_DONE_FLAG;
    memset(ctx->buf, 0, ctx->blklen);

    ctx->transform(ctx, ctx->buf, 1, sizeof(uint64_t));

    for(i = 0; i < (ctx->blklen / sizeof(uint64_t)); i++, digest += 8)
        UNPACK64BE(digest, ctx->key[i]);
}

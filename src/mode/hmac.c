/*
 *   Copyright (c) 2013-2016, Andrew Romanenko <melanhit@gmail.com>
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

#include "../akmos.h"
#include "../digest.h"

#include "hmac.h"

static int hmac_expkey(akmos_algo_id algo, const uint8_t *key, size_t len, uint8_t *ekey)
{
    akmos_digest_t *ctx;
    int err;

    err = akmos_digest_init(&ctx, algo);
    if(err)
        return err;

    akmos_digest_update(ctx, key, len);
    akmos_digest_done(ctx, ekey);

    return AKMOS_ERR_SUCCESS;
}

int akmos_hmac_init(akmos_hmac_t *ctx, akmos_algo_id algo)
{
    int err;

    err = akmos_digest_init(&ctx->dctx, algo);
    if(err)
        return err;

    ctx->outlen = akmos_digest_outlen(algo);
    if(!ctx->outlen)
        return AKMOS_ERR_ALGOID;

    ctx->blklen = akmos_digest_blklen(algo);
    if(!ctx->blklen)
        return AKMOS_ERR_ALGOID;;

    ctx->algo = algo;

    return AKMOS_ERR_SUCCESS;
}

int akmos_hmac_setkey(akmos_hmac_t *ctx, const uint8_t *key, size_t len)
{
    int err;
    size_t i;

    err = AKMOS_ERR_SUCCESS;

    ctx->i_key = malloc(ctx->blklen * 2);
    if(!ctx->i_key)
        return AKMOS_ERR_ENOMEM;

    memset(ctx->i_key, 0, ctx->blklen * 2);

    ctx->o_key = ctx->i_key + ctx->blklen;

    if(len <= ctx->blklen) {
        memcpy(ctx->i_key, key, len);
        memcpy(ctx->o_key, key, len);
    }

    if(len > ctx->blklen) {
        err = hmac_expkey(ctx->algo, key, len, ctx->i_key);
        if(err)
            goto out;
    }

    memcpy(ctx->o_key, ctx->i_key, ctx->blklen);

    for(i = 0; i < ctx->blklen; i++)
        ctx->i_key[i] ^= AKMOS_HMAC_IPAD;

    for(i = 0; i < ctx->blklen; i++)
        ctx->o_key[i] ^= AKMOS_HMAC_OPAD;

    akmos_digest_update(ctx->dctx, ctx->i_key, ctx->blklen);

    return AKMOS_ERR_SUCCESS;

/* process errors */
out:
    if(ctx->i_key)
        free(ctx->i_key);

    return err;
}

void akmos_hmac_update(akmos_hmac_t *ctx, const uint8_t *blk, size_t len)
{
    akmos_digest_update(ctx->dctx, blk, len);
}

int akmos_hmac_done(akmos_hmac_t *ctx, uint8_t *mac)
{
    uint8_t *buf;
    int err;

    buf = malloc(ctx->outlen);
    if(!buf)
        return AKMOS_ERR_ENOMEM;

    akmos_digest_done(ctx->dctx, buf);

    err = akmos_digest_init(&ctx->dctx, ctx->algo);
    if(err)
        goto out;

    akmos_digest_update(ctx->dctx, ctx->o_key, ctx->blklen);
    akmos_digest_update(ctx->dctx, buf, ctx->outlen);

    akmos_digest_done(ctx->dctx, mac);

out:
    akmos_memzero(buf, ctx->outlen);
    free(buf);

    akmos_memzero(ctx->i_key, ctx->blklen * 2);
    free(ctx->i_key);

    if(err)
        return err;

    return AKMOS_ERR_SUCCESS;
}

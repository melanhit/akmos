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
#include <string.h>

#include "../akmos.h"
#include "../cipher.h"

#include "cbc-mac.h"

static void cbcmac_update(akmos_cbcmac_t *ctx, const uint8_t *in_blk, size_t len)
{
    size_t i;

    for(i = 0; i < len; i += AKMOS_BUFSZ)
        akmos_cipher_crypt(ctx->actx, in_blk + i, AKMOS_BUFSZ, ctx->buf);
}

int akmos_cbcmac_init(akmos_cbcmac_t *ctx, akmos_algo_id algo)
{
    int err;

    memset(ctx, 0, sizeof(akmos_cbcmac_t));

    ctx->algo = algo;
    ctx->blklen = akmos_blklen(algo);
    if(!ctx->blklen)
        return AKMOS_ERR_ALGOID;

    err = akmos_cipher_init(&ctx->actx, algo, AKMOS_MODE_CBC, AKMOS_FORCE_ENCRYPT);
    if(err)
        return err;

    akmos_cipher_setiv(ctx->actx, NULL);

    return AKMOS_ERR_SUCCESS;
}

int akmos_cbcmac_setkey(akmos_cbcmac_t *ctx, const uint8_t *key, size_t len)
{
    int err;

    len /= 2;

    err = akmos_cipher_setkey(ctx->actx, key, len);
    if(err)
        return err;

    ctx->klen = len;
    ctx->key = malloc(ctx->klen);
    if(!ctx->key)
        return AKMOS_ERR_ENOMEM;

    memcpy(ctx->key, key + ctx->klen, ctx->klen);

    return AKMOS_ERR_SUCCESS;
}

void akmos_cbcmac_update(akmos_cbcmac_t *ctx, const uint8_t *in_blk, size_t len)
{
    size_t new_len, rem_len, tmp_len;
    const uint8_t *tbuf;

    tmp_len = AKMOS_BUFSZ - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(ctx->buf + ctx->len, in_blk, rem_len);
    if((ctx->len + len) < AKMOS_BUFSZ) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    tmp_len = (new_len / AKMOS_BUFSZ) * AKMOS_BUFSZ;

    tbuf = in_blk + rem_len;

    cbcmac_update(ctx, ctx->buf, AKMOS_BUFSZ);
    cbcmac_update(ctx, tbuf, tmp_len);

    rem_len = new_len % AKMOS_BUFSZ;
    if(rem_len > 0)
         memcpy(ctx->buf, tbuf + AKMOS_BUFSZ, rem_len);

    ctx->len = rem_len;
}

int akmos_cbcmac_done(akmos_cbcmac_t *ctx, uint8_t *mac)
{
    int err;
    size_t tmplen;

    err = AKMOS_ERR_SUCCESS;

    tmplen = (ctx->len / ctx->blklen) * ctx->blklen;
    akmos_cipher_crypt(ctx->actx, ctx->buf, tmplen, ctx->buf);

    memset(mac, 0, ctx->blklen);

    if((ctx->len % ctx->blklen) == 0) {
        mac[0] = 0x80;
    } else {
        memcpy(mac, ctx->buf + tmplen, ctx->len - tmplen);
        mac[ctx->len - tmplen] = 0x80;
    }

    akmos_cipher_crypt(ctx->actx, mac, ctx->blklen, mac);

    /* encrypt-last-block */
    err = akmos_cipher_ex(AKMOS_FORCE_ENCRYPT, ctx->algo, AKMOS_MODE_ECB, ctx->key, ctx->klen, NULL, mac, ctx->blklen, mac);
    if(err)
        goto out;

out:
    akmos_memzero(ctx->key, ctx->klen);
    free(ctx->key);

    return err;
}

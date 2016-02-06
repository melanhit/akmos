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

#include "../akmos.h"
#include "../cipher.h"

#include "cmac.h"

static const uint8_t CMAC_RB_128 [1] = {0x87};
static const uint8_t CMAC_RB_256 [2] = {0x04, 0x25};
static const uint8_t CMAC_RB_512 [2] = {0x01, 0x25};
static const uint8_t CMAC_RB_1024[3] = {0x08, 0x00, 0x43};

static void bitshift(uint8_t *buf, int len)
{
    int i;
    uint8_t c, n;

    for(i = len - 1, n = 0; i >= 0; i--) {
        c = (buf[i] & 0x80)?1:0;
        buf[i] <<= 1;
        buf[i] |= n;
        n = c;
    }
}

static void cmac_add_rb(uint8_t *p, size_t l)
{
    switch(l) {
        case 16:
            p[l-1] ^= CMAC_RB_128[0];
            break;

        case 32:
            p[l-1] ^= CMAC_RB_256[1];
            p[l-2] ^= CMAC_RB_256[0];
            break;

        case 64:
            p[l-1] ^= CMAC_RB_512[1];
            p[l-2] ^= CMAC_RB_512[0];
            break;

        case 128:
            p[l-1] ^= CMAC_RB_1024[2];
            p[l-2] ^= CMAC_RB_1024[1];
            p[l-3] ^= CMAC_RB_1024[0];
            break;

        default:
            break;
    }
}

static void cmac_update(akmos_cmac_t *ctx, const uint8_t *in_blk, size_t len)
{
    size_t i;

    for(i = 0; i < len; i += AKMOS_BUFSZ)
        akmos_cipher_crypt(ctx->actx, in_blk + i, AKMOS_BUFSZ, ctx->buf);
}

int akmos_cmac_init(akmos_cmac_t *ctx, akmos_algo_id algo)
{
    int err;

    memset(ctx, 0, sizeof(akmos_cmac_t));

    ctx->algo = algo;

    err = akmos_cipher_init(&ctx->actx, algo, AKMOS_MODE_CBC|AKMOS_MODE_ENCRYPT);
    if(err)
        return err;

    akmos_cipher_setiv(ctx->actx, NULL);

    return AKMOS_ERR_SUCCESS;
}

int akmos_cmac_setkey(akmos_cmac_t *ctx, const uint8_t *key, size_t len)
{
    uint8_t *k0;
    size_t l;
    int err;

    l = akmos_blklen(ctx->algo);
    k0 = malloc(l);
    if(!k0)
        return AKMOS_ERR_ENOMEM;

    memset(k0, 0, l);
    err = akmos_cipher_ex(ctx->algo, AKMOS_MODE_ECB|AKMOS_MODE_ENCRYPT, key, len, NULL, k0, l, k0);
    if(err)
        goto out;

    ctx->klen = len;
    ctx->sklen = l;
    ctx->key = malloc(ctx->klen + (ctx->sklen * 2));
    if(!ctx->key) {
        err = AKMOS_ERR_ENOMEM;
        goto out;
    }

    ctx->key1 = ctx->key + ctx->klen;
    ctx->key2 = ctx->key1 + ctx->sklen;

    /* set prime key */
    err = akmos_cipher_setkey(ctx->actx, key, len);
    if(err)
        goto out;

    /* set subkey 1 */
    memcpy(ctx->key1, k0, l);
    if((ctx->key1[0] & 0x80) == 0x80){
        bitshift(ctx->key1, l);
        cmac_add_rb(ctx->key1, l);
    } else {
        bitshift(ctx->key1, l);
    }

    /* set subkey 2 */
    memcpy(ctx->key2, ctx->key1, l);
    if((ctx->key2[0] & 0x80) == 0x80) {
        bitshift(ctx->key2, l);
        cmac_add_rb(ctx->key1, l);
    } else {
        bitshift(ctx->key2, l);
    }

out:
    if(k0) {
        akmos_memzero(k0, l);
        free(k0);
    }

    return err;
}

void akmos_cmac_update(akmos_cmac_t *ctx, const uint8_t *in_blk, size_t len)
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

    cmac_update(ctx, ctx->buf, AKMOS_BUFSZ);
    cmac_update(ctx, tbuf, tmp_len);

    rem_len = new_len % AKMOS_BUFSZ;
    if(rem_len > 0)
        memcpy(ctx->buf, tbuf + AKMOS_BUFSZ, rem_len);

    ctx->len = rem_len;
    ctx->c = 1;
}

int akmos_cmac_done(akmos_cmac_t *ctx, uint8_t *mac)
{
    uint8_t *p;
    size_t blklen, tmplen;
    int err, i;

    err = AKMOS_ERR_SUCCESS;
    blklen = akmos_blklen(ctx->algo);

    if(!ctx->len && ctx->c) {
        err = akmos_cipher_ex(ctx->algo, AKMOS_MODE_ECB|AKMOS_MODE_DECRYPT, ctx->key, ctx->klen,
                              NULL, ctx->buf + (AKMOS_BUFSZ - blklen), blklen, ctx->buf);
        if(err)
            goto out;

        ctx->len = blklen;
    }

    tmplen = (ctx->len / blklen) * blklen;

    if((tmplen == ctx->len) && ctx->c) {
        for(i = 0, p = ctx->buf + (ctx->len - blklen); i < blklen; i++)
            p[i] ^= ctx->key1[i];
    } else {
        tmplen += blklen;
        akmos_padadd(ctx->buf, ctx->len, ctx->buf, tmplen);
        for(i = 0, p = ctx->buf + (tmplen - blklen); i < blklen; i++)
            p[i] ^= ctx->key2[i];
    }

    akmos_cipher_crypt(ctx->actx, ctx->buf, tmplen, ctx->buf);
    memcpy(mac, ctx->buf + (tmplen - blklen), blklen);

out:
    akmos_cipher_free(ctx->actx);
    akmos_memzero(ctx->buf, AKMOS_BUFSZ);

    akmos_memzero(ctx->key, ctx->klen + (ctx->sklen * 2));
    free(ctx->key);

    return err;
}

/*
 *   Copyright (c) 2014-2018, Andrew Romanenko <melanhit@gmail.com>
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

#include "akmos.h"
#include "error.h"
#include "cipher.h"
#include "pxor.h"

#include "mask.h"

static int cipher_init_mode(akmos_cipher_t ctx, akmos_mode_id mode)
{
    switch(mode & AKMOS_MODE_CIPHER_MASK) {
        case AKMOS_MODE_ECB:
            ctx->xmode  = &akmos_xmode_ecb;
            break;

        case AKMOS_MODE_CBC:
            ctx->xmode  = &akmos_xmode_cbc;
            break;

        case AKMOS_MODE_OFB:
            ctx->xmode  = &akmos_xmode_ofb;
            break;

        case AKMOS_MODE_CTR:
            ctx->xmode  = &akmos_xmode_ctr;
            break;

        case AKMOS_MODE_CFB:
            ctx->xmode  = &akmos_xmode_cfb;
            break;

        case AKMOS_MODE_CFB1:
            ctx->xmode  = &akmos_xmode_cfb1;
            break;

        default:
            return AKMOS_ERR_MODEID;
    }

    switch(mode & AKMOS_MODE_FLAG_MASK) {
        case AKMOS_MODE_ENCRYPT:
            ctx->crypt = ctx->xmode->encrypt;
            break;

        case AKMOS_MODE_DECRYPT:
            ctx->crypt = ctx->xmode->decrypt;
            break;

        default:
            return AKMOS_ERR_MODEID;
    }

    return AKMOS_ERR_SUCCESS;
}

static void cipher_init_stream(akmos_cipher_t ctx)
{
    ctx->xmode = &akmos_xmode_ctr;
    ctx->crypt = &akmos_ctr_stream;
}

static void cipher_setkey(akmos_cipher_t ctx, const uint8_t *key, size_t len)
{
    ctx->xalgo->setkey(&ctx->actx[0], key, len);
}

static void cipher_encrypt(akmos_cipher_t ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    ctx->xalgo->encrypt(&ctx->actx[0], in_blk, out_blk);
}

static void cipher_decrypt(akmos_cipher_t ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    ctx->xalgo->decrypt(&ctx->actx[0], in_blk, out_blk);
}

static void cipher_tde_setkey(akmos_cipher_t ctx, const uint8_t *key, size_t len)
{
    ctx->xalgo->setkey(&ctx->actx[0], key, len);
    ctx->xalgo->setkey(&ctx->actx[1], key + len, len);
    ctx->xalgo->setkey(&ctx->actx[2], key + len * 2, len);
}

static void cipher_ede_encrypt(akmos_cipher_t ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    ctx->xalgo->encrypt(&ctx->actx[0], in_blk, out_blk);
    ctx->xalgo->decrypt(&ctx->actx[1], out_blk, out_blk);
    ctx->xalgo->encrypt(&ctx->actx[2], out_blk, out_blk);
}

static void cipher_ede_decrypt(akmos_cipher_t ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    ctx->xalgo->decrypt(&ctx->actx[2], in_blk, out_blk);
    ctx->xalgo->encrypt(&ctx->actx[1], out_blk, out_blk);
    ctx->xalgo->decrypt(&ctx->actx[0], out_blk, out_blk);
}

static void cipher_eee_encrypt(akmos_cipher_t ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    ctx->xalgo->encrypt(&ctx->actx[0], in_blk, out_blk);
    ctx->xalgo->encrypt(&ctx->actx[1], out_blk, out_blk);
    ctx->xalgo->encrypt(&ctx->actx[2], out_blk, out_blk);
}

static void cipher_eee_decrypt(akmos_cipher_t ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    ctx->xalgo->decrypt(&ctx->actx[2], in_blk, out_blk);
    ctx->xalgo->decrypt(&ctx->actx[1], out_blk, out_blk);
    ctx->xalgo->decrypt(&ctx->actx[0], out_blk, out_blk);
}

static int cipher_init_tde(akmos_cipher_t ctx, akmos_algo_id algo)
{
    if((algo & AKMOS_ALGO_STMCIPH_MASK))
        return AKMOS_ERR_STMTDEA;

    switch(algo & AKMOS_ALGO_FLAG_MASK) {
        case AKMOS_ALGO_FLAG_EDE:
            ctx->setkey  = &cipher_tde_setkey;
            ctx->encrypt = &cipher_ede_encrypt;
            ctx->decrypt = &cipher_ede_decrypt;
            break;

        case AKMOS_ALGO_FLAG_EEE:
            ctx->setkey  = &cipher_tde_setkey;
            ctx->encrypt = &cipher_eee_encrypt;
            ctx->decrypt = &cipher_eee_decrypt;
            break;

        default:
            ctx->setkey  = &cipher_setkey;
            ctx->encrypt = &cipher_encrypt;
            ctx->decrypt = &cipher_decrypt;
            break;
    }

    return AKMOS_ERR_SUCCESS;
}

static int cipher_init_pxor(akmos_cipher_t ctx)
{
    switch(ctx->xalgo->desc.blklen) {
        case 8:
            ctx->pxor = &akmos_pxor8;
            break;

        case 16:
            ctx->pxor = &akmos_pxor16;
            break;

        case 32:
            ctx->pxor = &akmos_pxor32;
            break;

        case 64:
            ctx->pxor = &akmos_pxor64;
            break;

        case 128:
            ctx->pxor = &akmos_pxor128;
            break;

        default:
            return AKMOS_ERR_BLKLEN;
    }

    return AKMOS_ERR_SUCCESS;
}

int akmos_cipher_init(akmos_cipher_t *ctx, akmos_algo_id algo, akmos_mode_id mode)
{
    akmos_cipher_t ptr;
    int err;

    err = AKMOS_ERR_SUCCESS;

    ptr = *ctx = malloc(sizeof(struct akmos_cipher_s));
    if(!ptr)
        return AKMOS_ERR_ENOMEM;

    memset(ptr, 0, sizeof(struct akmos_cipher_s));

    ptr->xalgo = akmos_cipher_xalgo(algo);
    if(!ptr->xalgo) {
        err = AKMOS_ERR_ALGOID;
        goto out;
    }

    /* stream cipher support only CTR mode */
    if((algo & AKMOS_ALGO_STMCIPH_MASK)) {
        if((mode & AKMOS_MODE_CIPHER_MASK) != AKMOS_MODE_CTR) {
            err = AKMOS_ERR_STMMODE;
            goto out;
        }

        cipher_init_stream(ptr);
    /* set mode for block cipher */
    } else {
        err = cipher_init_mode(ptr, mode);
        if(err)
            goto out;
    }

    /* set iv routines */
    if(ptr->xmode->setiv)
        ptr->setiv = ptr->xmode->setiv;

    /* set cnt routines */
    if(ptr->xmode->setcnt)
        ptr->setcnt = ptr->xmode->setcnt;

    /* TDEA */
    err = cipher_init_tde(ptr, algo & AKMOS_ALGO_FLAG_MASK);
    if(err)
        goto out;

    /* set parallel xor routines */
    err = cipher_init_pxor(ptr);
    if(err)
        goto out;

    return AKMOS_ERR_SUCCESS;

/* process errors */
out:
    if(ptr)
        free(ptr);

    return err;
}

int akmos_cipher_setkey(akmos_cipher_t ctx, const uint8_t *key, size_t len)
{
    if(len < ctx->xalgo->desc.keymin || len > ctx->xalgo->desc.keymax)
        return AKMOS_ERR_KEYLEN;

    if((len % ctx->xalgo->desc.keystep) != 0)
        return AKMOS_ERR_KEYLEN;

    ctx->setkey(ctx, key, len);

    return AKMOS_ERR_SUCCESS;
}

void akmos_cipher_setiv(akmos_cipher_t ctx, const uint8_t *iv)
{
    if(ctx->setiv)
        ctx->setiv(ctx, iv);
}

void akmos_cipher_setcnt(akmos_cipher_t ctx, const uint8_t *cnt)
{
    if(ctx->setcnt)
        ctx->setcnt(ctx, cnt);
}

void akmos_cipher_crypt(akmos_cipher_t ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    ctx->crypt(ctx, in_blk, in_len, out_blk);
}

void akmos_cipher_free(akmos_cipher_t ctx)
{
    if(!ctx)
        return;

    akmos_memzero(ctx, sizeof(struct akmos_cipher_s));
    free(ctx);
}

int akmos_cipher(akmos_algo_id algo, akmos_mode_id mode, const uint8_t *key, size_t keylen,
                 const uint8_t *iv, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_cipher_t ctx;
    int err;

    err = akmos_cipher_init(&ctx, algo, mode);
    if(err)
        return err;

    err = akmos_cipher_setkey(ctx, key, keylen);
    if(err)
        goto out;

    akmos_cipher_setiv(ctx, iv);

    if(mode == AKMOS_MODE_CTR)
        akmos_cipher_setcnt(ctx, 0);

    akmos_cipher_crypt(ctx, in_blk, in_len, out_blk);

out:
    if(ctx)
        akmos_cipher_free(ctx);

    return err;
}

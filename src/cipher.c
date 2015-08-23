/*
 *   Copyright (c) 2014-2015, Andrew Romanenko <melanhit@gmail.com>
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
#include "cipher.h"

static int cipher_init_algo(akmos_cipher_ctx *ctx, akmos_algo_id algo)
{
    switch(algo) {
        case AKMOS_ALGO_ANUBIS:
            ctx->xalgo  = &akmos_xalgo_anubis;
            break;

        case AKMOS_ALGO_CAST6:
            ctx->xalgo  = &akmos_xalgo_cast6;
            break;

        case AKMOS_ALGO_RC6:
            ctx->xalgo  = &akmos_xalgo_rc6;
            break;

        case AKMOS_ALGO_SERPENT:
            ctx->xalgo  = &akmos_xalgo_serpent;
            break;

        case AKMOS_ALGO_TWOFISH:
            ctx->xalgo  = &akmos_xalgo_twofish;
            break;

        case AKMOS_ALGO_THREEFISH_256:
            ctx->xalgo  = &akmos_xalgo_threefish_256;
            break;

        case AKMOS_ALGO_THREEFISH_512:
            ctx->xalgo  = &akmos_xalgo_threefish_512;
            break;

        case AKMOS_ALGO_THREEFISH_1024:
            ctx->xalgo  = &akmos_xalgo_threefish_1024;
            break;

        case AKMOS_ALGO_CAMELLIA:
            ctx->xalgo  = &akmos_xalgo_camellia;
            break;

        case AKMOS_ALGO_RIJNDAEL:
            ctx->xalgo  = &akmos_xalgo_rijndael;
            break;

        case AKMOS_ALGO_BLOWFISH:
            ctx->xalgo  = &akmos_xalgo_blowfish;
            break;

        case AKMOS_ALGO_SEED:
            ctx->xalgo  = &akmos_xalgo_seed;
            break;

        default:
            return AKMOS_ERR_ALGOID;
    }

    return AKMOS_ERR_SUCCESS;
}

static int cipher_init_mode(akmos_cipher_ctx *ctx, akmos_mode_id mode, akmos_force_id force)
{
    if(force != AKMOS_FORCE_ENCRYPT && force != AKMOS_FORCE_DECRYPT)
        return AKMOS_ERR_FORCEID;

    switch(mode) {
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

        default:
            return AKMOS_ERR_MODEID;
    }

    if(force == AKMOS_FORCE_ENCRYPT)
        ctx->crypt = ctx->xmode->encrypt;
    else
        ctx->crypt = ctx->xmode->decrypt;

    return AKMOS_ERR_SUCCESS;
}

int akmos_cipher_init(akmos_cipher_ctx **ctx, akmos_algo_id algo, akmos_mode_id mode, akmos_force_id force)
{
    akmos_cipher_ctx *ptr;
    int err;

    err = AKMOS_ERR_SUCCESS;

    ptr = *ctx = malloc(sizeof(akmos_cipher_ctx));
    if(!ptr)
        return AKMOS_ERR_ENOMEM;

    memset(ptr, 0, sizeof(akmos_cipher_ctx));

    err = cipher_init_algo(ptr, algo);
    if(err)
        goto out;

    if(force == AKMOS_FORCE_DECRYPT) {
        switch(algo) {
            case AKMOS_ALGO_RIJNDAEL:
                ptr->xalgo->setkey = (void *)&akmos_rijndael_setkey1;
                break;

            default:
                break;
        }
    }

    err = cipher_init_mode(ptr, mode, force);
    if(err)
        goto out;

    return AKMOS_ERR_SUCCESS;

/* process errors */
out:
    if(ptr)
        free(ptr);

    return err;
}

int akmos_cipher_setkey(akmos_cipher_ctx *ctx, const uint8_t *key, size_t len)
{
    if(len < ctx->xalgo->keymin || len > ctx->xalgo->keymax)
        return AKMOS_ERR_KEYLEN;

    if((len % ctx->xalgo->keystep) != 0)
        return AKMOS_ERR_KEYLEN;

    ctx->xalgo->setkey(&ctx->actx, key, len);

    return AKMOS_ERR_SUCCESS;
}

void akmos_cipher_setiv(akmos_cipher_ctx *ctx, const uint8_t *iv)
{
    if(ctx->xmode->setiv)
        ctx->xmode->setiv(ctx, iv);
}

void akmos_cipher_crypt(akmos_cipher_ctx *ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    ctx->crypt(ctx, in_blk, in_len, out_blk);
}

void akmos_cipher_free(akmos_cipher_ctx *ctx)
{
    if(!ctx)
        return;

    if(ctx->xmode->zero)
        ctx->xmode->zero(ctx);

    akmos_memzero(ctx, sizeof(akmos_cipher_ctx));
    free(ctx);
}

int akmos_cipher_ex(akmos_force_id force, akmos_algo_id algo, akmos_mode_id mode, const uint8_t *key, size_t keylen,
                    const uint8_t *iv, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_cipher_ctx *ctx;
    int err;

    err = akmos_cipher_init(&ctx, algo, mode, force);
    if(err)
        goto out;

    err = akmos_cipher_setkey(ctx, key, keylen);
    if(err)
        goto out;

    akmos_cipher_setiv(ctx, iv);

    akmos_cipher_crypt(ctx, in_blk, in_len, out_blk);

out:
    if(ctx)
        akmos_cipher_free(ctx);

    return err;
}

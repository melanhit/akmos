/*
 *   Copyright (c) 2014-2016, Andrew Romanenko <melanhit@gmail.com>
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
#include "mac.h"

int akmos_mac_init(akmos_mac_t *ctx, akmos_algo_id algo, akmos_mode_id mode)
{
    akmos_mac_t ptr;
    int err;

    err = AKMOS_ERR_SUCCESS;

    ptr = *ctx = malloc(sizeof(struct akmos_mac_s));
    if(!ptr)
        return AKMOS_ERR_ENOMEM;

    memset(ptr, 0, sizeof(struct akmos_mac_s));

    switch(mode) {
        case AKMOS_MODE_HMAC:
            ptr->xmode = &akmos_xmode_hmac;
            break;

        case AKMOS_MODE_CBCMAC:
            ptr->xmode = &akmos_xmode_cbcmac;
            break;

        case AKMOS_MODE_CMAC:
            ptr->xmode = &akmos_xmode_cmac;
            break;

        default:
            free(ptr);
            return AKMOS_ERR_MODEID;
    }

    err = ptr->xmode->init(&ptr->mctx, algo);
    if(err)
        goto out;

    return AKMOS_ERR_SUCCESS;

/* process errors */
out:
    free(ptr);

    return err;
}

int akmos_mac_setkey(akmos_mac_t ctx, const uint8_t *key, size_t len)
{
    return ctx->xmode->setkey(&ctx->mctx, key, len);
}

void akmos_mac_update(akmos_mac_t ctx, const uint8_t *blk, size_t len)
{
    ctx->xmode->update(&ctx->mctx, blk, len);
}

int akmos_mac_done(akmos_mac_t ctx, uint8_t *out)
{
    int err;

    err = ctx->xmode->done(&ctx->mctx, out);
    if(err)
        return err;

    akmos_memzero(ctx, sizeof(struct akmos_mac_s));
    free(ctx);

    return AKMOS_ERR_SUCCESS;
}

int akmos_mac_ex(akmos_algo_id algo, akmos_mode_id mode,
                 const uint8_t *key, size_t keylen,
                 const uint8_t *blk, size_t blklen,
                 uint8_t *out)
{
    akmos_mac_t ctx;
    int err;

    if(!(key || blk || out))
        return AKMOS_ERR_FAILED;

    err = akmos_mac_init(&ctx, algo, mode);
    if(err)
        return err;

    err = akmos_mac_setkey(ctx, key, keylen);
    if(err)
        return err;

    akmos_mac_update(ctx, blk, blklen);

    err = akmos_mac_done(ctx, out);
    if(err)
        return err;

    return AKMOS_ERR_SUCCESS;
}

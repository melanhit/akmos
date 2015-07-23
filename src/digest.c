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
#include "digest.h"

int akmos_digest_init(akmos_digest_ctx **ctx, akmos_algo_id algo)
{
    akmos_digest_ctx *ptr;

    ptr = *ctx = malloc(sizeof(akmos_digest_ctx));
    if(!ptr)
        return AKMOS_ERR_ENOMEM;

    memset(ptr, 0, sizeof(akmos_digest_ctx));

    switch(algo) {
        case AKMOS_ALGO_SHA1:
            ptr->xalgo = &akmos_xalgo_sha1;
            break;

        case AKMOS_ALGO_SHA2_224:
            ptr->xalgo = &akmos_xalgo_sha2_224;
            break;

        case AKMOS_ALGO_SHA2_256:
            ptr->xalgo = &akmos_xalgo_sha2_256;
            break;

        case AKMOS_ALGO_SHA2_384:
            ptr->xalgo = &akmos_xalgo_sha2_384;
            break;

        case AKMOS_ALGO_SHA2_512:
            ptr->xalgo = &akmos_xalgo_sha2_512;
            break;

        case AKMOS_ALGO_SHA3_224:
            ptr->xalgo = &akmos_xalgo_sha3_224;
            break;

        case AKMOS_ALGO_SHA3_256:
            ptr->xalgo = &akmos_xalgo_sha3_256;
            break;

        case AKMOS_ALGO_SHA3_384:
            ptr->xalgo = &akmos_xalgo_sha3_384;
            break;

        case AKMOS_ALGO_SHA3_512:
            ptr->xalgo = &akmos_xalgo_sha3_512;
            break;

        case AKMOS_ALGO_RIPEMD_160:
            ptr->xalgo = &akmos_xalgo_ripemd_160;
            break;

        case AKMOS_ALGO_RIPEMD_256:
            ptr->xalgo = &akmos_xalgo_ripemd_256;
            break;

        case AKMOS_ALGO_RIPEMD_320:
            ptr->xalgo = &akmos_xalgo_ripemd_320;
            break;
        
        case AKMOS_ALGO_TIGER:
            ptr->xalgo = &akmos_xalgo_tiger;
            break;

        default:
            free(ptr);
            return AKMOS_ERR_ALGOID;
    }

    ptr->xalgo->init(&ptr->actx);

    return AKMOS_ERR_SUCCESS;
}

void akmos_digest_update(akmos_digest_ctx *ctx, const uint8_t *blk, size_t len)
{
    ctx->xalgo->update(&ctx->actx, blk, len);
}

void akmos_digest_done(akmos_digest_ctx *ctx, uint8_t *dgst)
{
    if(!ctx)
        return;

    ctx->xalgo->done(&ctx->actx, dgst);

    akmos_memzero(ctx, sizeof(akmos_digest_ctx));
    free(ctx);
}

int akmos_digest_ex(akmos_algo_id algo, const uint8_t *blk, size_t len, uint8_t *out)
{
    akmos_digest_ctx *ctx;
    int err;

    if(!blk || !out)
        return AKMOS_ERR_FAILED;

    err = akmos_digest_init(&ctx, algo);
    if(err)
        return err;

    akmos_digest_update(ctx, blk, len);
    akmos_digest_done(ctx, out);

    return AKMOS_ERR_SUCCESS;
}

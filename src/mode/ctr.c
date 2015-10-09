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
#include "../macro.h"
#include "../cipher.h"

void akmos_ctr_setiv(akmos_cipher_ctx *ctx, const uint8_t *iv)
{
    akmos_ctr_t *ptr;
    size_t len;

    len = ctx->xalgo->blklen - sizeof(uint64_t);

    ptr = &ctx->mctx.ctr;

    ptr->cnt = 0;
    ptr->ctr = ptr->iv + len;

    if(!iv)
        memset(ptr->iv, 0, len);
    else
        memcpy(ptr->iv, iv, len);

    memset(ptr->ctr, 0, sizeof(uint64_t));
}

void akmos_ctr_encrypt(akmos_cipher_ctx *ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_ctr_t *ptr;
    size_t i, n, blklen;

    ptr = &ctx->mctx.ctr;
    if(ptr->rem_len) {
        for(i = 0; i < ptr->rem_len; i++) {
            if(i == in_len)
                break;

            out_blk[i] = ptr->rem_buf[i] ^ in_blk[i];
        }

        out_blk += i;
        in_blk  += i;

        in_len -= i;
        ptr->rem_len -= i;

        if(ptr->rem_len)
            ptr->rem_buf += i;
    }

    blklen = ctx->xalgo->blklen;
    n = in_len / blklen;

    for(i = 0; i < n; i++) {
        ctx->xalgo->encrypt(ctx->actx, ptr->iv, ptr->tmp);
        ptr->cnt++;
        UNPACK64BE(ptr->ctr, ptr->cnt);

        ctx->pxor(in_blk, ptr->tmp, out_blk);

        out_blk += ctx->xalgo->blklen;
        in_blk  += ctx->xalgo->blklen;
    }

    n = in_len - (n * blklen);
    if(!n)
        return;

    ctx->xalgo->encrypt(ctx->actx, ptr->iv, ptr->tmp);
    ptr->cnt++;
    UNPACK64BE(ptr->ctr, ptr->cnt);

    for(i = 0; i < in_len; i++)
        out_blk[i] = ptr->tmp[i] ^ in_blk[i];

    ptr->rem_len = blklen - i;
    ptr->rem_buf = ptr->tmp + i;
}

void akmos_ctr_zero(akmos_cipher_ctx *ctx)
{
    akmos_ctr_t *ptr;

    if(!ctx)
        return;

    ptr = &ctx->mctx.ctr;

    akmos_memzero(ptr->tmp, ctx->xalgo->blklen);
    akmos_memzero(ptr->iv, ctx->xalgo->blklen);
}

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

#include "../akmos.h"
#include "../cipher.h"

void akmos_cfb_setiv(akmos_cipher_t ctx, const uint8_t *iv)
{
    akmos_cfb_t *ptr = &ctx->mctx.cfb;

    if(!iv)
        memset(ptr->iv, 0, ctx->xalgo->desc.blklen);
    else
        memcpy(ptr->iv, iv, ctx->xalgo->desc.blklen);
}

void akmos_cfb_encrypt(akmos_cipher_t ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_cfb_t *ptr;
    size_t i, nb, blklen;

    ptr = &ctx->mctx.cfb;
    blklen = ctx->xalgo->desc.blklen;

    nb = in_len / blklen;

    for(i = 0; i < nb; i++, in_blk += blklen, out_blk += blklen) {
        ctx->encrypt(ctx, ptr->iv, ptr->iv);

        ctx->pxor(ptr->iv, in_blk, ptr->iv);
        memcpy(out_blk, ptr->iv, blklen);
    }
}

void akmos_cfb_decrypt(akmos_cipher_t ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_cfb_t *cfb;
    size_t i, nb, blklen;

    cfb = &ctx->mctx.cfb;
    blklen = ctx->xalgo->desc.blklen;

    nb = in_len / blklen;

    for(i = 0; i < nb; i++, in_blk += blklen, out_blk += blklen) {
        ctx->encrypt(ctx, cfb->iv, cfb->buf);
        memcpy(cfb->iv, in_blk, blklen);

        ctx->pxor(cfb->buf, in_blk, out_blk);
    }
}

void akmos_cfb1_encrypt(akmos_cipher_t ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_cfb_t *cfb;
    size_t i;

    cfb = &ctx->mctx.cfb;

    for(i = 0; i < in_len; i++) {
        ctx->encrypt(ctx, cfb->iv, cfb->iv);
        cfb->iv[0] ^= in_blk[i];
        out_blk[i] = cfb->iv[0];
    }
}

void akmos_cfb1_decrypt(akmos_cipher_t ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_cfb_t *cfb;
    size_t i;

    cfb = &ctx->mctx.cfb;

    for(i = 0; i < in_len; i++) {
        ctx->encrypt(ctx, cfb->iv, cfb->iv);
        cfb->iv[0] = in_blk[i];
        out_blk[i] = cfb->iv[0] ^ in_blk[i];
    }
}

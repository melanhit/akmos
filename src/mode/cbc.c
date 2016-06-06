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

#include "../akmos.h"
#include "../cipher.h"

void akmos_cbc_setiv(akmos_cipher_t ctx, const uint8_t *iv)
{
    akmos_cbc_t *ptr = &ctx->mctx.cbc;

    if(!iv)
        memset(ptr->iv, 0, ctx->xalgo->desc.blklen);
    else
        memcpy(ptr->iv, iv, ctx->xalgo->desc.blklen);
}

void akmos_cbc_encrypt(akmos_cipher_t ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_cbc_t *ptr;
    size_t i, nb, blklen;

    ptr = &ctx->mctx.cbc;
    blklen = ctx->xalgo->desc.blklen;

    nb = in_len / blklen;

    for(i = 0; i < nb; i++, in_blk += blklen, out_blk += blklen) {
        ctx->pxor(ptr->iv, in_blk, ptr->iv);

        ctx->encrypt(ctx, ptr->iv, out_blk);

        memcpy(ptr->iv, out_blk, blklen);
    }
}

void akmos_cbc_decrypt(akmos_cipher_t ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    akmos_cbc_t *ptr;
    size_t i, nb, blklen;

    ptr = &ctx->mctx.cbc;
    blklen = ctx->xalgo->desc.blklen;

    nb = in_len / blklen;

    for(i = 0; i < nb; i++, in_blk += blklen, out_blk += blklen) {
        ctx->decrypt(ctx, in_blk, ptr->buf);

        ctx->pxor(ptr->iv, ptr->buf, ptr->buf);

        memcpy(ptr->iv, in_blk, blklen);
        memcpy(out_blk, ptr->buf, blklen);
    }
}

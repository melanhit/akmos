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

#include "../akmos.h"
#include "../cipher.h"

void akmos_ecb_encrypt(akmos_cipher_ctx *ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    size_t i, nb, blklen;

    blklen = ctx->xalgo->desc.blklen;
    nb = in_len / blklen;

    for(i = 0; i < nb; i++, in_blk += blklen, out_blk += blklen)
        ctx->encrypt(ctx, in_blk, out_blk);
}

void akmos_ecb_decrypt(akmos_cipher_ctx *ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk)
{
    size_t i, nb, blklen;

    blklen = ctx->xalgo->desc.blklen;
    nb = in_len / blklen;

    for(i = 0; i < nb; i++, in_blk += blklen, out_blk += blklen)
        ctx->decrypt(ctx, in_blk, out_blk);
}

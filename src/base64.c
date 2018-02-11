/*
 *   Copyright (c) 2018, Andrew Romanenko <melanhit@gmail.com>
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
#include "base64.h"

#define BASE64_ENC_BLKLEN   6
#define BASE64_ENC_OUTLEN   8

#define BASE64_DEC_BLKLEN   8
#define BASE64_DEC_OUTLEN   6

#define BASE64_BITS         6

#define BASE64_MASK_DEC     UINT8_C (0x7f)
#define BASE64_MASK_ENC     UINT64_C(0x000000000000003f)

#define BASE64_ENCODE(b, n) (sbox[(b >> (n)) & BASE64_MASK_ENC] & 0xff)
#define BASE64_DECODE(i, n) ((uint64_t)(sbox[in_blk[(i)] & BASE64_MASK_DEC]) << (n))

#define BASE64_RSHIFT(b, n) ((uint8_t)(b >> n))

#define BASE64_PACK48(pt)       \
(                               \
      ((uint64_t)(pt)[5] << 16) \
    ^ ((uint64_t)(pt)[4] << 24) \
    ^ ((uint64_t)(pt)[3] << 32) \
    ^ ((uint64_t)(pt)[2] << 40) \
    ^ ((uint64_t)(pt)[1] << 48) \
    ^ ((uint64_t)(pt)[0] << 56) \
)

static const uint8_t base64_enc_sbox[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static const uint8_t base64_dec_sbox[128] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t base64url_enc_sbox[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '-', '_'
};

static const uint8_t base64url_dec_sbox[128] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x3f,
    0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void base64_encode(const uint8_t *sbox, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk, size_t *out_len)
{
    size_t i, j, len, tmplen, bits;
    uint64_t b;

    for(i = BASE64_ENC_BLKLEN, len = 0; i <= in_len; i += BASE64_ENC_BLKLEN) {
        b = BASE64_PACK48(in_blk);

        out_blk[0] = BASE64_ENCODE(b, 58);
        out_blk[1] = BASE64_ENCODE(b, 52);
        out_blk[2] = BASE64_ENCODE(b, 46);
        out_blk[3] = BASE64_ENCODE(b, 40);
        out_blk[4] = BASE64_ENCODE(b, 34);
        out_blk[5] = BASE64_ENCODE(b, 28);
        out_blk[6] = BASE64_ENCODE(b, 22);
        out_blk[7] = BASE64_ENCODE(b, 16);

        in_blk  += BASE64_ENC_BLKLEN;
        out_blk += BASE64_ENC_OUTLEN;

        len += BASE64_ENC_OUTLEN;
    }

    /* process remain */
    tmplen = in_len % BASE64_ENC_BLKLEN;
    if(tmplen) {
        for(i = 0, b = 0; i < tmplen; i++) {
            b ^= (uint64_t)in_blk[i];
            b <<= 8;
        }

        bits = tmplen * 8;
        for(i = 0, j = 0; i < bits; i += BASE64_BITS, j++)
            out_blk[j] = BASE64_ENCODE(b, (bits + 2 - i));

        out_blk += j;
        len += j;

        tmplen = tmplen % (BASE64_ENC_BLKLEN / 2);
        if(tmplen) {
            for(i = tmplen, j = 0; i < (BASE64_ENC_BLKLEN / 2); i++, j++)
                out_blk[j] = '=';

            len += j;
        }
    }

    *out_len = len;
}

static void base64_decode(const uint8_t *sbox, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk, size_t *out_len)
{
    size_t i, len, tmplen;
    uint64_t b;

    for(i = BASE64_DEC_BLKLEN, len = 0; i <= in_len; i += BASE64_DEC_BLKLEN) {
        b  = BASE64_DECODE(0, 58);
        b ^= BASE64_DECODE(1, 52);
        b ^= BASE64_DECODE(2, 46);
        b ^= BASE64_DECODE(3, 40);
        b ^= BASE64_DECODE(4, 34);
        b ^= BASE64_DECODE(5, 28);
        b ^= BASE64_DECODE(6, 22);
        b ^= BASE64_DECODE(7, 16);

        out_blk[0] = BASE64_RSHIFT(b, 56);
        out_blk[1] = BASE64_RSHIFT(b, 48);
        out_blk[2] = BASE64_RSHIFT(b, 40);
        out_blk[3] = BASE64_RSHIFT(b, 32);
        out_blk[4] = BASE64_RSHIFT(b, 24);
        out_blk[5] = BASE64_RSHIFT(b, 16);

        len += BASE64_DEC_OUTLEN;
        /* process padding */
        if(in_blk[7] == '=') {
            len--;

            if(in_blk[6] == '=')
                len--;

            *out_len = len;

            return;
        }

        in_blk  += BASE64_DEC_BLKLEN;
        out_blk += BASE64_DEC_OUTLEN;
    }

    tmplen = in_len % BASE64_DEC_BLKLEN;
    if(tmplen == (BASE64_DEC_BLKLEN / 2)) {
        b  = BASE64_DECODE(0, 58);
        b ^= BASE64_DECODE(1, 52);
        b ^= BASE64_DECODE(2, 46);
        b ^= BASE64_DECODE(3, 40);

        out_blk[0] = BASE64_RSHIFT(b, 56);
        out_blk[1] = BASE64_RSHIFT(b, 48);
        out_blk[2] = BASE64_RSHIFT(b, 40);

        len += BASE64_DEC_OUTLEN / 2;
        if(in_blk[3] == '=') {
            len--;

            if(in_blk[2] == '=')
                len--;
        }
    }

    *out_len = len;
}

int akmos_base64_init(akmos_base64_t *ctx, akmos_algo_id algo, akmos_mode_id mode)
{
    akmos_base64_t ptr;
    const uint8_t *e_sbox, *d_sbox;

    ptr = *ctx = malloc(sizeof(struct akmos_base64_s));
    if(!ptr)
        return AKMOS_ERR_ENOMEM;

    memset(ptr, 0, sizeof(struct akmos_base64_s));

    switch(algo) {
        case AKMOS_ALGO_BASE64:
            e_sbox = base64_enc_sbox;
            d_sbox = base64_dec_sbox;
            break;

        case AKMOS_ALGO_BASE64URL:
            e_sbox = base64url_enc_sbox;
            d_sbox = base64url_dec_sbox;
            break;

        default:
            free(ptr);
            return AKMOS_ERR_ALGOID;
    }

    switch(mode) {
        case AKMOS_MODE_ENCODE:
            ptr->sbox = e_sbox;
            ptr->update = &base64_encode;
            ptr->blklen = BASE64_ENC_BLKLEN;
            break;

        case AKMOS_MODE_DECODE:
            ptr->sbox = d_sbox;
            ptr->update = &base64_decode;
            ptr->blklen = BASE64_DEC_BLKLEN;
            break;

        default:
            free(ptr);
            return AKMOS_ERR_MODEID;
    }

    return AKMOS_ERR_SUCCESS;
}

int akmos_base64_update(akmos_base64_t ctx, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk, size_t *out_len)
{
    size_t nb, len, tmplen;

    tmplen = 0;

    len = in_len + ctx->len;
    if(len < ctx->blklen) {
        memcpy(ctx->blk + ctx->len, in_blk, in_len);
        ctx->len += in_len;
        *out_len = 0;

        return AKMOS_ERR_SUCCESS;
    }

    if(ctx->len) {
        len = ctx->blklen - ctx->len;
        memcpy(ctx->blk + ctx->len, in_blk, len);

        ctx->update(ctx->sbox, ctx->blk, ctx->blklen, out_blk, out_len);

        in_blk += len;
        out_blk += *out_len;

        ctx->len = 0;
        in_len -= len;
        tmplen = *out_len;
    }

    nb = in_len / ctx->blklen;
    if(nb) {
        ctx->update(ctx->sbox, in_blk, nb * ctx->blklen, out_blk, out_len);
        *out_len += tmplen;
    }

    len = in_len % ctx->blklen;
    if(len) {
        memcpy(ctx->blk, in_blk + (in_len - len), len);
        ctx->len = len;
    }

    return AKMOS_ERR_SUCCESS;
}

int akmos_base64_done(akmos_base64_t ctx, uint8_t *out_blk, size_t *out_len)
{
    int err;

    err = AKMOS_ERR_SUCCESS;

    if(ctx->len) {
        if(out_blk)
            ctx->update(ctx->sbox, ctx->blk, ctx->len, out_blk, out_len);

    } else {
        *out_len = 0;
    }

    free(ctx);

    return err;
}

static int base64(akmos_algo_id algo, akmos_mode_id mode, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk, size_t *out_len)
{
    akmos_base64_t ctx;
    size_t len;
    int err;

    err = akmos_base64_init(&ctx, algo, mode);
    if(err)
        return err;

    len = *out_len;
    err = akmos_base64_update(ctx, in_blk, in_len, out_blk, out_len);
    if(err)
        return err;

    len -= *out_len;
    err = akmos_base64_done(ctx, out_blk + *out_len, &len);
    if(err)
        return err;

    *out_len += len;

    return AKMOS_ERR_SUCCESS;
}

int akmos_base64_encode(akmos_algo_id algo, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk, size_t *out_len)
{
    return base64(algo, AKMOS_MODE_ENCODE, in_blk, in_len, out_blk, out_len);
}

int akmos_base64_decode(akmos_algo_id algo, const uint8_t *in_blk, size_t in_len, uint8_t *out_blk, size_t *out_len)
{
    return base64(algo, AKMOS_MODE_DECODE, in_blk, in_len, out_blk, out_len);
}

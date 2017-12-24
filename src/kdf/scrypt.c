/*
 *   Copyright (c) 2017, Andrew Romanenko <melanhit@gmail.com>
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
#include "../error.h"
#include "../bits.h"

#define SCRYPT_BLKLEN   8   /* r = 8 */
#define SALSA_BLKLEN    16  /* via uint32_t */

#define QROUND(a, b, c, n)  s[a] ^= ROTL32((s[b] + s[c]), n)

static void scrypt_pxor(uint32_t *in_blk, uint32_t *out_blk, size_t blklen)
{
    size_t i;

    for(i = 0; i < blklen; i++)
        out_blk[i] ^= in_blk[i];
}

static void scrypt_salsa(uint32_t *in_blk, uint32_t *out_blk)
{
    uint32_t s[16];
    size_t i;

    for(i = 0; i < SALSA_BLKLEN; i++)
        s[i] = in_blk[i];

    for(i = 0; i < 4; i++) {
        QROUND( 4,  0, 12,  7); QROUND( 9,  5,  1,  7);
        QROUND(14, 10,  6,  7); QROUND( 3, 15, 11,  7);
        QROUND( 8,  4,  0,  9); QROUND(13,  9,  5,  9);
        QROUND( 2, 14, 10,  9); QROUND( 7,  3, 15,  9);
        QROUND(12,  8,  4, 13); QROUND( 1, 13,  9, 13);
        QROUND( 6,  2, 14, 13); QROUND(11,  7,  3, 13);
        QROUND( 0, 12,  8, 18); QROUND( 5,  1, 13, 18);
        QROUND(10,  6,  2, 18); QROUND(15, 11,  7, 18);

        QROUND( 1,  0,  3,  7); QROUND( 6,  5,  4,  7);
        QROUND(11, 10,  9,  7); QROUND(12, 15, 14,  7);
        QROUND( 2,  1,  0,  9); QROUND( 7,  6,  5,  9);
        QROUND( 8, 11, 10,  9); QROUND(13, 12, 15,  9);
        QROUND( 3,  2,  1, 13); QROUND( 4,  7,  6, 13);
        QROUND( 9,  8, 11, 13); QROUND(14, 13, 12, 13);
        QROUND( 0,  3,  2, 18); QROUND( 5,  4,  7, 18);
        QROUND(10,  9,  8, 18); QROUND(15, 14, 13, 18);
    }

    for(i = 0; i < SALSA_BLKLEN; i++)
        out_blk[i] = s[i] + in_blk[i];
}

static void scrypt_blkmix(uint32_t *in_blk, uint32_t *out_blk, uint32_t *tmp_blk, uint32_t blklen)
{
    uint32_t buf[16], *out, *out1, *out2;
    uint32_t i, r;

    r = blklen / SALSA_BLKLEN;

    memcpy(buf, in_blk + (blklen - SALSA_BLKLEN), (SALSA_BLKLEN * sizeof(uint32_t)));

    out1 = tmp_blk;
    out2 = tmp_blk + (blklen / 2);
    for(i = 0; i < r; i++, in_blk += SALSA_BLKLEN) {
        scrypt_pxor(in_blk, buf, SALSA_BLKLEN);
        scrypt_salsa(buf, buf);

        if((i % 2) == 0) {
            out = out1;
            out1 += SALSA_BLKLEN;
        } else {
            out = out2;
            out2 += SALSA_BLKLEN;
        }

        memcpy(out, buf, (SALSA_BLKLEN * sizeof(uint32_t)));
    }

    memcpy(out_blk, tmp_blk, (blklen * sizeof(uint32_t)));
}

static int scrypt_romix(uint8_t *in_blk, uint8_t *out_blk, uint32_t in_len, uint32_t N)
{
    uint32_t *buf, *vbuf, *xbuf, *tbuf;
    uint32_t blklen, i;
    uint64_t j;

    buf = malloc(in_len * (N + 2));
    if(!buf)
        return AKMOS_ERR_ENOMEM;

    blklen =  in_len / sizeof(uint32_t);
    vbuf = buf;
    xbuf = buf + (blklen * N);
    tbuf = buf + (blklen * (N + 1));

    memcpy(xbuf, in_blk, in_len);

    for(i = 0; i <= (N - 1); i++, vbuf += blklen) {
        memcpy(vbuf, xbuf, in_len);
        scrypt_blkmix(xbuf, xbuf, tbuf, blklen);
    }

    for(i = 0, vbuf = buf; i <= (N - 1); i++) {
        memcpy(&j, xbuf + (blklen - SALSA_BLKLEN), 8);
        j = (j % N) * blklen;

        scrypt_pxor(vbuf + j, xbuf, blklen);
        scrypt_blkmix(xbuf, xbuf, tbuf, blklen);
    }

    memcpy(out_blk, xbuf, in_len);

    if(buf) {
        akmos_memzero(buf, in_len * (N + 2));
        free(buf);
    }

    return AKMOS_ERR_SUCCESS;
}

int akmos_kdf_scrypt(uint8_t *key, size_t keylen,
                     const uint8_t *salt, size_t saltlen,
                     const uint8_t *pass, size_t passlen,
                     uint32_t N, uint32_t p)
{
    uint8_t *buf, *blk;
    uint32_t buflen, blklen, i;
    int err;

    blklen = 128 * SCRYPT_BLKLEN;
    buflen = blklen * p;

    buf = malloc(buflen);
    if(!buf)
        return AKMOS_ERR_ENOMEM;

    err = akmos_kdf_pbkdf2(buf, buflen, salt, saltlen, pass, passlen, 1, AKMOS_ALGO_SHA2_256);
    if(err)
        goto out;

    for(i = 0, blk = buf; i < p; i++, blk += blklen) {
        err = scrypt_romix(blk, blk, blklen, N);
        if(err)
            goto out;
    }

    err = akmos_kdf_pbkdf2(key, keylen, buf, buflen, pass, passlen, 1, AKMOS_ALGO_SHA2_256);
    if(err)
        goto out;

out:
    if(buf) {
        akmos_memzero(buf, buflen);
        free(buf);
    }

    return err;
}

/*
 *   Copyright (c) 2015-2017, Andrew Romanenko <melanhit@gmail.com>
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

#include "pbkdf2.h"

int akmos_pbkdf2(uint8_t *key, size_t keylen,
                 const uint8_t *salt, size_t saltlen,
                 const uint8_t *pass, size_t passlen,
                 uint32_t iter, akmos_algo_id algo)
{
    akmos_mac_t ctx;
    uint32_t i, y;
    size_t j, l, r, mdlen, tlen;
    uint8_t *md, *tbuf, *pkey;
    uint8_t cnt[sizeof(uint32_t)];
    int err;

    ctx = NULL;
    md = NULL;
    err = AKMOS_ERR_SUCCESS;

    mdlen = akmos_digest_outlen(algo);
    if(!mdlen) {
        err = AKMOS_ERR_ALGOID;
        goto out;
    }

    md = malloc(mdlen*2);
    if(!md) {
        err = AKMOS_ERR_ENOMEM;
        goto out;
    }
    tbuf = md + mdlen;

    l = keylen / mdlen;
    if(keylen != (l*mdlen))
        l++;

    r = keylen - ((l - 1) * mdlen);

    pkey = key;
    tlen = mdlen;
    for(i = 1; i <= l; i++) {
        UNPACK32LE(cnt, i);

        err = akmos_mac_init(&ctx, algo, AKMOS_MODE_HMAC);
        if(err)
            goto out;

        err = akmos_mac_setkey(ctx, pass, passlen);
        if(err)
            goto out;

        akmos_mac_update(ctx, salt, saltlen);
        akmos_mac_update(ctx, cnt, sizeof(uint32_t));

        err = akmos_mac_done(ctx, md);
        if(err)
            goto out;

        memcpy(tbuf, md, mdlen);

        for(y = 1; y < iter; y++) {
            err = akmos_mac(algo, AKMOS_MODE_HMAC, pass, passlen, md, mdlen, md);
            if(err)
                goto out;

            for(j = 0; j < mdlen; j++)
                tbuf[j] ^= md[j];
        }

        if((i + 1) > l)
            tlen = r;

        memcpy(pkey, tbuf, tlen);
        pkey += tlen;
    }

out:
    if(md) {
        memset(md, 0, mdlen*2);
        free(md);
    }

    memset(cnt, 0, sizeof(uint32_t));

    return err;
}

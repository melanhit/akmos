/*
 *   Copyright (c) 2014-2017, Andrew Romanenko <melanhit@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "akmos.h"
#include "error.h"
#include "cipher.h"
#include "digest.h"
#include "mac.h"

#include "mask.h"

static char version_str[32];

akmos_mode_id akmos_str2mode(const char *name)
{
    if(name == NULL)
        return 0;
    else if(strcasecmp(name, akmos_xmode_ecb.name) == 0)
        return AKMOS_MODE_ECB;
    else if(strcasecmp(name, akmos_xmode_cbc.name) == 0)
        return AKMOS_MODE_CBC;
    else if(strcasecmp(name, akmos_xmode_hmac.name) == 0)
        return AKMOS_MODE_HMAC;
    else if(strcasecmp(name, akmos_xmode_ofb.name) == 0)
        return AKMOS_MODE_OFB;
    else if(strcasecmp(name, akmos_xmode_ctr.name) == 0)
        return AKMOS_MODE_CTR;
    else if(strcasecmp(name, akmos_xmode_cfb.name) == 0)
        return AKMOS_MODE_CFB;
    else if(strcasecmp(name, akmos_xmode_cbcmac.name) == 0)
        return AKMOS_MODE_CBCMAC;
    else if(strcasecmp(name, akmos_xmode_cmac.name) == 0)
        return AKMOS_MODE_CMAC;
    else
        return 0;
}

const char *akmos_mode2str(akmos_mode_id mode)
{
    switch(mode & AKMOS_MODE_MASK) {
        case AKMOS_MODE_ECB:
            return akmos_xmode_ecb.name;

        case AKMOS_MODE_CBC:
            return akmos_xmode_cbc.name;

        case AKMOS_MODE_HMAC:
            return akmos_xmode_hmac.name;

        case AKMOS_MODE_OFB:
            return akmos_xmode_ofb.name;

        case AKMOS_MODE_CTR:
            return akmos_xmode_ctr.name;

        case AKMOS_MODE_CFB:
            return akmos_xmode_cfb.name;

        case AKMOS_MODE_CBCMAC:
            return akmos_xmode_cbcmac.name;

        case AKMOS_MODE_CMAC:
            return akmos_xmode_cmac.name;

        default:
            return NULL;
    }
}

int akmos_perror(int err)
{
    switch(err) {
        case AKMOS_ERR_ALGOID:
            fprintf(stderr, "Invalid algorithm (err = %d)\n", err);
            break;

        case AKMOS_ERR_MODEID:
            fprintf(stderr, "Invalid mode (err = %d)\n", err);
            break;

        case AKMOS_ERR_KEYLEN:
            fprintf(stderr, "Invalid key length (err = %d)\n", err);
            break;

        case AKMOS_ERR_BLKLEN:
            fprintf(stderr, "Unsupported block length (err = %d)\n", err);
            break;

        case AKMOS_ERR_FLAGID:
            fprintf(stderr, "Invalid flag (err = %d)\n", err);
            break;

        case AKMOS_ERR_STMMODE:
            fprintf(stderr, "Unsupported mode for stream cipher (err = %d)\n", err);
            break;

        case AKMOS_ERR_STMTDEA:
            fprintf(stderr, "Stream cipher unsupport TDEA (err = %d)\n", err);
            break;

        default:
            fprintf(stderr, "Unknown error (err = %d)\n", err);
            break;
    }

    return err;
}

void akmos_padadd(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
    if(out != in)
        memcpy(out, in, in_len);

    out[in_len] = 0x80;

    memset(out + in_len + 1, 0, out_len - in_len - 1);
}

size_t akmos_padrem(uint8_t *in, size_t len)
{
    size_t i;

    if(!len)
        return len;

    for(i = len - 1; ; i--) {
        if((!in[i]) && (i != 0))
            continue;

        if(in[i] == 0x80)
            return i;

        if(!i)
            return 0;
    }

    return len;
}

void akmos_memzero(volatile void *p, size_t len)
{
    volatile uint8_t *_p = p;

    while(len--)
        *_p++=0;
}

const char *akmos_version()
{
    sprintf(version_str, "akmos %d.%d.%d", AKMOS_MAJOR_VERSION, AKMOS_MINOR_VERSION, AKMOS_PATCH_VERSION);

    return version_str;
}

const akmos_cipher_xalgo_t *akmos_cipher_xalgo(akmos_algo_id algo)
{
    const akmos_cipher_xalgo_t *xalgo;

    for(xalgo = akmos_cipher_xlist; xalgo->desc.id; xalgo++) {
        if(xalgo->desc.id == (algo & AKMOS_ALGO_CIPHER_MASK))
            break;
    }

    return xalgo;
}

const akmos_cipher_xdesc_t *akmos_cipher_desc(akmos_algo_id algo)
{
    const akmos_cipher_xalgo_t *xalgo;

    xalgo = akmos_cipher_xalgo(algo);
    if(!xalgo)
        return NULL;

    return &xalgo->desc;
}

const char *akmos_cipher_name(akmos_algo_id algo)
{
    const akmos_cipher_xdesc_t *desc;

    desc = akmos_cipher_desc(algo);
    if(!desc)
        return NULL;

    return desc->name;
}

akmos_algo_id akmos_cipher_id(const char *name)
{
    const akmos_cipher_xalgo_t *xalgo;

    for(xalgo = akmos_cipher_xlist; xalgo->desc.id; xalgo++) {
        if(strcasecmp(xalgo->desc.name, name) == 0)
            return xalgo->desc.id;
    }

    return 0;
}

size_t akmos_cipher_blklen(akmos_algo_id algo)
{
    const akmos_cipher_xdesc_t *desc;

    desc = akmos_cipher_desc(algo);
    if(!desc)
        return 0;

    return desc->blklen;
}

size_t akmos_cipher_ivlen(akmos_algo_id algo)
{
    const akmos_cipher_xdesc_t *desc;

    desc = akmos_cipher_desc(algo);
    if(!desc)
        return 0;

    return desc->ivlen;
}

const akmos_digest_xalgo_t *akmos_digest_xalgo(akmos_algo_id algo)
{
    const akmos_digest_xalgo_t *xalgo;

    for(xalgo = akmos_digest_xlist; xalgo->desc.id; xalgo++) {
        if(xalgo->desc.id == (algo & AKMOS_ALGO_DIGEST_MASK))
            break;
    }

    return xalgo;
}

const akmos_digest_xdesc_t *akmos_digest_desc(akmos_algo_id algo)
{
    const akmos_digest_xalgo_t *xalgo;

    xalgo = akmos_digest_xalgo(algo);
    if(!xalgo)
        return NULL;

    return &xalgo->desc;
}

const char *akmos_digest_name(akmos_algo_id algo)
{
    const akmos_digest_xdesc_t *desc;

    desc = akmos_digest_desc(algo);
    if(!desc)
        return NULL;

    return desc->name;
}

akmos_algo_id akmos_digest_id(const char *name)
{
    const akmos_digest_xalgo_t *xalgo;

    for(xalgo = akmos_digest_xlist; xalgo->desc.id; xalgo++) {
        if(strcasecmp(xalgo->desc.name, name) == 0)
            return xalgo->desc.id;
    }

    return 0;
}

size_t akmos_digest_blklen(akmos_algo_id algo)
{
    const akmos_digest_xdesc_t *desc;

    desc = akmos_digest_desc(algo);
    if(!desc)
        return 0;

    return desc->blklen;
}

size_t akmos_digest_outlen(akmos_algo_id algo)
{
    const akmos_digest_xdesc_t *desc;

    desc = akmos_digest_desc(algo);
    if(!desc)
        return 0;

    return desc->outlen;
}

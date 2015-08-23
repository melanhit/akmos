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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "akmos.h"
#include "cipher.h"
#include "digest.h"
#include "mac.h"

int akmos_str2algo(const char *name)
{
    if(name == NULL)
        return -1;
    else if(strcasecmp(name, akmos_xalgo_anubis.name) == 0)
        return AKMOS_ALGO_ANUBIS;
    else if(strcasecmp(name, akmos_xalgo_cast6.name) == 0)
        return AKMOS_ALGO_CAST6;
    else if(strcasecmp(name, akmos_xalgo_rc6.name) == 0)
        return AKMOS_ALGO_RC6;
    else if(strcasecmp(name, akmos_xalgo_serpent.name) == 0)
        return AKMOS_ALGO_SERPENT;
    else if(strcasecmp(name, akmos_xalgo_sha1.name) == 0)
        return AKMOS_ALGO_SHA1;
    else if(strcasecmp(name, akmos_xalgo_sha2_224.name) == 0)
        return AKMOS_ALGO_SHA2_224;
    else if(strcasecmp(name, akmos_xalgo_sha2_256.name) == 0)
        return AKMOS_ALGO_SHA2_256;
    else if(strcasecmp(name, akmos_xalgo_sha2_384.name) == 0)
        return AKMOS_ALGO_SHA2_384;
    else if(strcasecmp(name, akmos_xalgo_sha2_512.name) == 0)
        return AKMOS_ALGO_SHA2_512;
    else if(strcasecmp(name, akmos_xalgo_sha3_224.name) == 0)
        return AKMOS_ALGO_SHA3_224;
    else if(strcasecmp(name, akmos_xalgo_sha3_256.name) == 0)
        return AKMOS_ALGO_SHA3_256;
    else if(strcasecmp(name, akmos_xalgo_sha3_384.name) == 0)
        return AKMOS_ALGO_SHA3_384;
    else if(strcasecmp(name, akmos_xalgo_sha3_512.name) == 0)
        return AKMOS_ALGO_SHA3_512;
    else if(strcasecmp(name, akmos_xalgo_twofish.name) == 0)
        return AKMOS_ALGO_TWOFISH;
    else if(strcasecmp(name, akmos_xalgo_ripemd_160.name) == 0)
        return AKMOS_ALGO_RIPEMD_160;
    else if(strcasecmp(name, akmos_xalgo_ripemd_256.name) == 0)
        return AKMOS_ALGO_RIPEMD_256;
    else if(strcasecmp(name, akmos_xalgo_ripemd_320.name) == 0)
        return AKMOS_ALGO_RIPEMD_320;
    else if(strcasecmp(name, akmos_xalgo_threefish_256.name) == 0)
        return AKMOS_ALGO_THREEFISH_256;
    else if(strcasecmp(name, akmos_xalgo_threefish_512.name) == 0)
        return AKMOS_ALGO_THREEFISH_512;
    else if(strcasecmp(name, akmos_xalgo_threefish_1024.name) == 0)
        return AKMOS_ALGO_THREEFISH_1024;
    else if(strcasecmp(name, akmos_xalgo_camellia.name) == 0)
        return AKMOS_ALGO_CAMELLIA;
    else if(strcasecmp(name, akmos_xalgo_rijndael.name) == 0)
        return AKMOS_ALGO_RIJNDAEL;
    else if(strcasecmp(name, akmos_xalgo_tiger.name) == 0)
        return AKMOS_ALGO_TIGER;
    else if(strcasecmp(name, akmos_xalgo_whirlpool.name) == 0)
        return AKMOS_ALGO_WHIRLPOOL;
    else if(strcasecmp(name, akmos_xalgo_blowfish.name) == 0)
        return AKMOS_ALGO_BLOWFISH;
    else if(strcasecmp(name, akmos_xalgo_seed.name) == 0)
        return AKMOS_ALGO_SEED;
    else
        return -1;
}

int akmos_str2mode(const char *name)
{
    if(name == NULL)
        return -1;
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
        return -1;
}

const char *akmos_algo2str(akmos_algo_id algo)
{
    switch(algo) {
        case AKMOS_ALGO_ANUBIS:
            return akmos_xalgo_anubis.name;

        case AKMOS_ALGO_CAST6:
            return akmos_xalgo_cast6.name;

        case AKMOS_ALGO_RC6:
            return akmos_xalgo_rc6.name;

        case AKMOS_ALGO_SERPENT:
            return akmos_xalgo_serpent.name;

        case AKMOS_ALGO_SHA1:
            return akmos_xalgo_sha1.name;

        case AKMOS_ALGO_SHA2_224:
            return akmos_xalgo_sha2_224.name;

        case AKMOS_ALGO_SHA2_256:
            return akmos_xalgo_sha2_256.name;

        case AKMOS_ALGO_SHA2_384:
            return akmos_xalgo_sha2_384.name;

        case AKMOS_ALGO_SHA2_512:
            return akmos_xalgo_sha2_512.name;

        case AKMOS_ALGO_SHA3_224:
            return akmos_xalgo_sha3_224.name;

        case AKMOS_ALGO_SHA3_256:
            return akmos_xalgo_sha3_256.name;

        case AKMOS_ALGO_SHA3_384:
            return akmos_xalgo_sha3_384.name;

        case AKMOS_ALGO_SHA3_512:
            return akmos_xalgo_sha3_512.name;

        case AKMOS_ALGO_TWOFISH:
            return akmos_xalgo_twofish.name;

        case AKMOS_ALGO_RIPEMD_160:
            return akmos_xalgo_ripemd_160.name;

        case AKMOS_ALGO_RIPEMD_256:
            return akmos_xalgo_ripemd_256.name;

        case AKMOS_ALGO_RIPEMD_320:
            return akmos_xalgo_ripemd_320.name;

        case AKMOS_ALGO_THREEFISH_256:
            return akmos_xalgo_threefish_256.name;

        case AKMOS_ALGO_THREEFISH_512:
            return akmos_xalgo_threefish_512.name;

        case AKMOS_ALGO_THREEFISH_1024:
            return akmos_xalgo_threefish_1024.name;

        case AKMOS_ALGO_CAMELLIA:
            return akmos_xalgo_camellia.name;

        case AKMOS_ALGO_RIJNDAEL:
            return akmos_xalgo_rijndael.name;

        case AKMOS_ALGO_TIGER:
            return akmos_xalgo_tiger.name;

        case AKMOS_ALGO_WHIRLPOOL:
            return akmos_xalgo_whirlpool.name;

        case AKMOS_ALGO_BLOWFISH:
            return akmos_xalgo_blowfish.name;

        case AKMOS_ALGO_SEED:
            return akmos_xalgo_seed.name;

        default:
            return NULL;
    }
}

const char *akmos_mode2str(akmos_mode_id mode)
{
    switch(mode) {
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

size_t akmos_diglen(akmos_algo_id algo)
{
    switch(algo) {
        case AKMOS_ALGO_SHA1:
            return AKMOS_SHA1_DIGLEN;

        case AKMOS_ALGO_SHA2_224:
            return AKMOS_SHA2_224_DIGLEN;

        case AKMOS_ALGO_SHA2_256:
            return AKMOS_SHA2_256_DIGLEN;

        case AKMOS_ALGO_SHA2_384:
            return AKMOS_SHA2_384_DIGLEN;

        case AKMOS_ALGO_SHA2_512:
            return AKMOS_SHA2_512_DIGLEN;

        case AKMOS_ALGO_SHA3_224:
            return AKMOS_SHA3_224_DIGLEN;

        case AKMOS_ALGO_SHA3_256:
            return AKMOS_SHA3_256_DIGLEN;

        case AKMOS_ALGO_SHA3_384:
            return AKMOS_SHA3_384_DIGLEN;

        case AKMOS_ALGO_SHA3_512:
            return AKMOS_SHA3_512_DIGLEN;

        case AKMOS_ALGO_RIPEMD_160:
            return AKMOS_RIPEMD_160_DIGLEN;

        case AKMOS_ALGO_RIPEMD_256:
            return AKMOS_RIPEMD_256_DIGLEN;

        case AKMOS_ALGO_RIPEMD_320:
            return AKMOS_RIPEMD_320_DIGLEN;

        case AKMOS_ALGO_TIGER:
            return AKMOS_TIGER_DIGLEN;

        case AKMOS_ALGO_WHIRLPOOL:
            return AKMOS_WHIRLPOOL_DIGLEN;

        default:
            return 0;
    }
}

size_t akmos_blklen(akmos_algo_id algo)
{
    switch(algo) {
        case AKMOS_ALGO_ANUBIS:
            return AKMOS_ANUBIS_BLKLEN;

        case AKMOS_ALGO_CAST6:
            return AKMOS_CAST6_BLKLEN;

        case AKMOS_ALGO_RC6:
            return AKMOS_RC6_BLKLEN;

        case AKMOS_ALGO_SERPENT:
            return AKMOS_SERPENT_BLKLEN;

        case AKMOS_ALGO_SHA1:
            return AKMOS_SHA1_BLKLEN;

        case AKMOS_ALGO_SHA2_224:
            return AKMOS_SHA2_224_BLKLEN;

        case AKMOS_ALGO_SHA2_256:
            return AKMOS_SHA2_256_BLKLEN;

        case AKMOS_ALGO_SHA2_384:
            return AKMOS_SHA2_384_BLKLEN;

        case AKMOS_ALGO_SHA2_512:
            return AKMOS_SHA2_512_BLKLEN;

        case AKMOS_ALGO_SHA3_224:
            return AKMOS_SHA3_224_BLKLEN;

        case AKMOS_ALGO_SHA3_256:
            return AKMOS_SHA3_256_BLKLEN;

        case AKMOS_ALGO_SHA3_384:
            return AKMOS_SHA3_384_BLKLEN;

        case AKMOS_ALGO_SHA3_512:
            return AKMOS_SHA3_512_BLKLEN;

        case AKMOS_ALGO_TWOFISH:
            return AKMOS_TWOFISH_BLKLEN;

        case AKMOS_ALGO_RIPEMD_160:
            return AKMOS_RIPEMD_160_BLKLEN;

        case AKMOS_ALGO_RIPEMD_256:
            return AKMOS_RIPEMD_256_BLKLEN;

        case AKMOS_ALGO_RIPEMD_320:
            return AKMOS_RIPEMD_320_BLKLEN;

        case AKMOS_ALGO_THREEFISH_256:
            return AKMOS_THREEFISH_256_BLKLEN;

        case AKMOS_ALGO_THREEFISH_512:
            return AKMOS_THREEFISH_512_BLKLEN;

        case AKMOS_ALGO_THREEFISH_1024:
            return AKMOS_THREEFISH_1024_BLKLEN;

        case AKMOS_ALGO_CAMELLIA:
            return AKMOS_CAMELLIA_BLKLEN;

        case AKMOS_ALGO_RIJNDAEL:
            return AKMOS_RIJNDAEL_BLKLEN;

        case AKMOS_ALGO_TIGER:
            return AKMOS_TIGER_BLKLEN;

        case AKMOS_ALGO_WHIRLPOOL:
            return AKMOS_WHIRLPOOL_BLKLEN;

        case AKMOS_ALGO_BLOWFISH:
            return AKMOS_BLOWFISH_BLKLEN;

        case AKMOS_ALGO_SEED:
            return AKMOS_SEED_BLKLEN;

        default:
            return 0;
    }
}

int akmos_perror(akmos_err_id e)
{
    switch(e) {
        case AKMOS_ERR_ALGOID:
            printf("Invalid algorithm (err = %d)\n", e);
            break;

        case AKMOS_ERR_MODEID:
            printf("Invalid mode (err = %d)\n", e);
            break;

        case AKMOS_ERR_KEYLEN:
            printf("Invalid key length (err = %d)\n", e);
            break;

        case AKMOS_ERR_FORCEID:
            printf("Invalid force (err = %d)\n", e);
            break;

        default:
            printf("Unknown error (err = %d)\n", e);
            break;
    }

    return e;
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
    int i;

    if(!len)
        return len;

    for(i = len - 1; i >= 0; i--) {
        if(!in[i])
            continue;

        if(in[i] == 0x80)
            return i;
    }

    return len;
}

void akmos_memzero(volatile void *p, size_t len)
{
    volatile uint8_t *_p = p;

    while(len--)
        *_p++=0;
}

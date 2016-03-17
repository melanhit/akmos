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

#include "../akmos.h"
#include "../cipher.h"

/* cipher algos */
const akmos_cipher_xalgo_t akmos_cipher_xlist[] = {
    {
        {
            AKMOS_ALGO_ANUBIS, "Anubis",
            AKMOS_ANUBIS_BLKLEN,
            AKMOS_ANUBIS_KEYMIN,
            AKMOS_ANUBIS_KEYMAX,
            AKMOS_ANUBIS_KEYSTEP
        },
        (void *)&akmos_anubis_setkey,
        (void *)&akmos_anubis_encrypt,
        (void *)&akmos_anubis_decrypt
    },
    {
        {
            AKMOS_ALGO_BLOWFISH, "Blowfish",
            AKMOS_BLOWFISH_BLKLEN,
            AKMOS_BLOWFISH_KEYMIN,
            AKMOS_BLOWFISH_KEYMAX,
            AKMOS_BLOWFISH_KEYSTEP
        },
        (void *)&akmos_blowfish_setkey,
        (void *)&akmos_blowfish_encrypt,
        (void *)&akmos_blowfish_decrypt
    },
    {
        {
            AKMOS_ALGO_CAMELLIA, "Camellia",
            AKMOS_CAMELLIA_BLKLEN,
            AKMOS_CAMELLIA_KEYMIN,
            AKMOS_CAMELLIA_KEYMAX,
            AKMOS_CAMELLIA_KEYSTEP
        },
        (void *)&akmos_camellia_setkey,
        (void *)&akmos_camellia_encrypt,
        (void *)&akmos_camellia_decrypt
    },
    {
        {
            AKMOS_ALGO_CAST6, "CAST6",
            AKMOS_CAST6_BLKLEN,
            AKMOS_CAST6_KEYMIN,
            AKMOS_CAST6_KEYMAX,
            AKMOS_CAST6_KEYSTEP
        },
        (void *)&akmos_cast6_setkey,
        (void *)&akmos_cast6_encrypt,
        (void *)&akmos_cast6_decrypt
    },
    {
        {
            AKMOS_ALGO_RC6, "RC6",
            AKMOS_RC6_BLKLEN,
            AKMOS_RC6_KEYMIN,
            AKMOS_RC6_KEYMAX,
            AKMOS_RC6_KEYSTEP
        },
        (void *)&akmos_rc6_setkey,
        (void *)&akmos_rc6_encrypt,
        (void *)&akmos_rc6_decrypt
    },
    {
        {
            AKMOS_ALGO_RIJNDAEL, "Rijndael",
            AKMOS_RIJNDAEL_BLKLEN,
            AKMOS_RIJNDAEL_KEYMIN,
            AKMOS_RIJNDAEL_KEYMAX,
            AKMOS_RIJNDAEL_KEYSTEP
        },
        (void *)&akmos_rijndael_setkey,
        (void *)&akmos_rijndael_encrypt,
        (void *)&akmos_rijndael_decrypt
    },
    {
        {
            AKMOS_ALGO_SERPENT, "Serpent",
            AKMOS_SERPENT_BLKLEN,
            AKMOS_SERPENT_KEYMIN,
            AKMOS_SERPENT_KEYMAX,
            AKMOS_SERPENT_KEYSTEP
        },
        (void *)&akmos_serpent_setkey,
        (void *)&akmos_serpent_encrypt,
        (void *)&akmos_serpent_decrypt
    },
    {
        {
            AKMOS_ALGO_SEED, "SEED",
            AKMOS_SEED_BLKLEN,
            AKMOS_SEED_KEYMIN,
            AKMOS_SEED_KEYMAX,
            AKMOS_SEED_KEYSTEP
        },
        (void *)&akmos_seed_setkey,
        (void *)&akmos_seed_encrypt,
        (void *)&akmos_seed_decrypt
    },
    {
        {
            AKMOS_ALGO_THREEFISH_256, "Threefish-256",
            AKMOS_THREEFISH_256_BLKLEN,
            AKMOS_THREEFISH_256_KEYMIN,
            AKMOS_THREEFISH_256_KEYMAX,
            AKMOS_THREEFISH_256_KEYSTEP
        },
        (void *)&akmos_threefish_256_setkey,
        (void *)&akmos_threefish_256_encrypt,
        (void *)&akmos_threefish_256_decrypt
    },
    {
        {
            AKMOS_ALGO_THREEFISH_512, "Threefish-512",
            AKMOS_THREEFISH_512_BLKLEN,
            AKMOS_THREEFISH_512_KEYMIN,
            AKMOS_THREEFISH_512_KEYMAX,
            AKMOS_THREEFISH_512_KEYSTEP
        },
        (void *)&akmos_threefish_512_setkey,
        (void *)&akmos_threefish_512_encrypt,
        (void *)&akmos_threefish_512_decrypt
    },
    {
        {
            AKMOS_ALGO_THREEFISH_1024, "Threefish-1024",
            AKMOS_THREEFISH_1024_BLKLEN,
            AKMOS_THREEFISH_1024_KEYMIN,
            AKMOS_THREEFISH_1024_KEYMAX,
            AKMOS_THREEFISH_1024_KEYSTEP
        },
        (void *)&akmos_threefish_1024_setkey,
        (void *)&akmos_threefish_1024_encrypt,
        (void *)&akmos_threefish_1024_decrypt
    },
    {
        {
            AKMOS_ALGO_TWOFISH, "Twofish",
            AKMOS_TWOFISH_BLKLEN,
            AKMOS_TWOFISH_KEYMIN,
            AKMOS_TWOFISH_KEYMAX,
            AKMOS_TWOFISH_KEYSTEP
        },
        (void *)&akmos_twofish_setkey,
        (void *)&akmos_twofish_encrypt,
        (void *)&akmos_twofish_decrypt
    },
    {
        { 0 , NULL, 0, 0, 0, 0 },
        NULL, NULL, NULL
    }
};

/* cipher modes */
const akmos_cipher_xmode_t akmos_xmode_ecb = {
    AKMOS_MODE_ECB, "ECB",
    NULL, NULL,
    (void *)&akmos_ecb_encrypt,
    (void *)&akmos_ecb_decrypt
};

const akmos_cipher_xmode_t akmos_xmode_cbc = {
    AKMOS_MODE_CBC, "CBC",
    (void *)&akmos_cbc_setiv,
    NULL,
    (void *)&akmos_cbc_encrypt,
    (void *)&akmos_cbc_decrypt
};

const akmos_cipher_xmode_t akmos_xmode_cfb = {
    AKMOS_MODE_CFB, "CFB",
    (void *)&akmos_cfb_setiv,
    NULL,
    (void *)&akmos_cfb_encrypt,
    (void *)&akmos_cfb_decrypt
};

/* some modes use only encrypt() routines */
const akmos_cipher_xmode_t akmos_xmode_ctr = {
    AKMOS_MODE_CTR, "CTR",
    (void *)&akmos_ctr_setiv,
    (void *)&akmos_ctr_setcnt,
    (void *)&akmos_ctr_encrypt,
    (void *)&akmos_ctr_encrypt
};

const akmos_cipher_xmode_t akmos_xmode_ofb = {
    AKMOS_MODE_OFB, "OFB",
    (void *)&akmos_ofb_setiv,
    NULL,
    (void *)&akmos_ofb_encrypt,
    (void *)&akmos_ofb_encrypt
};

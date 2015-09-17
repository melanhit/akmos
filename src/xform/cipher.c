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

#include <stdlib.h>
#include <stdint.h>

#include "../akmos.h"
#include "../cipher.h"

/* cipher algos */
const akmos_cipher_xalgo_t akmos_xalgo_anubis = {
    AKMOS_ALGO_ANUBIS, "Anubis",
    16, 16, 40, 8,
    (void *)&akmos_anubis_setkey,
    (void *)&akmos_anubis_encrypt,
    (void *)&akmos_anubis_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_blowfish = {
    AKMOS_ALGO_BLOWFISH, "Blowfish",
    8, 8, 56, 4,
    (void *)&akmos_blowfish_setkey,
    (void *)&akmos_blowfish_encrypt,
    (void *)&akmos_blowfish_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_camellia = {
    AKMOS_ALGO_CAMELLIA, "Camellia",
    16, 16, 32, 8,
    (void *)&akmos_camellia_setkey,
    (void *)&akmos_camellia_encrypt,
    (void *)&akmos_camellia_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_cast6 = {
    AKMOS_ALGO_CAST6, "CAST6",
    16, 16, 32, 8,
    (void *)&akmos_cast6_setkey,
    (void *)&akmos_cast6_encrypt,
    (void *)&akmos_cast6_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_rc6 = {
    AKMOS_ALGO_RC6, "RC6",
    16, 16, 32, 8,
    (void *)&akmos_rc6_setkey,
    (void *)&akmos_rc6_encrypt,
    (void *)&akmos_rc6_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_rijndael = {
    AKMOS_ALGO_RIJNDAEL, "Rijndael",
    16, 16, 32, 8,
    (void *)&akmos_rijndael_setkey,
    (void *)&akmos_rijndael_encrypt,
    (void *)&akmos_rijndael_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_serpent = {
    AKMOS_ALGO_SERPENT, "Serpent",
    16, 16, 32, 8,
    (void *)&akmos_serpent_setkey,
    (void *)&akmos_serpent_encrypt,
    (void *)&akmos_serpent_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_seed = {
    AKMOS_ALGO_SEED, "SEED",
    16, 16, 16, 16,
    (void *)&akmos_seed_setkey,
    (void *)&akmos_seed_encrypt,
    (void *)&akmos_seed_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_threefish_256 = {
    AKMOS_ALGO_THREEFISH_256, "Threefish-256",
    32, 32, 32, 32,
    (void *)&akmos_threefish_256_setkey,
    (void *)&akmos_threefish_256_encrypt,
    (void *)&akmos_threefish_256_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_threefish_512 = {
    AKMOS_ALGO_THREEFISH_512, "Threefish-512",
    64, 64, 64, 64,
    (void *)&akmos_threefish_512_setkey,
    (void *)&akmos_threefish_512_encrypt,
    (void *)&akmos_threefish_512_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_threefish_1024 = {
    AKMOS_ALGO_THREEFISH_1024, "Threefish-1024",
    128, 128, 128, 128,
    (void *)&akmos_threefish_1024_setkey,
    (void *)&akmos_threefish_1024_encrypt,
    (void *)&akmos_threefish_1024_decrypt
};

const akmos_cipher_xalgo_t akmos_xalgo_twofish = {
    AKMOS_ALGO_TWOFISH, "Twofish",
    16, 16, 32, 8,
    (void *)&akmos_twofish_setkey,
    (void *)&akmos_twofish_encrypt,
    (void *)&akmos_twofish_decrypt
};

/* cipher modes */
const akmos_cipher_xmode_t akmos_xmode_ecb = {
    AKMOS_MODE_ECB, "ECB",
    NULL,
    (void *)&akmos_ecb_encrypt,
    (void *)&akmos_ecb_decrypt,
    NULL
};

const akmos_cipher_xmode_t akmos_xmode_cbc = {
    AKMOS_MODE_CBC, "CBC",
    (void *)&akmos_cbc_setiv,
    (void *)&akmos_cbc_encrypt,
    (void *)&akmos_cbc_decrypt,
    (void *)&akmos_cbc_zero
};

const akmos_cipher_xmode_t akmos_xmode_cfb = {
    AKMOS_MODE_CFB, "CFB",
    (void *)&akmos_cfb_setiv,
    (void *)&akmos_cfb_encrypt,
    (void *)&akmos_cfb_decrypt,
    (void *)&akmos_cfb_zero
};

/* some modes use only encrypt() routines */
const akmos_cipher_xmode_t akmos_xmode_ctr = {
    AKMOS_MODE_CTR, "CTR",
    (void *)&akmos_ctr_setiv,
    (void *)&akmos_ctr_encrypt,
    (void *)&akmos_ctr_encrypt,
    (void *)&akmos_ctr_zero
};

const akmos_cipher_xmode_t akmos_xmode_ofb = {
    AKMOS_MODE_OFB, "OFB",
    (void *)&akmos_ofb_setiv,
    (void *)&akmos_ofb_encrypt,
    (void *)&akmos_ofb_encrypt,
    (void *)&akmos_ofb_zero
};

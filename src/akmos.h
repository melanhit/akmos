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

#ifndef AKMOS_H
#define AKMOS_H

typedef enum {
    AKMOS_ERR_SUCCESS,
    AKMOS_ERR_FAILED,
    AKMOS_ERR_ALGOID,
    AKMOS_ERR_MODEID,
    AKMOS_ERR_KEYLEN,
    AKMOS_ERR_ENOMEM,
    AKMOS_ERR_FORCEID,
    AKMOS_ERR_BLKLEN
} akmos_err_id;

typedef enum {
    AKMOS_ALGO_TWOFISH,
    AKMOS_ALGO_SHA1,
    AKMOS_ALGO_SERPENT,
    AKMOS_ALGO_RC6,
    AKMOS_ALGO_CAST6,
    AKMOS_ALGO_ANUBIS,
    AKMOS_ALGO_SHA2_224,
    AKMOS_ALGO_SHA2_256,
    AKMOS_ALGO_SHA2_384,
    AKMOS_ALGO_SHA2_512,
    AKMOS_ALGO_RIPEMD_160,
    AKMOS_ALGO_RIPEMD_256,
    AKMOS_ALGO_RIPEMD_320,
    AKMOS_ALGO_SHA3_224,
    AKMOS_ALGO_SHA3_256,
    AKMOS_ALGO_SHA3_384,
    AKMOS_ALGO_SHA3_512,
    AKMOS_ALGO_THREEFISH_256,
    AKMOS_ALGO_THREEFISH_512,
    AKMOS_ALGO_THREEFISH_1024,
    AKMOS_ALGO_CAMELLIA,
    AKMOS_ALGO_RIJNDAEL,
    AKMOS_ALGO_TIGER,
    AKMOS_ALGO_WHIRLPOOL,
    AKMOS_ALGO_BLOWFISH,
    AKMOS_ALGO_SEED
} akmos_algo_id;

typedef enum {
    AKMOS_MODE_ECB,
    AKMOS_MODE_CBC,
    AKMOS_MODE_HMAC,
    AKMOS_MODE_OFB,
    AKMOS_MODE_CTR,
    AKMOS_MODE_CFB,
    AKMOS_MODE_CBCMAC,
    AKMOS_MODE_CMAC
} akmos_mode_id;

typedef enum {
    AKMOS_FORCE_ENCRYPT,
    AKMOS_FORCE_DECRYPT
} akmos_force_id;

/* Cipher */
typedef struct akmos_cipher_s akmos_cipher_ctx;

int  akmos_cipher_init   (akmos_cipher_ctx **, akmos_algo_id, akmos_mode_id, akmos_force_id);
int  akmos_cipher_setkey (akmos_cipher_ctx *, const uint8_t *, size_t);
void akmos_cipher_setiv  (akmos_cipher_ctx *, const uint8_t *);
void akmos_cipher_setcnt (akmos_cipher_ctx *, uint64_t);
void akmos_cipher_crypt  (akmos_cipher_ctx *, const uint8_t *, size_t, uint8_t *);
void akmos_cipher_free   (akmos_cipher_ctx *);
int  akmos_cipher_ex     (akmos_force_id, akmos_algo_id, akmos_mode_id, const uint8_t *, size_t,
                          const uint8_t *, const uint8_t *, size_t, uint8_t *);

/* Hashing */
typedef struct akmos_digest_s akmos_digest_ctx;

int  akmos_digest_init  (akmos_digest_ctx **, akmos_algo_id);
void akmos_digest_update(akmos_digest_ctx *, const uint8_t *, size_t);
void akmos_digest_done  (akmos_digest_ctx *, uint8_t *);
int  akmos_digest_ex    (akmos_algo_id, const uint8_t *, size_t, uint8_t *);

/* Message authentication code (MAC) */
typedef struct akmos_mac_s akmos_mac_ctx;

int  akmos_mac_init  (akmos_mac_ctx **, akmos_algo_id, akmos_mode_id);
int  akmos_mac_setkey(akmos_mac_ctx *, const uint8_t *, size_t);
void akmos_mac_update(akmos_mac_ctx *, const uint8_t *, size_t);
int  akmos_mac_done  (akmos_mac_ctx *, uint8_t *);
int  akmos_mac_ex    (akmos_algo_id, akmos_mode_id, const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *);

/* Key derivation function */
int akmos_kdf_pbkdf2(uint8_t *, size_t, const uint8_t *, size_t, const char *, uint32_t, akmos_algo_id);
int akmos_kdf_kdf2(uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, uint32_t, akmos_algo_id);

/* Misc */
int   akmos_str2algo(const char *);
int   akmos_str2mode(const char *);
const char *akmos_algo2str(akmos_algo_id);
const char *akmos_mode2str(akmos_mode_id);
void  akmos_memzero(volatile void *, size_t);

size_t akmos_diglen(akmos_algo_id);
size_t akmos_blklen(akmos_algo_id);

void   akmos_padadd(const uint8_t *, size_t, uint8_t *, size_t);
size_t akmos_padrem(uint8_t *, size_t);

int akmos_perror(akmos_err_id);

/* xform objects */
typedef struct akmos_cipher_xalgo_s {
    akmos_algo_id id;
    char   *name;
    size_t blklen;
    size_t keymin;
    size_t keymax;
    size_t keystep;
    void (*setkey)  (void *, const uint8_t *, size_t);
    void (*encrypt) (void *, const uint8_t *, uint8_t *);
    void (*decrypt) (void *, const uint8_t *, uint8_t *);
} akmos_cipher_xalgo_t;

typedef struct akmos_digest_xalgo_s {
    akmos_algo_id id;
    char *name;
    size_t blklen;
    size_t diglen;
    void (*init)   (void *);
    void (*update) (void *, const uint8_t *, size_t);
    void (*done)   (void *, uint8_t *);
} akmos_digest_xalgo_t;

const akmos_cipher_xalgo_t *akmos_xalgo_cipher(akmos_algo_id);
const akmos_digest_xalgo_t *akmos_xalgo_digest(akmos_algo_id);

#endif  /* AKMOS_H */

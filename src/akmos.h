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

#ifndef AKMOS_H
#define AKMOS_H

/* version */
#define AKMOS_MAJOR_VERSION 0
#define AKMOS_MINOR_VERSION 6
#define AKMOS_PATCH_VERSION 0

typedef enum {
    /* block cipher algo */
    AKMOS_ALGO_ANUBIS           = 0x00000001,
    AKMOS_ALGO_BLOWFISH         = 0x00000002,
    AKMOS_ALGO_CAMELLIA         = 0x00000003,
    AKMOS_ALGO_CAST6            = 0x00000004,
    AKMOS_ALGO_RC6              = 0x00000005,
    AKMOS_ALGO_RIJNDAEL         = 0x00000006,
    AKMOS_ALGO_SEED             = 0x00000007,
    AKMOS_ALGO_SERPENT          = 0x00000008,
    AKMOS_ALGO_THREEFISH_256    = 0x00000009,
    AKMOS_ALGO_THREEFISH_512    = 0x0000000a,
    AKMOS_ALGO_THREEFISH_1024   = 0x0000000b,
    AKMOS_ALGO_TWOFISH          = 0x0000000c,

    /* stream cipher algo */
    AKMOS_ALGO_SALSA            = 0x00000100,
    AKMOS_ALGO_CHACHA           = 0x00000200,

    /* digest algo */
    AKMOS_ALGO_RIPEMD_160       = 0x00001000,
    AKMOS_ALGO_RIPEMD_256       = 0x00002000,
    AKMOS_ALGO_RIPEMD_320       = 0x00003000,
    AKMOS_ALGO_SHA1             = 0x00004000,
    AKMOS_ALGO_SHA2_224         = 0x00005000,
    AKMOS_ALGO_SHA2_256         = 0x00006000,
    AKMOS_ALGO_SHA2_384         = 0x00007000,
    AKMOS_ALGO_SHA2_512         = 0x00008000,
    AKMOS_ALGO_SHA3_224         = 0x00009000,
    AKMOS_ALGO_SHA3_256         = 0x0000a000,
    AKMOS_ALGO_SHA3_384         = 0x0000b000,
    AKMOS_ALGO_SHA3_512         = 0x0000c000,
    AKMOS_ALGO_TIGER            = 0x0000d000,
    AKMOS_ALGO_WHIRLPOOL        = 0x0000e000,
    AKMOS_ALGO_SKEIN_256        = 0x0000f000,
    AKMOS_ALGO_SKEIN_512        = 0x00010000,
    AKMOS_ALGO_SKEIN_1024       = 0x00020000,

    /* cipher algo flag */
    AKMOS_ALGO_FLAG_EDE         = 0x10000000,
    AKMOS_ALGO_FLAG_EEE         = 0x20000000
} akmos_algo_id;

typedef enum {
    /* block cipher mode */
    AKMOS_MODE_ECB              = 0x00000001,
    AKMOS_MODE_CBC              = 0x00000002,
    AKMOS_MODE_OFB              = 0x00000003,
    AKMOS_MODE_CTR              = 0x00000004,
    AKMOS_MODE_CFB              = 0x00000005,

    /* MAC mode */
    AKMOS_MODE_HMAC             = 0x00000010,
    AKMOS_MODE_CBCMAC           = 0x00000020,
    AKMOS_MODE_CMAC             = 0x00000030,

    /* cipher mode flag */
    AKMOS_MODE_ENCRYPT          = 0x10000000,
    AKMOS_MODE_DECRYPT          = 0x20000000,
} akmos_mode_id;

typedef enum {
    AKMOS_KDF_PBKDF2            = 0x00000001,
    AKMOS_KDF_SCRYPT            = 0x00000002
} akmos_kdf_id;

/* Cipher */
typedef struct akmos_cipher_s *akmos_cipher_t;

typedef struct akmos_cipher_xdesc_s {
    akmos_algo_id id;
    char   *name;
    size_t blklen;
    size_t ivlen;
    size_t keymin;
    size_t keymax;
    size_t keystep;
} akmos_cipher_xdesc_t;

int  akmos_cipher_init   (akmos_cipher_t *, akmos_algo_id, akmos_mode_id);
int  akmos_cipher_setkey (akmos_cipher_t, const uint8_t *, size_t);
void akmos_cipher_setiv  (akmos_cipher_t, const uint8_t *);
void akmos_cipher_setcnt (akmos_cipher_t, const uint8_t *);
void akmos_cipher_crypt  (akmos_cipher_t, const uint8_t *, size_t, uint8_t *);
void akmos_cipher_free   (akmos_cipher_t);
int  akmos_cipher_ex     (akmos_algo_id, akmos_mode_id, const uint8_t *, size_t,
                          const uint8_t *, const uint8_t *, size_t, uint8_t *);

const char *akmos_cipher_name(akmos_algo_id);
akmos_algo_id akmos_cipher_id(const char *);
size_t akmos_cipher_blklen   (akmos_algo_id);
size_t akmos_cipher_ivlen    (akmos_algo_id);

const akmos_cipher_xdesc_t *akmos_cipher_desc(akmos_algo_id);

/* Hashing */
typedef struct akmos_digest_s *akmos_digest_t;

typedef struct akmos_digest_xdesc_s {
    akmos_algo_id id;
    char *name;
    size_t blklen;
    size_t outlen;
} akmos_digest_xdesc_t;

int  akmos_digest_init  (akmos_digest_t *, akmos_algo_id);
void akmos_digest_update(akmos_digest_t, const uint8_t *, size_t);
void akmos_digest_done  (akmos_digest_t, uint8_t *);
int  akmos_digest_ex    (akmos_algo_id, const uint8_t *, size_t, uint8_t *);

const char *akmos_digest_name(akmos_algo_id);
akmos_algo_id akmos_digest_id(const char *);
size_t akmos_digest_blklen   (akmos_algo_id);
size_t akmos_digest_outlen   (akmos_algo_id);

const akmos_digest_xdesc_t *akmos_digest_desc(akmos_algo_id);

/* Message authentication code (MAC) */
typedef struct akmos_mac_s *akmos_mac_t;

int  akmos_mac_init  (akmos_mac_t *, akmos_algo_id, akmos_mode_id);
int  akmos_mac_setkey(akmos_mac_t, const uint8_t *, size_t);
void akmos_mac_update(akmos_mac_t, const uint8_t *, size_t);
int  akmos_mac_done  (akmos_mac_t, uint8_t *);
int  akmos_mac_ex    (akmos_algo_id, akmos_mode_id, const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *);

/* Key derivation function */
/*
 * params depending of the kdf algo:
 * pbkdf2 - akmos_algo_id algo, uint32_t iter
 * scrypt - uint32_t N, uint32_t p
 */
int akmos_kdf(uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, akmos_kdf_id, ...);

/* Misc */
akmos_mode_id akmos_str2mode(const char *);
const char *akmos_mode2str(akmos_mode_id);

void  akmos_memzero(volatile void *, size_t);

void   akmos_padadd(const uint8_t *, size_t, uint8_t *, size_t);
size_t akmos_padrem(uint8_t *, size_t);

int akmos_perror(int);

const char *akmos_version(void);

#endif  /* AKMOS_H */

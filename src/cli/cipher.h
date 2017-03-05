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

#ifndef AKMOS_CLI_CIPHER
#define AKMOS_CLI_CIPHER

#define CIPHER_DEFAULT_EALGO    AKMOS_ALGO_TWOFISH
#define CIPHER_DEFAULT_BMODE    AKMOS_MODE_CBC
#define CIPHER_DEFAULT_SMODE    AKMOS_MODE_CTR
#define CIPHER_DEFAULT_DALGO    AKMOS_ALGO_SHA2_512
#define CIPHER_DEFAULT_KEYLEN   128
#define CIPHER_DEFAULT_ITER     4096

#define CIPHER_MAX_KEYLEN       128
#define CIPHER_MAX_BLKLEN       128

#define CIPHER_HEADER_MD        AKMOS_ALGO_SHA2_256
#define CIPHER_HEADER_MDLEN     32

#define CIPHER_VERSION_V01      0x01
#define CIPHER_VERSION_V02      0x02
#define CIPHER_VERSION          CIPHER_VERSION_V02

typedef struct cipher_opt_s {
    akmos_algo_id algo;
    akmos_algo_id flag;
    akmos_mode_id mode;
    size_t blklen;
    size_t keylen;
    uint32_t iter;
    char pass[PW_MAX_PASSLEN];
    char *passf;
    char *key;
    char *input;
    char *output;
    struct {
        int algo;
        int mode;
        int passw;
        int passf;
        int key;
        int keylen;
        int iter;
        int over;
    } set;
    int ver;
} cipher_opt_t;

typedef struct __attribute__((__packed__)) cipher_header_s {
    uint8_t iv [CIPHER_MAX_BLKLEN * 3];
    uint8_t key[CIPHER_MAX_KEYLEN * 3];
    uint8_t version;
    uint8_t md[CIPHER_HEADER_MDLEN];
    uint8_t pad[223];
} cipher_header_t; /* 1024 bytes */

#endif  /* AKMOS_CLI_CIPHER */

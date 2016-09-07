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

#ifndef AKMOS_CLI_H
#define AKMOS_CLI_H

#define AMALLOC(buf, len, err)          \
{                                       \
    buf = malloc(len);                  \
    if(!buf) {                          \
        printf("%s\n", strerror(errno));\
        err = errno;                    \
    }                                   \
}

#define CIPHER_MAX_KEYLEN   128
#define CIPHER_MAX_BLKLEN   128

#define CIPHER_VERSION      0x01

typedef struct __attribute__((__packed__)) akmos_cipher_header_s {
    uint8_t iv [CIPHER_MAX_BLKLEN * 3];
    uint8_t key[CIPHER_MAX_KEYLEN * 3];
    uint8_t version;
    uint8_t pad[255];
} akmos_cipher_header_t; /* 1024 bytes */

int akmos_cli_help(void);
int akmos_cli_digest(int, char **);
int akmos_cli_cipher(int, char **, akmos_mode_id);
int akmos_cli_mac(int, char **);

#endif  /* AKMOS_CLI_H */

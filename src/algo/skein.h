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

#ifndef AKMOS_ALGO_SKEIN_H
#define AKMOS_ALGO_SKEIN_H

#define AKMOS_SKEIN_256_DIGLEN  32
#define AKMOS_SKEIN_256_BLKLEN  32

#define AKMOS_SKEIN_512_DIGLEN  64
#define AKMOS_SKEIN_512_BLKLEN  64

#define AKMOS_SKEIN_1024_DIGLEN 128
#define AKMOS_SKEIN_1024_BLKLEN 128

#define AKMOS_SKEIN_256_WORDS   4
#define AKMOS_SKEIN_256_ROUNDS  9
#define AKMOS_SKEIN_256_SKEYS   ((AKMOS_SKEIN_256_ROUNDS * 2) + 1)

#define AKMOS_SKEIN_512_WORDS   8
#define AKMOS_SKEIN_512_ROUNDS  9
#define AKMOS_SKEIN_512_SKEYS   ((AKMOS_SKEIN_512_ROUNDS * 2) + 1)

#define AKMOS_SKEIN_1024_WORDS  16
#define AKMOS_SKEIN_1024_ROUNDS 10
#define AKMOS_SKEIN_1024_SKEYS  ((AKMOS_SKEIN_1024_ROUNDS * 2) + 1)

#define AKMOS_SKEIN_MAX_WORDS   (AKMOS_SKEIN_1024_WORDS + 1)
#define AKMOS_SKEIN_MAX_BLKLEN  AKMOS_SKEIN_1024_BLKLEN
#define AKMOS_SKEIN_MAX_SKEYS   AKMOS_SKEIN_1024_SKEYS

#define AKMOS_SKEIN_C240        UINT64_C(0x1bd11bdaa9fc1a22)
#define AKMOS_SKEIN_SCHEMA      UINT64_C(0x0000000133414853)

#define AKMOS_SKEIN_FLAG_FIRST  UINT64_C(0x4000000000000000)
#define AKMOS_SKEIN_FLAG_FINAL  UINT64_C(0x8000000000000000)
#define AKMOS_SKEIN_FLAG_PAD    UINT64_C(0x0080000000000000)

#define AKMOS_SKEIN_TYPE_CFG    UINT64_C(0x0400000000000000)
#define AKMOS_SKEIN_TYPE_MSG    UINT64_C(0x3000000000000000)
#define AKMOS_SKEIN_TYPE_OUT    UINT64_C(0x3f00000000000000)

#define AKMOS_SKEIN_CFG_LEN     32

typedef struct akmos_skein_s {
    uint64_t  key[AKMOS_SKEIN_MAX_WORDS];
    uint64_t  tw[3];
    uint64_t  skey[AKMOS_SKEIN_MAX_SKEYS * AKMOS_SKEIN_MAX_WORDS];
    uint8_t   buf[AKMOS_SKEIN_MAX_BLKLEN];
    size_t    len;
    size_t    blklen;
    struct {
        void(*transform) (struct akmos_skein_s *, const uint8_t *, size_t, size_t);
    };
} akmos_skein_t;

void akmos_skein_256_init   (akmos_skein_t *);
void akmos_skein_512_init   (akmos_skein_t *);
void akmos_skein_1024_init  (akmos_skein_t *);

void akmos_skein_update     (akmos_skein_t *, const uint8_t *, size_t);
void akmos_skein_done       (akmos_skein_t *, uint8_t *);

#endif  /* AKMOS_ALGO_SKEIN_H */

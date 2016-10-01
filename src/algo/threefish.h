/*
 *   Copyright (c) 2015-2016, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_ALGO_THREEFISH_H
#define AKMOS_ALGO_THREEFISH_H

#define AKMOS_THREEFISH_256_BLKLEN      32
#define AKMOS_THREEFISH_256_KEYMIN      32
#define AKMOS_THREEFISH_256_KEYMAX      32
#define AKMOS_THREEFISH_256_KEYSTEP     32

#define AKMOS_THREEFISH_512_BLKLEN      64
#define AKMOS_THREEFISH_512_KEYMIN      64
#define AKMOS_THREEFISH_512_KEYMAX      64
#define AKMOS_THREEFISH_512_KEYSTEP     64

#define AKMOS_THREEFISH_1024_BLKLEN     128
#define AKMOS_THREEFISH_1024_KEYMIN     128
#define AKMOS_THREEFISH_1024_KEYMAX     128
#define AKMOS_THREEFISH_1024_KEYSTEP    128

#define AKMOS_THREEFISH_WORDS_256       4
#define AKMOS_THREEFISH_WORDS_512       8
#define AKMOS_THREEFISH_WORDS_1024      16

typedef struct {
    uint64_t S[AKMOS_THREEFISH_WORDS_256 * 19];
    uint64_t k[AKMOS_THREEFISH_WORDS_256 + 1];
} akmos_threefish_256_t;

typedef struct {
    uint64_t S[AKMOS_THREEFISH_WORDS_512 * 19];
    uint64_t k[AKMOS_THREEFISH_WORDS_512 + 1];
} akmos_threefish_512_t;

typedef struct {
    uint64_t S[AKMOS_THREEFISH_WORDS_1024 * 21];
    uint64_t k[AKMOS_THREEFISH_WORDS_1024 + 1];
} akmos_threefish_1024_t;

void akmos_threefish_256_setkey (akmos_threefish_256_t *, const uint8_t *, size_t);
void akmos_threefish_256_encrypt(akmos_threefish_256_t *, const uint8_t *, uint8_t *);
void akmos_threefish_256_decrypt(akmos_threefish_256_t *, const uint8_t *, uint8_t *);

void akmos_threefish_512_setkey (akmos_threefish_512_t *, const uint8_t *, size_t);
void akmos_threefish_512_encrypt(akmos_threefish_512_t *, const uint8_t *, uint8_t *);
void akmos_threefish_512_decrypt(akmos_threefish_512_t *, const uint8_t *, uint8_t *);

void akmos_threefish_1024_setkey (akmos_threefish_1024_t *, const uint8_t *, size_t);
void akmos_threefish_1024_encrypt(akmos_threefish_1024_t *, const uint8_t *, uint8_t *);
void akmos_threefish_1024_decrypt(akmos_threefish_1024_t *, const uint8_t *, uint8_t *);

#endif  /* AKMOS_ALGO_THREEFISH_H */

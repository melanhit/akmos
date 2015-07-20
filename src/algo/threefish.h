/*
 *   Copyright (c) 2015, Andrew Romanenko <melanhit@gmail.com>
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

#define AKMOS_THREEFISH_256_BLKLEN  32
#define AKMOS_THREEFISH_512_BLKLEN  64
#define AKMOS_THREEFISH_1024_BLKLEN 128

typedef struct {
    uint64_t S[4*19];
} akmos_threefish_256_t;

typedef struct {
    uint64_t S[8*19];
} akmos_threefish_512_t;

typedef struct {
    uint64_t S[16*21];
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

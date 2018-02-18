/*
 *   Copyright (c) 2014-2018, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_ALGO_SHA2_H
#define AKMOS_ALGO_SHA2_H

#define AKMOS_SHA2_224_DIGLEN 28
#define AKMOS_SHA2_224_BLKLEN 64

#define AKMOS_SHA2_256_DIGLEN 32
#define AKMOS_SHA2_256_BLKLEN 64

#define AKMOS_SHA2_384_DIGLEN 48
#define AKMOS_SHA2_384_BLKLEN 128

#define AKMOS_SHA2_512_DIGLEN 64
#define AKMOS_SHA2_512_BLKLEN 128

#define AKMOS_SHA2_MAX_BLKLEN AKMOS_SHA2_512_BLKLEN

typedef struct akmos_sha2_s {
    uint64_t total;
    size_t   len;
    uint8_t  block[AKMOS_SHA2_MAX_BLKLEN];
    size_t   diglen;
    size_t   blklen;
    union {
        uint32_t h32[8+64];
        uint64_t h64[8+80];
    } h;
    struct {
        void(*transform) (void *, const uint8_t *, size_t);
        void(*out)       (struct akmos_sha2_s *, uint8_t *);
    };
} akmos_sha2_t;

void akmos_sha2_224_init  (akmos_digest_algo_t *);
void akmos_sha2_256_init  (akmos_digest_algo_t *);
void akmos_sha2_384_init  (akmos_digest_algo_t *);
void akmos_sha2_512_init  (akmos_digest_algo_t *);

void akmos_sha2_update    (akmos_digest_algo_t *, const uint8_t *, size_t);
void akmos_sha2_done      (akmos_digest_algo_t *, uint8_t *);

#endif  /* AKMOS_ALGO_SHA2_H */

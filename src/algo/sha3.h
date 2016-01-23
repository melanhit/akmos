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

#ifndef AKMOS_ALGO_SHA3_H
#define AKMOS_ALGO_SHA3_H

#define AKMOS_SHA3_224_DIGLEN   28
#define AKMOS_SHA3_224_BLKLEN   144

#define AKMOS_SHA3_256_DIGLEN   32
#define AKMOS_SHA3_256_BLKLEN   136

#define AKMOS_SHA3_384_DIGLEN   48
#define AKMOS_SHA3_384_BLKLEN   104

#define AKMOS_SHA3_512_DIGLEN   64
#define AKMOS_SHA3_512_BLKLEN   72

#define AKMOS_SHA3_ROUNDS       24

typedef struct {
    uint64_t S[25];
    uint8_t  b[AKMOS_SHA3_224_BLKLEN * 2];
    size_t   r;
    size_t   blklen;
    size_t   diglen;
    size_t   len;
} akmos_sha3_t;

void akmos_sha3_224_init (akmos_sha3_t *);
void akmos_sha3_256_init (akmos_sha3_t *);
void akmos_sha3_384_init (akmos_sha3_t *);
void akmos_sha3_512_init (akmos_sha3_t *);

#ifdef AKMOS_ASM
void akmos_sha3_transform(akmos_sha3_t *, const uint8_t *, size_t, size_t);
#else
void akmos_sha3_transform(akmos_sha3_t *, const uint8_t *, size_t);
#endif /* AKMOS_ASM */

void akmos_sha3_update   (akmos_sha3_t *, const uint8_t *, size_t);
void akmos_sha3_done     (akmos_sha3_t *, uint8_t *);

#endif  /* AKMOS_ALGO_SHA3_H */

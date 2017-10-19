/*
 *   Copyright (c) 2015-2017, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_ALGO_RIPEMD_H
#define AKMOS_ALGO_RIPEMD_H

#define AKMOS_RIPEMD_160_DIGLEN 20
#define AKMOS_RIPEMD_256_DIGLEN 32
#define AKMOS_RIPEMD_320_DIGLEN 40

#define AKMOS_RIPEMD_BLKLEN     64

typedef struct {
    uint32_t h[10+16];
    uint64_t total;
    uint8_t  block[AKMOS_RIPEMD_BLKLEN];
    size_t   diglen;
    size_t   blklen;
    size_t   len;
    struct {
        void(*transform) (uint32_t *, const uint8_t *, size_t);
    };
} akmos_ripemd_t;

void akmos_ripemd_160_init(akmos_ripemd_t *);
void akmos_ripemd_256_init(akmos_ripemd_t *);
void akmos_ripemd_320_init(akmos_ripemd_t *);

void akmos_ripemd_update (akmos_ripemd_t *, const uint8_t *, size_t);
void akmos_ripemd_done   (akmos_ripemd_t *, uint8_t *);

#endif  /* AKMOS_ALGO_RIPEMD_H */

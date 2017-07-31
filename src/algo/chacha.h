/*
 *   Copyright (c) 2016-2017, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_ALGO_CHACHA_H
#define AKMOS_ALGO_CHACHA_H

#define AKMOS_CHACHA_BLKLEN     64
#define AKMOS_CHACHA_IVLEN      12
#define AKMOS_CHACHA_KEYMIN     32
#define AKMOS_CHACHA_KEYMAX     32
#define AKMOS_CHACHA_KEYSTEP    32

#define AKMOS_CHACHA_ROUNDS     20

typedef struct {
    uint32_t s[16];
#ifndef AKMOS_ASM_SSE2
} akmos_chacha_t;
#else
} akmos_chacha_t __attribute__((aligned (16)));
#endif

void akmos_chacha_setiv (akmos_chacha_t *, const uint8_t *);
void akmos_chacha_setcnt(akmos_chacha_t *, const uint8_t *);
void akmos_chacha_setkey(akmos_chacha_t *, const uint8_t *, size_t);
void akmos_chacha_stream(akmos_chacha_t *, uint8_t *);

#endif  /* AKMOS_ALGO_CHACHA_H */

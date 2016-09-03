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

#ifndef AKMOS_ALGO_ANUBIS_H
#define AKMOS_ALGO_ANUBIS_H

#define AKMOS_ANUBIS_BLKLEN     16
#define AKMOS_ANUBIS_KEYMIN     16
#define AKMOS_ANUBIS_KEYMAX     40
#define AKMOS_ANUBIS_KEYSTEP    8

#define AKMOS_ANUBIS_MAX_N      10
#define AKMOS_ANUBIS_MAX_R      (AKMOS_ANUBIS_MAX_N + 8)

const uint32_t akmos_anubis_sbox[6][256];

typedef struct {
    int r;
    uint32_t e_key[(AKMOS_ANUBIS_MAX_R + 1) * 4];
    uint32_t d_key[(AKMOS_ANUBIS_MAX_R + 1) * 4];
    uint32_t kappa[AKMOS_ANUBIS_MAX_N];
    uint32_t inter[AKMOS_ANUBIS_MAX_N];
    uint32_t state[4];
} akmos_anubis_t;

void akmos_anubis_setkey (akmos_anubis_t *, const uint8_t *, size_t);
void akmos_anubis_encrypt(akmos_anubis_t *, const uint8_t *, uint8_t *);
void akmos_anubis_decrypt(akmos_anubis_t *, const uint8_t *, uint8_t *);

#endif  /* AKMOS_ALGO_ANUBIS_H */

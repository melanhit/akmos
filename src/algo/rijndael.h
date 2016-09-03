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

#ifndef AKMOS_ALGO_RIJNDAEL_H
#define AKMOS_ALGO_RIJNDAEL_H

#define AKMOS_RIJNDAEL_BLKLEN   16
#define AKMOS_RIJNDAEL_KEYMIN   16
#define AKMOS_RIJNDAEL_KEYMAX   32
#define AKMOS_RIJNDAEL_KEYSTEP  8

const uint32_t akmos_rijndael_s   [256];
const uint32_t akmos_rijndael_sbox[5][256];
const uint32_t akmos_rijndael_si  [5][256];

void akmos_rijndael_setkey (akmos_rijndael_t *, const uint8_t *, size_t);
typedef struct {
    uint32_t ke[4*(14+1)];
    uint32_t kd[4*(14+1)];
    uint32_t w[4];
    size_t   r;
} akmos_rijndael_t;

void akmos_rijndael_encrypt(akmos_rijndael_t *, const uint8_t *, uint8_t *);
void akmos_rijndael_decrypt(akmos_rijndael_t *, const uint8_t *, uint8_t *);

#endif  /* AKMOS_ALGO_RIJNDAEL_H */

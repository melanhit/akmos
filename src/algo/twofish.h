/*
 *   Copyright (c) 2014-2016, Andrew Romanenko <melanhit@gmail.com>
 *   Copyright (c) 1999, Dr B. R Gladman (gladman@seven77.demon.co.uk)
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

#ifndef AKMOS_ALGO_TWOFISH_H
#define AKMOS_ALGO_TWOFISH_H

#define AKMOS_TWOFISH_BLKLEN    16
#define AKMOS_TWOFISH_KEYMIN    16
#define AKMOS_TWOFISH_KEYMAX    32
#define AKMOS_TWOFISH_KEYSTEP   8

typedef struct {
    uint32_t l_key[40];
    uint32_t s_key[AKMOS_TWOFISH_BLKLEN];
    uint32_t mk_tab[4*256];
    uint32_t k_len;
} akmos_twofish_t;

void akmos_twofish_setkey (akmos_twofish_t *, const uint8_t *, size_t);
void akmos_twofish_encrypt(akmos_twofish_t *, const uint8_t *, uint8_t *);
void akmos_twofish_decrypt(akmos_twofish_t *, const uint8_t *, uint8_t *);

#endif  /* AKMOS_ALGO_TWOFISH_H */

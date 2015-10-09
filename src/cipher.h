/*
 *   Copyright (c) 2014-2015, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_CIPHER_H
#define AKMOS_CIPHER_H

#define AKMOS_CIPHER_MAX_BLKLEN     (1024/8)    /* threefish */

#include "algo/anubis.h"
#include "algo/cast6.h"
#include "algo/rc6.h"
#include "algo/serpent.h"
#include "algo/twofish.h"
#include "algo/threefish.h"
#include "algo/camellia.h"
#include "algo/rijndael.h"
#include "algo/blowfish.h"
#include "algo/seed.h"

#include "mode/ecb.h"
#include "mode/cbc.h"
#include "mode/ofb.h"
#include "mode/ctr.h"
#include "mode/cfb.h"

typedef union {
    akmos_anubis_t          anubis;
    akmos_blowfish_t        blowfish;
    akmos_camellia_t        camellia;
    akmos_cast6_t           cast6;
    akmos_rc6_t             rc6;
    akmos_rijndael_t        rijndael;
    akmos_serpent_t         serpent;
    akmos_seed_t            seed;
    akmos_threefish_256_t   tf_256;
    akmos_threefish_512_t   tf_512;
    akmos_threefish_1024_t  tf_1024;
    akmos_twofish_t         twofish;
} akmos_cipher_algo_ctx;

typedef union {
    akmos_cbc_t cbc;
    akmos_cfb_t cfb;
    akmos_ctr_t ctr;
    akmos_ofb_t ofb;
} akmos_cipher_mode_ctx;

typedef struct {
    akmos_mode_id   id;
    char            *name;
    void (*setiv)   (akmos_cipher_ctx *, const uint8_t *);
    void (*encrypt) (akmos_cipher_ctx *, const uint8_t *, size_t, uint8_t *);
    void (*decrypt) (akmos_cipher_ctx *, const uint8_t *, size_t, uint8_t *);
    void (*zero)    (akmos_cipher_ctx *);
} akmos_cipher_xmode_t;

struct akmos_cipher_s {
    /* algo */
    const akmos_cipher_xalgo_t  *xalgo;
    akmos_cipher_algo_ctx       actx;
    /* mode */
    const akmos_cipher_xmode_t  *xmode;
    akmos_cipher_mode_ctx       mctx;
    void (*crypt)               (akmos_cipher_ctx *, const uint8_t *, size_t, uint8_t *);
    void (*pxor)                (const uint8_t *, const uint8_t *, uint8_t *);
};

extern const akmos_cipher_xalgo_t akmos_xalgo_anubis;
extern const akmos_cipher_xalgo_t akmos_xalgo_blowfish;
extern const akmos_cipher_xalgo_t akmos_xalgo_camellia;
extern const akmos_cipher_xalgo_t akmos_xalgo_cast6;
extern const akmos_cipher_xalgo_t akmos_xalgo_rc6;
extern const akmos_cipher_xalgo_t akmos_xalgo_rijndael;
extern const akmos_cipher_xalgo_t akmos_xalgo_serpent;
extern const akmos_cipher_xalgo_t akmos_xalgo_seed;
extern const akmos_cipher_xalgo_t akmos_xalgo_threefish_256;
extern const akmos_cipher_xalgo_t akmos_xalgo_threefish_512;
extern const akmos_cipher_xalgo_t akmos_xalgo_threefish_1024;
extern const akmos_cipher_xalgo_t akmos_xalgo_twofish;

extern const akmos_cipher_xmode_t akmos_xmode_ecb;
extern const akmos_cipher_xmode_t akmos_xmode_cbc;
extern const akmos_cipher_xmode_t akmos_xmode_cfb;
extern const akmos_cipher_xmode_t akmos_xmode_ctr;
extern const akmos_cipher_xmode_t akmos_xmode_ofb;

#endif  /* AKMOS_CIPHER_H */

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

#ifndef AKMOS_CIPHER_H
#define AKMOS_CIPHER_H

#define AKMOS_CIPHER_MAX_BLKLEN AKMOS_THREEFISH_1024_BLKLEN
#define AKMOS_CIPHER_MAX_IVLEN  AKMOS_THREEFISH_1024_BLKLEN

typedef union akmos_cipher_algo_u akmos_cipher_algo_t;

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
#include "algo/salsa.h"
#include "algo/chacha.h"

#include "mode/ecb.h"
#include "mode/cbc.h"
#include "mode/ofb.h"
#include "mode/ctr.h"
#include "mode/cfb.h"

union akmos_cipher_algo_u {
    akmos_anubis_t          anubis;
    akmos_blowfish_t        blowfish;
    akmos_camellia_t        camellia;
    akmos_cast6_t           cast6;
    akmos_rc6_t             rc6;
    akmos_rijndael_t        rijndael;
    akmos_salsa_t           salsa;
    akmos_chacha_t          chacha;
    akmos_serpent_t         serpent;
    akmos_seed_t            seed;
    akmos_threefish_256_t   tf_256;
    akmos_threefish_512_t   tf_512;
    akmos_threefish_1024_t  tf_1024;
    akmos_twofish_t         twofish;
};

typedef union {
    akmos_cbc_t cbc;
    akmos_cfb_t cfb;
    akmos_ctr_t ctr;
    akmos_ofb_t ofb;
} akmos_cipher_mode_t;

typedef struct akmos_cipher_xalgo_s {
    akmos_cipher_xdesc_t desc;

    /* stream cipher routines */
    void (*setcnt)  (akmos_cipher_algo_t *, const uint8_t *);
    void (*setiv)   (akmos_cipher_algo_t *, const uint8_t *);
    void (*stream)  (akmos_cipher_algo_t *, uint8_t *);

    /* common cipher routines */
    void (*setkey)  (akmos_cipher_algo_t *, const uint8_t *, size_t);

    /* block cipher routines */
    void (*encrypt) (akmos_cipher_algo_t *, const uint8_t *, uint8_t *);
    void (*decrypt) (akmos_cipher_algo_t *, const uint8_t *, uint8_t *);
} akmos_cipher_xalgo_t;

typedef struct {
    akmos_mode_id   id;
    char            *name;
    void (*setiv)   (akmos_cipher_t, const uint8_t *);
    void (*setcnt)  (akmos_cipher_t, const uint8_t *);
    void (*encrypt) (akmos_cipher_t, const uint8_t *, size_t, uint8_t *);
    void (*decrypt) (akmos_cipher_t, const uint8_t *, size_t, uint8_t *);
} akmos_cipher_xmode_t;

struct akmos_cipher_s {
    /* algo */
    const akmos_cipher_xalgo_t  *xalgo;
    akmos_cipher_algo_t         actx[3];

    /* mode */
    const akmos_cipher_xmode_t  *xmode;
    akmos_cipher_mode_t         mctx;
    void (*setkey)              (akmos_cipher_t, const uint8_t *, size_t);
    void (*setiv)               (akmos_cipher_t, const uint8_t *);
    void (*setcnt)              (akmos_cipher_t, const uint8_t *);
    void (*encrypt)             (akmos_cipher_t, const uint8_t *, uint8_t *);
    void (*decrypt)             (akmos_cipher_t, const uint8_t *, uint8_t *);
    void (*crypt)               (akmos_cipher_t, const uint8_t *, size_t, uint8_t *);
    void (*pxor)                (const uint8_t *, const uint8_t *, uint8_t *);
};

const akmos_cipher_xalgo_t *akmos_cipher_xalgo(akmos_algo_id);

extern const akmos_cipher_xalgo_t akmos_cipher_xlist[];

extern const akmos_cipher_xmode_t akmos_xmode_ecb;
extern const akmos_cipher_xmode_t akmos_xmode_cbc;
extern const akmos_cipher_xmode_t akmos_xmode_cfb;
extern const akmos_cipher_xmode_t akmos_xmode_ctr;
extern const akmos_cipher_xmode_t akmos_xmode_ofb;

#endif  /* AKMOS_CIPHER_H */

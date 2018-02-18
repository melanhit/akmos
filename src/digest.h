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

#ifndef AKMOS_DIGEST_H
#define AKMOS_DIGEST_H

typedef union akmos_digest_algo_u akmos_digest_algo_t;

#include "algo/ripemd.h"
#include "algo/sha1.h"
#include "algo/sha2.h"
#include "algo/sha3.h"
#include "algo/tiger.h"
#include "algo/whirlpool.h"
#include "algo/skein.h"

union akmos_digest_algo_u {
    akmos_ripemd_t      ripemd;
    akmos_sha1_t        sha1;
    akmos_sha2_t        sha2;
    akmos_sha3_t        sha3;
    akmos_tiger_t       tiger;
    akmos_whirlpool_t   whirlpool;
    akmos_skein_t       skein;
};

typedef struct akmos_digest_xalgo_s {
    akmos_digest_xdesc_t desc;
    void (*init)   (akmos_digest_algo_t *);
    void (*update) (akmos_digest_algo_t *, const uint8_t *, size_t);
    void (*done)   (akmos_digest_algo_t *, uint8_t *);
} akmos_digest_xalgo_t;

struct akmos_digest_s {
    const akmos_digest_xalgo_t  *xalgo;
    akmos_digest_algo_t         actx;
};

const akmos_digest_xalgo_t *akmos_digest_xalgo(akmos_algo_id);

extern const akmos_digest_xalgo_t akmos_digest_xlist[];

#endif  /* AKMOS_DIGEST_H */

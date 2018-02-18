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

#ifndef AKMOS_MAC_H
#define AKMOS_MAC_H

typedef union akmos_mac_mode_u akmos_mac_mode_t;

#include "mode/hmac.h"
#include "mode/cmac.h"
#include "mode/cbc-mac.h"

union akmos_mac_mode_u {
    akmos_hmac_t    hmac;
    akmos_cmac_t    cmac;
    akmos_cbcmac_t  cbcmac;
};

typedef struct {
    akmos_mode_id   id;
    char *name;
    int  (*init)    (akmos_mac_mode_t *, akmos_algo_id);
    int  (*setkey)  (akmos_mac_mode_t *, const uint8_t *, size_t);
    void (*update)  (akmos_mac_mode_t *, const uint8_t *, size_t);
    int  (*done)    (akmos_mac_mode_t *, uint8_t *);
} akmos_mac_xmode_t;

struct akmos_mac_s {
    const akmos_mac_xmode_t *xmode;
    akmos_mac_mode_t        mctx;
};

extern const akmos_mac_xmode_t akmos_xmode_hmac;
extern const akmos_mac_xmode_t akmos_xmode_cmac;
extern const akmos_mac_xmode_t akmos_xmode_cbcmac;

#endif  /* AKMOS_MAC_H */

/*
 *   Copyright (c) 2014-2016, Andrew Romanenko <melanhit@gmail.com>
 *   Copyright (c) Paulo S.L.M. Barreto, Vincent Rijmen
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

#include <stdlib.h>
#include <stdint.h>

#include "../akmos.h"
#include "../bits.h"

#include "anubis.h"
#include "anubis_sb32.h"

static const uint32_t rc[] = {
    0xba542f74, 0x53d3d24d, 0x50ac8dbf, 0x70529a4c,
    0xead597d1, 0x33515ba6, 0xde48a899, 0xdb32b7fc,
    0xe39e919b, 0xe2bb416e, 0xa5cb6b95, 0xa1f3b102,
    0xccc41d14, 0xc363da5d, 0x5fdc7dcd, 0x7f5a6c5c,
    0xf726ffed, 0xe89d6f8e, 0x19a0f089
};

void akmos_anubis_setkey(akmos_anubis_t *ctx, const uint8_t *key, size_t len)
{
    int N, R, i, j, r;
    uint32_t kappa[AKMOS_ANUBIS_MAX_N];
    uint32_t inter[AKMOS_ANUBIS_MAX_N];
    uint32_t v, K0, K1, K2, K3;

    N = (len * 8) >> 5;
    ctx->R = R = 8 + N;

    for(i = 0; i < N; i++, key += 4)
        kappa[i] = PACK32LE(key);

    for (r = 0; r <= R; r++) {
        K0 = S4[(kappa[N - 1] >> 24)       ];
        K1 = S4[(kappa[N - 1] >> 16) & 0xff];
        K2 = S4[(kappa[N - 1] >>  8) & 0xff];
        K3 = S4[(kappa[N - 1]      ) & 0xff];

        for (i = N - 2; i >= 0; i--) {
            K0 = S4[(kappa[i] >> 24)       ] ^
                (S5[(K0 >> 24)       ] & 0xff000000U) ^
                (S5[(K0 >> 16) & 0xff] & 0x00ff0000U) ^
                (S5[(K0 >>  8) & 0xff] & 0x0000ff00U) ^
                (S5[(K0      ) & 0xff] & 0x000000ffU);
            K1 = S4[(kappa[i] >> 16) & 0xff] ^
                (S5[(K1 >> 24)       ] & 0xff000000U) ^
                (S5[(K1 >> 16) & 0xff] & 0x00ff0000U) ^
                (S5[(K1 >>  8) & 0xff] & 0x0000ff00U) ^
                (S5[(K1      ) & 0xff] & 0x000000ffU);
            K2 = S4[(kappa[i] >>  8) & 0xff] ^
                (S5[(K2 >> 24)       ] & 0xff000000U) ^
                (S5[(K2 >> 16) & 0xff] & 0x00ff0000U) ^
                (S5[(K2 >>  8) & 0xff] & 0x0000ff00U) ^
                (S5[(K2      ) & 0xff] & 0x000000ffU);
            K3 = S4[(kappa[i]      ) & 0xff] ^
                (S5[(K3 >> 24)       ] & 0xff000000U) ^
                (S5[(K3 >> 16) & 0xff] & 0x00ff0000U) ^
                (S5[(K3 >>  8) & 0xff] & 0x0000ff00U) ^
                (S5[(K3      ) & 0xff] & 0x000000ffU);
        }

        ctx->e_key[r][0] = K0;
        ctx->e_key[r][1] = K1;
        ctx->e_key[r][2] = K2;
        ctx->e_key[r][3] = K3;

        if (r == R)
            break;

        for (i = 0; i < N; i++) {
            j = i;
            inter[i]  = S0[(kappa[j--] >> 24)       ]; if (j < 0) j = N - 1;
            inter[i] ^= S1[(kappa[j--] >> 16) & 0xff]; if (j < 0) j = N - 1;
            inter[i] ^= S2[(kappa[j--] >>  8) & 0xff]; if (j < 0) j = N - 1;
            inter[i] ^= S3[(kappa[j  ]      ) & 0xff];
        }

        kappa[0] = inter[0] ^ rc[r];
        for (i = 1; i < N; i++)
            kappa[i] = inter[i];
    }

    for (i = 0; i < 4; i++) {
        ctx->d_key[0][i] = ctx->e_key[R][i];
        ctx->d_key[R][i] = ctx->e_key[0][i];
    }

    for (r = 1; r < R; r++) {
        for (i = 0; i < 4; i++) {
            v = ctx->e_key[R - r][i];
            ctx->d_key[r][i] =
                S0[S4[(v >> 24)       ] & 0xff] ^
                S1[S4[(v >> 16) & 0xff] & 0xff] ^
                S2[S4[(v >>  8) & 0xff] & 0xff] ^
                S3[S4[(v      ) & 0xff] & 0xff];
        }
    }
}

static void anubis_crypt(const uint32_t r_key[AKMOS_ANUBIS_MAX_R + 1][4],
                         int R,
                         const uint8_t *in_blk,
                         uint8_t *out_blk)
{
    int r;
    uint32_t state[4], inter[4];

    state[0] = PACK32LE(in_blk     ) ^ r_key[0][0];
    state[1] = PACK32LE(in_blk +  4) ^ r_key[0][1];
    state[2] = PACK32LE(in_blk +  8) ^ r_key[0][2];
    state[3] = PACK32LE(in_blk + 12) ^ r_key[0][3];

    for (r = 1; r < R; r++) {
        inter[0] =
            S0[(state[0] >> 24)       ] ^
            S1[(state[1] >> 24)       ] ^
            S2[(state[2] >> 24)       ] ^
            S3[(state[3] >> 24)       ] ^
            r_key[r][0];
        inter[1] =
            S0[(state[0] >> 16) & 0xff] ^
            S1[(state[1] >> 16) & 0xff] ^
            S2[(state[2] >> 16) & 0xff] ^
            S3[(state[3] >> 16) & 0xff] ^
            r_key[r][1];
        inter[2] =
            S0[(state[0] >>  8) & 0xff] ^
            S1[(state[1] >>  8) & 0xff] ^
            S2[(state[2] >>  8) & 0xff] ^
            S3[(state[3] >>  8) & 0xff] ^
            r_key[r][2];
        inter[3] =
            S0[(state[0]      ) & 0xff] ^
            S1[(state[1]      ) & 0xff] ^
            S2[(state[2]      ) & 0xff] ^
            S3[(state[3]      ) & 0xff] ^
            r_key[r][3];

        state[0] = inter[0];
        state[1] = inter[1];
        state[2] = inter[2];
        state[3] = inter[3];
    }

    inter[0] =
        (S0[(state[0] >> 24)       ] & 0xff000000U) ^
        (S1[(state[1] >> 24)       ] & 0x00ff0000U) ^
        (S2[(state[2] >> 24)       ] & 0x0000ff00U) ^
        (S3[(state[3] >> 24)       ] & 0x000000ffU) ^
        r_key[R][0];
    inter[1] =
        (S0[(state[0] >> 16) & 0xff] & 0xff000000U) ^
        (S1[(state[1] >> 16) & 0xff] & 0x00ff0000U) ^
        (S2[(state[2] >> 16) & 0xff] & 0x0000ff00U) ^
        (S3[(state[3] >> 16) & 0xff] & 0x000000ffU) ^
        r_key[R][1];
    inter[2] =
        (S0[(state[0] >>  8) & 0xff] & 0xff000000U) ^
        (S1[(state[1] >>  8) & 0xff] & 0x00ff0000U) ^
        (S2[(state[2] >>  8) & 0xff] & 0x0000ff00U) ^
        (S3[(state[3] >>  8) & 0xff] & 0x000000ffU) ^
        r_key[R][2];
    inter[3] =
        (S0[(state[0]      ) & 0xff] & 0xff000000U) ^
        (S1[(state[1]      ) & 0xff] & 0x00ff0000U) ^
        (S2[(state[2]      ) & 0xff] & 0x0000ff00U) ^
        (S3[(state[3]      ) & 0xff] & 0x000000ffU) ^
        r_key[R][3];

    UNPACK32LE(out_blk     , inter[0]);
    UNPACK32LE(out_blk +  4, inter[1]);
    UNPACK32LE(out_blk +  8, inter[2]);
    UNPACK32LE(out_blk + 12, inter[3]);
}

void akmos_anubis_encrypt(akmos_anubis_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    anubis_crypt((const uint32_t (*)[4])ctx->e_key, ctx->R, in_blk, out_blk);
}

void akmos_anubis_decrypt(akmos_anubis_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    anubis_crypt((const uint32_t (*)[4])ctx->d_key, ctx->R, in_blk, out_blk);
}

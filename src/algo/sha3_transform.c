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

#include <stdint.h>
#include <string.h>

#include "../bits.h"

#include "sha3.h"

static const uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008
};


static const uint32_t RO[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

#define f_theta(S)                              \
{                                               \
    C[0] = S[0] ^ S[5] ^ S[10] ^ S[15] ^ S[20]; \
    C[1] = S[1] ^ S[6] ^ S[11] ^ S[16] ^ S[21]; \
    C[2] = S[2] ^ S[7] ^ S[12] ^ S[17] ^ S[22]; \
    C[3] = S[3] ^ S[8] ^ S[13] ^ S[18] ^ S[23]; \
    C[4] = S[4] ^ S[9] ^ S[14] ^ S[19] ^ S[24]; \
                                                \
    D[0] = ROTL64(C[1], 1) ^ C[4];              \
    D[1] = ROTL64(C[2], 1) ^ C[0];              \
    D[2] = ROTL64(C[3], 1) ^ C[1];              \
    D[3] = ROTL64(C[4], 1) ^ C[2];              \
    D[4] = ROTL64(C[0], 1) ^ C[3];              \
                                                \
    S[ 0] ^= D[0]; S[ 5] ^= D[0]; S[10] ^= D[0];\
    S[15] ^= D[0]; S[20] ^= D[0];               \
                                                \
    S[ 1] ^= D[1]; S[ 6] ^= D[1]; S[11] ^= D[1];\
    S[16] ^= D[1]; S[21] ^= D[1];               \
                                                \
    S[ 2] ^= D[2]; S[ 7] ^= D[2]; S[12] ^= D[2];\
    S[17] ^= D[2]; S[22] ^= D[2];               \
                                                \
    S[ 3] ^= D[3]; S[ 8] ^= D[3]; S[13] ^= D[3];\
    S[18] ^= D[3]; S[23] ^= D[3];               \
                                                \
    S[ 4] ^= D[4]; S[ 9] ^= D[4]; S[14] ^= D[4];\
    S[19] ^= D[4]; S[24] ^= D[4];               \
}

#define f_rho_pi(S)                             \
{                                               \
/*  B[ 0] = ROTL64(S[ 0], RO[ 0]);*/            \
    B[ 0] = S[0];                               \
    B[16] = ROTL64(S[ 5], RO[ 5]);              \
    B[ 7] = ROTL64(S[10], RO[10]);              \
    B[23] = ROTL64(S[15], RO[15]);              \
    B[14] = ROTL64(S[20], RO[20]);              \
                                                \
    B[10] = ROTL64(S[ 1], RO[ 1]);              \
    B[ 1] = ROTL64(S[ 6], RO[ 6]);              \
    B[17] = ROTL64(S[11], RO[11]);              \
    B[ 8] = ROTL64(S[16], RO[16]);              \
    B[24] = ROTL64(S[21], RO[21]);              \
                                                \
    B[20] = ROTL64(S[ 2], RO[ 2]);              \
    B[11] = ROTL64(S[ 7], RO[ 7]);              \
    B[ 2] = ROTL64(S[12], RO[12]);              \
    B[18] = ROTL64(S[17], RO[17]);              \
    B[ 9] = ROTL64(S[22], RO[22]);              \
                                                \
    B[ 5] = ROTL64(S[ 3], RO[ 3]);              \
    B[21] = ROTL64(S[ 8], RO[ 8]);              \
    B[12] = ROTL64(S[13], RO[13]);              \
    B[ 3] = ROTL64(S[18], RO[18]);              \
    B[19] = ROTL64(S[23], RO[23]);              \
                                                \
    B[15] = ROTL64(S[ 4], RO[ 4]);              \
    B[ 6] = ROTL64(S[ 9], RO[ 9]);              \
    B[22] = ROTL64(S[14], RO[14]);              \
    B[13] = ROTL64(S[19], RO[19]);              \
    B[ 4] = ROTL64(S[24], RO[24]);              \
}

#define f_chi(S)                                \
{                                               \
    S[ 0] = B[ 0] ^ ((~B[ 1]) & B[ 2]);         \
    S[ 1] = B[ 1] ^ ((~B[ 2]) & B[ 3]);         \
    S[ 2] = B[ 2] ^ ((~B[ 3]) & B[ 4]);         \
    S[ 3] = B[ 3] ^ ((~B[ 4]) & B[ 0]);         \
    S[ 4] = B[ 4] ^ ((~B[ 0]) & B[ 1]);         \
                                                \
    S[ 5] = B[ 5] ^ ((~B[ 6]) & B[ 7]);         \
    S[ 6] = B[ 6] ^ ((~B[ 7]) & B[ 8]);         \
    S[ 7] = B[ 7] ^ ((~B[ 8]) & B[ 9]);         \
    S[ 8] = B[ 8] ^ ((~B[ 9]) & B[ 5]);         \
    S[ 9] = B[ 9] ^ ((~B[ 5]) & B[ 6]);         \
                                                \
    S[10] = B[10] ^ ((~B[11]) & B[12]);         \
    S[11] = B[11] ^ ((~B[12]) & B[13]);         \
    S[12] = B[12] ^ ((~B[13]) & B[14]);         \
    S[13] = B[13] ^ ((~B[14]) & B[10]);         \
    S[14] = B[14] ^ ((~B[10]) & B[11]);         \
                                                \
    S[15] = B[15] ^ ((~B[16]) & B[17]);         \
    S[16] = B[16] ^ ((~B[17]) & B[18]);         \
    S[17] = B[17] ^ ((~B[18]) & B[19]);         \
    S[18] = B[18] ^ ((~B[19]) & B[15]);         \
    S[19] = B[19] ^ ((~B[15]) & B[16]);         \
                                                \
    S[20] = B[20] ^ ((~B[21]) & B[22]);         \
    S[21] = B[21] ^ ((~B[22]) & B[23]);         \
    S[22] = B[22] ^ ((~B[23]) & B[24]);         \
    S[23] = B[23] ^ ((~B[24]) & B[20]);         \
    S[24] = B[24] ^ ((~B[20]) & B[21]);         \
}

#define f_iota(S, y)                            \
{                                               \
    S[0] ^= RC[y];                              \
}

void akmos_sha3_transform(akmos_sha3_t *ctx, const uint8_t *blk, size_t nb)
{
    uint64_t B[25], C[5], D[5];
    size_t i, y;

    for(i = 0; i < nb; i++) {
        for(y = 0; y < ctx->r; y++) {
            ctx->S[y] ^= PACK64BE(blk);
            blk += sizeof(uint64_t);
        }

        for(y = 0; y < AKMOS_SHA3_ROUNDS; y++) {
            f_theta(ctx->S);
            f_rho_pi(ctx->S);
            f_chi(ctx->S);
            f_iota(ctx->S, y);
        }
    }
}

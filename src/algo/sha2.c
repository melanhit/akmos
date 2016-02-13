/*
 *   Copyright (c) 2014-2016, Andrew Romanenko <melanhit@gmail.com>
 *   Copyright (C) 2005, 2007, Olivier Gay <olivier.gay@a3.epfl.ch>
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
#include <string.h>

#include "../akmos.h"
#include "../bits.h"

#include "sha2.h"

#define SHFR(x, n)   (x >> n)
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define SHA256_F2(x) (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SHA256_F3(x) (ROTR32(x,  7) ^ ROTR32(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHFR(x, 10))

#define SHA512_F1(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SHA512_F2(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SHA512_F3(x) (ROTR64(x,  1) ^ ROTR64(x,  8) ^ SHFR(x,  7))
#define SHA512_F4(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHFR(x,  6))

#define SHA256_SCR(i)                           \
{                                               \
    w[i] = SHA256_F4(w[i -  2]) + w[i -  7]     \
    + SHA256_F3(w[i - 15]) + w[i - 16];         \
}

#define SHA512_SCR(i)                           \
{                                               \
    w[i] =  SHA512_F4(w[i -  2]) + w[i -  7]    \
    + SHA512_F3(w[i - 15]) + w[i - 16];         \
}

#define SHA256_EXP(a, b, c, d, e, f, g, h, j)               \
{                                                           \
    t1 = wv[h] + SHA256_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
    + sha256_k[j] + w[j];                                   \
                                                            \
    t2 = SHA256_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

#define SHA512_EXP(a, b, c, d, e, f, g ,h, j)               \
{                                                           \
    t1 = wv[h] + SHA512_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
    + sha512_k[j] + w[j];                                   \
                                                            \
    t2 = SHA512_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

static const uint32_t sha224_h0[8] = {
    0xc1059ed8, 0x367cd507,
    0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511,
    0x64f98fa7, 0xbefa4fa4
};

static const uint32_t sha256_h0[8] = {
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
};

static const uint64_t sha384_h0[8] = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
    0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

static const uint64_t sha512_h0[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
    0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210,
    0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910,
    0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60,
    0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9,
    0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static void sha256_transform(akmos_sha2_256_t *ctx, const uint8_t *m, size_t nb)
{
    uint32_t w[128], *wv, t1, t2;
    const uint8_t *sub;
    size_t i;

    wv = w + 64;

    for(i = 0; i < nb; i++) {
        sub = m + (i << 6);

        w[ 0] = PACK32LE(sub     ); w[ 1] = PACK32LE(sub +  4);
        w[ 2] = PACK32LE(sub +  8); w[ 3] = PACK32LE(sub + 12);
        w[ 4] = PACK32LE(sub + 16); w[ 5] = PACK32LE(sub + 20);
        w[ 6] = PACK32LE(sub + 24); w[ 7] = PACK32LE(sub + 28);
        w[ 8] = PACK32LE(sub + 32); w[ 9] = PACK32LE(sub + 36);
        w[10] = PACK32LE(sub + 40); w[11] = PACK32LE(sub + 44);
        w[12] = PACK32LE(sub + 48); w[13] = PACK32LE(sub + 52);
        w[14] = PACK32LE(sub + 56); w[15] = PACK32LE(sub + 60);

        SHA256_SCR(16); SHA256_SCR(17); SHA256_SCR(18); SHA256_SCR(19);
        SHA256_SCR(20); SHA256_SCR(21); SHA256_SCR(22); SHA256_SCR(23);
        SHA256_SCR(24); SHA256_SCR(25); SHA256_SCR(26); SHA256_SCR(27);
        SHA256_SCR(28); SHA256_SCR(29); SHA256_SCR(30); SHA256_SCR(31);
        SHA256_SCR(32); SHA256_SCR(33); SHA256_SCR(34); SHA256_SCR(35);
        SHA256_SCR(36); SHA256_SCR(37); SHA256_SCR(38); SHA256_SCR(39);
        SHA256_SCR(40); SHA256_SCR(41); SHA256_SCR(42); SHA256_SCR(43);
        SHA256_SCR(44); SHA256_SCR(45); SHA256_SCR(46); SHA256_SCR(47);
        SHA256_SCR(48); SHA256_SCR(49); SHA256_SCR(50); SHA256_SCR(51);
        SHA256_SCR(52); SHA256_SCR(53); SHA256_SCR(54); SHA256_SCR(55);
        SHA256_SCR(56); SHA256_SCR(57); SHA256_SCR(58); SHA256_SCR(59);
        SHA256_SCR(60); SHA256_SCR(61); SHA256_SCR(62); SHA256_SCR(63);

        wv[0] = ctx->h[0]; wv[1] = ctx->h[1];
        wv[2] = ctx->h[2]; wv[3] = ctx->h[3];
        wv[4] = ctx->h[4]; wv[5] = ctx->h[5];
        wv[6] = ctx->h[6]; wv[7] = ctx->h[7];

        SHA256_EXP(0,1,2,3,4,5,6,7, 0); SHA256_EXP(7,0,1,2,3,4,5,6, 1);
        SHA256_EXP(6,7,0,1,2,3,4,5, 2); SHA256_EXP(5,6,7,0,1,2,3,4, 3);
        SHA256_EXP(4,5,6,7,0,1,2,3, 4); SHA256_EXP(3,4,5,6,7,0,1,2, 5);
        SHA256_EXP(2,3,4,5,6,7,0,1, 6); SHA256_EXP(1,2,3,4,5,6,7,0, 7);
        SHA256_EXP(0,1,2,3,4,5,6,7, 8); SHA256_EXP(7,0,1,2,3,4,5,6, 9);
        SHA256_EXP(6,7,0,1,2,3,4,5,10); SHA256_EXP(5,6,7,0,1,2,3,4,11);
        SHA256_EXP(4,5,6,7,0,1,2,3,12); SHA256_EXP(3,4,5,6,7,0,1,2,13);
        SHA256_EXP(2,3,4,5,6,7,0,1,14); SHA256_EXP(1,2,3,4,5,6,7,0,15);
        SHA256_EXP(0,1,2,3,4,5,6,7,16); SHA256_EXP(7,0,1,2,3,4,5,6,17);
        SHA256_EXP(6,7,0,1,2,3,4,5,18); SHA256_EXP(5,6,7,0,1,2,3,4,19);
        SHA256_EXP(4,5,6,7,0,1,2,3,20); SHA256_EXP(3,4,5,6,7,0,1,2,21);
        SHA256_EXP(2,3,4,5,6,7,0,1,22); SHA256_EXP(1,2,3,4,5,6,7,0,23);
        SHA256_EXP(0,1,2,3,4,5,6,7,24); SHA256_EXP(7,0,1,2,3,4,5,6,25);
        SHA256_EXP(6,7,0,1,2,3,4,5,26); SHA256_EXP(5,6,7,0,1,2,3,4,27);
        SHA256_EXP(4,5,6,7,0,1,2,3,28); SHA256_EXP(3,4,5,6,7,0,1,2,29);
        SHA256_EXP(2,3,4,5,6,7,0,1,30); SHA256_EXP(1,2,3,4,5,6,7,0,31);
        SHA256_EXP(0,1,2,3,4,5,6,7,32); SHA256_EXP(7,0,1,2,3,4,5,6,33);
        SHA256_EXP(6,7,0,1,2,3,4,5,34); SHA256_EXP(5,6,7,0,1,2,3,4,35);
        SHA256_EXP(4,5,6,7,0,1,2,3,36); SHA256_EXP(3,4,5,6,7,0,1,2,37);
        SHA256_EXP(2,3,4,5,6,7,0,1,38); SHA256_EXP(1,2,3,4,5,6,7,0,39);
        SHA256_EXP(0,1,2,3,4,5,6,7,40); SHA256_EXP(7,0,1,2,3,4,5,6,41);
        SHA256_EXP(6,7,0,1,2,3,4,5,42); SHA256_EXP(5,6,7,0,1,2,3,4,43);
        SHA256_EXP(4,5,6,7,0,1,2,3,44); SHA256_EXP(3,4,5,6,7,0,1,2,45);
        SHA256_EXP(2,3,4,5,6,7,0,1,46); SHA256_EXP(1,2,3,4,5,6,7,0,47);
        SHA256_EXP(0,1,2,3,4,5,6,7,48); SHA256_EXP(7,0,1,2,3,4,5,6,49);
        SHA256_EXP(6,7,0,1,2,3,4,5,50); SHA256_EXP(5,6,7,0,1,2,3,4,51);
        SHA256_EXP(4,5,6,7,0,1,2,3,52); SHA256_EXP(3,4,5,6,7,0,1,2,53);
        SHA256_EXP(2,3,4,5,6,7,0,1,54); SHA256_EXP(1,2,3,4,5,6,7,0,55);
        SHA256_EXP(0,1,2,3,4,5,6,7,56); SHA256_EXP(7,0,1,2,3,4,5,6,57);
        SHA256_EXP(6,7,0,1,2,3,4,5,58); SHA256_EXP(5,6,7,0,1,2,3,4,59);
        SHA256_EXP(4,5,6,7,0,1,2,3,60); SHA256_EXP(3,4,5,6,7,0,1,2,61);
        SHA256_EXP(2,3,4,5,6,7,0,1,62); SHA256_EXP(1,2,3,4,5,6,7,0,63);

        ctx->h[0] += wv[0]; ctx->h[1] += wv[1];
        ctx->h[2] += wv[2]; ctx->h[3] += wv[3];
        ctx->h[4] += wv[4]; ctx->h[5] += wv[5];
        ctx->h[6] += wv[6]; ctx->h[7] += wv[7];
    }

    akmos_memzero(w, sizeof(w));
}

static void sha512_transform(akmos_sha2_512_t *ctx, const uint8_t *m, size_t nb)
{
    uint64_t w[88], *wv, t1, t2;
    const uint8_t *sub;
    size_t i, j;

    wv = w + 80;

    for(i = 0; i <  nb; i++) {
        sub = m + (i << 7);

        w[ 0] = PACK64LE(sub      ); w[ 1] = PACK64LE(sub +  8);
        w[ 2] = PACK64LE(sub +  16); w[ 3] = PACK64LE(sub +  24);
        w[ 4] = PACK64LE(sub +  32); w[ 5] = PACK64LE(sub +  40);
        w[ 6] = PACK64LE(sub +  48); w[ 7] = PACK64LE(sub +  56);
        w[ 8] = PACK64LE(sub +  64); w[ 9] = PACK64LE(sub +  72);
        w[10] = PACK64LE(sub +  80); w[11] = PACK64LE(sub +  88);
        w[12] = PACK64LE(sub +  96); w[13] = PACK64LE(sub + 104);
        w[14] = PACK64LE(sub + 112); w[15] = PACK64LE(sub + 120);

        SHA512_SCR(16); SHA512_SCR(17); SHA512_SCR(18); SHA512_SCR(19);
        SHA512_SCR(20); SHA512_SCR(21); SHA512_SCR(22); SHA512_SCR(23);
        SHA512_SCR(24); SHA512_SCR(25); SHA512_SCR(26); SHA512_SCR(27);
        SHA512_SCR(28); SHA512_SCR(29); SHA512_SCR(30); SHA512_SCR(31);
        SHA512_SCR(32); SHA512_SCR(33); SHA512_SCR(34); SHA512_SCR(35);
        SHA512_SCR(36); SHA512_SCR(37); SHA512_SCR(38); SHA512_SCR(39);
        SHA512_SCR(40); SHA512_SCR(41); SHA512_SCR(42); SHA512_SCR(43);
        SHA512_SCR(44); SHA512_SCR(45); SHA512_SCR(46); SHA512_SCR(47);
        SHA512_SCR(48); SHA512_SCR(49); SHA512_SCR(50); SHA512_SCR(51);
        SHA512_SCR(52); SHA512_SCR(53); SHA512_SCR(54); SHA512_SCR(55);
        SHA512_SCR(56); SHA512_SCR(57); SHA512_SCR(58); SHA512_SCR(59);
        SHA512_SCR(60); SHA512_SCR(61); SHA512_SCR(62); SHA512_SCR(63);
        SHA512_SCR(64); SHA512_SCR(65); SHA512_SCR(66); SHA512_SCR(67);
        SHA512_SCR(68); SHA512_SCR(69); SHA512_SCR(70); SHA512_SCR(71);
        SHA512_SCR(72); SHA512_SCR(73); SHA512_SCR(74); SHA512_SCR(75);
        SHA512_SCR(76); SHA512_SCR(77); SHA512_SCR(78); SHA512_SCR(79);

        wv[0] = ctx->h[0]; wv[1] = ctx->h[1];
        wv[2] = ctx->h[2]; wv[3] = ctx->h[3];
        wv[4] = ctx->h[4]; wv[5] = ctx->h[5];
        wv[6] = ctx->h[6]; wv[7] = ctx->h[7];

        j = 0;

        do {
            SHA512_EXP(0,1,2,3,4,5,6,7,j); j++;
            SHA512_EXP(7,0,1,2,3,4,5,6,j); j++;
            SHA512_EXP(6,7,0,1,2,3,4,5,j); j++;
            SHA512_EXP(5,6,7,0,1,2,3,4,j); j++;
            SHA512_EXP(4,5,6,7,0,1,2,3,j); j++;
            SHA512_EXP(3,4,5,6,7,0,1,2,j); j++;
            SHA512_EXP(2,3,4,5,6,7,0,1,j); j++;
            SHA512_EXP(1,2,3,4,5,6,7,0,j); j++;
        } while (j < 80);

        ctx->h[0] += wv[0]; ctx->h[1] += wv[1];
        ctx->h[2] += wv[2]; ctx->h[3] += wv[3];
        ctx->h[4] += wv[4]; ctx->h[5] += wv[5];
        ctx->h[6] += wv[6]; ctx->h[7] += wv[7];

    }

    akmos_memzero(w, sizeof(w));
}

void akmos_sha2_224_init(akmos_sha2_256_t *ctx)
{
    ctx->h[0] = sha224_h0[0];
    ctx->h[1] = sha224_h0[1];
    ctx->h[2] = sha224_h0[2];
    ctx->h[3] = sha224_h0[3];
    ctx->h[4] = sha224_h0[4];
    ctx->h[5] = sha224_h0[5];
    ctx->h[6] = sha224_h0[6];
    ctx->h[7] = sha224_h0[7];

    ctx->total = ctx->len = 0;
    ctx->diglen = AKMOS_SHA2_224_DIGLEN;
}

void akmos_sha2_256_init(akmos_sha2_256_t *ctx)
{
    ctx->h[0] = sha256_h0[0];
    ctx->h[1] = sha256_h0[1];
    ctx->h[2] = sha256_h0[2];
    ctx->h[3] = sha256_h0[3];
    ctx->h[4] = sha256_h0[4];
    ctx->h[5] = sha256_h0[5];
    ctx->h[6] = sha256_h0[6];
    ctx->h[7] = sha256_h0[7];

    ctx->total = ctx->len = 0;
    ctx->diglen = AKMOS_SHA2_256_DIGLEN;
}

void akmos_sha2_256_update(akmos_sha2_256_t *ctx, const uint8_t *input, size_t len)
{
    uint32_t nb, new_len, rem_len, tmp_len;
    const uint8_t *sfi;

    tmp_len = AKMOS_SHA2_256_BLKLEN - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], input, rem_len);

    if(ctx->len + len < AKMOS_SHA2_256_BLKLEN) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    nb = new_len / AKMOS_SHA2_256_BLKLEN;

    sfi = input + rem_len;

    sha256_transform(ctx, ctx->block, 1);
    sha256_transform(ctx, sfi, nb);

    rem_len = new_len % AKMOS_SHA2_256_BLKLEN;

    memcpy(ctx->block, &sfi[nb << 6], rem_len);

    ctx->len = rem_len;
    ctx->total += (nb + 1) << 6;
}

void akmos_sha2_256_done(akmos_sha2_256_t *ctx, uint8_t *digest)
{
    uint32_t i, nb, pm_len;
    uint64_t len_b;

    nb = (1 + ((AKMOS_SHA2_256_BLKLEN - 9) < (ctx->len % AKMOS_SHA2_256_BLKLEN)));

    len_b = (ctx->total + ctx->len) << 3;
    pm_len = nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK64LE(ctx->block + pm_len - 8, len_b);

    if(nb > 0)
        sha256_transform(ctx, ctx->block, nb);

    for(i = 0; i < ctx->diglen / (sizeof(uint32_t)); i++)
        UNPACK32LE(digest + (i * sizeof(uint32_t)), ctx->h[i]);
}

void akmos_sha2_384_init(akmos_sha2_512_t *ctx)
{
    ctx->h[0] = sha384_h0[0];
    ctx->h[1] = sha384_h0[1];
    ctx->h[2] = sha384_h0[2];
    ctx->h[3] = sha384_h0[3];
    ctx->h[4] = sha384_h0[4];
    ctx->h[5] = sha384_h0[5];
    ctx->h[6] = sha384_h0[6];
    ctx->h[7] = sha384_h0[7];

    ctx->total = ctx->len = 0;
    ctx->diglen = AKMOS_SHA2_384_DIGLEN;
}

void akmos_sha2_512_init(akmos_sha2_512_t *ctx)
{
    ctx->h[0] = sha512_h0[0];
    ctx->h[1] = sha512_h0[1];
    ctx->h[2] = sha512_h0[2];
    ctx->h[3] = sha512_h0[3];
    ctx->h[4] = sha512_h0[4];
    ctx->h[5] = sha512_h0[5];
    ctx->h[6] = sha512_h0[6];
    ctx->h[7] = sha512_h0[7];

    ctx->total = ctx->len = 0;
    ctx->diglen = AKMOS_SHA2_512_DIGLEN;
}

void akmos_sha2_512_update(akmos_sha2_512_t *ctx, const uint8_t *input, size_t len)
{
    uint32_t nb, new_len, rem_len, tmp_len;
    const uint8_t *sfi;

    tmp_len = AKMOS_SHA2_512_BLKLEN - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], input, rem_len);

    if(ctx->len + len < AKMOS_SHA2_512_BLKLEN) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    nb = new_len / AKMOS_SHA2_512_BLKLEN;

    sfi = input + rem_len;

    sha512_transform(ctx, ctx->block, 1);
    sha512_transform(ctx, sfi, nb);

    rem_len = new_len % AKMOS_SHA2_512_BLKLEN;

    memcpy(ctx->block, &sfi[nb << 7], rem_len);

    ctx->len = rem_len;
    ctx->total += (nb + 1) << 7;
}

void akmos_sha2_512_done(akmos_sha2_512_t *ctx, uint8_t *digest)
{
    uint32_t i, nb, pm_len;
    uint64_t len_b;

    nb = (1 + ((AKMOS_SHA2_512_BLKLEN - 17) < (ctx->len % AKMOS_SHA2_512_BLKLEN)));

    len_b = (ctx->total + ctx->len) << 3;
    pm_len = nb << 7;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK64LE(ctx->block + pm_len - 8, len_b);

    if(nb > 0)
        sha512_transform(ctx, ctx->block, nb);

    for(i = 0; i < ctx->diglen / (sizeof(uint64_t)); i++)
        UNPACK64LE(digest + (i * sizeof(uint64_t)), ctx->h[i]);
}

/*
 *   Copyright (c) 2014-2018, Andrew Romanenko <melanhit@gmail.com>
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

#include <config.h>

#include "../akmos.h"
#include "../bits.h"
#include "../digest.h"

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
    + tw[j];                                                \
                                                            \
    t2 = SHA256_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

#define SHA512_EXP(a, b, c, d, e, f, g ,h, j)               \
{                                                           \
    t1 = wv[h] + SHA512_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
    + tw[j];                                                \
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
    UINT64_C(0xcbbb9d5dc1059ed8), UINT64_C(0x629a292a367cd507),
    UINT64_C(0x9159015a3070dd17), UINT64_C(0x152fecd8f70e5939),
    UINT64_C(0x67332667ffc00b31), UINT64_C(0x8eb44a8768581511),
    UINT64_C(0xdb0c2e0d64f98fa7), UINT64_C(0x47b5481dbefa4fa4)
};

static const uint64_t sha512_h0[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
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
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)
};

static void sha256_transform(void *h32, const uint8_t *blk, size_t nb)
{
    uint32_t wv[8];
    uint32_t *h, *w, *tw, t1, t2;
    size_t i, j;

    h = h32;
    w = h + 8;

    for(i = 0; i < nb; i++, blk += AKMOS_SHA2_256_BLKLEN) {
        w[ 0] = PACK32LE(blk     ); w[ 1] = PACK32LE(blk +  4);
        w[ 2] = PACK32LE(blk +  8); w[ 3] = PACK32LE(blk + 12);
        w[ 4] = PACK32LE(blk + 16); w[ 5] = PACK32LE(blk + 20);
        w[ 6] = PACK32LE(blk + 24); w[ 7] = PACK32LE(blk + 28);
        w[ 8] = PACK32LE(blk + 32); w[ 9] = PACK32LE(blk + 36);
        w[10] = PACK32LE(blk + 40); w[11] = PACK32LE(blk + 44);
        w[12] = PACK32LE(blk + 48); w[13] = PACK32LE(blk + 52);
        w[14] = PACK32LE(blk + 56); w[15] = PACK32LE(blk + 60);

        for(j = 16; j < 64; j++)
            SHA256_SCR(j);

        for(j = 0; j < 64; j++)
            w[j] += sha256_k[j];

        wv[0] = h[0]; wv[1] = h[1];
        wv[2] = h[2]; wv[3] = h[3];
        wv[4] = h[4]; wv[5] = h[5];
        wv[6] = h[6]; wv[7] = h[7];

        tw = w;
        for(j = 0; j < 64; j += 8, tw += 8) {
            SHA256_EXP(0,1,2,3,4,5,6,7, 0);
            SHA256_EXP(7,0,1,2,3,4,5,6, 1);
            SHA256_EXP(6,7,0,1,2,3,4,5, 2);
            SHA256_EXP(5,6,7,0,1,2,3,4, 3);
            SHA256_EXP(4,5,6,7,0,1,2,3, 4);
            SHA256_EXP(3,4,5,6,7,0,1,2, 5);
            SHA256_EXP(2,3,4,5,6,7,0,1, 6);
            SHA256_EXP(1,2,3,4,5,6,7,0, 7);
        }

        h[0] += wv[0]; h[1] += wv[1];
        h[2] += wv[2]; h[3] += wv[3];
        h[4] += wv[4]; h[5] += wv[5];
        h[6] += wv[6]; h[7] += wv[7];
    }
}

static void sha512_transform(void *h64, const uint8_t *blk, size_t nb)
{
    uint64_t wv[8];
    uint64_t *h, *w, *tw, t1, t2;
    size_t i, j;

    h = h64;
    w = h + 8;

    for(i = 0; i <  nb; i++, blk += AKMOS_SHA2_512_BLKLEN) {
        w[ 0] = PACK64LE(blk      ); w[ 1] = PACK64LE(blk +  8);
        w[ 2] = PACK64LE(blk +  16); w[ 3] = PACK64LE(blk +  24);
        w[ 4] = PACK64LE(blk +  32); w[ 5] = PACK64LE(blk +  40);
        w[ 6] = PACK64LE(blk +  48); w[ 7] = PACK64LE(blk +  56);
        w[ 8] = PACK64LE(blk +  64); w[ 9] = PACK64LE(blk +  72);
        w[10] = PACK64LE(blk +  80); w[11] = PACK64LE(blk +  88);
        w[12] = PACK64LE(blk +  96); w[13] = PACK64LE(blk + 104);
        w[14] = PACK64LE(blk + 112); w[15] = PACK64LE(blk + 120);

        for(j = 16; j < 80; j++)
            SHA512_SCR(j);

        wv[0] = h[0]; wv[1] = h[1];
        wv[2] = h[2]; wv[3] = h[3];
        wv[4] = h[4]; wv[5] = h[5];
        wv[6] = h[6]; wv[7] = h[7];

        for(j = 0; j < 80; j++)
            w[j] += sha512_k[j];

        tw = w;
        for(j = 0; j < 80; j += 8, tw += 8) {
            SHA512_EXP(0,1,2,3,4,5,6,7,0);
            SHA512_EXP(7,0,1,2,3,4,5,6,1);
            SHA512_EXP(6,7,0,1,2,3,4,5,2);
            SHA512_EXP(5,6,7,0,1,2,3,4,3);
            SHA512_EXP(4,5,6,7,0,1,2,3,4);
            SHA512_EXP(3,4,5,6,7,0,1,2,5);
            SHA512_EXP(2,3,4,5,6,7,0,1,6);
            SHA512_EXP(1,2,3,4,5,6,7,0,7);
        }

        h[0] += wv[0]; h[1] += wv[1];
        h[2] += wv[2]; h[3] += wv[3];
        h[4] += wv[4]; h[5] += wv[5];
        h[6] += wv[6]; h[7] += wv[7];

    }
}

static void sha256_out(struct akmos_sha2_s *ctx, uint8_t *digest)
{
    size_t i;

    for(i = 0; i < ctx->diglen / (sizeof(uint32_t)); i++)
        UNPACK32LE(digest + (i * sizeof(uint32_t)), ctx->h.h32[i]);
}

static void sha512_out(struct akmos_sha2_s *ctx, uint8_t *digest)
{
    size_t i;

    for(i = 0; i < ctx->diglen / (sizeof(uint64_t)); i++)
        UNPACK64LE(digest + (i * sizeof(uint64_t)), ctx->h.h64[i]);
}

void akmos_sha2_224_init(akmos_digest_algo_t *uctx)
{
    akmos_sha2_t *ctx;

    ctx = &uctx->sha2;

    ctx->h.h32[0] = sha224_h0[0];
    ctx->h.h32[1] = sha224_h0[1];
    ctx->h.h32[2] = sha224_h0[2];
    ctx->h.h32[3] = sha224_h0[3];
    ctx->h.h32[4] = sha224_h0[4];
    ctx->h.h32[5] = sha224_h0[5];
    ctx->h.h32[6] = sha224_h0[6];
    ctx->h.h32[7] = sha224_h0[7];

    ctx->total  = ctx->len = 0;
    ctx->diglen = AKMOS_SHA2_224_DIGLEN;
    ctx->blklen = AKMOS_SHA2_224_BLKLEN;

    ctx->transform = sha256_transform;
    ctx->out       = sha256_out;
}

void akmos_sha2_256_init(akmos_digest_algo_t *uctx)
{
    akmos_sha2_t *ctx;

    ctx = &uctx->sha2;

    ctx->h.h32[0] = sha256_h0[0];
    ctx->h.h32[1] = sha256_h0[1];
    ctx->h.h32[2] = sha256_h0[2];
    ctx->h.h32[3] = sha256_h0[3];
    ctx->h.h32[4] = sha256_h0[4];
    ctx->h.h32[5] = sha256_h0[5];
    ctx->h.h32[6] = sha256_h0[6];
    ctx->h.h32[7] = sha256_h0[7];

    ctx->total  = ctx->len = 0;
    ctx->diglen = AKMOS_SHA2_256_DIGLEN;
    ctx->blklen = AKMOS_SHA2_256_BLKLEN;

    ctx->transform = sha256_transform;
    ctx->out       = sha256_out;
}

void akmos_sha2_384_init(akmos_digest_algo_t *uctx)
{
    akmos_sha2_t *ctx;

    ctx = &uctx->sha2;

    ctx->h.h64[0] = sha384_h0[0];
    ctx->h.h64[1] = sha384_h0[1];
    ctx->h.h64[2] = sha384_h0[2];
    ctx->h.h64[3] = sha384_h0[3];
    ctx->h.h64[4] = sha384_h0[4];
    ctx->h.h64[5] = sha384_h0[5];
    ctx->h.h64[6] = sha384_h0[6];
    ctx->h.h64[7] = sha384_h0[7];

    ctx->total  = ctx->len = 0;
    ctx->diglen = AKMOS_SHA2_384_DIGLEN;
    ctx->blklen = AKMOS_SHA2_384_BLKLEN;

    ctx->transform = sha512_transform;
    ctx->out       = sha512_out;
}

void akmos_sha2_512_init(akmos_digest_algo_t *uctx)
{
    akmos_sha2_t *ctx;

    ctx = &uctx->sha2;

    ctx->h.h64[0] = sha512_h0[0];
    ctx->h.h64[1] = sha512_h0[1];
    ctx->h.h64[2] = sha512_h0[2];
    ctx->h.h64[3] = sha512_h0[3];
    ctx->h.h64[4] = sha512_h0[4];
    ctx->h.h64[5] = sha512_h0[5];
    ctx->h.h64[6] = sha512_h0[6];
    ctx->h.h64[7] = sha512_h0[7];

    ctx->total  = ctx->len = 0;
    ctx->diglen = AKMOS_SHA2_512_DIGLEN;
    ctx->blklen = AKMOS_SHA2_512_BLKLEN;

    ctx->transform = sha512_transform;
    ctx->out       = sha512_out;
}

void akmos_sha2_update(akmos_digest_algo_t *uctx, const uint8_t *input, size_t len)
{
    akmos_sha2_t *ctx;
    size_t nb, tmp_len;

    ctx = &uctx->sha2;

    tmp_len = len + ctx->len;

    if(tmp_len < ctx->blklen) {
        memcpy(ctx->block + ctx->len, input, len);
        ctx->len += len;
        return;
    }

    if(ctx->len) {
        tmp_len = ctx->blklen - ctx->len;
        memcpy(ctx->block + ctx->len, input, tmp_len);

        ctx->transform(&ctx->h, ctx->block, 1 & SIZE_T_MAX);

        ctx->len = 0;
        ctx->total++;

        len -= tmp_len;
        input += tmp_len;
    }

    nb = len / ctx->blklen;
    if(nb)
        ctx->transform(&ctx->h, input, nb);

    tmp_len = len % ctx->blklen;
    if(tmp_len) {
        memcpy(ctx->block, input + (len - tmp_len), tmp_len);
        ctx->len = tmp_len;
    }

    ctx->total += nb;
}

void akmos_sha2_done(akmos_digest_algo_t *uctx, uint8_t *digest)
{
    akmos_sha2_t *ctx;
    uint64_t len_b;

    ctx = &uctx->sha2;

    len_b = ((ctx->total * ctx->blklen) + ctx->len) * 8;
    ctx->block[ctx->len] = 0x80;
    ctx->len++;

    if(ctx->len > (ctx->blklen - sizeof(uint64_t))) {
        memset(ctx->block + ctx->len, 0, ctx->blklen - ctx->len);
        ctx->transform(&ctx->h, ctx->block, 1);
        ctx->len = 0;
    }

    memset(ctx->block + ctx->len, 0, ctx->blklen - ctx->len);
    UNPACK64LE(ctx->block + (ctx->blklen - sizeof(uint64_t)), len_b);
    ctx->transform(&ctx->h, ctx->block, 1);

    ctx->out(ctx, digest);
}

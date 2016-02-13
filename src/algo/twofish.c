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

#include <stdlib.h>
#include <stdint.h>

#include "../akmos.h"
#include "../bits.h"

#include "twofish.h"
#include "twofish_sb32.h"

#define q(n,x)  q_tab[n][x]

static uint32_t h_fun(akmos_twofish_t *ctx, const uint32_t x, const uint32_t *key)
{
    uint32_t  b0, b1, b2, b3;

    b0 = EXTBYTE(x, 0);
    b1 = EXTBYTE(x, 1);
    b2 = EXTBYTE(x, 2);
    b3 = EXTBYTE(x, 3);

    switch (ctx->k_len) {
        case 4:
            b0 = Q1[(uint8_t) b0] ^ EXTBYTE(key[3],0);
            b1 = Q0[(uint8_t) b1] ^ EXTBYTE(key[3],1);
            b2 = Q0[(uint8_t) b2] ^ EXTBYTE(key[3],2);
            b3 = Q1[(uint8_t) b3] ^ EXTBYTE(key[3],3);
        case 3:
            b0 = Q1[(uint8_t) b0] ^ EXTBYTE(key[2],0);
            b1 = Q1[(uint8_t) b1] ^ EXTBYTE(key[2],1);
            b2 = Q0[(uint8_t) b2] ^ EXTBYTE(key[2],2);
            b3 = Q0[(uint8_t) b3] ^ EXTBYTE(key[2],3);
        case 2:
            b0 = Q0[(uint8_t) (Q0[(uint8_t) b0] ^ EXTBYTE(key[1],0))] ^ EXTBYTE(key[0],0);
            b1 = Q0[(uint8_t) (Q1[(uint8_t) b1] ^ EXTBYTE(key[1],1))] ^ EXTBYTE(key[0],1);
            b2 = Q1[(uint8_t) (Q0[(uint8_t) b2] ^ EXTBYTE(key[1],2))] ^ EXTBYTE(key[0],2);
            b3 = Q1[(uint8_t) (Q1[(uint8_t) b3] ^ EXTBYTE(key[1],3))] ^ EXTBYTE(key[0],3);
    }

    return  S0[b0] ^ S1[b1] ^ S2[b2] ^ S3[b3];

}

#define q20(x)  Q0[Q0[x] ^ EXTBYTE(key[1],0)] ^ EXTBYTE(key[0],0)
#define q21(x)  Q0[Q1[x] ^ EXTBYTE(key[1],1)] ^ EXTBYTE(key[0],1)
#define q22(x)  Q1[Q0[x] ^ EXTBYTE(key[1],2)] ^ EXTBYTE(key[0],2)
#define q23(x)  Q1[Q1[x] ^ EXTBYTE(key[1],3)] ^ EXTBYTE(key[0],3)

#define q30(x)  Q0[Q0[Q1[x] ^ EXTBYTE(key[2],0)] ^ EXTBYTE(key[1],0)] ^ EXTBYTE(key[0],0)
#define q31(x)  Q0[Q1[Q1[x] ^ EXTBYTE(key[2],1)] ^ EXTBYTE(key[1],1)] ^ EXTBYTE(key[0],1)
#define q32(x)  Q1[Q0[Q0[x] ^ EXTBYTE(key[2],2)] ^ EXTBYTE(key[1],2)] ^ EXTBYTE(key[0],2)
#define q33(x)  Q1[Q1[Q0[x] ^ EXTBYTE(key[2],3)] ^ EXTBYTE(key[1],3)] ^ EXTBYTE(key[0],3)

#define q40(x)  Q0[Q0[Q1[Q1[x] ^ EXTBYTE(key[3],0)] ^ EXTBYTE(key[2],0)] ^ EXTBYTE(key[1],0)] ^ EXTBYTE(key[0],0)
#define q41(x)  Q0[Q1[Q1[Q0[x] ^ EXTBYTE(key[3],1)] ^ EXTBYTE(key[2],1)] ^ EXTBYTE(key[1],1)] ^ EXTBYTE(key[0],1)
#define q42(x)  Q1[Q0[Q0[Q0[x] ^ EXTBYTE(key[3],2)] ^ EXTBYTE(key[2],2)] ^ EXTBYTE(key[1],2)] ^ EXTBYTE(key[0],2)
#define q43(x)  Q1[Q1[Q0[Q1[x] ^ EXTBYTE(key[3],3)] ^ EXTBYTE(key[2],3)] ^ EXTBYTE(key[1],3)] ^ EXTBYTE(key[0],3)

static void gen_mk_tab(akmos_twofish_t *ctx, uint32_t *key)
{
    uint32_t  i;
    uint8_t  by;

    uint32_t *mk_tab = ctx->mk_tab;

    switch (ctx->k_len) {
        case 2:
            for (i = 0; i < 256; ++i) {
                by = (uint8_t)i;
                mk_tab[0 + 4*i] = S0[q20(by)];
                mk_tab[1 + 4*i] = S1[q21(by)];
                mk_tab[2 + 4*i] = S2[q22(by)];
                mk_tab[3 + 4*i] = S3[q23(by)];
            }
            break;

        case 3:
            for (i = 0; i < 256; ++i) {
                by = (uint8_t)i;
                mk_tab[0 + 4*i] = S0[q30(by)];
                mk_tab[1 + 4*i] = S1[q31(by)];
                mk_tab[2 + 4*i] = S2[q32(by)];
                mk_tab[3 + 4*i] = S3[q33(by)];
            }
            break;

        case 4:
            for (i = 0; i < 256; ++i) {
                by = (uint8_t)i;
                mk_tab[0 + 4*i] = S0[q40(by)];
                mk_tab[1 + 4*i] = S1[q41(by)];
                mk_tab[2 + 4*i] = S2[q42(by)];
                mk_tab[3 + 4*i] = S3[q43(by)];
            }
    }
}

#define g0_fun(x) ( mk_tab[0 + 4*EXTBYTE(x,0)] ^ mk_tab[1 + 4*EXTBYTE(x,1)] \
                    ^ mk_tab[2 + 4*EXTBYTE(x,2)] ^ mk_tab[3 + 4*EXTBYTE(x,3)] )
#define g1_fun(x) ( mk_tab[0 + 4*EXTBYTE(x,3)] ^ mk_tab[1 + 4*EXTBYTE(x,0)] \
                    ^ mk_tab[2 + 4*EXTBYTE(x,1)] ^ mk_tab[3 + 4*EXTBYTE(x,2)] )


/* The (12,8) Reed Soloman code has the generator polynomial */

#define G_MOD   0x0000014d

static uint32_t mds_rem(uint32_t p0, uint32_t p1)
{
    uint32_t  i, t, u;

    for (i = 0; i < 8; ++i) {
        t = p1 >> 24;                   /* get most significant coefficient */
        p1 = (p1 << 8) | (p0 >> 24); p0 <<= 8;  /* shift others up */

        /* multiply t by a (the primitive element - i.e. left shift) */
        u = (t << 1);
        if (t & 0x80)                   /* subtract modular polynomial on overflow */
            u ^= G_MOD;

        p1 ^= t ^ (u << 16);            /* remove t * (a * x^2 + 1) */
        u ^= (t >> 1);                  /* form u = a * t + t / a = t * (a + 1 / a); */

        if (t & 0x01)                   /* add the modular polynomial on underflow */
            u ^= G_MOD >> 1;

        p1 ^= (u << 24) | (u << 8);     /* remove t * (a + 1/a) * (x^3 + x) */
    }

    return p1;
}

void akmos_twofish_setkey(akmos_twofish_t *ctx, const uint8_t *in_key, size_t len)
{
    uint32_t  i, a, b, me_key[8], *mo_key;
    uint32_t *l_key, *s_key;

    mo_key = me_key + 4;

    l_key = ctx->l_key;
    s_key = ctx->s_key;

    ctx->k_len = len / 8;   /* 2, 3 or 4 */

    for (i = 0; i < ctx->k_len; ++i) {
        a = PACK32BE(in_key + i*8);
        me_key[i] = a;

        b = PACK32BE(in_key + ((i+i+1)*4));
        mo_key[i] = b;

        s_key[ctx->k_len - i - 1] = mds_rem(a, b);
    }

    for (i = 0; i < 40; i += 2) {
        a = 0x01010101 * i;
        b = a + 0x01010101;

        a = h_fun(ctx, a, me_key);
        b = ROTL32(h_fun(ctx, b, mo_key), 8);
        l_key[i] = a + b;
        l_key[i + 1] = ROTL32(a + 2 * b, 9);
    }

    gen_mk_tab(ctx, s_key);

    akmos_memzero(me_key, sizeof(me_key));
}

/* encrypt a block of text  */
#define f_rnd(i)                                                    \
    t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);                       \
    blk[2] = ROTR32(blk[2] ^ (t0 + t1 + l_key[4 * (i) + 8]), 1);    \
    blk[3] = ROTL32(blk[3], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 9]);\
    t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);                       \
    blk[0] = ROTR32(blk[0] ^ (t0 + t1 + l_key[4 * (i) + 10]), 1);   \
    blk[1] = ROTL32(blk[1], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 11])

void akmos_twofish_encrypt(akmos_twofish_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint32_t  t0, t1, blk[4];

    uint32_t *l_key = ctx->l_key;
    uint32_t *mk_tab = ctx->mk_tab;

    blk[0] = PACK32BE(in_blk     ); blk[0] ^= l_key[0];
    blk[1] = PACK32BE(in_blk +  4); blk[1] ^= l_key[1];
    blk[2] = PACK32BE(in_blk +  8); blk[2] ^= l_key[2];
    blk[3] = PACK32BE(in_blk + 12); blk[3] ^= l_key[3];

    f_rnd(0); f_rnd(1); f_rnd(2); f_rnd(3);
    f_rnd(4); f_rnd(5); f_rnd(6); f_rnd(7);

    UNPACK32BE(out_blk     , blk[2] ^ l_key[4]);
    UNPACK32BE(out_blk +  4, blk[3] ^ l_key[5]);
    UNPACK32BE(out_blk +  8, blk[0] ^ l_key[6]);
    UNPACK32BE(out_blk + 12, blk[1] ^ l_key[7]);
}

/* decrypt a block of text  */
#define i_rnd(i)                                                        \
    t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);                           \
    blk[2] = ROTL32(blk[2], 1) ^ (t0 + t1 + l_key[4 * (i) + 10]);       \
    blk[3] = ROTR32(blk[3] ^ (t0 + 2 * t1 + l_key[4 * (i) + 11]), 1);   \
    t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);                           \
    blk[0] = ROTL32(blk[0], 1) ^ (t0 + t1 + l_key[4 * (i) +  8]);       \
    blk[1] = ROTR32(blk[1] ^ (t0 + 2 * t1 + l_key[4 * (i) +  9]), 1)

void akmos_twofish_decrypt(akmos_twofish_t *ctx, const uint8_t *in_blk, uint8_t *out_blk)
{
    uint32_t  t0, t1, blk[4];
    uint32_t *l_key = ctx->l_key;
    uint32_t *mk_tab = ctx->mk_tab;

    blk[0] = PACK32BE(in_blk     ); blk[0] ^= l_key[4];
    blk[1] = PACK32BE(in_blk +  4); blk[1] ^= l_key[5];
    blk[2] = PACK32BE(in_blk +  8); blk[2] ^= l_key[6];
    blk[3] = PACK32BE(in_blk + 12); blk[3] ^= l_key[7];

    i_rnd(7); i_rnd(6); i_rnd(5); i_rnd(4);
    i_rnd(3); i_rnd(2); i_rnd(1); i_rnd(0);

    UNPACK32BE(out_blk     , blk[2] ^ l_key[0]);
    UNPACK32BE(out_blk +  4, blk[3] ^ l_key[1]);
    UNPACK32BE(out_blk +  8, blk[0] ^ l_key[2]);
    UNPACK32BE(out_blk + 12, blk[1] ^ l_key[3]);
}

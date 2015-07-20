/*
 *   Copyright (c) 2015, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_ALGO_THREEFISH_MIX_H
#define AKMOS_ALGO_THREEFISH_MIX_H

#define threefish_256_emix(x, d1, d2, d3, d4)   \
{                                               \
    x[0] += x[1]; x[1] = ROTL(x[1], d1) ^ x[0]; \
    x[2] += x[3]; x[3] = ROTL(x[3], d2) ^ x[2]; \
                                                \
    x[0] += x[3]; x[3] = ROTL(x[3], d3) ^ x[0]; \
    x[2] += x[1]; x[1] = ROTL(x[1], d4) ^ x[2]; \
}

#define threefish_256_dmix(x, d1, d2, d3, d4)           \
{                                                       \
    x[3] ^= x[0]; x[3] = ROTR(x[3], d1); x[0] -= x[3];  \
    x[1] ^= x[2]; x[1] = ROTR(x[1], d2); x[2] -= x[1];  \
                                                        \
    x[1] ^= x[0]; x[1] = ROTR(x[1], d3); x[0] -= x[1];  \
    x[3] ^= x[2]; x[3] = ROTR(x[3], d4); x[2] -= x[3];  \
}

#define threefish_512_emix1(x, d1, d2, d3, d4)  \
{                                               \
    x[0] += x[1]; x[1] = ROTL(x[1], d1) ^ x[0]; \
    x[2] += x[3]; x[3] = ROTL(x[3], d2) ^ x[2]; \
    x[4] += x[5]; x[5] = ROTL(x[5], d3) ^ x[4]; \
    x[6] += x[7]; x[7] = ROTL(x[7], d4) ^ x[6]; \
}

#define threefish_512_emix2(x, d1, d2, d3, d4)  \
{                                               \
    x[2] += x[1]; x[1] = ROTL(x[1], d1) ^ x[2]; \
    x[4] += x[7]; x[7] = ROTL(x[7], d2) ^ x[4]; \
    x[6] += x[5]; x[5] = ROTL(x[5], d3) ^ x[6]; \
    x[0] += x[3]; x[3] = ROTL(x[3], d4) ^ x[0]; \
}

#define threefish_512_emix3(x, d1, d2, d3, d4)  \
{                                               \
    x[4] += x[1]; x[1] = ROTL(x[1], d1) ^ x[4]; \
    x[6] += x[3]; x[3] = ROTL(x[3], d2) ^ x[6]; \
    x[0] += x[5]; x[5] = ROTL(x[5], d3) ^ x[0]; \
    x[2] += x[7]; x[7] = ROTL(x[7], d4) ^ x[2]; \
}

#define threefish_512_emix4(x, d1, d2, d3, d4)  \
{                                               \
    x[6] += x[1]; x[1] = ROTL(x[1], d1) ^ x[6]; \
    x[0] += x[7]; x[7] = ROTL(x[7], d2) ^ x[0]; \
    x[2] += x[5]; x[5] = ROTL(x[5], d3) ^ x[2]; \
    x[4] += x[3]; x[3] = ROTL(x[3], d4) ^ x[4]; \
}

#define threefish_512_dmix1(x, d1, d2, d3, d4)          \
{                                                       \
    x[3] ^= x[4]; x[3] = ROTR(x[3], d1); x[4] -= x[3];  \
    x[5] ^= x[2]; x[5] = ROTR(x[5], d2); x[2] -= x[5];  \
    x[7] ^= x[0]; x[7] = ROTR(x[7], d3); x[0] -= x[7];  \
    x[1] ^= x[6]; x[1] = ROTR(x[1], d4); x[6] -= x[1];  \
}

#define threefish_512_dmix2(x, d1, d2, d3, d4)          \
{                                                       \
    x[7] ^= x[2]; x[7] = ROTR(x[7], d1); x[2] -= x[7];  \
    x[5] ^= x[0]; x[5] = ROTR(x[5], d2); x[0] -= x[5];  \
    x[3] ^= x[6]; x[3] = ROTR(x[3], d3); x[6] -= x[3];  \
    x[1] ^= x[4]; x[1] = ROTR(x[1], d4); x[4] -= x[1];  \
}

#define threefish_512_dmix3(x, d1, d2, d3, d4)          \
{                                                       \
    x[3] ^= x[0]; x[3] = ROTR(x[3], d1); x[0] -= x[3];  \
    x[5] ^= x[6]; x[5] = ROTR(x[5], d2); x[6] -= x[5];  \
    x[7] ^= x[4]; x[7] = ROTR(x[7], d3); x[4] -= x[7];  \
    x[1] ^= x[2]; x[1] = ROTR(x[1], d4); x[2] -= x[1];  \
}

#define threefish_512_dmix4(x, d1, d2, d3, d4)          \
{                                                       \
    x[7] ^= x[6]; x[7] = ROTR(x[7], d1); x[6] -= x[7];  \
    x[5] ^= x[4]; x[5] = ROTR(x[5], d2); x[4] -= x[5];  \
    x[3] ^= x[2]; x[3] = ROTR(x[3], d3); x[2] -= x[3];  \
    x[1] ^= x[0]; x[1] = ROTR(x[1], d4); x[0] -= x[1];  \
}

#define threefish_1024_emix1(x, d1, d2, d3, d4, d5, d6, d7, d8) \
{                                                               \
    x[ 0] += x[ 1]; x[ 1] = ROTL(x[ 1], d1) ^ x[ 0];            \
    x[ 2] += x[ 3]; x[ 3] = ROTL(x[ 3], d2) ^ x[ 2];            \
    x[ 4] += x[ 5]; x[ 5] = ROTL(x[ 5], d3) ^ x[ 4];            \
    x[ 6] += x[ 7]; x[ 7] = ROTL(x[ 7], d4) ^ x[ 6];            \
    x[ 8] += x[ 9]; x[ 9] = ROTL(x[ 9], d5) ^ x[ 8];            \
    x[10] += x[11]; x[11] = ROTL(x[11], d6) ^ x[10];            \
    x[12] += x[13]; x[13] = ROTL(x[13], d7) ^ x[12];            \
    x[14] += x[15]; x[15] = ROTL(x[15], d8) ^ x[14];            \
}

#define threefish_1024_emix2(x, d1, d2, d3, d4, d5, d6, d7, d8) \
{                                                               \
    x[ 0] += x[ 9]; x[ 9] = ROTL(x[ 9], d1) ^ x[ 0];            \
    x[ 2] += x[13]; x[13] = ROTL(x[13], d2) ^ x[ 2];            \
    x[ 6] += x[11]; x[11] = ROTL(x[11], d3) ^ x[ 6];            \
    x[ 4] += x[15]; x[15] = ROTL(x[15], d4) ^ x[ 4];            \
    x[10] += x[ 7]; x[ 7] = ROTL(x[ 7], d5) ^ x[10];            \
    x[12] += x[ 3]; x[ 3] = ROTL(x[ 3], d6) ^ x[12];            \
    x[14] += x[ 5]; x[ 5] = ROTL(x[ 5], d7) ^ x[14];            \
    x[ 8] += x[ 1]; x[ 1] = ROTL(x[ 1], d8) ^ x[ 8];            \
}

#define threefish_1024_emix3(x, d1, d2, d3, d4, d5, d6, d7, d8) \
{                                                               \
    x[ 0] += x[ 7]; x[ 7] = ROTL(x[ 7], d1) ^ x[ 0];            \
    x[ 2] += x[ 5]; x[ 5] = ROTL(x[ 5], d2) ^ x[ 2];            \
    x[ 4] += x[ 3]; x[ 3] = ROTL(x[ 3], d3) ^ x[ 4];            \
    x[ 6] += x[ 1]; x[ 1] = ROTL(x[ 1], d4) ^ x[ 6];            \
    x[12] += x[15]; x[15] = ROTL(x[15], d5) ^ x[12];            \
    x[14] += x[13]; x[13] = ROTL(x[13], d6) ^ x[14];            \
    x[ 8] += x[11]; x[11] = ROTL(x[11], d7) ^ x[ 8];            \
    x[10] += x[ 9]; x[ 9] = ROTL(x[ 9], d8) ^ x[10];            \
}

#define threefish_1024_emix4(x, d1, d2, d3, d4, d5, d6, d7, d8) \
{                                                               \
    x[ 0] += x[15]; x[15] = ROTL(x[15], d1) ^ x[ 0];            \
    x[ 2] += x[11]; x[11] = ROTL(x[11], d2) ^ x[ 2];            \
    x[ 6] += x[13]; x[13] = ROTL(x[13], d3) ^ x[ 6];            \
    x[ 4] += x[ 9]; x[ 9] = ROTL(x[ 9], d4) ^ x[ 4];            \
    x[14] += x[ 1]; x[ 1] = ROTL(x[ 1], d5) ^ x[14];            \
    x[ 8] += x[ 5]; x[ 5] = ROTL(x[ 5], d6) ^ x[ 8];            \
    x[10] += x[ 3]; x[ 3] = ROTL(x[ 3], d7) ^ x[10];            \
    x[12] += x[ 7]; x[ 7] = ROTL(x[ 7], d8) ^ x[12];            \
}

#define threefish_1024_dmix1(x, d1, d2, d3, d4, d5, d6, d7, d8) \
{                                                               \
    x[ 7] ^= x[12]; x[ 7] = ROTR(x[ 7], d1); x[12] -= x[ 7];    \
    x[ 3] ^= x[10]; x[ 3] = ROTR(x[ 3], d2); x[10] -= x[ 3];    \
    x[ 5] ^= x[ 8]; x[ 5] = ROTR(x[ 5], d3); x[ 8] -= x[ 5];    \
    x[ 1] ^= x[14]; x[ 1] = ROTR(x[ 1], d4); x[14] -= x[ 1];    \
    x[ 9] ^= x[ 4]; x[ 9] = ROTR(x[ 9], d5); x[ 4] -= x[ 9];    \
    x[13] ^= x[ 6]; x[13] = ROTR(x[13], d6); x[ 6] -= x[13];    \
    x[11] ^= x[ 2]; x[11] = ROTR(x[11], d7); x[ 2] -= x[11];    \
    x[15] ^= x[ 0]; x[15] = ROTR(x[15], d8); x[ 0] -= x[15];    \
}

#define threefish_1024_dmix2(x, d1, d2, d3, d4, d5, d6, d7, d8) \
{                                                               \
    x[ 9] ^= x[10]; x[ 9] = ROTR(x[ 9], d1); x[10] -= x[ 9];    \
    x[11] ^= x[ 8]; x[11] = ROTR(x[11], d2); x[ 8] -= x[11];    \
    x[13] ^= x[14]; x[13] = ROTR(x[13], d3); x[14] -= x[13];    \
    x[15] ^= x[12]; x[15] = ROTR(x[15], d4); x[12] -= x[15];    \
    x[ 1] ^= x[ 6]; x[ 1] = ROTR(x[ 1], d5); x[ 6] -= x[ 1];    \
    x[ 3] ^= x[ 4]; x[ 3] = ROTR(x[ 3], d6); x[ 4] -= x[ 3];    \
    x[ 5] ^= x[ 2]; x[ 5] = ROTR(x[ 5], d7); x[ 2] -= x[ 5];    \
    x[ 7] ^= x[ 0]; x[ 7] = ROTR(x[ 7], d8); x[ 0] -= x[ 7];    \
}

#define threefish_1024_dmix3(x, d1, d2, d3, d4, d5, d6, d7, d8) \
{                                                               \
    x[ 1] ^= x[ 8]; x[ 1] = ROTR(x[ 1], d1); x[ 8] -= x[ 1];    \
    x[ 5] ^= x[14]; x[ 5] = ROTR(x[ 5], d2); x[14] -= x[ 5];    \
    x[ 3] ^= x[12]; x[ 3] = ROTR(x[ 3], d3); x[12] -= x[ 3];    \
    x[ 7] ^= x[10]; x[ 7] = ROTR(x[ 7], d4); x[10] -= x[ 7];    \
    x[15] ^= x[ 4]; x[15] = ROTR(x[15], d5); x[ 4] -= x[15];    \
    x[11] ^= x[ 6]; x[11] = ROTR(x[11], d6); x[ 6] -= x[11];    \
    x[13] ^= x[ 2]; x[13] = ROTR(x[13], d7); x[ 2] -= x[13];    \
    x[ 9] ^= x[ 0]; x[ 9] = ROTR(x[ 9], d8); x[ 0] -= x[ 9];    \
}

#define threefish_1024_dmix4(x, d1, d2, d3, d4, d5, d6, d7, d8) \
{                                                               \
    x[15] ^= x[14]; x[15] = ROTR(x[15], d1); x[14] -= x[15];    \
    x[13] ^= x[12]; x[13] = ROTR(x[13], d2); x[12] -= x[13];    \
    x[11] ^= x[10]; x[11] = ROTR(x[11], d3); x[10] -= x[11];    \
    x[ 9] ^= x[ 8]; x[ 9] = ROTR(x[ 9], d4); x[ 8] -= x[ 9];    \
    x[ 7] ^= x[ 6]; x[ 7] = ROTR(x[ 7], d5); x[ 6] -= x[ 7];    \
    x[ 5] ^= x[ 4]; x[ 5] = ROTR(x[ 5], d6); x[ 4] -= x[ 5];    \
    x[ 3] ^= x[ 2]; x[ 3] = ROTR(x[ 3], d7); x[ 2] -= x[ 3];    \
    x[ 1] ^= x[ 0]; x[ 1] = ROTR(x[ 1], d8); x[ 0] -= x[ 1];    \
}

#endif  /* AKMOS_ALGO_THREEFISH_MIX_H */

/*
 *   Copyright (c) 2017, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_SKEIN_SKEY_H
#define AKMOS_SKEIN_SKEY_H

#define SKEIN_R256(skey, key, tw, k0, k1, k2, k3,   \
                   tw1, tw2, r)                     \
{                                                   \
    skey[(r*4)+0] = key[k0];                        \
    skey[(r*4)+1] = key[k1] + tw[tw1];              \
    skey[(r*4)+2] = key[k2] + tw[tw2];              \
    skey[(r*4)+3] = key[k3] + r;                    \
}

#define SKEIN_R512(skey, key, tw, k0, k1, k2, k3,   \
                   k4, k5, k6, k7, tw1, tw2, r)     \
{                                                   \
    skey[(r*8)+0] = key[k0];                        \
    skey[(r*8)+1] = key[k1];                        \
    skey[(r*8)+2] = key[k2];                        \
    skey[(r*8)+3] = key[k3];                        \
    skey[(r*8)+4] = key[k4];                        \
    skey[(r*8)+5] = key[k5] + tw[tw1];              \
    skey[(r*8)+6] = key[k6] + tw[tw2];              \
    skey[(r*8)+7] = key[k7] + r;                    \
}

#define SKEIN_R1024(skey, key, tw, k0, k1, k2, k3,  \
                    k4, k5, k6, k7, k8, k9, k10,    \
                    k11, k12, k13, k14, k15,        \
                    tw1, tw2, r)                    \
{                                                   \
    skey[(r*16)+0] = key[k0];                       \
    skey[(r*16)+1] = key[k1];                       \
    skey[(r*16)+2] = key[k2];                       \
    skey[(r*16)+3] = key[k3];                       \
    skey[(r*16)+4] = key[k4];                       \
    skey[(r*16)+5] = key[k5];                       \
    skey[(r*16)+6] = key[k6];                       \
    skey[(r*16)+7] = key[k7];                       \
    skey[(r*16)+8] = key[k8];                       \
    skey[(r*16)+9] = key[k9];                       \
    skey[(r*16)+10] = key[k10];                     \
    skey[(r*16)+11] = key[k11];                     \
    skey[(r*16)+12] = key[k12];                     \
    skey[(r*16)+13] = key[k13] + tw[tw1];           \
    skey[(r*16)+14] = key[k14] + tw[tw2];           \
    skey[(r*16)+15] = key[k15] + r;                 \
}

#define SKEIN_SKEY_256(skey, key, tw)               \
{                                                   \
    SKEIN_R256(skey, key, tw, 0, 1, 2, 3, 0, 1, 0); \
    SKEIN_R256(skey, key, tw, 1, 2, 3, 4, 1, 2, 1); \
    SKEIN_R256(skey, key, tw, 2, 3, 4, 0, 2, 0, 2); \
    SKEIN_R256(skey, key, tw, 3, 4, 0, 1, 0, 1, 3); \
    SKEIN_R256(skey, key, tw, 4, 0, 1, 2, 1, 2, 4); \
    SKEIN_R256(skey, key, tw, 0, 1, 2, 3, 2, 0, 5); \
    SKEIN_R256(skey, key, tw, 1, 2, 3, 4, 0, 1, 6); \
    SKEIN_R256(skey, key, tw, 2, 3, 4, 0, 1, 2, 7); \
    SKEIN_R256(skey, key, tw, 3, 4, 0, 1, 2, 0, 8); \
    SKEIN_R256(skey, key, tw, 4, 0, 1, 2, 0, 1, 9); \
    SKEIN_R256(skey, key, tw, 0, 1, 2, 3, 1, 2, 10);\
    SKEIN_R256(skey, key, tw, 1, 2, 3, 4, 2, 0, 11);\
    SKEIN_R256(skey, key, tw, 2, 3, 4, 0, 0, 1, 12);\
    SKEIN_R256(skey, key, tw, 3, 4, 0, 1, 1, 2, 13);\
    SKEIN_R256(skey, key, tw, 4, 0, 1, 2, 2, 0, 14);\
    SKEIN_R256(skey, key, tw, 0, 1, 2, 3, 0, 1, 15);\
    SKEIN_R256(skey, key, tw, 1, 2, 3, 4, 1, 2, 16);\
    SKEIN_R256(skey, key, tw, 2, 3, 4, 0, 2, 0, 17);\
    SKEIN_R256(skey, key, tw, 3, 4, 0, 1, 0, 1, 18);\
}

#define SKEIN_SKEY_512(skey, key, tw)               \
{                                                   \
    SKEIN_R512(skey, key, tw,                       \
               0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 0);    \
    SKEIN_R512(skey, key, tw,                       \
               1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 1);    \
    SKEIN_R512(skey, key, tw,                       \
               2, 3, 4, 5, 6, 7, 8, 0, 2, 0, 2);    \
    SKEIN_R512(skey, key, tw,                       \
               3, 4, 5, 6, 7, 8, 0, 1, 0, 1, 3);    \
    SKEIN_R512(skey, key, tw,                       \
               4, 5, 6, 7, 8, 0, 1, 2, 1, 2, 4);    \
    SKEIN_R512(skey, key, tw,                       \
               5, 6, 7, 8, 0, 1, 2, 3, 2, 0, 5);    \
    SKEIN_R512(skey, key, tw,                       \
               6, 7, 8, 0, 1, 2, 3, 4, 0, 1, 6);    \
    SKEIN_R512(skey, key, tw,                       \
               7, 8, 0, 1, 2, 3, 4, 5, 1, 2, 7);    \
    SKEIN_R512(skey, key, tw,                       \
               8, 0, 1, 2, 3, 4, 5, 6, 2, 0, 8);    \
    SKEIN_R512(skey, key, tw,                       \
               0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 9);    \
    SKEIN_R512(skey, key, tw,                       \
               1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 10);   \
    SKEIN_R512(skey, key, tw,                       \
               2, 3, 4, 5, 6, 7, 8, 0, 2, 0, 11);   \
    SKEIN_R512(skey, key, tw,                       \
               3, 4, 5, 6, 7, 8, 0, 1, 0, 1, 12);   \
    SKEIN_R512(skey, key, tw,                       \
               4, 5, 6, 7, 8, 0, 1, 2, 1, 2, 13);   \
    SKEIN_R512(skey, key, tw,                       \
               5, 6, 7, 8, 0, 1, 2, 3, 2, 0, 14);   \
    SKEIN_R512(skey, key, tw,                       \
               6, 7, 8, 0, 1, 2, 3, 4, 0, 1, 15);   \
    SKEIN_R512(skey, key, tw,                       \
               7, 8, 0, 1, 2, 3, 4, 5, 1, 2, 16);   \
    SKEIN_R512(skey, key, tw,                       \
               8, 0, 1, 2, 3, 4, 5, 6, 2, 0, 17);   \
    SKEIN_R512(skey, key, tw,                       \
               0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 18);   \
}

#define SKEIN_SKEY_1024(skey, key, tw)              \
{                                                   \
    SKEIN_R1024(skey, key, tw,                      \
                 0,  1,  2,  3,  4,  5,  6,  7,     \
                 8,  9, 10, 11, 12, 13, 14, 15,     \
                 0,  1,  0);\
    SKEIN_R1024(skey, key, tw,                      \
                 1,  2,  3,  4,  5,  6,  7,  8,     \
                 9, 10, 11, 12, 13, 14, 15, 16,     \
                 1,  2,  1);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 2,  3,  4,  5,  6,  7,  8,  9,     \
                10, 11, 12, 13, 14, 15, 16,  0,     \
                 2,  0,  2);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 3,  4,  5,  6,  7,  8,  9, 10,     \
                11, 12, 13, 14, 15, 16,  0,  1,     \
                 0,  1,  3);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 4,  5,  6,  7,  8,  9, 10, 11,     \
                12, 13, 14, 15, 16,  0,  1,  2,     \
                 1,  2,  4);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 5,  6,  7,  8,  9, 10, 11, 12,     \
                13, 14, 15, 16,  0,  1,  2,  3,     \
                 2,  0,  5);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 6,  7,  8,  9, 10, 11, 12, 13,     \
                14, 15, 16,  0,  1,  2,  3,  4,     \
                 0,  1,  6);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 7,  8,  9, 10, 11, 12, 13, 14,     \
                15, 16,  0,  1,  2,  3,  4,  5,     \
                 1,  2,  7);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 8,  9, 10, 11, 12, 13, 14, 15,     \
                16,  0,  1,  2,  3,  4,  5,  6,     \
                 2,  0,  8);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 9, 10, 11, 12, 13, 14, 15, 16,     \
                 0,  1,  2,  3,  4,  5,  6,  7,     \
                 0,  1,  9);                        \
    SKEIN_R1024(skey, key, tw,                      \
                10, 11, 12, 13, 14, 15, 16,  0,     \
                 1,  2,  3,  4,  5,  6,  7,  8,     \
                 1,  2, 10);                        \
    SKEIN_R1024(skey, key, tw,                      \
                11, 12, 13, 14, 15, 16,  0,  1,     \
                 2,  3,  4,  5,  6,  7,  8,  9,     \
                 2,  0, 11);                        \
    SKEIN_R1024(skey, key, tw,                      \
                12, 13, 14, 15, 16,  0,  1,  2,     \
                 3,  4,  5,  6,  7,  8,  9, 10,     \
                 0,  1, 12);                        \
    SKEIN_R1024(skey, key, tw,                      \
                13, 14, 15, 16,  0,  1,  2,  3,     \
                 4,  5,  6,  7,  8,  9, 10, 11,     \
                 1,  2, 13);                        \
    SKEIN_R1024(skey, key, tw,                      \
                14, 15, 16,  0,  1,  2,  3,  4,     \
                 5,  6,  7,  8,  9, 10, 11, 12,     \
                 2,  0, 14);                        \
    SKEIN_R1024(skey, key, tw,                      \
                15, 16,  0,  1,  2,  3,  4,  5,     \
                 6,  7,  8,  9, 10, 11, 12, 13,     \
                 0,  1, 15);                        \
    SKEIN_R1024(skey, key, tw,                      \
                16,  0,  1,  2,  3,  4,  5,  6,     \
                 7,  8,  9, 10, 11, 12, 13, 14,     \
                 1,  2, 16);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 0,  1,  2,  3,  4,  5,  6,  7,     \
                 8,  9, 10, 11, 12, 13, 14, 15,     \
                 2,  0, 17);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 1,  2,  3,  4,  5,  6,  7,  8,     \
                 9, 10, 11, 12, 13, 14, 15, 16,     \
                 0,  1, 18);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 2,  3,  4,  5,  6,  7,  8,  9,     \
                10, 11, 12, 13, 14, 15, 16,  0,     \
                 1,  2, 19);                        \
    SKEIN_R1024(skey, key, tw,                      \
                 3,  4,  5,  6,  7,  8,  9, 10,     \
                11, 12, 13, 14, 15, 16,  0,  1,     \
                 2,  0, 20);                        \
}

#endif  /* AKMOS_SKEIN_SKEY_H */

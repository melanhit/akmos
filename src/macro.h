/*
 *   Copyright (c) 2014, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_MACRO_H
#define AKMOS_MACRO_H

/* rotate int into left (n - num bits) */
#ifndef ROTL
#define ROTL(x, n)  (((x) << (n)) | ((x) >> ((sizeof(x) << 3) - (n))))
#endif  /* ROTL */

/* rotate int into right (n - num bits) */
#ifndef ROTR
#define ROTR(x, n)  (((x) >> (n)) | ((x) << ((sizeof(x) << 3) - (n))))
#endif  /* ROTR */

/* extract byte */
#ifndef EXTBYTE
#define EXTBYTE(x, n)   ((uint8_t)((x) >> (8 * (n))))
#endif  /* EXTBYTE*/

/* swap uint32_t */
#ifndef SWAPU32
#define SWAPU32(x)                                  \
(                                                   \
      (((x) >> 24) & 0xff      )                    \
    ^ (((x) <<  8) & 0xff0000  )                    \
    ^ (((x) >>  8) & 0xff00    )                    \
    ^ (((x) << 24) & 0xff000000)                    \
)
#endif  /* SWAPU32 */

/* unpack uint32_t into 4 uint8_t (little-endian) */
#ifndef UNPACK32LE
#define UNPACK32LE(ct, st)                          \
{                                                   \
    (ct)[3] = (uint8_t)(st);                        \
    (ct)[2] = (uint8_t)((st) >> 8);                 \
    (ct)[1] = (uint8_t)((st) >> 16);                \
    (ct)[0] = (uint8_t)((st) >> 24);                \
}
#endif  /* UNPACK32LE */

/* unpack uint32_t into 4 uint8_t (big-endian) */
#ifndef UNPACK32BE
#define UNPACK32BE(ct, st)                          \
{                                                   \
    (ct)[0] = (uint8_t)(st);                        \
    (ct)[1] = (uint8_t)((st) >> 8);                 \
    (ct)[2] = (uint8_t)((st) >> 16);                \
    (ct)[3] = (uint8_t)((st) >> 24);                \
}
#endif  /* UNPACK32BE */

/* pack 4 uint8_t into uint32_t (little-endian) */
#ifndef PACK32LE
#define PACK32LE(pt)                                \
(                                                   \
      ((uint32_t)(pt)[3]      )                     \
    ^ ((uint32_t)(pt)[2] <<  8)                     \
    ^ ((uint32_t)(pt)[1] << 16)                     \
    ^ ((uint32_t)(pt)[0] << 24)                     \
)
#endif  /* PACK32LE */

/* pack 4 uint8_t into uint32_t (big-endian) */
#ifndef PACK32BE
#define PACK32BE(pt)                                \
(                                                   \
      ((uint32_t)(pt)[0]      )                     \
    ^ ((uint32_t)(pt)[1] <<  8)                     \
    ^ ((uint32_t)(pt)[2] << 16)                     \
    ^ ((uint32_t)(pt)[3] << 24)                     \
)
#endif  /* PACK32BE */

/* unpack uint64_t into 8 uint8_t (little-endian) */
#ifndef UNPACK64LE
#define UNPACK64LE(ct, st)                          \
{                                                   \
    (ct)[7] = (uint8_t)(st);                        \
    (ct)[6] = (uint8_t)((st) >> 8);                 \
    (ct)[5] = (uint8_t)((st) >> 16);                \
    (ct)[4] = (uint8_t)((st) >> 24);                \
    (ct)[3] = (uint8_t)((st) >> 32);                \
    (ct)[2] = (uint8_t)((st) >> 40);                \
    (ct)[1] = (uint8_t)((st) >> 48);                \
    (ct)[0] = (uint8_t)((st) >> 56);                \
}
#endif  /* UNPACK64LE */

/* unpack uint64_t into 8 uint8_t (big-endian) */
#ifndef UNPACK64BE
#define UNPACK64BE(ct, st)                          \
{                                                   \
    (ct)[0] = (uint8_t)(st);                        \
    (ct)[1] = (uint8_t)((st) >> 8);                 \
    (ct)[2] = (uint8_t)((st) >> 16);                \
    (ct)[3] = (uint8_t)((st) >> 24);                \
    (ct)[4] = (uint8_t)((st) >> 32);                \
    (ct)[5] = (uint8_t)((st) >> 40);                \
    (ct)[6] = (uint8_t)((st) >> 48);                \
    (ct)[7] = (uint8_t)((st) >> 56);                \
}
#endif  /* UNPACK64BE */

/* pack 8 uint8_t into uint64_t (little-endian) */
#ifndef PACK64LE
#define PACK64LE(pt)                                \
(                                                   \
      ((uint64_t)(pt)[7]      )                     \
    ^ ((uint64_t)(pt)[6] <<  8)                     \
    ^ ((uint64_t)(pt)[5] << 16)                     \
    ^ ((uint64_t)(pt)[4] << 24)                     \
    ^ ((uint64_t)(pt)[3] << 32)                     \
    ^ ((uint64_t)(pt)[2] << 40)                     \
    ^ ((uint64_t)(pt)[1] << 48)                     \
    ^ ((uint64_t)(pt)[0] << 56)                     \
)
#endif  /* PACK64LE */

/* pack 8 uint8_t into uint64_t (big-endian) */
#ifndef PACK64BE
#define PACK64BE(pt)                                \
(                                                   \
      ((uint64_t)(pt)[0]      )                     \
    ^ ((uint64_t)(pt)[1] <<  8)                     \
    ^ ((uint64_t)(pt)[2] << 16)                     \
    ^ ((uint64_t)(pt)[3] << 24)                     \
    ^ ((uint64_t)(pt)[4] << 32)                     \
    ^ ((uint64_t)(pt)[5] << 40)                     \
    ^ ((uint64_t)(pt)[6] << 48)                     \
    ^ ((uint64_t)(pt)[7] << 56)                     \
)
#endif  /* PACK64BE */

#endif  /* AKMOS_MACRO_H */

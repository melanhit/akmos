/*
 *   Copyright (c) 2018, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_BN_H
#define AKMOS_BN_H

#define BN_CMP_LT	    -1
#define BN_CMP_EQ	     0
#define BN_CMP_GT	     1

#define BN_FLAG_INT	    UINT64_C(0x8000000000000000)
#define BN_FLAG_ZERO	    UINT64_C(0x4000000000000000)

#define BN_BASE		    (sizeof(uint64_t) - 1)

#define BN_B2B(x, n)	    ((size_t)(((x) / (n)) + (((x) % (n)) > 0 ? 1 : 0)))

#define BN_SET_INT(x)	    (!(x->num[x->n - 1] & BN_FLAG_ZERO) ? x->num[x->n - 1] |= BN_FLAG_INT : 0)
#define BN_SET_UINT(x)	    (!(x->num[x->n - 1] & BN_FLAG_ZERO) ? x->num[x->n - 1] &= ~BN_FLAG_INT : 0)

#define BN_GET_SIGN(x)	    ((x->num[x->n - 1] & BN_FLAG_INT) ? 1 : 0)

typedef struct akmos_bn_s {
    size_t b;	/* length bignum in bytes */
    size_t l;	/* legnth bignum via *num */
    size_t n;	/* number of uint64_t chunks */
    uint64_t *num;
} *akmos_bn_t;

int  akmos_bn_init  (akmos_bn_t *, size_t);
void akmos_bn_free  (akmos_bn_t);

int  akmos_bn_load  (akmos_bn_t, const uint8_t *, size_t);
int  akmos_bn_store (akmos_bn_t, uint8_t *, size_t);
void akmos_bn_zero  (akmos_bn_t);

int  akmos_bn_cmp   (const akmos_bn_t, const akmos_bn_t);

#endif  /* AKMOS_BN_H */

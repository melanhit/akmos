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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/endian.h>

#include "akmos.h"
#include "bits.h"
#include "error.h"
#include "bn.h"

int akmos_bn_init(akmos_bn_t *bn, size_t len)
{
    struct akmos_bn_s *ptr;

    ptr = *bn = malloc(sizeof(struct akmos_bn_s));
    if(!ptr)
	return AKMOS_ERR_ENOMEM;

    memset(ptr, 0, sizeof(struct akmos_bn_s));

    ptr->b = len;
    ptr->n = BN_B2B(ptr->b, BN_BASE);
    ptr->l = ptr->n * sizeof(uint64_t);

    ptr->num = malloc(ptr->l);
    if(!ptr->num) {
	free(ptr);
	return AKMOS_ERR_ENOMEM;
    }

    memset(ptr->num, 0, ptr->l);

    return AKMOS_ERR_SUCCESS;
}

void akmos_bn_free(akmos_bn_t bn)
{
    if(!bn)
	return;

    if(bn->num) {
	akmos_memzero(bn->num, bn->l);
	free(bn->num);
    }

    akmos_memzero(bn, sizeof(struct akmos_bn_s));
    free(bn);
}

int akmos_bn_load(akmos_bn_t bn, const uint8_t *in, size_t inlen)
{
    const uint8_t *p_in;
    uint8_t buf[BN_BASE];
    size_t i, num, len;

    if(bn->b < inlen)
	return AKMOS_ERR_BNSMALL;

    if(inlen > BN_BASE)
	p_in = in + (inlen - BN_BASE);
    else
	p_in = in;

    num = inlen / BN_BASE;
    for(i = 0; i < num; i++, p_in -= BN_BASE)
	bn->num[i] = PACK56LE(p_in);

    len = inlen % BN_BASE;
    if(len) {
	memset(buf, 0, sizeof(buf));
	memcpy(buf + (sizeof(buf) - len), in, len);
	bn->num[num] = PACK56LE(buf);
	akmos_memzero(buf, sizeof(buf));
    }

    akmos_bn_zero(bn);

    return AKMOS_ERR_SUCCESS;
}

int akmos_bn_store(akmos_bn_t bn, uint8_t *out, size_t outlen)
{
    uint8_t *p;
    uint64_t num;
    size_t i, mod;

    if(bn->b > outlen)
	return AKMOS_ERR_BNSMALL;

    if(outlen > BN_BASE)
	p = out + (bn->b - BN_BASE);
    else
	p = out;

    for(i = 0; i < bn->n - 1; i++, p -= BN_BASE)
	UNPACK56LE(p, bn->num[i]);

    mod = bn->b % BN_BASE;
    if(mod) {
	num = bswap64(bn->num[bn->n - 1]) >> ((sizeof(uint64_t) - mod) * 8);
	memcpy(out, &num, mod);
    } else {
	UNPACK56LE(out, bn->num[bn->n - 1]);
    }

    return AKMOS_ERR_SUCCESS;
}

void akmos_bn_zero(akmos_bn_t bn)
{
    size_t i;

    for(i = 0; i < bn->n; i++) {
	if((bn->num[i] << (BN_BASE * 8)) > 0)
	    return;
    }

    bn->num[bn->n - 1] |= BN_FLAG_ZERO;
}

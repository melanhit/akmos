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

#include "bn.h"

static int bn_cmp(const akmos_bn_t bn1, const akmos_bn_t bn2)
{
    uint64_t *n1, *n2, *b1, *b2;
    int r1, r2;

    if(bn1->n > bn2->n) {
	r1 = BN_CMP_GT;
	r2 = BN_CMP_LT;

	b1 = bn1->num;
	b2 = bn2->num;

	n1 = bn1->num + (bn1->n - 1);
	n2 = bn2->num + (bn2->n - 1);
    } else {
	r1 = BN_CMP_LT;
	r2 = BN_CMP_GT;

	b1 = bn2->num;
	b2 = bn1->num;

	n1 = bn2->num + (bn2->n - 1);
	n2 = bn1->num + (bn1->n - 1);
    }

    for(; n1 >= b1; n1--) {
	if(*n1 > *n2)
	    return r1;

	if(*n1 < *n2)
	    return r2;

	if(n2 == b2) {
	    if(*n1)
		return r1;

	    continue;
	}

	n2--;
    }

    return BN_CMP_EQ;
}

int akmos_bn_cmp(const akmos_bn_t bn1, const akmos_bn_t bn2)
{
    int s1, s2;

    s1 = BN_GET_SIGN(bn1);
    s2 = BN_GET_SIGN(bn2);

    if(s1 == s2)
	return bn_cmp(bn1, bn2);

    if(s1 < s2)
	return BN_CMP_GT;

    if(s1 > s2)
	return BN_CMP_LT;

    return BN_CMP_EQ;
}

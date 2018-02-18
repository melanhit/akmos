/*
 *   Copyright (c) 2014-2018, Andrew Romanenko <melanhit@gmail.com>
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
#include "../digest.h"

const akmos_digest_xalgo_t akmos_digest_xlist[] = {
    {
        {
            AKMOS_ALGO_RIPEMD_160, "RIPEMD-160",
            AKMOS_RIPEMD_BLKLEN, AKMOS_RIPEMD_160_DIGLEN
        },
        &akmos_ripemd_160_init,
        &akmos_ripemd_update,
        &akmos_ripemd_done
    },
    {
        {
            AKMOS_ALGO_RIPEMD_256, "RIPEMD-256",
            AKMOS_RIPEMD_BLKLEN, AKMOS_RIPEMD_256_DIGLEN
        },
        &akmos_ripemd_256_init,
        &akmos_ripemd_update,
        &akmos_ripemd_done
    },
    {
        {
            AKMOS_ALGO_RIPEMD_320, "RIPEMD-320",
            AKMOS_RIPEMD_BLKLEN, AKMOS_RIPEMD_320_DIGLEN
        },
        &akmos_ripemd_320_init,
        &akmos_ripemd_update,
        &akmos_ripemd_done
    },
    {
        {
            AKMOS_ALGO_SHA1, "SHA1",
            AKMOS_SHA1_BLKLEN, AKMOS_SHA1_DIGLEN
        },
        &akmos_sha1_init,
        &akmos_sha1_update,
        &akmos_sha1_done
    },
    {
        {
            AKMOS_ALGO_SHA2_224, "SHA2-224",
            AKMOS_SHA2_224_BLKLEN, AKMOS_SHA2_224_DIGLEN
        },
        &akmos_sha2_224_init,
        &akmos_sha2_update,
        &akmos_sha2_done
    },
    {
        {
            AKMOS_ALGO_SHA2_256, "SHA2-256",
            AKMOS_SHA2_256_BLKLEN, AKMOS_SHA2_256_DIGLEN
        },
        &akmos_sha2_256_init,
        &akmos_sha2_update,
        &akmos_sha2_done
    },
    {
        {
            AKMOS_ALGO_SHA2_384, "SHA2-384",
            AKMOS_SHA2_384_BLKLEN, AKMOS_SHA2_384_DIGLEN
        },
        &akmos_sha2_384_init,
        &akmos_sha2_update,
        &akmos_sha2_done
    },
    {
        {
            AKMOS_ALGO_SHA2_512, "SHA2-512",
            AKMOS_SHA2_512_BLKLEN, AKMOS_SHA2_512_DIGLEN
        },
        &akmos_sha2_512_init,
        &akmos_sha2_update,
        &akmos_sha2_done
    },
    {
        {
            AKMOS_ALGO_SHA3_224, "SHA3-224",
            AKMOS_SHA3_224_BLKLEN, AKMOS_SHA3_224_DIGLEN
        },
        &akmos_sha3_224_init,
        &akmos_sha3_update,
        &akmos_sha3_done
    },
    {
        {
            AKMOS_ALGO_SHA3_256, "SHA3-256",
            AKMOS_SHA3_256_BLKLEN, AKMOS_SHA3_256_DIGLEN
        },
        &akmos_sha3_256_init,
        &akmos_sha3_update,
        &akmos_sha3_done
    },
    {
        {
            AKMOS_ALGO_SHA3_384, "SHA3-384",
            AKMOS_SHA3_384_BLKLEN, AKMOS_SHA3_384_DIGLEN
        },
        &akmos_sha3_384_init,
        &akmos_sha3_update,
        &akmos_sha3_done
    },
    {
        {
            AKMOS_ALGO_SHA3_512, "SHA3-512",
            AKMOS_SHA3_512_BLKLEN, AKMOS_SHA3_512_DIGLEN
        },
        &akmos_sha3_512_init,
        &akmos_sha3_update,
        &akmos_sha3_done
    },
    {
        {
            AKMOS_ALGO_TIGER, "Tiger",
            AKMOS_TIGER_BLKLEN, AKMOS_TIGER_DIGLEN
        },
        &akmos_tiger_init,
        &akmos_tiger_update,
        &akmos_tiger_done
    },
    {
        {
            AKMOS_ALGO_WHIRLPOOL, "Whirlpool",
            AKMOS_WHIRLPOOL_BLKLEN, AKMOS_WHIRLPOOL_DIGLEN
        },
        &akmos_whirlpool_init,
        &akmos_whirlpool_update,
        &akmos_whirlpool_done
    },
    {
        {
            AKMOS_ALGO_SKEIN_256, "Skein-256",
            AKMOS_SKEIN_256_BLKLEN, AKMOS_SKEIN_256_DIGLEN
        },
        &akmos_skein_256_init,
        &akmos_skein_update,
        &akmos_skein_done
    },
    {
        {
            AKMOS_ALGO_SKEIN_512, "Skein-512",
            AKMOS_SKEIN_512_BLKLEN, AKMOS_SKEIN_512_DIGLEN
        },
        &akmos_skein_512_init,
        &akmos_skein_update,
        &akmos_skein_done
    },
    {
        {
            AKMOS_ALGO_SKEIN_1024, "Skein-1024",
            AKMOS_SKEIN_1024_BLKLEN, AKMOS_SKEIN_1024_DIGLEN
        },
        &akmos_skein_1024_init,
        &akmos_skein_update,
        &akmos_skein_done
    },
    {
        { 0, NULL, 0, 0 },
        NULL, NULL, NULL
    }
};

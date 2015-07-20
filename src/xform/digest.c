/*
 *   Copyright (c) 2014-2015, Andrew Romanenko <melanhit@gmail.com>
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

akmos_digest_xalgo_t akmos_xalgo_ripemd_160 = {
    AKMOS_ALGO_RIPEMD_160, "RIPEMD-160",
    AKMOS_RIPEMD_160_BLKLEN, AKMOS_RIPEMD_160_DIGLEN,
    (void *)akmos_ripemd_160_init,
    (void *)akmos_ripemd_update,
    (void *)akmos_ripemd_done
};

akmos_digest_xalgo_t akmos_xalgo_ripemd_256 = {
    AKMOS_ALGO_RIPEMD_256, "RIPEMD-256",
    AKMOS_RIPEMD_256_BLKLEN, AKMOS_RIPEMD_256_DIGLEN,
    (void *)akmos_ripemd_256_init,
    (void *)akmos_ripemd_update,
    (void *)akmos_ripemd_done
};

akmos_digest_xalgo_t akmos_xalgo_ripemd_320 = {
    AKMOS_ALGO_RIPEMD_320, "RIPEMD-320",
    AKMOS_RIPEMD_320_BLKLEN, AKMOS_RIPEMD_320_DIGLEN,
    (void *)akmos_ripemd_320_init,
    (void *)akmos_ripemd_update,
    (void *)akmos_ripemd_done
};

akmos_digest_xalgo_t akmos_xalgo_sha1 = {
    AKMOS_ALGO_SHA1, "SHA1",
    AKMOS_SHA1_BLKLEN, AKMOS_SHA1_DIGLEN,
    (void *)akmos_sha1_init,
    (void *)akmos_sha1_update,
    (void *)akmos_sha1_done
};

akmos_digest_xalgo_t akmos_xalgo_sha2_224 = {
    AKMOS_ALGO_SHA2_224, "SHA2-224",
    AKMOS_SHA2_224_BLKLEN, AKMOS_SHA2_224_DIGLEN,
    (void *)akmos_sha2_224_init,
    (void *)akmos_sha2_256_update,
    (void *)akmos_sha2_256_done
};

akmos_digest_xalgo_t akmos_xalgo_sha2_256 = {
    AKMOS_ALGO_SHA2_256, "SHA2-256",
    AKMOS_SHA2_256_BLKLEN, AKMOS_SHA2_256_DIGLEN,
    (void *)akmos_sha2_256_init,
    (void *)akmos_sha2_256_update,
    (void *)akmos_sha2_256_done
};

akmos_digest_xalgo_t akmos_xalgo_sha2_384 = {
    AKMOS_ALGO_SHA2_384, "SHA2-384",
    AKMOS_SHA2_384_BLKLEN, AKMOS_SHA2_384_DIGLEN,
    (void *)akmos_sha2_384_init,
    (void *)akmos_sha2_512_update,
    (void *)akmos_sha2_512_done
};

akmos_digest_xalgo_t akmos_xalgo_sha2_512 = {
    AKMOS_ALGO_SHA2_512, "SHA2-512",
    AKMOS_SHA2_512_BLKLEN, AKMOS_SHA2_512_DIGLEN,
    (void *)akmos_sha2_512_init,
    (void *)akmos_sha2_512_update,
    (void *)akmos_sha2_512_done
};

akmos_digest_xalgo_t akmos_xalgo_sha3_224 = {
    AKMOS_ALGO_SHA3_224, "SHA3-224",
    AKMOS_SHA3_224_BLKLEN, AKMOS_SHA3_224_DIGLEN,
    (void *)akmos_sha3_224_init,
    (void *)akmos_sha3_update,
    (void *)akmos_sha3_done
};

akmos_digest_xalgo_t akmos_xalgo_sha3_256 = {
    AKMOS_ALGO_SHA3_256, "SHA3-256",
    AKMOS_SHA3_256_BLKLEN, AKMOS_SHA3_256_DIGLEN,
    (void *)akmos_sha3_256_init,
    (void *)akmos_sha3_update,
    (void *)akmos_sha3_done
};

akmos_digest_xalgo_t akmos_xalgo_sha3_384 = {
    AKMOS_ALGO_SHA3_384, "SHA3-384",
    AKMOS_SHA3_384_BLKLEN, AKMOS_SHA3_384_DIGLEN,
    (void *)akmos_sha3_384_init,
    (void *)akmos_sha3_update,
    (void *)akmos_sha3_done
};

akmos_digest_xalgo_t akmos_xalgo_sha3_512 = {
    AKMOS_ALGO_SHA3_512, "SHA3-512",
    AKMOS_SHA3_512_BLKLEN, AKMOS_SHA3_512_DIGLEN,
    (void *)akmos_sha3_512_init,
    (void *)akmos_sha3_update,
    (void *)akmos_sha3_done
};

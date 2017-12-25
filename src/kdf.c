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

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include "akmos.h"
#include "error.h"

#include "kdf/pbkdf2.h"
#include "kdf/scrypt.h"

int akmos_kdf(uint8_t *key, size_t keylen,
              const uint8_t *salt, size_t saltlen,
              const uint8_t *pass, size_t passlen,
              akmos_kdf_id kdf_algo, ...)
{
    akmos_algo_id algo;
    va_list ap;
    uint32_t iter, N, p;

    switch(kdf_algo) {
        case AKMOS_KDF_PBKDF2:
            va_start(ap, kdf_algo);
            iter = va_arg(ap, uint32_t);
            algo = va_arg(ap, akmos_algo_id);
            va_end(ap);
            return akmos_pbkdf2(key, keylen, salt, saltlen, pass, passlen, iter, algo);

        case AKMOS_KDF_SCRYPT:
            va_start(ap, kdf_algo);
            N = va_arg(ap, uint32_t);
            p = va_arg(ap, uint32_t);
            va_end(ap);
            return akmos_scrypt(key, keylen, salt, saltlen, pass, passlen, N, p);

        default:
            return AKMOS_ERR_KDFID;
    }

    return AKMOS_ERR_SUCCESS;
}

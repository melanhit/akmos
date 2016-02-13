/*
 *   Copyright (c) 2016, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef AKMOS_MASK_H
#define AKMOS_MASK_H

typedef enum akmos_algo_mask_e {
    AKMOS_ALGO_MASK         = 0x000fffff,
    AKMOS_ALGO_CIPHER_MASK  = 0x00000fff,
    AKMOS_ALGO_DIGEST_MASK  = 0x000ff000,
    AKMOS_ALGO_FLAG_MASK    = 0x70000000
} akmos_algo_mask_t;

typedef enum akmos_mode_mask_e {
    AKMOS_MODE_MASK         = 0x000000ff,
    AKMOS_MODE_CIPHER_MASK  = 0x0000000f,
    AKMOS_MODE_MAC_MASK     = 0x000000f0,
    AKMOS_MODE_FLAG_MASK    = 0x70000000
} akmos_mode_mask_t;

#endif  /* AKMOS_MASK_H */

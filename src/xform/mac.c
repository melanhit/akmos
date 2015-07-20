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
#include "../mac.h"

akmos_mac_xmode_t akmos_xmode_hmac = {
    AKMOS_MODE_HMAC, "HMAC",
    (void *)&akmos_hmac_init,
    (void *)&akmos_hmac_setkey,
    (void *)&akmos_hmac_update,
    (void *)&akmos_hmac_done
};

akmos_mac_xmode_t akmos_xmode_cmac = {
    AKMOS_MODE_CMAC, "CMAC",
    (void *)&akmos_cmac_init,
    (void *)&akmos_cmac_setkey,
    (void *)&akmos_cmac_update,
    (void *)&akmos_cmac_done
};

akmos_mac_xmode_t akmos_xmode_cbcmac = {
    AKMOS_MODE_CBCMAC, "CBC-MAC",
    (void *)&akmos_cbcmac_init,
    (void *)&akmos_cbcmac_setkey,
    (void *)&akmos_cbcmac_update,
    (void *)&akmos_cbcmac_done
};

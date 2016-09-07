/*
 *   Copyright (c) 2015-2016, Andrew Romanenko <melanhit@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <libgen.h>

#include "test.h"

int test_path_cipher(akmos_algo_id algo, akmos_mode_id mode, size_t keylen, char *argv0, char *path)
{
    char vname[128], *s;
    const char *alg_name, *mode_name, *dir_name;
    size_t i;

    alg_name = akmos_cipher_name(algo);
    if(!alg_name) {
        akmos_perror(AKMOS_ERR_ALGOID);
        return EXIT_FAILURE;
    }

    mode_name = akmos_mode2str(mode);
    if(!mode_name) {
        akmos_perror(AKMOS_ERR_MODEID);
        return EXIT_FAILURE;
    }

    s = strdup(argv0);
    dir_name = dirname(s);

    sprintf(vname, "%s-%s-%zd.bin", mode_name, alg_name, keylen);

    for(i = 0; i < strlen(vname); i++)
        vname[i] = (char)tolower(vname[i]);

    sprintf(path, "%s/%s", dir_name, vname);

    free(s);

    return EXIT_SUCCESS;
}

int test_path_digest(akmos_algo_id algo, char *argv0, char *path)
{
    char vname[128], *s;
    const char *alg_name, *dir_name;
    size_t i;

    alg_name = akmos_digest_name(algo);
    if(!alg_name) {
        akmos_perror(AKMOS_ERR_ALGOID);
        return EXIT_FAILURE;
    }

    s = strdup(argv0);
    dir_name = dirname(s);

    sprintf(vname, "digest-%s.bin", alg_name);

    for(i = 0; i < strlen(vname); i++)
        vname[i] = (char)tolower(vname[i]);

    sprintf(path, "%s/%s", dir_name, vname);

    free(s);

    return EXIT_SUCCESS;
}

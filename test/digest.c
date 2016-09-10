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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "test.h"

static int digest_calc(test_digest_t *dctx, akmos_algo_id algo, size_t diglen, size_t blklen, size_t *res)
{
    uint8_t *buf, *out, *p;
    int err;
    size_t i, len;
    akmos_digest_t ctx;

    buf = out = NULL;
    err = EXIT_SUCCESS;

    out = malloc(diglen);
    if(!out) {
        err = AKMOS_ERR_ENOMEM;
        goto out;
    }

    len = TEST_CNT * blklen;
    buf = malloc(len + 1);
    if(!buf) {
        err = AKMOS_ERR_ENOMEM;
        goto out;
    }

    test_rand(buf, len);

    /* test empty input */
    err = akmos_digest_ex(algo, buf, 0, out);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    if(memcmp(out, dctx->h1, diglen) != 0) {
        *res = TEST_FAIL;
        goto out;
    }

    /* test full input (TEST_CNT * blklen) */
    err = akmos_digest_ex(algo, buf, len, out);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    if(memcmp(out, dctx->h2, diglen) != 0) {
        *res = TEST_FAIL;
        goto out;
    }

    err = akmos_digest_init(&ctx, algo);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    p = buf;
    for(i = 0; i < len; i++, p++) {
        akmos_digest_update(ctx, p, 1);
    }

    akmos_digest_done(ctx, out);

    if(memcmp(out, dctx->h2, diglen) != 0) {
        *res = TEST_FAIL;
        goto out;
    }

    /* test input not multiple digest block length */
    len = blklen + 1;

    err = akmos_digest_ex(algo, buf, len, out);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    if(memcmp(out, dctx->h3, diglen) != 0) {
        *res = TEST_FAIL;
        goto out;
    }

    len = blklen - 1;

    err = akmos_digest_ex(algo, buf, len, out);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    if(memcmp(out, dctx->h4, diglen) != 0) {
        *res = TEST_FAIL;
        goto out;
    }

out:
    if(out)
        free(out);

    if(buf)
        free(buf);

    return err;
}

static int digest(akmos_algo_id algo, char *argv0, size_t *res)
{
    char path[512];
    uint8_t buf[BUFSIZ];
    size_t len;
    int err;
    FILE *fd;
    const akmos_digest_xdesc_t *desc;

    test_digest_t dctx;

    err = test_path_digest(algo, argv0, path);
    if(err)
        return err;

    fd = fopen(path, "r");
    if(!fd) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }

    len = fread(buf, 1, BUFSIZ, fd);
    if(ferror(fd)) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }

    fclose(fd);

    desc = akmos_digest_desc(algo);
    if(!desc)
        return akmos_perror(AKMOS_ERR_ALGOID);

    if(len != (desc->outlen * (sizeof(dctx) / sizeof(dctx.h1)))) {
        fprintf(stderr, "Invalid data in \"%s\"\n", path);
        return EXIT_FAILURE;
    }

    dctx.h1 = buf;
    dctx.h2 = buf + desc->outlen;
    dctx.h3 = buf + (desc->outlen * 2);
    dctx.h4 = buf + (desc->outlen * 3);

    err = digest_calc(&dctx, algo, desc->outlen, desc->blklen, res);
    if(err)
        return err;

    return EXIT_SUCCESS;
}

int test_digest(akmos_algo_id algo, char *argv0)
{
    char pname[128];
    size_t res;
    int err;
    const akmos_digest_xdesc_t *desc;

    desc = akmos_digest_desc(algo);
    if(!desc)
        return akmos_perror(AKMOS_ERR_ALGOID);

    res = TEST_PASS;
    err = digest(algo, argv0, &res);
    if(err)
        return err;

    sprintf(pname, "Digest-%s", desc->name);
    test_print(pname, res);
    test_total(res);

    return EXIT_SUCCESS;
}

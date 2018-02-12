/*
 *   Copyright (c) 2016-2018, Andrew Romanenko <melanhit@gmail.com>
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
#include <errno.h>

#include <time.h>
#include <pthread.h>

#include <akmos.h>

#include "bench.h"

static void *cipher(void *arg)
{
    akmos_cipher_t ctx;
    struct opt_bench_s *opt;
    unsigned j;

    opt = (struct opt_bench_s *)arg;
    opt->start = clock();

    for(;;) {
        opt->stop = clock();
        pthread_testcancel();

        opt->err = akmos_cipher_init(&ctx, opt->algo, opt->mode|AKMOS_MODE_ENCRYPT);
        if(opt->err)
            return NULL;

        opt->err = akmos_cipher_setkey(ctx, opt->key, opt->keylen);
        if(opt->err)
            return NULL;

        akmos_cipher_setiv(ctx, NULL);

        for(j = 0; j < opt->num; j++, opt->cnt++)
            akmos_cipher_crypt(ctx, opt->blk, opt->len, opt->blk);

        akmos_cipher_free(ctx);
    }

    return NULL;
}

int bench_cipher(akmos_algo_id algo, akmos_mode_id mode, struct opt_bench_s *opt)
{
    const akmos_cipher_xdesc_t *cd;
    pthread_t thread;
    size_t i;
    uint8_t key[BENCH_MAXKEYLEN];
    int err;

    opt->algo = algo;
    opt->mode = mode;

    cd = akmos_cipher_desc(algo);
    if(!cd)
        return EXIT_FAILURE;

    for(i = 0; i < sizeof(key); i++)
        key[i] = (i % UINT8_MAX) & UINT8_MAX;

    opt->key = key;
    for(i = cd->keymin; i <= cd->keymax; i += cd->keystep) {
        opt->cnt = 0;
        opt->keylen = i;

        err = pthread_create(&thread, NULL, &cipher, opt);
        if(err) {
            fprintf(stderr, "%s\n", strerror(errno));
            return err;
        }

        sleep(opt->time);

        pthread_cancel(thread);
        pthread_join(thread, NULL);

        if(opt->err) {
            akmos_perror(opt->err);
            return EXIT_FAILURE;
        }

        bench_print(opt);
    }

    return EXIT_SUCCESS;
}

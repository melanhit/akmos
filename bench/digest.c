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
#include <errno.h>

#include <time.h>
#include <pthread.h>

#include <akmos.h>

#include "bench.h"

static void *digest(void *arg)
{
    akmos_digest_t ctx;
    struct opt_bench_s *opt;
    unsigned j;
    uint8_t md[BENCH_MAXMDLEN];

    opt = (struct opt_bench_s *)arg;
    opt->start = clock();

    for(;;) {
        opt->stop = clock();
        pthread_testcancel();

        opt->err = akmos_digest_init(&ctx, opt->algo);
        if(opt->err)
            return NULL;

        for(j = 0; j < opt->num; j++, opt->cnt++)
            akmos_digest_update(ctx, opt->blk, opt->len);

        akmos_digest_done(ctx, md);
    }

    return NULL;
}

int bench_digest(akmos_algo_id algo, struct opt_bench_s *opt)
{
    pthread_t thread;
    int err;

    opt->algo = algo;
    opt->cnt = 0;

    err = pthread_create(&thread, NULL, &digest, opt);
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

    return EXIT_SUCCESS;
}

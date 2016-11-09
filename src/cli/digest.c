/*
 *   Copyright (c) 2014-2016, Andrew Romanenko <melanhit@gmail.com>
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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>

#include "../akmos.h"
#include "../error.h"
#include "cli.h"

#define DEFAULT_THREADS   2
#define MAX_THREADS     128

static akmos_algo_id algo;

struct opt_digest_s {
    size_t num;
    size_t thr_num;
    char **input;
    struct {
        int algo;
        int bin;
    } set;
};

struct opt_thread_s {
    const char *input;
    uint8_t *md;
};

static int parse_arg(struct opt_digest_s *opt, int argc, char **argv)
{
    int c, err;

    while((c = getopt(argc, argv, "a:n:bh")) != -1) {
        switch(c) {
            case 'a':
                algo = akmos_digest_id(optarg);
                if(algo)
                    return akmos_perror(AKMOS_ERR_ALGOID);

                opt->set.algo = c;
                break;

            case 'b':
                opt->set.bin = c;
                break;

            case 'n':
                err = sscanf(optarg, "%2lu", &opt->thr_num);
                if((err == EOF) || (!err) || (opt->thr_num < 1)) {
                    fprintf(stderr, "Invalid number of the threads\n");
                    return EXIT_FAILURE;
                }
                if(opt->thr_num > MAX_THREADS) {
                    fprintf(stderr, "Invalid number of the threads (maximum %d)\n", MAX_THREADS);
                    return EXIT_FAILURE;
                }

                break;

            case 'h':
            default:
                printf("Usage: akmos dgst [-a algo] [-n thread] [-b] <input>\n");
                return EXIT_FAILURE;
        }
    }

    if(!opt->set.algo)
        algo = AKMOS_ALGO_SHA2_256;

    opt->num   = (size_t)(argc - optind);
    opt->input = argv + optind;

    if(opt->num == 0) {
        opt->num = 1;
        opt->input[0] = NULL;
    }

    return EXIT_SUCCESS;
}

static void print_hex(const char *path, const char *stralg, uint8_t *md, size_t len)
{
    size_t i;
    const char *s = "-";

    for(i = 0; i < len; i++)
        printf("%.2x", md[i]);

    if(!path)
        path = s;

    printf(" = %s(%s)\n", stralg, path);
}

static void print_raw(uint8_t *md, size_t len)
{
    size_t i;

    for(i = 0; i < len; i++)
        printf("%c", md[i]);
}

static void *digest(void *arg)
{
    akmos_digest_t ctx;
    struct opt_thread_s *opt;
    int err;
    size_t len;
    uint8_t buf[BUFSIZ];
    FILE *fd;

    fd = NULL;

    opt = (struct opt_thread_s *)arg;

    if(!opt->input)
        fd = stdin;
    else
        fd = fopen(opt->input, "r");

    if(!fd) {
        fprintf(stderr, "%s: %s\n", opt->input, strerror(errno));
        return NULL;
    }

    err = akmos_digest_init(&ctx, algo);
    if(err) {
        akmos_perror(err);
        return NULL;
    }

    while((len = fread(buf, 1, BUFSIZ, fd)) != 0)
        akmos_digest_update(ctx, buf, len);

    if(ferror(fd)) {
        fprintf(stderr, "%s: %s\n", opt->input, strerror(errno));
        return NULL;
    }

    akmos_digest_done(ctx, opt->md);

    if(fd)
        fclose(fd);

    return NULL;
}

int akmos_cli_digest(int argc, char **argv)
{
    struct opt_digest_s opt;
    struct opt_thread_s thr_opt[MAX_THREADS];
    const akmos_digest_xdesc_t *desc;
    pthread_t *thread;
    uint8_t *md;
    size_t i, j, thr_cnt;
    int err;

    err = EXIT_SUCCESS;

    memset(&opt, 0, sizeof(opt));
    err = parse_arg(&opt, argc, argv);
    if(err)
        return err;

    if(!opt.thr_num)
        opt.thr_num = DEFAULT_THREADS;

    if(opt.num < opt.thr_num)
        opt.thr_num = opt.num;

    thread = malloc(sizeof(pthread_t) * opt.thr_num);
    if(thread == NULL) {
        fprintf(stderr, "%s\n", strerror(errno));
        return err;
    }

    desc = akmos_digest_desc(algo);
    if(!desc)
        return akmos_perror(AKMOS_ERR_ALGOID);

    err = amalloc(&md, desc->outlen * opt.thr_num);
    if(err)
        goto out;

    for(i = 0, j = 0; i < opt.thr_num; i++, j += desc->outlen)
        thr_opt[i].md = md + j;

    for(i = 0, thr_cnt = opt.thr_num; i < opt.num; i += opt.thr_num, opt.input += opt.thr_num) {
        if((opt.num - i) < opt.thr_num)
            thr_cnt = opt.num - i;

        for(j = 0; j < thr_cnt; j++) {
            thr_opt[j].input = opt.input[j];

            err = pthread_create(&thread[j], NULL, &digest, &thr_opt[j]);
            if(err) {
                fprintf(stderr, "%s\n", strerror(errno));
                goto out;
            }
        }

        for(j = 0; j < thr_cnt; j++) {
            err = pthread_join(thread[j], NULL);
            if(err) {
                fprintf(stderr, "%s\n", strerror(errno));
                goto out;
            }
        }

        for(j = 0; j < thr_cnt; j++) {
            if(!opt.set.bin)
                print_hex(thr_opt[j].input, desc->name, thr_opt[j].md, desc->outlen);
            else
                print_raw(thr_opt[j].md, desc->outlen);
        }
    }

out:
    if(md)
        free(md);

    if(thread)
        free(thread);

    return err;
}

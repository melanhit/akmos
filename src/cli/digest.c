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

#ifdef HAVE_ERROR_H
#include <error.h>
#else
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../akmos.h"
#include "cli.h"

struct opt_digest_s {
    int algo;
    int count;
    char **input;
    struct {
        char algo;
        char bin;
    } set;
};

static char *ch = "-";

static int parse_arg(struct opt_digest_s *opt, int argc, char **argv)
{
    int c;

    while((c = getopt(argc, argv, "a:bh")) != -1) {
        switch(c) {
            case 'a':
                opt->algo = akmos_str2algo(optarg);
                if(opt->algo == -1)
                    return akmos_perror(AKMOS_ERR_ALGOID);

                opt->set.algo = c;
                break;

            case 'b':
                opt->set.bin = c;
                break;

            case 'h':
            default:
                printf("Usage: akmos dgst [-a algo] [-b] <input>\n");
                return EXIT_FAILURE;
        }
    }

    if(!opt->set.algo)
        opt->algo = AKMOS_ALGO_SHA2_256;

    opt->count = argc - optind;
    opt->input = argv + optind;

    if(opt->count == 0) {
        opt->count = 1;
        opt->input[0] = ch;
    }

    return EXIT_SUCCESS;
}

static void digest_print_hex(const char *path, const char *stralg, uint8_t *md, size_t len)
{
    size_t i;

    for(i = 0; i < len; i++)
        printf("%.2x", md[i]);

    printf(" = %s(%s)\n", stralg, path);
}

static void digest_print_raw(uint8_t *md, size_t len)
{
    size_t i;

    for(i = 0; i < len; i++)
        printf("%c", md[i]);
}

int akmos_cli_digest(int argc, char **argv)
{
    akmos_digest_ctx *ctx;
    struct opt_digest_s opt;
    int i, err;
    ssize_t len, mdlen;
    uint8_t buf[BUFSIZ], *md;
    FILE *fd;

    fd = NULL;

    memset(&opt, 0, sizeof(opt));
    err = parse_arg(&opt, argc, argv);
    if(err)
        return err;

    mdlen = akmos_diglen(opt.algo);

    AMALLOC(md, mdlen, err);
    if(err)
        return err;

    for(i = 0; i < opt.count; i++) {
        if(strcmp(opt.input[i], "-") == 0)
            fd = stdin;
        else
            fd = fopen(opt.input[i], "r");

        if(!fd) {
            printf("%s: %s\n", opt.input[i], strerror(errno));
            free(md);
            return EXIT_FAILURE;
        }

        err = akmos_digest_init(&ctx, opt.algo);
        if(err) {
            free(md);
            return akmos_perror(err);
        }

        while((len = fread(buf, 1, BUFSIZ, fd)) != 0) {
            if(len == -1) {
                printf("%s: %s\n", opt.input[i], strerror(errno));
                free(md);
                return EXIT_FAILURE;
            }

            akmos_digest_update(ctx, buf, len);
        }

        akmos_digest_done(ctx, md);

        if(fd)
            fclose(fd);

        if(!opt.set.bin)
            digest_print_hex(opt.input[i], akmos_algo2str(opt.algo), md, mdlen);
        else
            digest_print_raw(md, mdlen);
    }

    if(md)
        free(md);

    return EXIT_SUCCESS;
}

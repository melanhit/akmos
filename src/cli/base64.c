/*
 *   Copyright (c) 2018, Andrew Romanenko <melanhit@gmail.com>
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
#include <fcntl.h>

#include "../akmos.h"
#include "../error.h"
#include "cli.h"

#define FMT_LEN 64

struct opt_base64_s {
    char *input;
    char *output;
    char buf[FMT_LEN];
    int mode;
    struct {
        int u;
    } set;
    int ver;
};

static int parse_arg(struct opt_base64_s *opt, int argc, char **argv)
{
    int c, len;

    while((c = getopt(argc, argv, "eduVh")) != -1) {
        switch(c) {
            case 'e':
            case 'd':
                opt->mode = c;
                break;

            case 'u':
                opt->set.u = c;
                break;

            case 'V':
                opt->ver = c;
                return EXIT_SUCCESS;

            case 'h':
            default:
                printf("Usage: akmos base64 [-e | -d] [-u] [-V] <input> <output>\n");
                return EXIT_FAILURE;
        }
    }

    if(!opt->mode)
        opt->mode = 'e';

    len = argc - optind;
    switch(len) {
        case 0:
            opt->input = NULL;
            opt->output = NULL;
            break;

        case 1:
            opt->input = argv[optind];
            opt->output = NULL;
            break;

        case 2:
            opt->input = argv[optind];
            opt->output = argv[optind + 1];
            break;

        default:
            fprintf(stderr, "Missing <input> or <output>\n");
            return EXIT_FAILURE;
     }

    return EXIT_SUCCESS;
}

static int base64_fread(FILE *fd, uint8_t *buf, size_t *buf_len)
{
    size_t i, j, len;

    len = fread(buf, 1, *buf_len, fd);
    for(i = 0, j = 0; i < len; i++) {
        if(buf[i] == '\n' || buf[i] == ' ')
            continue;

        buf[j] = buf[i];
        j++;
    }

    *buf_len = j;

    return EXIT_SUCCESS;
}

static int base64_fwrite(FILE *fd, uint8_t *buf, size_t len)
{
    const char c = '\n';
    static size_t wlen = 0;
    size_t i, n, tmplen;

    tmplen = FMT_LEN - wlen;
    if(tmplen > len) {
        if(fwrite(buf, 1, len, fd) != len)
            return EXIT_FAILURE;

        wlen += len;

        return EXIT_SUCCESS;
    } else {
        if(fwrite(buf, 1, tmplen, fd) != tmplen)
            return EXIT_FAILURE;

        if(fwrite(&c, 1, 1, fd) != 1)
            return EXIT_FAILURE;

        buf += tmplen;
        len -= tmplen;
        wlen = 0;
    }

    n = len / FMT_LEN;
    for(i = 0; i < n; i++) {
        if(fwrite(buf, 1, FMT_LEN, fd) != FMT_LEN)
            return EXIT_FAILURE;

        if(fwrite(&c, 1, 1, fd) != 1)
            return EXIT_FAILURE;

        buf += FMT_LEN;
    }

    n = len % FMT_LEN;
    if(n) {
        if(fwrite(buf, 1, n, fd) != n)
            return EXIT_FAILURE;

        wlen = n;
    }

    return EXIT_SUCCESS;
}

static int base64_bread(FILE *fd, uint8_t *buf, size_t *buf_len)
{
    *buf_len = fread(buf, 1, *buf_len, fd);
    if(ferror(fd))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static int base64_bwrite(FILE *fd, uint8_t *buf, size_t len)
{
    if(fwrite(buf, 1, len, fd) != len)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int akmos_cli_base64(int argc, char **argv)
{
    akmos_base64_t ctx;
    akmos_algo_id algo;
    akmos_mode_id mode;
    struct opt_base64_s opt;
    const char nl = '\n';
    uint8_t *buf, *buf_in, *buf_out;
    size_t buf_len, len_in, len_out;
    int err;
    FILE *fd_in, *fd_out;

    int(*base64_write)(FILE *, uint8_t *, size_t);
    int(*base64_read) (FILE *, uint8_t *, size_t *);

    ctx = NULL;
    buf = NULL;
    err = EXIT_SUCCESS;

    memset(&opt, 0, sizeof(opt));
    err = parse_arg(&opt, argc, argv);
    if(err)
        return err;

    if(opt.ver)
        return akmos_cli_version();

    fd_in = fd_out = NULL;

    if(!opt.input)
        fd_in = stdin;
    else
        fd_in = fopen(opt.input, "r");

    if(!fd_in) {
        fprintf(stderr, "%s: %s\n", opt.input, strerror(errno));
        err = AKMOS_ERR_FAILED;
        goto out;
    }

    if(!opt.output)
        fd_out = stdout;
    else
        fd_out = fopen(opt.output, "w");

    if(!fd_out) {
        fprintf(stderr, "%s: %s\n", opt.output, strerror(errno));
        err = AKMOS_ERR_FAILED;
        goto out;
    }

    buf_len = BUFSIZ;
    if(opt.mode == 'e') {
        buf_len += akmos_base64_enclen(BUFSIZ);
        mode = AKMOS_MODE_ENCODE;
        base64_read = &base64_bread;
        base64_write = &base64_fwrite;
    } else {
        buf_len += akmos_base64_declen(BUFSIZ);
        mode = AKMOS_MODE_DECODE;
        base64_read = &base64_fread;
        base64_write = &base64_bwrite;
    }

    if(opt.set.u)
        algo = AKMOS_ALGO_BASE64URL;
    else
        algo = AKMOS_ALGO_BASE64;

    buf = malloc(buf_len);
    if(!buf) {
        err = AKMOS_ERR_ENOMEM;
        goto out;
    }

    buf_in = buf;
    buf_out = buf + BUFSIZ;

    err = akmos_base64_init(&ctx, algo, mode);
    if(err)
        goto out;

    for(;;) {
        len_in = BUFSIZ;
        err = base64_read(fd_in, buf_in, &len_in);
        if(err != EXIT_SUCCESS) {
            fprintf(stderr, "%s: %s\n", opt.input, strerror(errno));
            goto out;
        }

        if(!len_in)
            break;

        err = akmos_base64_update(ctx, buf_in, len_in, buf_out, &len_out);
        if(err) {
            akmos_perror(err);
            goto out;
        }

        err = base64_write(fd_out, buf_out, len_out);
        if(err != EXIT_SUCCESS) {
            fprintf(stderr, "%s: %s\n", opt.output, strerror(errno));
            goto out;
        }
    }

    err = akmos_base64_done(ctx, buf_out, &len_out);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    err = base64_write(fd_out, buf_out, len_out);
    if(err != EXIT_SUCCESS) {
        fprintf(stderr, "%s: %s\n", opt.output, strerror(errno));
        goto out;
    }

    if(opt.mode == 'e') {
        if(fwrite(&nl, 1, 1, fd_out) != 1) {
            err = EXIT_FAILURE;
            fprintf(stderr, "%s: %s\n", opt.output, strerror(errno));
            goto out;
        }
    }

out:
    if(fd_in)
        fclose(fd_in);

    if(fd_out)
        fclose(fd_out);

    if(buf)
        free(buf);

    return err;
}

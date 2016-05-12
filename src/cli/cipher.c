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
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <termios.h>

#include "../akmos.h"
#include "cli.h"
#include "secur.h"

#define DEFAULT_EALGO   AKMOS_ALGO_TWOFISH
#define DEFAULT_BMODE   AKMOS_MODE_CBC
#define DEFAULT_SMODE   AKMOS_MODE_CTR
#define DEFAULT_DALGO   AKMOS_ALGO_SHA2_512
#define DEFAULT_KEYLEN  128
#define DEFAULT_ITER    4096

#define MAX_PASSLEN     128

#define BUFLEN          (BUFSIZ*2)

struct opt_cipher_s {
    int algo;
    int mode;
    size_t blklen;
    size_t keylen;
    uint32_t iter;
    char pass[MAX_PASSLEN];
    char *key;
    char *input;
    char *output;
    struct {
        char algo;
        char mode;
        char pass;
        char key;
        char keylen;
        char iter;
        char over;
        int flag;
    } set;
};

struct header_cipher_s {
    uint8_t *iv;
    uint8_t *key;
};

static int prompt_over(char *s, int flag)
{
    int ans;

    /* use flag for skip newline of printf, unclean but work :) */
    if(flag) {
        ans = getchar();

        if(ans == EOF)
            return 0;
    }

    printf("Overwrite %s? [Y/n] ", s);

    ans = getchar();
    if(ans == EOF)
        return 0;

    if(ans == 'y' || ans == 'Y' || ans == '\n')
        return 1;
    else
        return 0;
}

static int parse_algo(struct opt_cipher_s *opt, char *algo_str)
{
    char *s1, *s2, *sv;

    if(!algo_str) {
        printf("Missing cipher algorithm\n");
        return EXIT_FAILURE;
    }

    s1 = strtok_r(algo_str, ":", &sv);
    s2 = strtok_r(NULL, ":", &sv);

    if(!s2) {
        if(strcasecmp(s1, algo_str) != 0) {
            akmos_perror(AKMOS_ERR_ALGOID);
            return EXIT_FAILURE;
        }
        opt->set.flag = 0;
    } else {
        if(strcasecmp(s2, "ede") == 0)
            opt->set.flag = AKMOS_ALGO_FLAG_EDE;
        else if(strcasecmp(s2, "eee") == 0)
            opt->set.flag = AKMOS_ALGO_FLAG_EEE;
        else {
            printf("Unknown cipher flag \'%s\'\n", s2);
            return EXIT_FAILURE;
        }
    }

    opt->algo = akmos_cipher_id(s1);
    if(!opt->algo)
        return akmos_perror(AKMOS_ERR_ALGOID);

    return EXIT_SUCCESS;
}

static int parse_arg(struct opt_cipher_s *opt, int argc, char **argv)
{
    char *algo_str, *mode_str, *keylen_str;
    int c, err;

    algo_str = mode_str = keylen_str = NULL;

    while((c = getopt(argc, argv, "a:m:l:pk:i:hy")) != -1) {
        switch(c) {
            case 'a':
                algo_str = optarg;
                opt->set.algo = c;
                break;

            case 'm':
                mode_str = optarg;
                opt->set.mode = c;
                break;

            case 'l':
                keylen_str = optarg;
                opt->set.keylen = c;
                break;

            case 'p':
                opt->set.pass = c;
                break;

            case 'k':
                opt->key = optarg;
                opt->set.key = c;
                break;

            case 'i':
                err = sscanf(optarg, "%5u", &opt->iter);
                if(err == EOF || !err) {
                    printf("Invalid number iterations\n");
                    return EXIT_FAILURE;
                }

                opt->set.iter = c;
                break;

            case 'y':
                opt->set.over = c;
                break;

            case 'h':
            default:
                printf("Usage: akmos enc|dec [-a algo] [-m mode] [-k key] [-l keylen] [-p] [-i iter] [-y] [-h] <input> <output>\n");
                return EXIT_FAILURE;
        }
    }

    /* check input/output */
    if((argc - optind) != 2) {
        printf("Missing <input> or <output>\n");
        return EXIT_FAILURE;
    }

    opt->input = argv[optind];
    opt->output = argv[optind + 1];

    /* set algo */
    if(!opt->set.algo) {
        opt->algo = DEFAULT_EALGO;
    } else {
        err = parse_algo(opt, algo_str);
        if(err)
            return err;
    }

    /* set mode */
    if(!opt->set.mode) {
        switch(opt->algo) {
            case AKMOS_ALGO_SALSA:
            case AKMOS_ALGO_CHACHA:
                opt->mode = DEFAULT_SMODE;
                break;

            default:
                opt->mode = DEFAULT_BMODE;
                break;
        }
    } else {
        if(mode_str) {
            opt->mode = akmos_str2mode(mode_str);
            if(opt->mode == -1)
                return akmos_perror(AKMOS_ERR_MODEID);
        }
    }

    if(!opt->set.key && !opt->set.pass)
        opt->set.pass = 'p';

    /* set keylen */
    if(!opt->set.keylen) {
        switch(opt->algo) {
            case AKMOS_ALGO_THREEFISH_256:
                opt->keylen = 256;
                break;

            case AKMOS_ALGO_THREEFISH_512:
                opt->keylen = 512;
                break;

            case AKMOS_ALGO_THREEFISH_1024:
                opt->keylen = 1024;
                break;

            case AKMOS_ALGO_CHACHA:
                opt->keylen = 256;
                break;

            default:
                opt->keylen = DEFAULT_KEYLEN;
                break;
       }
    } else {
        if(keylen_str) {
            err = sscanf(keylen_str, "%4zu", &opt->keylen);
            if(err == EOF || !err)
                return akmos_perror(AKMOS_ERR_KEYLEN);
        }
    }

    if(opt->keylen > (CIPHER_MAX_KEYLEN*8) || opt->keylen == 0 || (opt->keylen % 8) != 0) {
        printf("Invalid key length (err = %d)\n", AKMOS_ERR_KEYLEN);
        return EXIT_FAILURE;
    }
    opt->keylen /= 8;

    if((opt->blklen = akmos_cipher_blklen(opt->algo)) == 0) {
        printf("Invalid algo\n");
        return EXIT_FAILURE;
    }

    /* read password */
    if(opt->set.pass) {
        err = secur_read_passw(opt->pass);
        if(err) {
            printf("Could not read password\n");
            return EXIT_FAILURE;
        }
    }

    if(opt->set.iter && opt->set.pass) {
        if(opt->iter > UINT16_MAX) {
            printf("Maximum number of iterations - %u\n", UINT32_MAX);
            return EXIT_FAILURE;
        }
    } else {
        opt->iter = DEFAULT_ITER;
    }

    if(opt->set.flag)
        opt->algo |= opt->set.flag;

    return EXIT_SUCCESS;
}

static int lb_padbuf(akmos_cipher_t *ctx, uint8_t *buf, size_t *rlen, size_t blklen, const int enc)
{
    size_t len, tmplen;

    len = *rlen;

    if(enc == AKMOS_MODE_ENCRYPT) {
        tmplen = (len / blklen) * blklen;
        akmos_padadd(buf + tmplen, len - tmplen, buf + tmplen, blklen);

        akmos_cipher_crypt(ctx, buf + tmplen, blklen, buf + tmplen);

        *rlen = tmplen + blklen;
    }

    if(enc == AKMOS_MODE_DECRYPT) {
        if((len % blklen) != 0 || len < blklen)
            return EXIT_FAILURE;

        tmplen = akmos_padrem(buf + (len - blklen), blklen);
        *rlen = len + tmplen - blklen;
    }

    return EXIT_SUCCESS;
}

int akmos_cli_cipher(int argc, char **argv, akmos_mode_id enc)
{
    akmos_cipher_t *ctx;
    struct opt_cipher_s opt;
    akmos_cipher_header_t hd;
    struct stat sb;
    uint8_t *keybuf, *keypass;
    uint8_t *buf, *tbuf, *hbuf, *hdp, *rbuf, *wbuf;
    size_t keylen, rlen, wlen, hlen, tmplen;
    mode_t mask;
    FILE *fd_in, *fd_out;
    int err;

    ctx = NULL;
    keybuf = hbuf = buf = NULL;
    fd_in = fd_out = NULL;

    memset(&opt, 0, sizeof(struct opt_cipher_s));
    err = parse_arg(&opt, argc, argv);
    if(err)
        return err;

    /* Setup master keys */
    keylen = opt.keylen * 2;
    if(opt.set.flag)
        keylen *= 3;

    AMALLOC(keybuf, keylen, err);
    if(err)
        return err;
    memset(keybuf, 0, keylen);

    keylen /= 2;
    keypass = keybuf + keylen;

    if(opt.set.pass) {
        tbuf = keypass;
        err = akmos_kdf_pbkdf2(tbuf, keylen, NULL, 0, opt.pass, opt.iter, DEFAULT_DALGO);
        if(err) {
            akmos_perror(err);
            goto out;
        }
    }

    if(opt.set.key) {
        /* keypass is used as salt */
        err = secur_mk_keyfile(opt.key, keybuf, keylen, keypass, keylen);
        if(err)
            goto out;
    } else {
        /* keypass is used as master key */
        memcpy(keybuf, keypass, keylen);
    }

    /* Open source and destination */
    fd_in = fopen(opt.input, "r");
    if(!fd_in) {
        err = EXIT_FAILURE;
        printf("%s: %s\n", opt.input, strerror(errno));
        goto out;
    }

    mask = umask(0);
    umask(mask);

    /* skip fifo and device */
    if(stat(opt.output, &sb) == 0) {
        switch(sb.st_mode & S_IFMT) {
            case S_IFBLK:
            case S_IFCHR:
            case S_IFIFO:
                break;

            default:
                if(!opt.set.over) {
                    if(!prompt_over(opt.output, opt.set.pass)) {
                        err = EXIT_SUCCESS;
                        printf("Not overwriting - exiting\n");
                        goto out;
                    }
                }
        }
    }

    fd_out = fopen(opt.output, "w");
    if(!fd_out) {
        err = EXIT_FAILURE;
        printf("%s: %s\n", opt.output, strerror(errno));
        goto out;
    }

    /* Create and cook header */
    hlen = sizeof(struct akmos_cipher_header_s);
    hdp = (uint8_t *)&hd;
    AMALLOC(hbuf, hlen, err);
    if(err)
        goto out;

    if(enc == AKMOS_MODE_DECRYPT) {
        if(fread(hdp, 1, hlen, fd_in) != hlen) {
            err = EXIT_FAILURE;
            printf("%s: %s\n", opt.input, strerror(errno));
            goto out;
        }
    } else {
        err = secur_rand_buf(hdp, hlen);
        if(err)
            goto out;

        hd.version = CIPHER_VERSION;
    }

    err = akmos_cipher_ex(opt.algo, opt.mode|enc, keybuf, opt.keylen, NULL, hdp, hlen, hbuf);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    /* store header in file or struct */
    if(enc == AKMOS_MODE_ENCRYPT) {
        if(fwrite(hbuf, 1, hlen, fd_out) != hlen) {
            err = EXIT_FAILURE;
            printf("%s: %s\n", opt.output, strerror(errno));
            goto out;
        }
    } else {
        memcpy(hdp, hbuf, hlen);
    }

    /* Create and init cipher contexts */
    err = akmos_cipher_init(&ctx, opt.algo, opt.mode|enc);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    /* Setup cipher key and IV */
    err = akmos_cipher_setkey(ctx, hd.key, opt.keylen);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    if(opt.mode != AKMOS_MODE_ECB)
        akmos_cipher_setiv(ctx, hd.iv);

    if(opt.mode == AKMOS_MODE_CTR)
        akmos_cipher_setcnt(ctx, NULL);

    /* enc/dec input to output */
    AMALLOC(buf, BUFLEN + opt.blklen, err);
    if(err)
        goto out;
    memset(buf, 0, BUFLEN + opt.blklen);

    rbuf = buf;
    wbuf = buf + BUFSIZ;

    rlen = fread(rbuf, 1, BUFSIZ, fd_in);
    while(1) {
        wlen = fread(wbuf, 1, BUFSIZ, fd_in);
        if(rlen == -1 || wlen == -1) {
            err = EXIT_FAILURE;
            printf("%s: %s\n", opt.input, strerror(errno));
            goto out;
        }

        akmos_cipher_crypt(ctx, rbuf, rlen, rbuf);

        if(!wlen)
            break;

        if(fwrite(rbuf, 1, rlen, fd_out) != rlen) {
            err = EXIT_FAILURE;
            printf("%s: %s\n", opt.output, strerror(errno));
            goto out;
        }

        tbuf = rbuf; rbuf = wbuf; wbuf = tbuf;
        tmplen = rlen; rlen = wlen; wlen = tmplen;
    }

    switch(opt.mode) {
        case AKMOS_MODE_ECB:
        case AKMOS_MODE_CBC:
        case AKMOS_MODE_CFB:
            err = lb_padbuf(ctx, rbuf, &rlen, opt.blklen, enc);
            if(err)
                goto out;

            break;

        default:
            break;
    }

    if(fwrite(rbuf, 1, rlen, fd_out) != rlen) {
        err = EXIT_FAILURE;
        printf("%s: %s\n", opt.output, strerror(errno));
        goto out;
    }

out:
    if(fd_in)
        fclose(fd_in);

    if(fd_out)
        fclose(fd_out);

    if(keybuf) {
        akmos_memzero(keybuf, keylen);
        free(keybuf);
    }

    if(buf) {
        akmos_memzero(buf, BUFLEN + opt.blklen);
        free(buf);
    }

    if(hbuf) {
        akmos_memzero(hbuf, hlen);
        free(hbuf);
    }

    akmos_memzero(&hd, hlen);

    if(ctx)
        akmos_cipher_free(ctx);

    return err;
}

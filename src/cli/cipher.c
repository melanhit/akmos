/*
 *   Copyright (c) 2014-2018, Andrew Romanenko <melanhit@gmail.com>
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
#include "../error.h"

#include "cli.h"
#include "pw.h"
#include "cipher.h"

#define BUFLEN  (BUFSIZ*2)

const char *cipher_mode[] = {"CBC", "CFB", "CTR", "ECB", "OFB", "OFB1", NULL};

static void cipher_list_blk(const char *algo, size_t keymin, size_t keymax, size_t keystep)
{
    const char **p;
    char buf[32];
    size_t i, j;

    for(i = keymin, j = 0, p = cipher_mode; i <= keymax; i += keystep, p = cipher_mode) {
        while(*p) {
            if(j == 3) {
                j = 0;
                fprintf(stdout, "\n");
            }

            snprintf(buf, sizeof(buf), "%s-%zd-%s", algo, i*8, *p);
            fprintf(stdout, "%-24.24s", buf);

            p++;
            j++;
        }
    }

    fprintf(stdout, "\n");
}

static void cipher_list_strm(const char *algo, size_t keymin, size_t keymax, size_t keystep)
{
    char buf[32];
    size_t i, j;

    for(i = keymin, j = 0; i <= keymax; i += keystep, j++) {
        if(j == 3) {
            j = 0;
            fprintf(stdout, "\n");
        }

        snprintf(buf, sizeof(buf), "%s-%zd", algo, i*8);
        fprintf(stdout, "%-24.24s", buf);
    }

    fprintf(stdout, "\n");
}

static int cipher_list_common(const char *algo_str)
{
    akmos_algo_id algo;
    const akmos_cipher_xdesc_t *desc;

    algo = akmos_cipher_id(algo_str);
    if(!algo)
        return akmos_perror(AKMOS_ERR_ALGOID);

    desc = akmos_cipher_desc(algo);
    if(!desc) {
        fprintf(stderr, "Invalid cipher algorithm\n");
        return EXIT_FAILURE;
    }

    if((algo == AKMOS_ALGO_SALSA) || (algo == AKMOS_ALGO_CHACHA))
        cipher_list_strm(desc->name, desc->keymin, desc->keymax, desc->keystep);
    else
        cipher_list_blk(desc->name, desc->keymin, desc->keymax, desc->keystep);

    return EXIT_SUCCESS;
}

static int cipher_list_threefish()
{
    akmos_algo_id algo;
    const akmos_cipher_xdesc_t *desc;
    const char *name = "Threefish";
    char buf[16];
    size_t i;

    for(i = 256; i <= 1024; i *= 2) {
        snprintf(buf, sizeof(buf), "%s-%zd", name, i);

        algo = akmos_cipher_id(buf);
        if(!algo)
            return akmos_perror(AKMOS_ERR_ALGOID);

        desc = akmos_cipher_desc(algo);
        if(!desc) {
            fprintf(stderr, "Invalid cipher algorithm\n");
            return EXIT_FAILURE;
        }

        cipher_list_blk(name, desc->keymin, desc->keymax, desc->keystep);
    }

    return EXIT_SUCCESS;
}

static int cipher_list(const char *algo_str)
{
    if(strcasecmp(algo_str, "threefish") != 0)
        return cipher_list_common(algo_str);
    else
        return cipher_list_threefish();
}

static int prompt_over(char *s)
{
    int ans;

    printf("Overwrite %s? [Y/n] ", s);

    ans = getchar();

    if(ans == EOF)
        return 0;

    if(ans == 'y' || ans == 'Y' || ans == '\n')
        return 1;
    else
        return 0;
}

static int parse_algo(cipher_opt_t *opt, char *algo_str)
{
    char s[32], s_algo[16], s_keylen[8], s_mode[8], s_tdea[8];
    int err, n;

    n = sscanf(algo_str, "%15[^-]-%7[^-]-%7[^:]:%7s", s_algo, s_keylen, s_mode, s_tdea);
    if(n < 2) {
        fprintf(stderr, "Invalid cipher algorithm\n");
        return EXIT_FAILURE;
    }

    /* set cipher algo id */
    if(strcasecmp("threefish", s_algo) == 0)
        snprintf(s, sizeof(s), "%s-%s", s_algo, s_keylen);
    else
        strcpy(s, s_algo);

    opt->algo = akmos_cipher_id(s);
    if(!opt->algo)
        return akmos_perror(AKMOS_ERR_ALGOID);

    /* set cipher key length */
    err = sscanf(s_keylen, "%4zu", &opt->keylen);
    if(err == EOF || !err)
        return akmos_perror(AKMOS_ERR_KEYLEN);

    /* check for stream cipher */
    if((opt->algo == AKMOS_ALGO_SALSA) || (opt->algo == AKMOS_ALGO_CHACHA)) {
        if(n != 2) {
            fprintf(stderr, "Invalid cipher algorithm\n");
            return EXIT_FAILURE;
        }
        opt->mode = CIPHER_DEFAULT_SMODE;
        opt->flag = 0;

        return EXIT_SUCCESS;
    }

    /* set cipher mode */
    opt->mode = akmos_str2mode(s_mode);
    if(!opt->mode)
    return akmos_perror(AKMOS_ERR_MODEID);

    /* set tdea */
    if(n == 4) {
        if(strcasecmp(s_tdea, "ede") == 0)
            opt->flag = AKMOS_ALGO_FLAG_EDE;
        else if(strcasecmp(s_tdea, "eee") == 0)
            opt->flag = AKMOS_ALGO_FLAG_EEE;
        else {
            fprintf(stderr, "Unknown cipher flag \'%s\'\n", s_tdea);
            return EXIT_FAILURE;
        }
    } else {
        opt->flag = 0;
    }

    return EXIT_SUCCESS;
}

static int parse_arg(cipher_opt_t *opt, int argc, char **argv)
{
    char *algo_str;
    int c, err, len;

    algo_str = NULL;

    while((c = getopt(argc, argv, "a:pP:k:l:i:yVh")) != -1) {
        switch(c) {
            case 'a':
                algo_str = optarg;
                opt->set.algo = c;
                break;

            case 'p':
                opt->set.passw = c;
                break;

            case 'P':
                opt->passf = optarg;
                opt->set.passf = c;
                break;

            case 'k':
                opt->key = optarg;
                opt->set.key = c;
                break;

            case 'y':
                opt->set.over = c;
                break;

            case 'V':
                opt->ver = c;
                return EXIT_SUCCESS;

            case 'l':
                opt->set.list = c;
                opt->s_algo = optarg;
                break;

            case 'h':
            default:
                printf("Usage: akmos enc|dec [-a algo] [-k key] [-p | -P passfile] [-l algo] [-y] [-h] [-V] <input> <output>\n");
                return EXIT_FAILURE;
        }
    }

    /* print cipher algo forms */
    if(opt->set.list)
        return EXIT_SUCCESS;

    /* check input/output */
    len = argc - optind;
    switch(len) {
        case 0:
            opt->input = NULL;
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

    /* set algo */
    if(!opt->set.algo) {
        opt->algo   = CIPHER_DEFAULT_EALGO;
        opt->mode   = CIPHER_DEFAULT_BMODE;
        opt->keylen = CIPHER_DEFAULT_KEYLEN;
    } else {
        err = parse_algo(opt, algo_str);
        if(err)
            return err;
    }

    if(opt->keylen > (CIPHER_MAX_KEYLEN*8) || opt->keylen == 0 || (opt->keylen % 8) != 0) {
        fprintf(stderr, "Invalid key length (err = %d)\n", AKMOS_ERR_KEYLEN);
        return EXIT_FAILURE;
    }
    opt->keylen /= 8;

    if((opt->blklen = akmos_cipher_blklen(opt->algo)) == 0) {
        fprintf(stderr, "Invalid cipher algorithm\n");
        return EXIT_FAILURE;
    }

    if(!opt->set.key && !opt->set.passw && !opt->set.passf)
        opt->set.passw = 'p';

    /* read password */
    if(opt->set.passw && opt->set.passf) {
        fprintf(stderr, "Options -p and -P are mutually exlusive\n");
        return EXIT_FAILURE;
    }

    if(opt->set.passw) {
        err = pw_read_passw(opt->pass);
        if(err)
            return err;
    }

    if(opt->set.passf) {
        err = pw_read_passf(opt->passf, opt->pass);
        if(err)
            return err;
    }

    if(opt->flag)
        opt->algo |= opt->flag;

    return EXIT_SUCCESS;
}

static int padbuf_hook(akmos_cipher_t ctx, uint8_t *buf, size_t *rlen, size_t blklen, akmos_mode_id enc)
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

static int header_encode(cipher_header_t *hd, uint8_t *buf)
{
    akmos_digest_t ctx;
    int err;

    hd->version = CIPHER_VERSION;

    memcpy(buf, hd->iv,  sizeof(hd->iv));  buf += sizeof(hd->iv);
    memcpy(buf, hd->key, sizeof(hd->key)); buf += sizeof(hd->key);
    *buf = hd->version; buf++;

    if(hd->version == CIPHER_VERSION_V02) {
        err = akmos_digest_init(&ctx, CIPHER_HEADER_MD);
        if(err) {
            akmos_perror(err);
            return err;
        }

        akmos_digest_update(ctx, hd->iv, sizeof(hd->iv));
        akmos_digest_update(ctx, hd->key, sizeof(hd->key));
        akmos_digest_update(ctx, &hd->version, sizeof(hd->version));
        akmos_digest_done(ctx, hd->md);

        memcpy(buf, hd->md, sizeof(hd->md));
        buf += sizeof(hd->md);
    }

    return EXIT_SUCCESS;
}

static int header_decode(uint8_t *buf, cipher_header_t *hd)
{
    akmos_digest_t ctx;
    uint8_t md[CIPHER_HEADER_MDLEN];
    int err;

    memcpy(hd->iv,  buf, sizeof(hd->iv));  buf += sizeof(hd->iv);
    memcpy(hd->key, buf, sizeof(hd->key)); buf += sizeof(hd->key);

    hd->version = *buf; buf++;
    if(hd->version > CIPHER_VERSION) {
        fprintf(stderr, "Invalid header version\n");
        return EXIT_FAILURE;
    }

    if(hd->version == CIPHER_VERSION_V02) {
        memcpy(hd->md, buf, sizeof(hd->md));

        err = akmos_digest_init(&ctx, CIPHER_HEADER_MD);
        if(err) {
            akmos_perror(err);
            return err;
        }

        akmos_digest_update(ctx, hd->iv, sizeof(hd->iv));
        akmos_digest_update(ctx, hd->key, sizeof(hd->key));
        akmos_digest_update(ctx, &hd->version, sizeof(hd->version));
        akmos_digest_done(ctx, md);

        if(memcmp(md, hd->md, sizeof(md)) != 0) {
            fprintf(stderr, "Invalid key or broken header\n");
            return EXIT_FAILURE;
        }

        akmos_memzero(md, sizeof(md));

        buf += sizeof(hd->md);
    }

    return EXIT_SUCCESS;
}

int akmos_cli_cipher(int argc, char **argv, akmos_mode_id enc)
{
    akmos_cipher_t ctx;
    cipher_opt_t opt;
    cipher_header_t hd;

    uint8_t *keybuf, *keypass;
    uint8_t *buf, *tbuf, *rbuf, *wbuf;
    size_t keylen, len, rlen, wlen, tmplen;
    mode_t mask;
    FILE *fd_in, *fd_out;
    int err;

    ctx = NULL;
    keybuf = buf = NULL;
    fd_in = fd_out = NULL;

    memset(&opt, 0, sizeof(struct cipher_opt_s));
    err = parse_arg(&opt, argc, argv);
    if(err)
        return err;

    if(opt.ver)
        return akmos_cli_version();

    if(opt.set.list)
        return cipher_list(opt.s_algo);

    /* Setup master keys */
    keylen = opt.keylen * 2;
    if(opt.flag)
        keylen *= 3;

    err = amalloc(&keybuf, keylen);
    if(err)
        return err;
    memset(keybuf, 0, keylen);

    keylen /= 2;
    keypass = keybuf + keylen;

    if(opt.set.passw || opt.set.passf) {
        tbuf = keypass;
        err = akmos_kdf_pbkdf2(tbuf, keylen, NULL, 0, (const uint8_t *)opt.pass, strlen(opt.pass),
                               CLI_PBKDF2_ALGO, CLI_PBKDF2_ITER);
        if(err) {
            akmos_perror(err);
            goto out;
        }
    }

    if(opt.set.key) {
        /* keypass is used as salt */
        err = pw_read_key(opt.key, keybuf, keylen, keypass, keylen);
        if(err)
            goto out;
    } else {
        /* keypass is used as master key */
        memcpy(keybuf, keypass, keylen);
    }

    /* Open source and destination */
    if(opt.input)
        fd_in = fopen(opt.input, "r");
    else
        fd_in = stdin;

    if(!fd_in) {
        err = EXIT_FAILURE;
        fprintf(stderr, "%s: %s\n", opt.input, strerror(errno));
        goto out;
    }

    /* check for overwrite */
    if(!opt.set.over && opt.output) {
        if(!access(opt.output, F_OK)) {
            if(!prompt_over(opt.output)) {
                err = EXIT_SUCCESS;
                fprintf(stderr, "%s: not overwrited - exiting\n", opt.output);
                goto out;
            }
        }
    }

    mask = umask(0);
    umask(mask);

    if(opt.output)
        fd_out = fopen(opt.output, "w");
    else
        fd_out = stdout;

    if(!fd_out) {
        err = EXIT_FAILURE;
        fprintf(stderr, "%s: %s\n", opt.output, strerror(errno));
        goto out;
    }

    /* allocate work buf */
    err = amalloc(&buf, BUFLEN + opt.blklen);
    if(err)
        goto out;
    memset(buf, 0, BUFLEN + opt.blklen);

    /* Create and cook header */
    len = sizeof(struct cipher_header_s);
    switch(enc) {
        case AKMOS_MODE_ENCRYPT:
            err = pw_rand_buf(&hd, len);
            if(err)
                goto out;

            err = header_encode(&hd, buf);
            if(err)
                goto out;

            err = akmos_cipher(opt.algo, opt.mode|enc, keybuf, opt.keylen, NULL, buf, len, buf);
            if(err) {
                akmos_perror(err);
                goto out;
            }

            if(fwrite(buf, 1, len, fd_out) != len) {
                err = EXIT_FAILURE;
                fprintf(stderr, "%s: %s\n", opt.output, strerror(errno));
                goto out;
            }
            break;

        case AKMOS_MODE_DECRYPT:
            if(fread(buf, 1, len, fd_in) != len) {
                err = EXIT_FAILURE;
                fprintf(stderr, "%s: %s\n", opt.input, strerror(errno));
                goto out;
            }

            err = akmos_cipher(opt.algo, opt.mode|enc, keybuf, opt.keylen, NULL, buf, len, buf);
            if(err) {
                akmos_perror(err);
                goto out;
            }

            err = header_decode(buf, &hd);
            if(err)
                goto out;

            break;

        default:
            break;
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

    /* ciphering */
    rbuf = buf;
    wbuf = buf + BUFSIZ;

    rlen = fread(rbuf, 1, BUFSIZ, fd_in);
    while(1) {
        wlen = fread(wbuf, 1, BUFSIZ, fd_in);
        if(ferror(fd_in)) {
            err = EXIT_FAILURE;
            fprintf(stderr, "%s: %s\n", opt.input, strerror(errno));
            goto out;
        }

        akmos_cipher_crypt(ctx, rbuf, rlen, rbuf);

        if(!wlen)
            break;

        if(fwrite(rbuf, 1, rlen, fd_out) != rlen) {
            err = EXIT_FAILURE;
            fprintf(stderr, "%s: %s\n", opt.output, strerror(errno));
            goto out;
        }

        tbuf = rbuf; rbuf = wbuf; wbuf = tbuf;
        tmplen = rlen; rlen = wlen; wlen = tmplen;
    }

    /* process padding */
    switch(opt.mode) {
        case AKMOS_MODE_ECB:
        case AKMOS_MODE_CBC:
        case AKMOS_MODE_CFB:
            err = padbuf_hook(ctx, rbuf, &rlen, opt.blklen, enc);
            if(err)
                goto out;

            break;

        default:
            break;
    }

    if(fwrite(rbuf, 1, rlen, fd_out) != rlen) {
        err = EXIT_FAILURE;
        fprintf(stderr, "%s: %s\n", opt.output, strerror(errno));
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

    akmos_memzero(&hd, sizeof(struct cipher_header_s));

    if(ctx)
        akmos_cipher_free(ctx);

    return err;
}

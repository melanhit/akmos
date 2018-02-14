/*
 *   Copyright (c) 2015-2018, Andrew Romanenko <melanhit@gmail.com>
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

#include "../akmos.h"
#include "../error.h"

#include "cli.h"
#include "pw.h"

#define DEFAULT_MODE    AKMOS_MODE_HMAC
#define DEFAULT_KEYLEN  128

struct opt_mac_s {
    akmos_algo_id algo;
    akmos_mode_id mode;
    size_t keylen;
    size_t maclen;
    char *key;
    char *passf;
    char pass[PW_MAX_PASSLEN];
    int  count;
    char **input;
    struct {
        int algo;
        int mode;
        int passw;
        int passf;
        int key;
        int keylen;
        int bin;
    } set;
    int ver;
};

static int parse_arg(struct opt_mac_s *opt, int argc, char **argv)
{
    char *algo_str, *mode_str, *keylen_str;
    int err, c, len;

    algo_str = mode_str = keylen_str = NULL;

    while((c = getopt(argc, argv, "a:m:k:l:pP:bVh")) != -1) {
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

            case 'k':
                opt->key = optarg;
                opt->set.key = c;
                break;

            case 'p':
                opt->set.passw = c;
                break;

            case 'P':
                opt->passf = optarg;
                opt->set.passf = c;
                break;

            case 'b':
                opt->set.bin = c;
                break;

            case 'V':
                opt->ver = c;
                return EXIT_SUCCESS;

            case 'h':
            default:
                printf("Usage: akmos dgst [-a algo] [-m mode] [-k keyfile] [-l keylen] [-p | -P passfile] [-b] [-h] <input>\n");
                return EXIT_FAILURE;
        }
    }

    len = argc - optind;
    switch(len) {
        case 0:
            opt->count = 1;
            opt->input = NULL;
            break;

        default:
            opt->count = argc - optind;
            opt->input = argv + optind;
            break;
    }

    if(!opt->set.mode) {
        opt->mode = DEFAULT_MODE;
        if(opt->set.algo) {
            fprintf(stderr, "Missing mac mode\n");
            return EXIT_FAILURE;
        }
    } else {
        if(mode_str) {
            opt->mode = akmos_str2mode(mode_str);
            if(!opt->mode)
                return akmos_perror(AKMOS_ERR_MODEID);
        }
    }

    if(!opt->set.algo) {
        switch(opt->mode) {
            case AKMOS_MODE_CBCMAC:
            case AKMOS_MODE_CMAC:
                opt->algo = AKMOS_ALGO_TWOFISH;
                break;

            case AKMOS_MODE_HMAC:
                opt->algo = AKMOS_ALGO_SHA2_256;
                break;

            default:
                break;
        }
    } else {
        if(algo_str) {
            if(!(opt->algo = akmos_digest_id(algo_str)))
                if(!(opt->algo = akmos_cipher_id(algo_str)))
                    return akmos_perror(AKMOS_ERR_ALGOID);
        }
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

    if(!opt->set.keylen) {
        switch(opt->algo) {
            case AKMOS_ALGO_THREEFISH_256:
                opt->keylen = 256/8;
                break;

            case AKMOS_ALGO_THREEFISH_512:
                opt->keylen = 512/8;
                break;

            case AKMOS_ALGO_THREEFISH_1024:
                opt->keylen = 1024/8;
                break;

            case AKMOS_ALGO_ANUBIS:
            case AKMOS_ALGO_BLOWFISH:
            case AKMOS_ALGO_CAMELLIA:
            case AKMOS_ALGO_CAST6:
            case AKMOS_ALGO_RC6:
            case AKMOS_ALGO_SERPENT:
            case AKMOS_ALGO_TWOFISH:
            case AKMOS_ALGO_RIJNDAEL:
                opt->keylen = 128/8;
                break;

            case AKMOS_ALGO_RIPEMD_160:
            case AKMOS_ALGO_RIPEMD_256:
            case AKMOS_ALGO_RIPEMD_320:
            case AKMOS_ALGO_SHA1:
            case AKMOS_ALGO_SHA2_224:
            case AKMOS_ALGO_SHA2_256:
            case AKMOS_ALGO_SHA2_384:
            case AKMOS_ALGO_SHA2_512:
            case AKMOS_ALGO_SHA3_224:
            case AKMOS_ALGO_SHA3_256:
            case AKMOS_ALGO_SHA3_384:
            case AKMOS_ALGO_SHA3_512:
                opt->keylen = akmos_digest_blklen(opt->algo);
                break;

            default:
                break;
        }
    } else {
        if(keylen_str) {
            err = sscanf(keylen_str, "%4zu", &opt->keylen);
            if(err == EOF || !err)
                return akmos_perror(AKMOS_ERR_KEYLEN);

            if((opt->keylen % 8) != 0)
                return akmos_perror(AKMOS_ERR_KEYLEN);

            opt->keylen /= 8;
        }
    }

    if(opt->mode == AKMOS_MODE_CBCMAC)
        opt->keylen *= 2;

    switch(opt->mode) {
        case AKMOS_MODE_HMAC:
            opt->maclen = akmos_digest_outlen(opt->algo);
            break;

        case AKMOS_MODE_CBCMAC:
        case AKMOS_MODE_CMAC:
            opt->maclen = akmos_cipher_blklen(opt->algo);
            break;

        default:
            break;
    }

    return EXIT_SUCCESS;
}

static void mac_print_hmac(akmos_algo_id algo, akmos_mode_id mode, const char *path)
{
    const char *algostr, *modestr;

    algostr = akmos_digest_name(algo);
    modestr = akmos_mode2str(mode);

    printf(" = %s/%s(%s)\n", modestr, algostr, path);
}

static void mac_print_cmac(akmos_algo_id algo, akmos_mode_id mode, const char *path, size_t keylen)
{
    const char *algostr, *modestr;
    char lenstr[8];

    algostr = akmos_cipher_name(algo);
    modestr = akmos_mode2str(mode);

    switch(algo) {
        case AKMOS_ALGO_THREEFISH_256:
        case AKMOS_ALGO_THREEFISH_512:
        case AKMOS_ALGO_THREEFISH_1024:
            printf(" = %s/%s(%s)\n", modestr, algostr, path);
            break;

        default:
            sprintf(lenstr, "%zd", keylen * 8);
            printf(" = %s/%s-%s(%s)\n", modestr, algostr, lenstr, path);
            break;
    }
}

static void mac_print_hex(struct opt_mac_s *opt, char *path, uint8_t *mac)
{
    const char *path_stdin = "-", *p;
    size_t i;

    for(i = 0; i < opt->maclen; i++)
        printf("%.2x", mac[i]);

    if(path)
        p = path;
    else
        p = path_stdin;

    switch(opt->mode) {
        case AKMOS_MODE_HMAC:
            mac_print_hmac(opt->algo, opt->mode, path);
            break;

        case AKMOS_MODE_CBCMAC:
            mac_print_cmac(opt->algo, opt->mode, path, opt->keylen / 2);
            break;

        case AKMOS_MODE_CMAC:
            mac_print_cmac(opt->algo, opt->mode, path, opt->keylen);
            break;

        default:
            break;
    }
}

static void mac_print_raw(uint8_t *md, size_t len)
{
    size_t i;

    for(i = 0; i < len; i++)
        printf("%c", md[i]);
}

static int mac_proc(struct opt_mac_s *opt, char *path, uint8_t *buf, uint8_t *keybuf, uint8_t *macbuf)
{
    akmos_mac_t ctx;
    size_t len;
    int err;
    FILE *fd;

    ctx = NULL;
    err = EXIT_SUCCESS;

    if(path)
        fd = fopen(path, "r");
    else
        fd = stdin;

    if(!fd) {
        err = EXIT_FAILURE;
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        goto out;
    }

    err = akmos_mac_init(&ctx, opt->algo, opt->mode);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    err = akmos_mac_setkey(ctx, keybuf, opt->keylen);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    while((len = fread(buf, 1, BUFSIZ, fd)) > 0)
        akmos_mac_update(ctx, buf, len);

    if(ferror(fd)) {
        err = EXIT_FAILURE;
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        goto out;
    }

    err = akmos_mac_done(ctx, macbuf);
    if(err) {
        akmos_perror(err);
        goto out;
    }

    /* print result */
    if(!opt->set.bin) {
        mac_print_hex(opt, path, macbuf);
    } else {
        mac_print_raw(macbuf, opt->maclen);
    }

out:
    if(fd)
        fclose(fd);

    return err;
}

int akmos_cli_mac(int argc, char **argv)
{
    struct opt_mac_s opt;
    uint8_t *buf, *keybuf, *keypass, *macbuf;
    size_t keylen;
    int i, err;

    keybuf = buf = macbuf = NULL;

    memset(&opt, 0, sizeof(struct opt_mac_s));
    err = parse_arg(&opt, argc, argv);
    if(err)
        return err;

    if(opt.ver)
        return akmos_cli_version();

    keylen = opt.keylen * 2;
    err = amalloc(&keybuf, keylen);
    if(err)
        return err;
    memset(keybuf, 0, keylen);

    keypass = keybuf + opt.keylen;
    if(opt.set.passw || opt.set.passf) {
        err = akmos_kdf_pbkdf2(keypass, opt.keylen, NULL, 0, (const uint8_t *)opt.pass, strlen(opt.pass),
                               CLI_PBKDF2_ALGO, CLI_PBKDF2_ITER);
        if(err) {
            akmos_perror(err);
            goto out;
        }
    }

    if(opt.set.key) {
        /* keypass is used as salt */
        err = pw_read_key(opt.key, keybuf, opt.keylen, keypass, opt.keylen);
        if(err)
            goto out;
    } else {
        memcpy(keybuf, keypass, opt.keylen);
    }

    err = amalloc(&macbuf, opt.maclen);
    if(err)
        goto out;

    err = amalloc(&buf, BUFSIZ);
    if(err)
        goto out;

    for(i = 0; i < opt.count; i++) {
        if(opt.input)
            err = mac_proc(&opt, opt.input[i], buf, keybuf, macbuf);
        else
            err = mac_proc(&opt, NULL, buf, keybuf, macbuf);

        if(err)
            goto out;
    }

out:
    if(keybuf) {
        akmos_memzero(keybuf, keylen);
        free(keybuf);
    }

    if(buf) {
        akmos_memzero(buf, BUFSIZ);
        free(buf);
    }

    if(macbuf)
        free(macbuf);

    return err;
}

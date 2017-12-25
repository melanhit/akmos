/*
 *   Copyright (c) 2015-2017, Andrew Romanenko <melanhit@gmail.com>
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

#include <fcntl.h>
#include <termios.h>

#include "../akmos.h"

#include "cli.h"
#include "pw.h"

int pw_read_passw(char *pass)
{
    struct termios t_old, t_new;
    int c;

    if(!pass)
        return EXIT_FAILURE;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= (unsigned)~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    printf("Enter password: ");
    scanf("%125[^\n]*c", pass);
    printf("\n");

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);

    while ((c = getchar()) != '\n' && c != EOF);

    return EXIT_SUCCESS;
}

int pw_read_passf(const char *path, char *pass)
{
    int fd, err;
    uint8_t buf[PW_MAX_PASSLEN+1];
    ssize_t len, i;

    err = EXIT_SUCCESS;

    fd = open(path, O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        err = EXIT_FAILURE;
        goto out;
    }

    len = read(fd, buf, PW_MAX_PASSLEN+1);
    if(len == -1) {
        err = EXIT_FAILURE;
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        goto out;
    }

    /* remove newline */
    for(i = 0; i < len; i++) {
        if(buf[i] == '\n') {
            len = i;
            break;
        }
    }

    if(len == PW_MAX_PASSLEN) {
        fprintf(stderr, "%s: maximum password length %d\n", path, PW_MAX_PASSLEN-1);
        err = EXIT_FAILURE;
        goto out;
    }

    memcpy(pass, buf, (size_t)len);
    pass[len] = 0;

out:
    if(fd > 0)
        close(fd);

    akmos_memzero(buf, PW_MAX_PASSLEN);

    return err;
}

int pw_read_key(const char *path, uint8_t *key, size_t keylen, uint8_t *salt, size_t saltlen)
{
    int fd, i, err;
    ssize_t klen, len;
    uint8_t *kbuf, *buf;

    kbuf = NULL;
    err = EXIT_SUCCESS;

    fd = open(path, O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        err = EXIT_FAILURE;
        goto out;
    }

    err = amalloc(&kbuf, (PW_MAX_KEYLEN + BUFSIZ));
    if(err)
        goto out;

    buf = kbuf;
    klen = 0;
    for(i = 0; i <= (PW_MAX_KEYLEN / BUFSIZ); i++) {
        len = read(fd, buf, BUFSIZ);
        if(len == -1) {
            err = EXIT_FAILURE;
            fprintf(stderr, "%s: %s\n", path, strerror(errno));
            goto out;
        }

        if(!len)
            break;

        klen += len;
        buf += BUFSIZ;
    }

    if(klen > PW_MAX_KEYLEN) {
        fprintf(stderr, "Keyfile \"%s\" is too big (maximum %d KiB)\n", path, (PW_MAX_KEYLEN / 1024));
        err = EXIT_FAILURE;
        goto out;
    }

    err = akmos_kdf(key, keylen, salt, saltlen, kbuf, (size_t)klen,
                    CLI_KDF_ALGO, CLI_PBKDF2_ITER, CLI_PBKDF2_ALGO);
    if(err)
        goto out;

out:
    if(fd > 0)
        close(fd);

    if(kbuf) {
        akmos_memzero(kbuf, (PW_MAX_KEYLEN + BUFSIZ));
        free(kbuf);
    }

    return err;
}

int pw_rand_buf(void *buf, size_t len)
{
    size_t i, j, l, tmplen, diglen;
    ssize_t t;
    int err, fd;
    uint8_t tbuf[BUFSIZ], *sbuf, *md, *key, *pbuf;

    err = EXIT_SUCCESS;
    diglen = akmos_digest_outlen(PW_ALGO);

    err = amalloc(&sbuf, diglen * 2);
    if(err)
        return err;

    md = sbuf;
    key = sbuf + diglen;

    fd = open(PW_RNDFILE, O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "%s: %s\n", PW_RNDFILE, strerror(errno));
        return EXIT_FAILURE;
    }

    l = len / diglen;

    memset(buf, 0, len);

    pbuf = buf;
    t = (ssize_t)diglen;
    for(i = 0, tmplen = diglen; i <= l; i++) {
        if(read(fd, key, diglen) != t) {
            fprintf(stderr, "%s: %s\n", PW_RNDFILE, strerror(errno));
            return EXIT_FAILURE;
        }

        if(read(fd, tbuf, BUFSIZ) != BUFSIZ) {
            fprintf(stderr, "%s: %s\n", PW_RNDFILE, strerror(errno));
            return EXIT_FAILURE;
        }

        err = akmos_mac(PW_ALGO, AKMOS_MODE_HMAC, key, diglen, tbuf, BUFSIZ, md);
        if(err) {
            akmos_perror(err);
            return err;
        }

        if((i + 1) > l)
            tmplen = len - (l * diglen);

        for(j = 0; j < tmplen; j++)
            pbuf[j] ^= md[j];

        pbuf += tmplen;
    }

    close(fd);

    if(sbuf) {
        akmos_memzero(sbuf, diglen * 2);
        free(sbuf);
    }

    akmos_memzero(tbuf, BUFSIZ);

    return EXIT_SUCCESS;
}

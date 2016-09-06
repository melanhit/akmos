/*
 *   Copyright (c) 2015-2016, Andrew Romanenko <melanhit@gmail.com>
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
#include "secur.h"

int secur_read_passw(char *pass)
{
    struct termios t_old, t_new;

    if(!pass)
        return EXIT_FAILURE;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= (unsigned)~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    printf("Enter password: ");
    if(!scanf("%125s", pass))
       return EXIT_FAILURE;
    printf("\n");

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);

    return EXIT_SUCCESS;
}

int secur_mk_keyfile(const char *path, uint8_t *key, size_t keylen, uint8_t *salt, size_t saltlen)
{
    int fd, err;
    ssize_t klen;
    uint8_t *kbuf, *kbuf1, *kbuf2;

    kbuf1 = kbuf2 = NULL;
    err = EXIT_SUCCESS;

    fd = open(path, O_RDONLY);
    if(fd == -1) {
        printf("%s: %s\n", path, strerror(errno));
        err = EXIT_FAILURE;
        goto out;
    }

    AMALLOC(kbuf1, SECUR_MIN_KEYBUF, err);
    if(err)
        goto out;

    kbuf = kbuf1;
    klen = read(fd, kbuf1, SECUR_MIN_KEYBUF);
    if(klen == SECUR_MIN_KEYBUF) {
        AMALLOC(kbuf2, SECUR_MAX_KEYBUF, err);
        if(err)
            goto out;

        kbuf = kbuf2;
        memcpy(kbuf2, kbuf1, SECUR_MIN_KEYBUF);

        klen += read(fd, kbuf2 + SECUR_MIN_KEYBUF, SECUR_MAX_KEYBUF - SECUR_MIN_KEYBUF);
    }

    if(klen == -1) {
        err = EXIT_FAILURE;
        printf("%s: %s\n", path, strerror(errno));
        goto out;
    }

    if(klen == SECUR_MAX_KEYBUF) {
        printf("Keyfile \"%s\" is too big (maximum %d KiB)\n", path, ((SECUR_MAX_KEYBUF - 1) / 1024));
        err = EXIT_FAILURE;
        goto out;
    }

    err = akmos_kdf_kdf2(key, keylen, salt, saltlen, kbuf, (size_t)klen, 0, SECUR_ALGO);
    if(err)
        goto out;

out:
    if(fd > 0)
        close(fd);

    if(kbuf1) {
        akmos_memzero(kbuf1, SECUR_MIN_KEYBUF);
        free(kbuf1);
    }

    if(kbuf2) {
        akmos_memzero(kbuf, SECUR_MAX_KEYBUF);
        free(kbuf2);
    }

    return err;
}

int secur_rand_buf(uint8_t *buf, size_t len)
{
    size_t i, j, l, tmplen, diglen;
    ssize_t t;
    int err, fd;
    uint8_t tbuf[BUFSIZ], *sbuf, *md, *key, *pbuf;

    err = EXIT_SUCCESS;
    diglen = akmos_digest_outlen(SECUR_ALGO);

    AMALLOC(sbuf, diglen * 2, err);
    if(err)
        return err;

    md = sbuf;
    key = sbuf + diglen;

    fd = open(SECUR_RNDFILE, O_RDONLY);
    if(fd == -1) {
        printf("%s: %s\n", SECUR_RNDFILE, strerror(errno));
        return EXIT_FAILURE;
    }

    l = len / diglen;

    memset(buf, 0, len);

    pbuf = buf;
    t = (ssize_t)diglen;
    for(i = 0, tmplen = diglen; i <= l; i++) {
        if(read(fd, key, diglen) != t) {
            printf("%s: %s\n", SECUR_RNDFILE, strerror(errno));
            return EXIT_FAILURE;
        }

        if(read(fd, tbuf, BUFSIZ) != BUFSIZ) {
            printf("%s: %s\n", SECUR_RNDFILE, strerror(errno));
            return EXIT_FAILURE;
        }

        err = akmos_mac_ex(SECUR_ALGO, AKMOS_MODE_HMAC, key, diglen, tbuf, BUFSIZ, md);
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

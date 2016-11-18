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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <akmos.h>

#include <config.h>

#include "bench.h"

static unsigned ci_convert(const char *input)
{
    char *str;
    int err;
    unsigned ulen;
    size_t len, ci;

    str = strdup(input);

    len = strlen(str);
    switch(str[len-1]) {
        case 'K':
        case 'k':
            ci = 1024;
            str[len-1] = '\0';
            break;

        case 'M':
        case 'm':
            ci = 1024*1024;
            str[len-1] = '\0';
            break;

        case 'G':
        case 'g':
            ci = 1024*1024*1024;
            str[len-1] = '\0';
            break;

        default:
            ci = 1;
            break;
    }

    err = sscanf(str, "%u", &ulen);
    if((err == EOF) || (!err))
        ulen = 0;

    ulen *= ci;

    free(str);

    return ulen;
}

int main(int argc, char **argv)
{
    struct opt_bench_s opt;
    akmos_algo_id algo;
    akmos_mode_id mode;
    int c, err;
    unsigned i;
    char *mode_str;

    mode_str = NULL;

    opt.len  = BENCH_DEFBLKLEN;
    opt.num  = BENCH_DEFBLKNUM;
    opt.time = BENCH_DEFTIME;

    algo = 0;
    mode = 0;
    err = EXIT_SUCCESS;

    while((c = getopt(argc, argv, "a:l:n:t:m:h")) != -1) {
         switch(c) {
             case 'a':
                algo = akmos_cipher_id(optarg);
                if(!algo)
                    algo = akmos_digest_id(optarg);

                if(!algo) {
                    fprintf(stderr, "Unsupported algorithm \"%s\"\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

             case 'm':
                mode_str = optarg;
                break;

             case 'l':
                opt.len = ci_convert(optarg);
                if(!opt.len) {
                    fprintf(stderr, "Invalid block length \"%s\"\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

             case 'n':
                opt.num = ci_convert(optarg);
                if(!opt.num) {
                    fprintf(stderr, "Invalid number of the blocks \"%s\"\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

             case 't':
                err = sscanf(optarg, "%u", &opt.time);
                if((err == EOF) || (!err) || !opt.time) {
                    fprintf(stderr, "Invalid benchmark time \"%s\"\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

             case 'h':
                fprintf(stdout, "Usage: akmos_bench [-a algo] [-l block len] [-n num blocks] [-t time]\n");
                return EXIT_SUCCESS;

             default:
                break;
        }
    }

    if(opt.len > BENCH_MAXBLKLEN) {
        fprintf(stderr, "Error: reached maximum block length %d MiB\n", BENCH_MAXBLKLEN / (1024 * 1024));
        return EXIT_FAILURE;
    }

    opt.blk = malloc(opt.len);
    if(!opt.blk) {
        fprintf(stderr, "%s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    for(i = 0; i < opt.len; i++)
        opt.blk[i] = i % UINT8_MAX;

    if(mode_str && !(algo & BENCH_CIPHER_MASK))
        fprintf(stderr, "Ignore cipher mode option \"-m %s\"\n", mode_str);

    /* benchmark only checked algorithm */
    if((algo & BENCH_DIGEST_MASK) > 0) {
        err = bench_digest(algo, &opt);
        goto out;
    }

    if((algo & BENCH_CIPHER_MASK) > 0) {
        if(mode_str) {
            mode = akmos_str2mode(mode_str);
            if(!(mode & BENCH_CIPHER_MODE_MASK)) {
                fprintf(stderr, "Invalid cipher mode \"%s\"\n", mode_str);
                err = EXIT_FAILURE;
                goto out;
            }

            err = bench_cipher(algo, mode, &opt);
            goto out;
        }

        err = bench_cipher(algo, AKMOS_MODE_ECB, &opt);
        if(err) goto out;

        err = bench_cipher(algo, AKMOS_MODE_CBC, &opt);
        if(err) goto out;

        err = bench_cipher(algo, AKMOS_MODE_CTR, &opt);
        if(err) goto out;

        err = bench_cipher(algo, AKMOS_MODE_CFB, &opt);
        if(err) goto out;

        err = bench_cipher(algo, AKMOS_MODE_OFB, &opt);
        goto out;
    }

    /* benchmark all algorithms */
    /* ciphers */
    printf("Ciphers:\n");

    err = bench_cipher(AKMOS_ALGO_ANUBIS, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_ANUBIS, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_ANUBIS, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_ANUBIS, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_ANUBIS, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_BLOWFISH, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_BLOWFISH, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_BLOWFISH, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_BLOWFISH, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_BLOWFISH, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAMELLIA, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAMELLIA, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAMELLIA, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAMELLIA, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAMELLIA, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAST6, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAST6, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAST6, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAST6, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CAST6, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_CHACHA, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RC6, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RC6, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RC6, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RC6, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RC6, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RIJNDAEL, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RIJNDAEL, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RIJNDAEL, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RIJNDAEL, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_RIJNDAEL, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SALSA, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SEED, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SEED, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SEED, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SEED, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SEED, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SERPENT, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SERPENT, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SERPENT, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SERPENT, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_SERPENT, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_256, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_256, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_256, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_256, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_256, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_512, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_512, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_512, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_512, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_512, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_1024, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_1024, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_1024, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_1024, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_THREEFISH_1024, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_TWOFISH, AKMOS_MODE_ECB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_TWOFISH, AKMOS_MODE_CBC, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_TWOFISH, AKMOS_MODE_CTR, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_TWOFISH, AKMOS_MODE_CFB, &opt);
    if(err) goto out;

    err = bench_cipher(AKMOS_ALGO_TWOFISH, AKMOS_MODE_OFB, &opt);
    if(err) goto out;

    /* diegsts */
    printf("Digests:\n");

    err = bench_digest(AKMOS_ALGO_RIPEMD_160, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_RIPEMD_256, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_RIPEMD_320, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA1, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA2_224, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA2_256, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA2_384, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA2_512, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA3_224, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA3_256, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA3_384, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_SHA3_512, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_TIGER, &opt);
    if(err) goto out;

    err = bench_digest(AKMOS_ALGO_WHIRLPOOL, &opt);
    if(err) goto out;

out:
    if(opt.blk)
        free(opt.blk);

    return err;
}

void bench_print(struct opt_bench_s *opt)
{
    char name[32];
    double speed;

    speed = (opt->len * opt->cnt / (1024*1024)) / ((opt->stop - opt->start) / CLOCKS_PER_SEC);

    if((opt->algo & BENCH_DIGEST_MASK) > 0)
        fprintf(stdout, " %-32s %12.2f MiB/s\n", akmos_digest_name(opt->algo), speed);

    if((opt->algo & BENCH_CIPHER_MASK) > 0) {
        sprintf(name, "%s-%lu-%s", akmos_cipher_name(opt->algo), opt->keylen*8, akmos_mode2str(opt->mode));
        fprintf(stdout, " %-32s %12.2f MiB/s\n", name, speed);
    }
}

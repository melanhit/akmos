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

#include "test.h"

struct {
    size_t pass;
    size_t fail;
} total = {
    0, 0
};

int main(int __attribute__((unused)) argc, char **argv)
{
    /* cipher ECB-mode */
    if(test_mode_ecb(AKMOS_ALGO_ANUBIS, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_BLOWFISH, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_CAMELLIA, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_CAST6, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_RC6, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_RIJNDAEL, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_SEED, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_SERPENT, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_THREEFISH_256, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_THREEFISH_512, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_THREEFISH_1024, argv[0]))
        return EXIT_FAILURE;
    if(test_mode_ecb(AKMOS_ALGO_TWOFISH, argv[0]))
        return EXIT_FAILURE;

    /* digest */
    if(test_digest(AKMOS_ALGO_RIPEMD_160, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_RIPEMD_256, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_RIPEMD_320, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA1, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA2_224, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA2_256, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA2_384, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA2_512, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA3_224, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA3_256, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA3_384, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SHA3_512, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SKEIN_256, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SKEIN_512, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_SKEIN_1024, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_TIGER, argv[0]))
        return EXIT_FAILURE;
    if(test_digest(AKMOS_ALGO_WHIRLPOOL, argv[0]))
        return EXIT_FAILURE;

    if(total.fail)
        printf("\n  PASSED: %zd, FAILED: %zd\n", total.pass, total.fail);
    else
        printf("\n All tests are PASSED\n");

    return EXIT_SUCCESS;
}

void test_print(char *s, size_t f)
{
    printf("  %-32s", s);

    if(f)
        printf("%s\n", "PASS");
    else
        printf("%s\n", "!FAIL");
}

void test_total(size_t t)
{
    if(t == TEST_PASS)
        total.pass++;

    if(t == TEST_FAIL)
        total.fail++;
}

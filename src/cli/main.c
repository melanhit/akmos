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

#include "../akmos.h"
#include "cli.h"

#define AKMOS_CLI_DIGEST    1
#define AKMOS_CLI_CIPHER_E  2
#define AKMOS_CLI_CIPHER_D  3
#define AKMOS_CLI_MAC       4
#define AKMOS_CLI_HELP      5
#define AKMOS_CLI_UNKNOWN   6

int akmos_cli_help() {
    printf("Usage: akmos <command> <options>\n"
           "Available commands:\n"
           " dgst - make digest (hash)\n"
           " enc  - encrypt\n"
           " dec  - decrypt\n"
           " mac  - compute MAC\n"
           " help - print help\n");

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    int opt;

    if(argc < 2)
        return akmos_cli_help();

    if(strcmp(argv[1], "dgst") == 0)
        opt = AKMOS_CLI_DIGEST;
    else if(strcmp(argv[1], "enc") == 0)
        opt = AKMOS_CLI_CIPHER_E;
    else if(strcmp(argv[1], "dec") == 0)
        opt = AKMOS_CLI_CIPHER_D;
    else if(strcmp(argv[1], "mac") == 0)
        opt = AKMOS_CLI_MAC;
    else if(strcmp(argv[1], "help") == 0)
        opt = AKMOS_CLI_HELP;
    else
        opt = AKMOS_CLI_UNKNOWN;

    switch(opt) {
        case AKMOS_CLI_DIGEST:
            return akmos_cli_digest(--argc, ++argv);

        case AKMOS_CLI_CIPHER_E:
            return akmos_cli_cipher(--argc, ++argv, AKMOS_MODE_ENCRYPT);

        case AKMOS_CLI_CIPHER_D:
            return akmos_cli_cipher(--argc, ++argv, AKMOS_MODE_DECRYPT);

        case AKMOS_CLI_MAC:
            return akmos_cli_mac(--argc, ++argv);

        case AKMOS_CLI_HELP:
            return akmos_cli_help();

        case AKMOS_CLI_UNKNOWN:
            printf("Unknown action '%s'\n", argv[1]);
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

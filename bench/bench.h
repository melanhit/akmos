/*
 *   Copyright (c) 2016-2018, Andrew Romanenko <melanhit@gmail.com>
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

#ifndef BENCH_H
#define BENCH_H

#define BENCH_CIPHER_MASK       0x00000fff
#define BENCH_DIGEST_MASK       0x000ff000
#define BENCH_CIPHER_MODE_MASK  0x0000000f

#define BENCH_DEFTIME           5
#define BENCH_MAXBLKLEN         (1024*1024*1024)
#define BENCH_DEFBLKLEN         (BUFSIZ*1024)
#define BENCH_DEFBLKNUM         1

#define BENCH_MAXKEYLEN         128
#define BENCH_MAXMDLEN          64

struct opt_bench_s {
    akmos_algo_id algo;
    akmos_mode_id mode;
    unsigned len;
    unsigned num;
    unsigned time;
    size_t keylen;
    uint8_t *key;
    uint8_t *blk;
    uint64_t cnt;
    clock_t start;
    clock_t stop;
    int err;
};

void bench_print(struct opt_bench_s *);

int bench_digest(akmos_algo_id, struct opt_bench_s *);
int bench_cipher(akmos_algo_id, akmos_mode_id, struct opt_bench_s *);

#endif  /* BENCH_H */

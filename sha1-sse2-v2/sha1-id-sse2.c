
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "sha1.h"

#ifdef __INTEL_COMPILER
#include <emmintrin.h>
#else
#include <xmmintrin.h>
#endif

static void inline sha1_init(uint32_t h[5])
{
    h[0] = 0x67452301UL;
    h[1] = 0xEFCDAB89UL;
    h[2] = 0x98BADCFEUL;
    h[3] = 0x10325476UL;
    h[4] = 0xC3D2E1F0UL;
}

#ifndef PRIx32
# define PRIx32 "x"
#endif

static void dump(const uint32_t x[5])
{
    printf("%08" PRIx32 "%08" PRIx32 "%08" PRIx32
           "%08" PRIx32 "%08" PRIx32,
        x[0], x[1], x[2], x[3], x[4]);
}

#define SWAP(x)	\
    (((x) >> 24) | \
     (((x) & 0x00FF0000UL) >> 8) | \
     (((x) & 0x0000FF00UL) << 8) | \
     ((x) << 24))

static void prep(uint8_t *dst, uint64_t dstlen,
           const uint8_t *src, uint64_t srclen)
{
    memcpy(dst, src, srclen);
    memset(dst + srclen, 0, dstlen - srclen); /*  */
    dst[0] = 0x80; /* append the bit '1' to the message */

    {
        uint32_t *dst32 = (uint32_t*)dst;
        //unsigned i;
        //for (i = 0; i < 15; i++)
            //dst32[i] = SWAP(dst32[i]);
        dst32[15] = SWAP(((uint32_t)srclen * 8));
    }
}

#if 0
void dump_H(const uint32_t *h)
{
	int i;
	for (i = 0; i < 16; i++)
		printf(" %08x", h[i]);
}
#endif

static time_t Start;

static void report(uint64_t cnt)
{
    time_t elapsed = time(0) - Start;
    if (elapsed == 0)
        elapsed = 1;
    fprintf(stderr, "%.1fB(%.1fM/sec) ",
        (double)cnt / 1e9,
        (double)cnt / 1e6 / elapsed);
}

int main(void)
{
    uint32_t h[5] __attribute__((aligned(16))),
             x[16] __attribute__((aligned(16)));
    uint64_t cnt = 0;
 
    Start = time(0);

    sha1_init(h);
    prep((uint8_t*)x, sizeof x, (uint8_t*)"", 0);
    //printf("message:"); dump_H(x); fputc('\n', stdout);
    sha1_step(h, x, 1);

    do {
        memcpy(x, h, sizeof h);
        sha1_step(h, x, 1);
        cnt++;
        if ((cnt & 0xfffffffUL) == 0)
            report(cnt);
    } while (memcmp(h, x, sizeof h));

    printf("holy shit! cnt=%llu\n", cnt);
    printf("h="); dump(h); fputc('\n', stdout);
    printf("x="); dump(x); fputc('\n', stdout);

    return 0;
}



#include <stdio.h>
#include <string.h>
#include <stdint.h>
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

static void dump(const uint8_t s[20])
{
    const uint32_t *x = (uint32_t*)s;
    printf("%08" PRIx32
           "%08" PRIx32
           "%08" PRIx32
           "%08" PRIx32
           "%08" PRIx32,
        x[0], x[1], x[2], x[3], x[4]);

#if 0
    printf("%02x""%02x""%02x""%02x"
           "%02x""%02x""%02x""%02x"
           "%02x""%02x""%02x""%02x"
           "%02x""%02x""%02x""%02x"
           "%02x""%02x""%02x""%02x",
           s[ 3], s[ 2], s[ 1], s[ 0],
           s[ 7], s[ 6], s[ 5], s[ 4],
           s[11], s[10], s[ 9], s[ 8],
           s[15], s[14], s[13], s[12],
           s[19], s[18], s[17], s[16]);
           ///s[ 0], s[ 1], s[ 2], s[ 3],
           ///s[ 4], s[ 5], s[ 6], s[ 7],
           ///s[ 8], s[ 9], s[10], s[11],
           ///s[12], s[13], s[14], s[15],
           ///s[16], s[17], s[18], s[19]);
#endif
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
    //dst[srclen] = 1; /* append the bit '1' to the message */

    {
        uint32_t *dst32 = (uint32_t*)dst;
        //unsigned i;
        //for (i = 0; i < 15; i++)
            //dst32[i] = SWAP(dst32[i]);
        dst32[15] = SWAP(((uint32_t)srclen * 8));
    }
}

void dump_H(const uint32_t *h)
{
	int i;
	for (i = 0; i < 16; i++)
		printf(" %08x", h[i]);
}


int main(void)
{
    uint32_t h[5] __attribute__((aligned(16))),
             x[16] __attribute__((aligned(16))),
             y[16] __attribute__((aligned(16)));
    uint64_t cnt = 0;

    memset(x, 0, sizeof x);
    memset(y, 0, sizeof y);

    sha1_init(h);
    prep((uint8_t*)x, sizeof x,
         (uint8_t*)x, 0);
    printf("message:"); dump_H(x); fputc('\n', stdout);

    do {
#if 1
        memcpy(y, x, sizeof y);
#else
        *(__m128i*)y = *(__m128i*)x, y[4] = x[4];
#endif
        sha1_step(h, x, 1);
        cnt++;
        if ((cnt & 0xfffffffUL) == 0)
        {
            fprintf(stderr, "%.1fB ", (double)cnt / 1e9);
        }
    }
#if 0
    while (memcmp(x, y, sizeof x))
    while (memcmp(x, y, 20))
    while (*x != *y || memcmp(x, y, 20))
    while (x[0] != y[0] || x[1] != y[1] || x[2] != y[2] || x[3] != y[3] || x[4] != y[4])
#endif
#if 0
    while (((uint64_t*)x)[0] != ((uint64_t*)y)[0] ||
           ((uint64_t*)x)[1] != ((uint64_t*)y)[1] ||
           x[4] != y[4])
#endif
    //while (((uint128_t*)x)[0] != ((uint128_t*)y)[0] || x[4] != y[4])
    while(0)
    ;

    printf("holy shit! cnt=%llu\n", cnt);
    printf("h="); dump((uint8_t*)h); fputc('\n', stdout);
    printf("x="); dump((uint8_t*)x); fputc('\n', stdout);
    printf("y="); dump((uint8_t*)y); fputc('\n', stdout);

    return 0;
}


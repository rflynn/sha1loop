
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
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
# define PRIu64 "llu"
#endif

static char * dump(char buf[41], const uint32_t x[5])
{
    snprintf(buf, 41,
        "%08" PRIx32 "%08" PRIx32 "%08" PRIx32
        "%08" PRIx32 "%08" PRIx32,
        x[0], x[1], x[2], x[3], x[4]);
    return buf;
}

#define SWAP(x)	\
    (((x) >> 24) | \
     (((x) & 0x00FF0000UL) >> 8) | \
     (((x) & 0x0000FF00UL) << 8) | \
     ((x) << 24))

static void prep(uint8_t *dst, uint64_t dstlen,
           const uint8_t *src, uint64_t srclen)
{
    memset(dst, 0, dstlen);
    memcpy(dst, src, srclen);
    dst[srclen] = 0x80; /* append the bit '1' to the message */

    {
        uint32_t *dst32 = (uint32_t*)dst;
        //unsigned i;
        //for (i = 0; i < 15; i++)
            //dst32[i] = SWAP(dst32[i]);
        dst32[15] = SWAP(((uint32_t)srclen * 8));
    }
}

static time_t Start;
static char Buf[41];

static void report(uint64_t nth, const uint32_t h[5])
{
    unsigned long long elapsed = time(0) - Start;
    char buf[41];
    fprintf(stderr, "t=%llu nth=%" PRIu64 " (%s) ",
        elapsed, nth, dump(buf, h));
}

static void init(int argc, char *argv[],
                 uint64_t *nth, uint32_t h[5], uint32_t x[16])
{
    Start = time(0);
    if (argc != 1)
    {
        /* from cmdline, let us restart farther in */
        if (argc != 3)
        {
            fprintf(stderr, "Usage: %s <nth> <sha1>\n", argv[0]);
            exit(1);
        }
        *nth = strtoull(argv[1], NULL, 10);
        assert(5 == sscanf(argv[2],
            "%08" PRIx32 "%08" PRIx32 "%08" PRIx32
            "%08" PRIx32 "%08" PRIx32,
            h, h+1, h+2, h+3, h+4));
        prep((uint8_t*)x, 64,
             (uint8_t*)h, 20);
        printf("nth=%" PRIu64 " sha1=%s\n",
            *nth, dump(Buf, h));
    } else {
        /* init from start */
        sha1_init(h);
        prep((uint8_t*)x, 64,
             (uint8_t*)"", 0);
        sha1_step(h, x, 1);
    }
}

static void search(uint64_t nth, uint32_t h[5], uint32_t x[16])
{
    do {
        memcpy(x, h, sizeof h);
        sha1_step(h, x, 1);
        nth++;
        if ((nth & 0xfffffffUL) == 0)
            report(nth, h);
    } while (memcmp(h, x, sizeof h));

    printf("holy shit!\n");
    report(nth, h);
    printf("h=%s\n", dump(Buf, h));
    printf("x=%s\n", dump(Buf, x));
}

int main(int argc, char *argv[])
{
    uint32_t h[5], x[16];
    uint64_t nth = 0;

    init(argc, argv, &nth, h, x);
    report(nth, h);
    search(nth, h, x);

    return 0;
}


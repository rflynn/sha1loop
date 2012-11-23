
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "sha1.h"

#ifdef __INTEL_COMPILER
#include <emmintrin.h>
#else
#include <xmmintrin.h>
#endif

static void inline ctx_init(uint32_t h[5])
{
    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;
}

static void dump(const uint8_t s[20])
{
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
}

#define SWAP(x)	(((x) >> 24) | (((x)&0x00FF0000) >> 8) | (((x)&0x0000FF00) << 8) | (x << 24))
//#define SWAP(x) (x)

static void prep(uint8_t *dst, uint64_t dstlen,
        const uint8_t *src, uint64_t srclen)
{
    memcpy(dst, src, srclen);
    memset(dst + srclen, 0, dstlen - srclen);
    dst[srclen] = 0x80;

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

uint32_t x[16] __attribute__((aligned(16))) = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000
};

int main(void)
{
    uint32_t //x[5] __attribute__((aligned(16))),
             y[5] __attribute__((aligned(16)));
    uint64_t cnt = 0;

    ctx_init(x);
    prep((uint8_t*)x, sizeof x,
         (uint8_t*)x, 20);
    printf("message:"); dump_H(x); fputc('\n', stdout);
	sha1_step(x, x, 1);

    y[0] = x[0]+1; /* different */

    //while (((uint64_t*)x)[0] != ((uint64_t*)y)[0] ||
          //((uint64_t*)x)[1] != ((uint64_t*)y)[1] ||
           //x[4] != y[4])
    while (x[0] != y[0] || x[1] != y[1] || x[2] != y[2] || x[3] != y[3] || x[4] != y[4])
    {
        *(__m128i*)y = *(__m128i*)x, y[4] = x[4];
        //memcpy(y, x, sizeof y);
        sha1_step(x, x, 1);
        cnt++;
        if ((cnt & 0xfffffff) == 0)
            fprintf(stderr, "%.1fB ", (double)cnt / 1e9);
    }

    printf("holy shit! cnt=%llu\n", cnt);
    printf("x="); dump((uint8_t*)x); fputc('\n', stdout);
    printf("y="); dump((uint8_t*)y); fputc('\n', stdout);

    return 0;
}


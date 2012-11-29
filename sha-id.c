
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#include "sha1.h"

#ifdef __INTEL_COMPILER
#include <emmintrin.h>
#else
#include <xmmintrin.h>
#endif

static char * dump(char buf[41], const void *v)
{
    const uint8_t *s = v;
    snprintf(buf, 41,
           "%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x",
           s[ 0], s[ 1], s[ 2], s[ 3], s[ 4],
           s[ 5], s[ 6], s[ 7], s[ 8], s[ 9],
           s[10], s[11], s[12], s[13], s[14],
           s[15], s[16], s[17], s[18], s[19]);
    return buf;
}

int main(int argc, char *argv[])
{
    SHA1Context ctx;
    uint64_t x[3] __attribute__((aligned(16))) = { 0, 0, 0 },
             y[3] __attribute__((aligned(16))) = { 0, 0, 0 },
             cnt = 0;
    char buf[41];
    time_t Started = time(0);

    SHA1Reset(&ctx);

    if (argc != 1)
    {
        if (argc != 3)
        {
            fputs("Usage: sha1-id <cnt> <sha1>\n", stderr);
            exit(1);
        } else {
            uint32_t *x32 = (uint32_t*)x;
            cnt = strtoull(argv[1], NULL, 10);
            assert(strlen(argv[2]) == 40);
            assert(5 == sscanf(argv[2], "%08x%08x%08x%08x%08x",
                            x32, x32+1, x32+2, x32+3, x32+4));
            for (int i = 0; i < 5; i++)
                x32[i] = ntohl(x32[i]);
            assert(0 == strcmp(dump(buf, x), argv[2]));
            SHA1Input(&ctx, (uint8_t*)x, 20);
        }
    }

    SHA1Result(&ctx, (uint8_t*)x);
    printf("0 %llu %s\n", cnt, dump(buf, x));

    y[0] = x[0]+1; /* different */

    //while (memcmp(x, y, 20))
    while (x[0] != y[0] || x[1] != y[1] || x[2] != y[2])
    {
        ((__m128i*)y)[0] = ((__m128i*)x)[0], y[2] = x[2];
        //y[0] = x[0], y[1] = x[1], y[2] = x[2];
        SHA1Reset(&ctx);
        SHA1Input(&ctx, (uint8_t*)x, 20);
        SHA1Result(&ctx, (uint8_t*)x);
        cnt++;
        if ((cnt & 0xffffffff) == 0)
        {
            time_t elapsed = time(0) - Started;
            printf("%zu %llu %s\n",
                (size_t)elapsed, cnt, dump(buf, x));
        }
    }

    printf("holy shit! cnt=%llu\n", cnt);
    printf("x=%s\n", dump(buf, x));
    printf("y=%s\n", dump(buf, y));

    return 0;
}


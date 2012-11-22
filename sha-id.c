
#include <stdio.h>
#include "sha1.h"

static void dump(const uint8_t s[20])
{
    printf("%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x",
           s[ 0], s[ 1], s[ 2], s[ 3], s[ 4],
           s[ 5], s[ 6], s[ 7], s[ 8], s[ 9],
           s[10], s[11], s[12], s[13], s[14],
           s[15], s[16], s[17], s[18], s[19]);
}

int main(void)
{
    SHA1Context ctx;
    uint64_t x[3], y[3], cnt = 0;

    SHA1Reset(&ctx);
    SHA1Result(&ctx, (uint8_t*)x);
    y[0] = x[0]+1;

    while (cnt < 0 || x[0] != y[0] || x[1] != y[1] || x[2] != y[2])
    {
        y[0] = x[0], y[1] = x[1], y[2] = x[2];
        SHA1Reset(&ctx);
        SHA1Input(&ctx, (uint8_t*)x, 20);
        SHA1Result(&ctx, (uint8_t*)x);
        cnt++;
        if ((cnt & 0xfffff) == 0)
            fprintf(stderr, "%.1fB ", (double)cnt / 1e9);
    }

    printf("holy shit! cnt=%llu\n", cnt);
    printf("x="); dump((uint8_t*)x); fputc('\n', stdout);
    printf("y="); dump((uint8_t*)y); fputc('\n', stdout);

    return 0;
}


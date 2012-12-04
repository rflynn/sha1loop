
#include <stdio.h>
#include <stdint.h>
#include <string.h>

//extern void sha1_update_intel(uint32_t *hash, const uint8_t* input);

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

inline static void sha1_init(uint32_t h[5])
{
    h[0] = 0x67452301UL;
    h[1] = 0xEFCDAB89UL;
    h[2] = 0x98BADCFEUL;
    h[3] = 0x10325476UL;
    h[4] = 0xC3D2E1F0UL;
}

int main(void)
{
    uint64_t cnt = 0;
    uint32_t x[5], y[5];
    uint8_t block[64];

    memset(block, 0, sizeof block);
    block[0] = 0x80;

    sha1_init(x);
    sha1_update_intel(x, block);
    dump((uint8_t*)x);
    fputc('\n', stdout);

#if 0
    while (x[0] != y[0] || x[1] != y[1] || x[2] != y[2])
    {
        y[0] = x[0], y[1] = x[1], y[2] = x[2];
        SHA1Reset(&ctx);
        SHA1Input(&ctx, (uint8_t*)x, 20);
        SHA1Result(&ctx, (uint8_t*)x);
        cnt++;
        if ((cnt & 0xffffffff) == 0)
        {
            printf("%llu ", cnt);
            dump((uint8_t*)x);
            fputc('\n', stdout);
        }
    }

    printf("holy shit! cnt=%llu\n", cnt);
    printf("x="); dump((uint8_t*)x); fputc('\n', stdout);
    printf("y="); dump((uint8_t*)y); fputc('\n', stdout);
#endif

    return 0;
}


/* ex: set ts=4 et: */

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

#define S(x) (x)

#define SWAP(x)                    \
    (((x) >> 24)                 | \
     (((x) & 0x00FF0000UL) >> 8) | \
     (((x) & 0x0000FF00UL) << 8) | \
     ((x) << 24))

#define SHA1_INIT   \
    { 0x67452301, \
      0xEFCDAB89, \
      0x98BADCFE, \
      0x10325476, \
      0xC3D2E1F0  \
    }

static void inline sha1_init(uint32_t h[5])
{
    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;
}

static time_t Start;
static char Buf[64];

static char * dump_sha1(char buf[64], const uint32_t h[5])
{
    const uint8_t *c = (const uint8_t*)h;
    snprintf(buf, 64,
        "%02x%02x%02x%02x%02x" "%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x" "%02x%02x%02x%02x%02x",
        c[3],  c[2],  c[1],  c[0],
        c[7],  c[6],  c[5],  c[4],
        c[11], c[10], c[9],  c[8],
        c[15], c[14], c[13], c[12],
        c[19], c[18], c[17], c[16]);
    return buf;
}

static void dump_msg(const uint32_t *chunk)
{
    const uint8_t *c = (const uint8_t*)chunk;
	for (unsigned i = 0; i < 64; i += 4)
		printf("%02x%02x%02x%02x ", c[i], c[i+1], c[i+2], c[i+3]);
}

static void dump_state(const uint32_t h[5], const uint32_t chunk[16])
{
    printf("h=%s chunk=", dump_sha1(Buf, h));
    dump_msg(chunk);
    fputc('\n', stdout);
}

static void report(uint64_t nth, const uint32_t h[5], const uint32_t chunk[16])
{
    unsigned long long elapsed = time(0) - Start;
    printf("t=%llu nth=%llu ", elapsed, nth);
    dump_state(h, chunk);
}

/*
$ echo -n "" | sha1sum
da39a3ee5e6b4b0d3255bfef95601890afd80709  -
$ echo -ne '\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09' | sha1sum -b
be1bdec0aa74b4dcb079943e70528096cca985f8  -
$ echo -ne '\xee\xa3\x39\xda\x0d\x4b\x6b\x5e\xef\xbf\x55\x32\x90\x18\x60\x95\x09\x07\xd8\xaf' | sha1sum -b
7aeccd0ff516c1eac7014fff48549666a7106cf4 *-

$ echo -ne '\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09' | od -t x1
0000000 da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90
0000020 af d8 07 09
*/

static const uint32_t Chunk_DA39[5] =
{
    S(0xda39a3ee),
    S(0x5e6b4b0d),
    S(0x3255bfef),
    S(0x95601890),
    S(0xafd80709)
};

static void test_empty(void)
{
    uint32_t h[5] = SHA1_INIT;
    const uint32_t chunk[16] = {
        SWAP(0x80000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
        SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
        SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
        SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000)
    };
    const uint32_t *expect = Chunk_DA39;
    sha1_step(h, chunk, 1);
    dump_state(h, chunk);
    printf("expect=%s\n", dump_sha1(Buf, expect));
    assert(0 == memcmp(h, expect, sizeof h));
}


static void test_da39(void)
{
    uint32_t h[5] = SHA1_INIT;
    const uint32_t chunk[16] = {
        SWAP(0xda39a3ee), SWAP(0x5e6b4b0d), SWAP(0x3255bfef), SWAP(0x95601890),
        SWAP(0xafd80709), SWAP(0x80000000), SWAP(0x00000000), SWAP(0x00000000),
        SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
        SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x000000a0)
    };
    const uint32_t expect[5] = {
        0xbe1bdec0, 0xaa74b4dc, 0xb079943e, 0x70528096, 0xcca985f8
    };

    printf("%s chunk=", __func__);
    dump_msg(chunk);
    fputc('\n', stdout);

    sha1_step(h, chunk, 1);
    dump_state(h, chunk);
    printf("expect=%s\n", dump_sha1(Buf, expect));
    assert(0 == memcmp(h, expect, sizeof h));
}

static void prep(uint8_t *dst, uint64_t dstlen,
           const uint8_t *src, uint64_t srclen)
{
    uint32_t *dst32 = (uint32_t*)dst;
    memset(dst, 0, dstlen);
    memcpy(dst, src, srclen);
    dst[srclen] = 0x80; /* append the bit '1' to the message */
    for (unsigned i = 0; i < 16; i++)
    {
        //dst32[i] = SWAP(dst32[i]);
    }
    dst32[15] = SWAP((uint32_t)(srclen * 8));
}

static void test_da39_prep(void)
{
    uint32_t h[5] = SHA1_INIT;
    uint32_t chunk[16];
    const uint8_t input[20] = {
        0xda, 0x39, 0xa3, 0xee,
        0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef,
        0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09
    };
    const uint32_t expect[5] = {
        0xbe1bdec0, 0xaa74b4dc, 0xb079943e, 0x70528096, 0xcca985f8
    };
    prep(chunk, sizeof chunk,
         input, sizeof input);

    printf("%s chunk=", __func__);
    dump_msg(chunk);
    fputc('\n', stdout);

    sha1_step(h, chunk, 1);
    dump_state(h, chunk);
    printf("expect=%s\n", dump_sha1(Buf, expect));
    assert(0 == memcmp(h, expect, sizeof h));
}

static void test_6162(void)
{
    uint32_t h[5] = SHA1_INIT;
    const uint32_t chunk[SHA1_STEP_SIZE] = {
	    SWAP(0x61626380), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	    SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	    SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	    SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000018)
    };
    const uint32_t expect[5] = {
	    0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d
    };
    sha1_step(h, chunk, 1);
    dump_state(h, chunk);
    assert(0 == memcmp(h, expect, sizeof expect));
}

#ifndef PRIx32
#define PRIx32 "x"
#endif

static void init(int argc, char *argv[],
                 uint64_t *nth, uint32_t h[5], uint32_t chunk[16])
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
        prep((uint8_t*)chunk, 64,
             (uint8_t*)h, 20);
        printf("nth=%llu sha1=%s\n",
            *nth, dump_sha1(Buf, h));
    } else {
        /* init from start */
        *nth = 0;
        sha1_init(h);
        prep((uint8_t*)chunk, 64,
             (uint8_t*)"", 0);
        report(*nth, h, chunk);

        *nth = 1;
        sha1_step(h, chunk, 1);
        report(*nth, h, chunk);
    }
}

static void search(uint64_t nth, uint32_t h[5], uint32_t chunk[16])
{
    prep((uint8_t*)chunk, 64,
         (uint8_t*)h, nth ? 20 : 0);

    printf("%s chunk=", __func__);
    dump_msg(chunk);
    fputc('\n', stdout);

/*
for real...
    t=0 nth=0 h=0000000000000000000000000000000000000000 chunk=80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    t=0 nth=1 h=0ffd8d43b4e33c7c53461bd10f27a5461050d90d chunk=80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    search chunk=438dfd0f 7c3ce3b4 d11b4653 46a5270f 0dd95010 80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000a0
        h=0ffd8d43b4e33c7c53461bd10f27a5461050d90d chunk=438dfd0f 7c3ce3b4 d11b4653 46a5270f 0dd95010 80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000a0
    t=0 nth=2 h=c76d9a1c9eb5333d11d5c7d45b401d59cc549f02 chunk=438dfd0f 7c3ce3b4 d11b4653 46a5270f 0dd95010 80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000a0
*/

    dump_state(h, chunk);
    if (nth == 0)
        assert(0 == memcmp(chunk, Chunk_DA39, sizeof Chunk_DA39));

    do {
        memcpy(chunk, h, 20);
        sha1_init(h);
        sha1_step(h, chunk, 1);
        nth++;
        if ((nth & 0xfffffffUL) == 2) /* every so often */
            report(nth, h, chunk);
    } while (memcmp(h, chunk, sizeof h));

    printf("holy shit!\n");
    report(nth, h, chunk);
}

int main(int argc, char *argv[])
{
    uint32_t h[5], chunk[16];
    uint64_t nth = 0;

    printf("tests...\n");
    test_empty();
    test_da39();
    test_da39_prep();
    test_6162();
    printf("for real...\n");
    init(argc, argv, &nth, h, chunk);
    search(nth, h, chunk);

    return 0;
}

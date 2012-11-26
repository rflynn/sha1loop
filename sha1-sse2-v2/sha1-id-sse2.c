
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

#define SHA1_INIT   \
    { 0x67452301UL, \
      0xEFCDAB89UL, \
      0x98BADCFEUL, \
      0x10325476UL, \
      0xC3D2E1F0UL  \
    }

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

static time_t Start;
static char Buf[64];

static char * dump_sha1(char buf[64], const uint32_t h[5])
{
    snprintf(buf, 64,
        "%08" PRIx32 " %08" PRIx32 " %08" PRIx32
        " %08" PRIx32 " %08" PRIx32,
        h[0], h[1], h[2], h[3], h[4]);
    return buf;
}

static void dump_msg(const uint32_t *chunk)
{
	for (unsigned i = 0; i < 16; i++)
		printf("%08x ", chunk[i]);
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
    printf("t=%llu nth=%" PRIu64 " ", elapsed, nth);
    dump_state(h, chunk);
}

#if 0
$ echo -n "" | sha1sum
da39a3ee5e6b4b0d3255bfef95601890afd80709  -
$ echo -ne '\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09' | sha1sum -b
be1bdec0aa74b4dcb079943e70528096cca985f8  -
$ echo -ne '\xee\xa3\x39\xda\x0d\x4b\x6b\x5e\xef\xbf\x55\x32\x90\x18\x60\x95\x09\x07\xd8\xaf' | sha1sum -b
7aeccd0ff516c1eac7014fff48549666a7106cf4 *-

$ echo -ne '\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09' | od -t x1
0000000 da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90
0000020 af d8 07 09

#endif

#define S(x) (x)

#define SWAP(x)	\
    (((x) >> 24) | \
     (((x) & 0x00FF0000UL) >> 8) | \
     (((x) & 0x0000FF00UL) << 8) | \
     ((x) << 24))

static const uint8_t Chunk_DA39[20] =
    //"\xda\x39\xa3\xee"
    //"\x5e\x6b\x4b\x0d"
    //"\x32\x55\xbf\xef"
    //"\x95\x60\x18\x90"
    //"\xaf\xd8\x07\x09";
    "\xee\xa3\x39\xda"
    "\x0d\x4b\x6b\x5e"
    "\xef\xbf\x55\x32"
    "\x90\x18\x60\x95"
    "\x09\x07\xd8\xaf";

static void test_empty(void)
{
    uint32_t h[5] = SHA1_INIT;
    const uint32_t chunk[16] = {
        S(0x00000080), S(0x00000000), S(0x00000000), S(0x00000000), S(0x00000000),
        S(0x00000000), S(0x00000000), S(0x00000000), S(0x00000000), S(0x00000000),
        S(0x00000000), S(0x00000000), S(0x00000000), S(0x00000000), S(0x00000000),
        S(0x00000000)
    };
    const uint8_t *expect = Chunk_DA39;
    sha1_step(h, chunk, 1);
    dump_state(h, chunk);
    assert(0 == memcmp(h, expect, sizeof expect));
}

static void test_da39(void)
{
    uint32_t h[5] = SHA1_INIT;
    const uint32_t *chunk = (uint32_t*)Chunk_DA39;
    const uint32_t expect[5] = {
        0x2085e9ba, 0x62755587, 0xc413088f, 0xe2ab1523, 0xeaba1f95
        // eb3c2c07 6026ec86 ff8b7193 ed0099b3 5b577796
    };
    sha1_step(h, chunk, 1);
    dump_state(h, chunk);
    assert(0 == memcmp(h, expect, sizeof expect));
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

#if 0
$ echo -ne '\x92\x00\x39\x6e\x48\x3b\x4a\xdf\x96\xcb\xc0\xab\x59\xb3\xf3\x4c\x6d\xf2\xa9\xbb' | sha1sum
02f4815b027af73010cdcb1dcf8378ce621868b9  -

h=2a1dcd0c 3ba1019e 9e1e6b6e 377bb26f 1139abc7 chunk=9200396e 483b4adf 96cbc0ab 59b3f34c 6df2a9bb 00000080 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000a0
#endif

static void test_9200(void)
{
    uint32_t h[5] = SHA1_INIT;
    const uint32_t chunk[16] = {
        S(0x9200396e), S(0x483b4adf), S(0x96cbc0ab), S(0x59b3f34c), S(0x6df2a9bb),
        S(0x00000080), S(0x00000000), S(0x00000000), S(0x00000000), S(0x00000000),
        S(0x00000000), S(0x00000000), S(0x00000000), S(0x00000000), S(0x00000000),
        S(0x000000a0)
    };
    const uint32_t expect[5] = {
        0x02f4815b, 0x027af730, 0x10cdcb1d, 0xcf8378ce, 0x621868b9
    };
    sha1_step(h, chunk, 1);
    dump_state(h, chunk);
    assert(0 == memcmp(h, expect, sizeof expect));
}

static void prep(uint8_t *dst, uint64_t dstlen,
           const uint8_t *src, uint64_t srclen)
{
    uint32_t *dst32 = (uint32_t*)dst;

    memset(dst, 0, dstlen);
    memcpy(dst, src, srclen);
    dst[srclen] = 0x80; /* append the bit '1' to the message */
    dst32[15] =((uint32_t)(srclen * 8));

    //for (unsigned i = 0; i < 16; i++)
        //dst32[i] =(dst32[i]);
}

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
        printf("nth=%" PRIu64 " sha1=%s\n",
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
    ((uint8_t*)chunk)[20] = 0x80; /* set '1' bit */
    ((uint32_t*)chunk)[15] = (uint32_t)(20 * 8); /* set bit length */
    memcpy(chunk, h, 20);
    dump_state(h, chunk);
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
    test_6162();
    test_9200();

    printf("for real...\n");
    init(argc, argv, &nth, h, chunk);
    search(nth, h, chunk);

    return 0;
}



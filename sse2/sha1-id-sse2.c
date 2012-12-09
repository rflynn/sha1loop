/* ex: set ts=4 et: */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include "sha1.h"

#ifdef __INTEL_COMPILER
#include <emmintrin.h>
#else
#include <xmmintrin.h>
#endif

# define BSWAP32 ntohl /* NOTE: works on little-endian only, but x86 is assumed... */
# define BSWAP64 __bswap_64 /* GCC built-in */

#define SHA1_INIT \
    { 0x67452301, \
      0xEFCDAB89, \
      0x98BADCFE, \
      0x10325476, \
      0xC3D2E1F0  \
    }

inline static void sha1_init(uint32_t h[5])
{
    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;
}

static time_t Start;
static char Buf[64];
static char Buf[64];

static char * dump_sha1(char buf[64], const uint32_t h[5])
{
    snprintf(buf, 64,
        "%08x%08x%08x%08x%08x",
        h[0], h[1], h[2], h[3], h[4]);
    return buf;
}

static void dump_msg(const uint32_t *chunk)
{
    printf("%08x %08x %08x %08x %08x %08x ... %08x",
        BSWAP32(chunk[0]),
        BSWAP32(chunk[1]),
        BSWAP32(chunk[2]),
        BSWAP32(chunk[3]),
        BSWAP32(chunk[4]),
        BSWAP32(chunk[5]),
        BSWAP32(chunk[15]));
}

static void dump_state(const uint32_t h[5], const uint32_t chunk[16])
{
    printf("h=%s chunk=", dump_sha1(Buf, h));
    dump_msg(chunk);
    fputc('\n', stdout);
}

#if 0
static void dump_state2(const uint32_t h[5], const uint32_t chunk[16])
{
    printf("h=%s chunk=%s\n", dump_sha1(Buf, h), dump_msg(MsgBuf, chunk));
}
#endif

static void report(uint64_t nth, const uint32_t h[5], const uint32_t chunk[16])
{
    unsigned long long elapsed = time(0) - Start;
    if (elapsed  == 0)
        elapsed = 1;
    printf("t=%llu nth=%llu %4.1fM/sec ",
        elapsed, nth, (double)nth / 1e6 / elapsed);
    if (h || chunk)
        dump_state(h, chunk);
    else
        fputc('\n', stdout);
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
    0xda39a3ee,
    0x5e6b4b0d,
    0x3255bfef,
    0x95601890,
    0xafd80709
};

static void test_empty(void)
{
    uint32_t h[5] = SHA1_INIT;
    const uint32_t chunk[16] = {
        BSWAP32(0x80000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000),
        BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000),
        BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000),
        BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000)
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
        BSWAP32(0xda39a3ee), BSWAP32(0x5e6b4b0d), BSWAP32(0x3255bfef), BSWAP32(0x95601890),
        BSWAP32(0xafd80709), BSWAP32(0x80000000), BSWAP32(0x00000000), BSWAP32(0x00000000),
        BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000),
        BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x000000a0)
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
        //dst32[i] = BSWAP32(dst32[i]);
    }
    dst32[15] = BSWAP32((uint32_t)(srclen * 8));
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

    prep((uint8_t*)chunk, sizeof chunk,
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
        BSWAP32(0x61626380), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000),
        BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000),
        BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000),
        BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000000), BSWAP32(0x00000018)
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
        sha1_step(h, chunk, 1);
        report(*nth, h, chunk);

        prep((uint8_t*)chunk, 64,
             (uint8_t*)h, 20);
    }
}

static int search(uint64_t *nth, uint32_t h[5], uint32_t chunk[16])
{
#if 0
    printf("%s chunk=", __func__);
    dump_msg(chunk);
    fputc('\n', stdout);

    dump_state(h, chunk);
#endif

    do {
        /* use hash output for next input */
        chunk[0] = BSWAP32(h[0]);
        chunk[1] = BSWAP32(h[1]);
        chunk[2] = BSWAP32(h[2]);
        chunk[3] = BSWAP32(h[3]);
        chunk[4] = BSWAP32(h[4]);
        sha1_init(h);
        sha1_step(h, chunk, 1);
        ++*nth;
    } while (*h != *chunk || memcmp(h, chunk, 20));

    printf("holy shit!\n");
    report(*nth, h, chunk);

    return 0;
}

static unsigned long cpucnt(void)
{
    unsigned long cpus = 1;
#if defined(linux) && defined(_SC_NPROCESSORS_CONF)
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs > 0)
    {
        cpus = (unsigned long)nprocs;
    }
#elif defined(__APPLE__)
    FILE *f = popen("PATH=$PATH:/usr/sbin:/sbin sysctl -n hw.ncpu", "r");
    if (f)
    {
        char buf[32];
        if (fgets(buf, sizeof buf, f))
        {
            unsigned long n = strtoul(buf, NULL, 10);
            cpus = n;
        }
    }
    pclose(f);
#else
    /* use default... */
#endif
    return cpus;
}

struct searchparams {
    unsigned long worker;
    uint64_t nth;
    uint32_t h[5];
    uint32_t chunk[16];
};

static void *search_thread(void *args)
{
    struct searchparams *params = args;
    search(&params->nth, params->h, params->chunk);
    printf("done\n");
    exit(0);
    pthread_exit(NULL);
}

static int run_search(uint64_t nth, uint32_t h[5], uint32_t chunk[16])
{
    unsigned long workers = cpucnt();
    struct searchparams *params = calloc(workers, sizeof *params);
    pthread_t *thread = calloc(workers, sizeof *thread);
    unsigned secs = 10;

    printf("workers=%lu\n", workers);

    for (unsigned long i = 0; i < workers; i++)
    {
        params[i].worker = i;
        params[i].nth = nth;

        for (int j = 0; j < 5; j++)
            params[i].h[j] = (uint32_t)((rand() << 15) + rand());

        printf("params[%lu]=%s\n", i, dump_sha1(Buf, params[i].h));

        memcpy(params[i].chunk, chunk, 64);
        pthread_create(thread, NULL, search_thread, params+i);
    }

    while (1)
    {
        uint64_t n;

        sleep(secs);
        if (secs < 600)
            secs += 10; /* gradually increase */

        n = 0;
        for (unsigned long i = 0; i < workers; i++)
            n += params[i].nth;
        report(n, NULL, NULL);
    }

    /*
     * wait for one of them to find it and blow up
     */
    pthread_join(*thread, NULL);

    return search(&nth, h, chunk); /* never run */
}

static int run(int argc, char *argv[])
{
    uint32_t h[5], chunk[16];
    uint64_t nth = 0;

    printf("search...\n");
    init(argc, argv, &nth, h, chunk);

    return run_search(nth, h, chunk);
}

static void test(void)
{
    printf("test...\n");
    test_empty();
    test_da39();
    test_da39_prep();
    test_6162();
}

int main(int argc, char *argv[])
{
    srand(time(0));
    test();
    return run(argc, argv);
}

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha1.h"

#define SWAP(x)	(((x) >> 24) | (((x)&0x00FF0000) >> 8) | (((x)&0x0000FF00) << 8) | ((uint8_t)x << 24))

const uint32_t message0[SHA1_STEP_SIZE] = {
	SWAP(0x61626380), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000018)
};

const uint32_t H_expected0[SHA1_HASH_SIZE] = {
	0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d
};


const uint32_t message1[2*SHA1_STEP_SIZE] = {
	SWAP(0x61626364), SWAP(0x62636465), SWAP(0x63646566), SWAP(0x64656667),
	SWAP(0x65666768), SWAP(0x66676869), SWAP(0x6768696a), SWAP(0x68696a6b),
	SWAP(0x696a6b6c), SWAP(0x6a6b6c6d), SWAP(0x6b6c6d6e), SWAP(0x6c6d6e6f),
	SWAP(0x6d6e6f70), SWAP(0x6e6f7071), SWAP(0x80000000), SWAP(0x00000000),

	SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000),
	SWAP(0x00000000), SWAP(0x00000000), SWAP(0x00000000), SWAP(0x000001c0)
};

const uint32_t H_expected1[SHA1_HASH_SIZE] = {
	0x84983e44, 0x1c3bd26e, 0xbaae4aa1, 0xf95129e5, 0xe54670f1
};



uint32_t H[SHA1_HASH_SIZE];

void init_H(void)
{
	H[0] = 0x67452301;
	H[1] = 0xefcdab89;
	H[2] = 0x98badcfe;
	H[3] = 0x10325476;
	H[4] = 0xc3d2e1f0;
}


void dump_H(const uint32_t *h)
{
	int i;

	for (i = 0; i < SHA1_HASH_SIZE; ++i) {
		printf(" %08x", h[i]);
	}
}


int test(const uint32_t *message, uint32_t num_steps, const uint32_t *H_expected)
{
	unsigned i;

    printf("num_steps=%lu\n", (unsigned long)num_steps);
	init_H();

	sha1_step(H, message, num_steps);

	printf("\nmessage:");
	for (i = 0; i < num_steps * SHA1_STEP_SIZE; ++i) {
		if (i % 8 == 0) {
			printf("\n\t");
		}
		printf(" %08x", SWAP(message[i]));
	}
	printf("\nexpected:");
	dump_H(H_expected);
	printf("\nresult  :");
	dump_H(H);
	printf("\n");

	if (memcmp(H, H_expected, SHA1_HASH_SIZE*sizeof(uint32_t))) {
		printf("==> FAILURE\n");
		return 1;
	}
	printf("==> PASS\n");
	return 0;
}


int main(void)
{
	int fails;

	fails = 0;

	fails += test(message0, sizeof(message0)/sizeof(uint32_t)/SHA1_STEP_SIZE, H_expected0);
	fails += test(message1, sizeof(message1)/sizeof(uint32_t)/SHA1_STEP_SIZE, H_expected1);

	return fails != 0;
}

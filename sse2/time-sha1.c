#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>

#include "sha1.h"


#define N (2048)

uint32_t buf[N] __attribute__((aligned(4096)));
uint32_t H[SHA1_HASH_SIZE];

#define N_SAMPLE (10)

void one(unsigned n)
{
	unsigned i, j;
	struct timeval tv_start, tv_end;
	double delta;
	double best;
	unsigned n_iter;

	n_iter =  1000*(8192/n);
	best = INFINITY;
	for (j = 0; j < N_SAMPLE; ++j) {
		gettimeofday(&tv_start, 0);
		for (i = 0; i < n_iter; ++i) {
			sha1_step(H, buf, n/SHA1_STEP_SIZE);
		}
		gettimeofday(&tv_end, 0);

		__asm volatile("emms");

		delta = (double)(tv_end.tv_sec - tv_start.tv_sec)
			+ (double)(tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;
		if (delta < best) {
			best = delta;
		}
	}
	/* print a number similar to what openssl reports */
	printf("%.2f KB/s (for %lu byte buffer)\n",
		(double)(n * sizeof(uint32_t) * n_iter) / best / 1000.0 + 0.005,
		(unsigned long)n*sizeof(uint32_t));
}


int main(void)
{
	memset(buf, 0, sizeof(buf));
	one(16);
	one(64);
	one(256);
	one(1024);
	one(2048);

	return 0;
}

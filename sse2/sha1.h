#ifndef SHA1_H_INCLUDED
#define SHA1_H_INCLUDED 1

#include <stdint.h>
#include <stddef.h>

#define SHA1_HASH_SIZE	(5)
#define SHA1_STEP_SIZE	(16)

extern void sha1_step(uint32_t * restrict H, const uint32_t * restrict input, size_t num_steps);

#endif

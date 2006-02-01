#ifndef SURFRAND
#define SURFRAND

#include <sysdeps.h>
#include <crypto/surf.h>

struct surfrand
{
  unsigned used;
  uint32 generated[SURF_OUT_U32];
  uint32 seed[SURF_SEED_U32];
  uint32 counter[SURF_IN_U32];
};

extern void surfrand_init(struct surfrand* c, const uint32* data, unsigned words);
extern void surfrand_fill(struct surfrand* c, unsigned char* buf, unsigned len);
extern uint32 surfrand_uint32(struct surfrand* c);
extern double surfrand_double(struct surfrand* c);
extern void surfrand_initmisc(struct surfrand* s);
extern int surfrand_initfile(struct surfrand* s, const char* path);

#endif

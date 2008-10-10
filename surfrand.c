#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "surfrand.h"

static void generate(struct surfrand* c)
{
  unsigned i = 0;
  uint32* p;
  for (p = c->counter, i = 0; i < SURF_IN_U32; ++i, ++p)
    if (++*p > 0)
      break;
  surf(c->generated, c->counter, c->seed);
  c->used = 0;
}

void surfrand_init(struct surfrand* c, const uint32* data, unsigned words)
{
  uint32* ptr;
  unsigned i;
  /* If there are more bytes to use than the size of the seed,
   * add bytes together where they overlap. */
  if (words > SURF_SEED_U32) {
    memcpy(c->seed, data, sizeof c->seed);
    data += SURF_SEED_U32;
    words -= SURF_SEED_U32;
    while (words > 0) {
      for (i = 0, ptr = c->seed; words > 0 && i < SURF_SEED_U32; ++i, --words)
	*ptr++ += *data++;
    }
  }
  /* Otherwise, repeat the given bytes until the seed is filled. */
  else {
    for (i = 0, ptr = c->seed;
	 i + words < SURF_SEED_U32;
	 i += words, ptr += words)
      memcpy(ptr, data, words * sizeof(uint32));
    memcpy(ptr, data, sizeof c->seed - i * SURF_SEED_U32);
  }
  memset(c->counter, 0, sizeof c->counter);
  generate(c);
}

void surfrand_fill(struct surfrand* c, unsigned char* buf, unsigned len)
{
  unsigned todo;
  while (len > (todo = sizeof c->generated - c->used)) {
    memcpy(buf, c->generated + c->used, todo);
    len -= todo;
    buf += todo;
    generate(c);
  }
  memcpy(buf, c->generated + c->used, len);
  c->used += len;
}

uint32 surfrand_uint32(struct surfrand* c)
{
  uint32 u;
  if ((c->used = (c->used & ~3) + 4) >= sizeof c->generated)
    generate(c);
  u = c->generated[c->used/4];
  c->used += 4;
  /* surfrand_fill(c, (unsigned char*)&u, sizeof u); */
  return u;
}

double surfrand_double(struct surfrand* c)
{
  const uint32 u1 = surfrand_uint32(c);
  const uint32 u2 = surfrand_uint32(c);
  return u1 * (1.0/4294967296.0) + u2 * (1.0/4294967296.0/4294967296.0);
}

void surfrand_initmisc(struct surfrand* s)
{
  uint32 bits[3];
  struct timeval tv;
  gettimeofday(&tv, 0);
  bits[0] = tv.tv_sec;
  bits[1] = tv.tv_usec;
  bits[2] = getpid();
  surfrand_init(s, bits, 3);
}

int surfrand_initfile(struct surfrand* s, const char* path)
{
  int fd;
  char* p;
  int left;
  int rd;
  memset(s->seed, 0, SURF_SEED);
  if ((fd = open(path, O_RDONLY)) == -1)
    return -1;
  for (left = SURF_SEED, p = (char*)s->seed; left > 0; left -= rd, p += rd) {
    if ((rd = read(fd, p, left)) == -1) {
      close(fd);
      return -1;
    }
    if (rd == 0)
      break;
  }
  close(fd);
  memset(s->counter, 0, sizeof s->counter);
  generate(s);
  return 0;
}

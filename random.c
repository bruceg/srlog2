/* $Id$ */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <systime.h>
#include <msg/msg.h>

#include "srlog2.h"

static unsigned char* pool;
static unsigned pool_size;
static unsigned pool_used;
static unsigned pool_uses;
static unsigned pool_use_count;

static void brandom_refill(void)
{
  int fd;
  if ((fd = open("/dev/urandom", O_RDONLY)) == -1 ||
      (unsigned)read(fd, pool, pool_size) != pool_size)
    die1sys(1, "Could not read from /dev/urandom");
  close(fd);
  pool_use_count = 0;
}

void brandom_init(unsigned size, unsigned maxuses)
{
  if (size < 28) size = 28;
  if ((pool = malloc(size)) == 0)
    die1(1, "Could not allocate random pool");
  pool_size = size;
  pool_uses = maxuses;
  brandom_refill();
}

static void stir(void)
{
  /* FIXME: use a better randomization algorithm
   * This is not a real algorithm, but it fools gzip and bzip2,
   * and is only used for the (hidden encrypted) padding. */
  unsigned i;
  if (pool_uses && ++pool_use_count >= pool_uses)
    brandom_refill();
  else {
    unsigned j, k;
    for (i = 0, j = 13, k = 27; i < pool_size; ++i, ++j, ++k) {
      if (j > pool_size) j = 0;
      if (k > pool_size) k = 0;
      pool[i] += pool[j] + pool[k];
    }
  }
  pool_used = 0;
}

void brandom_fill(char* buf, unsigned len)
{
  unsigned todo;
  while (len > (todo = pool_size - pool_used)) {
    memcpy(buf, pool+pool_used, todo);
    stir();
    len -= todo;
    buf += todo;
  }
  memcpy(buf, pool+pool_used, len);
  pool_used += len;
}

#ifdef SELFTEST
void msg_die(int x, const char* a, const char* b, const char* c, const char* d,
	     const char* e, const char* f, int sys)
{
  exit(x);
}

int main(int argc, char* argv[])
{
  int size = 32;
  char buf[4096];
  if (argc > 1) size = atoi(argv[1]);
  brandom_init(size, 0);
  for (;;) {
    brandom_fill(buf, sizeof buf);
    write(1, buf, sizeof buf);
  }
}
#endif

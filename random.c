/* $Id$ */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <systime.h>
#include <msg/msg.h>

#include "srlog2.h"
#include "surfrand.h"

static struct surfrand pool;

void brandom_init(unsigned size, unsigned maxuses)
{
  if (surfrand_initfile(&pool, "/dev/urandom") != 0)
    die1sys(1, "Error initializing random generator");
  (void)size;
  (void)maxuses;
}

void brandom_fill(char* buf, unsigned len)
{
  surfrand_fill(&pool, buf, len);
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

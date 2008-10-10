#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <systime.h>
#include <msg/msg.h>

#include "srlog2.h"
#include "surfrand.h"

static struct surfrand pool;

void brandom_init(void)
{
  if (surfrand_initfile(&pool, "/dev/urandom") != 0)
    die1sys(1, "Error initializing random generator");
}

void brandom_fill(unsigned char* buf, unsigned len)
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
  char buf[4096];
  brandom_init();
  for (;;) {
    brandom_fill(buf, sizeof buf);
    write(1, buf, sizeof buf);
  }
}
#endif

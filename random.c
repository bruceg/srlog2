#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <bglibs/systime.h>
#include <bglibs/msg.h>
#include <bglibs/surfrand.h>

#include "srlog2.h"

static struct surfrand pool;

int brandom_initfile(const char* path)
{
  int fd;
  char* p;
  int left;
  int rd;
  uint32 seed[SURF_SEED_U32];
  if ((fd = open(path, O_RDONLY)) == -1)
    return -1;
  for (left = SURF_SEED, p = (char*)seed; left > 0; left -= rd, p += rd) {
    if ((rd = read(fd, p, left)) == -1) {
      close(fd);
      return -1;
    }
    if (rd == 0)
      break;
  }
  close(fd);
  surfrand_init(&pool, seed, SURF_SEED_U32);
  return 0;
}

void brandom_init(void)
{
  if (brandom_initfile("/dev/urandom") != 0)
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

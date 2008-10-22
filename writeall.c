#include <sysdeps.h>
#include <unistd.h>
#include "srlog2.h"

static void delay(void)
{
  iopoll(0, 0, 1000);
}

void writeall(int fd, const char* buf, size_t len)
{
  ssize_t wr;
  while (len > 0) {
    wr = write(fd, buf, len);
    if (wr <= 0) {
      warn1("Could not write to buffer, pausing");
      delay();
    }
    else {
      buf += wr;
      len -= wr;
    }
  }
}

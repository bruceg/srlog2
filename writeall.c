#include <sysdeps.h>
#include <unistd.h>
#include "srlog2.h"

void delay(const char* msg)
{
  warn1("Could not ", msg, ", pausing");
  iopoll(0, 0, 1000);
}

void writeall(int fd, const char* buf, size_t len)
{
  ssize_t wr;
  while (len > 0) {
    wr = write(fd, buf, len);
    if (wr <= 0)
      delay("write to buffer");
    else {
      buf += wr;
      len -= wr;
    }
  }
}

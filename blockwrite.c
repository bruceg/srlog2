#include <bglibs/sysdeps.h>
#include <errno.h>
#define open XXX_open
#include <fcntl.h>
#undef open
#include <string.h>
#include <syscall.h>
#include <unistd.h>

#define SYS_OPEN(PATHNAME,FLAGS,MODE) syscall(SYS_open,PATHNAME,FLAGS,MODE)
#define SYS_WRITE(FD,BUF,COUNT) syscall(SYS_write,FD,BUF,COUNT)

#define maxbytes 1024
static int buffer_fd = -1;
static int blockit = 0;

int open(const char *pathname, int flags, mode_t mode)
{
  int fd;
  fd = SYS_OPEN(pathname, flags, mode);
  if (fd >= 0
      && strcmp(pathname, "buffer") == 0
      && (flags & O_WRONLY) != 0)
    buffer_fd = fd;
  return fd;
}

ssize_t write(int fd, const void *buf, size_t count)
{
  if (fd > 0 && fd == buffer_fd) {
    blockit = !blockit;
    if (blockit) {
      errno = ENOSPC;
      return -1;
    }
  }
  return SYS_WRITE(fd, buf, count);
}

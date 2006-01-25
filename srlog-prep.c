/* $Id$ */
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <base64/base64.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>

#include "srlog.h"

const char program[] = "srlog-prep";
const int msg_show_pid = 0;

static nistp224key public;
static nistp224key secret;
static str line;

int write_key(const char* filename, int mode, const char* keyline)
{
  obuf out;
  if (!obuf_open(&out, filename,
		 OBUF_CREATE|OBUF_TRUNCATE|OBUF_EXCLUSIVE, mode, 0)) {
    error3sys("Could not open '", filename, "' for writing");
    return 0;
  }
  if (!obuf_puts(&out, keyline) ||
      !obuf_putc(&out, LF) ||
      !obuf_close(&out)){
    error3sys("Could not write to '", filename, "'");
    return 0;
  }
  return 1;
}

void encode_key(str* s, const nistp224key key)
{
  if (!str_truncate(s, 0) ||
      !base64_encode_line(key, KEY_LENGTH, s))
    die1(1, "Out of memory");
}

int exists(const char* path)
{
  struct stat st;
  return stat(path, &st) == 0;
}

int main(int argc, char* argv[])
{
  int i;
  int cwd;
  if (argc < 2) die3(1, "usage: ", program, " directory [directory ...]");
  if ((cwd = open(".", O_RDONLY)) == -1)
    die1sys(1, "Could not open current directory");

  for (i = 1; i < argc; ++i) {
    if (fchdir(cwd)) die1sys(1, "Could not return to startup directory");
    if (chdir(argv[i]) == -1) {
      error3sys("Could not chdir to '", argv[i], "'");
      continue;
    }
    if (exists("secret") && exists("public")) {
      error3("The key pair for '", argv[i], "' appears to exist already");
      continue;
    }
    brandom_init(28, 1);
    brandom_key(secret, public);
    encode_key(&line, secret);
    if (!write_key("secret", 0400, line.s)) continue;
    encode_key(&line, public);
    if (!write_key("public", 0444, line.s)) continue;
    msg4("Public key for '", argv[i], "' is ", line.s);
  }
  return 0;
}

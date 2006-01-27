/* $Id$ */
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <base64/base64.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <msg/wrap.h>

#include "srlog2.h"
#include "srlog2-keygen-cli.h"

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
  wrap_str(str_truncate(s, 0));
  wrap_str(base64_encode_line(key, KEY_LENGTH, s));
}

int exists(const char* path)
{
  struct stat st;
  return stat(path, &st) == 0;
}

int cli_main(int argc, char* argv[])
{
  wrap_chdir(argv[0]);
  if (exists("secret") && exists("public"))
    die3(1, "The key pair for '", argv[0], "' appears to exist already");
  brandom_init(28, 1);
  brandom_key(secret, public);
  encode_key(&line, secret);
  if (!write_key("secret", 0400, line.s)) return 1;
  encode_key(&line, public);
  if (!write_key("public", 0444, line.s)) return 1;
  msg4("Public key for '", argv[0], "' is ", line.s);
  return 0;
  (void)argc;
}

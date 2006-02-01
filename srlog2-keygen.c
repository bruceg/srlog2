/* $Id$ */
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <base64/base64.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <msg/wrap.h>

#include "conf_etc.c"
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
  str secret_path = {0,0,0};
  str public_path = {0,0,0};
  if (argc > 0)
    wrap_str(str_copys(&secret_path, argv[0]));
  else
    wrap_str(str_copy2s(&secret_path, conf_etc, "/nistp224"));
  wrap_str(str_copy(&public_path, &secret_path));
  wrap_str(str_cats(&public_path, ".pub"));
  if (exists(secret_path.s) && exists(public_path.s))
    die3(1, "The key pair for '", secret_path.s, "' appears to exist already");
  brandom_init();
  brandom_key(secret, public);
  encode_key(&line, secret);
  if (!write_key(secret_path.s, 0400, line.s)) return 1;
  encode_key(&line, public);
  if (!write_key(public_path.s, 0444, line.s)) return 1;
  msg4("Public key for '", secret_path.s, "' is ", line.s);
  return 0;
  (void)argc;
}

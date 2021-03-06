#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bglibs/base64.h>
#include <bglibs/iobuf.h>
#include <bglibs/msg.h>
#include <bglibs/wrap.h>

#include "conf_etc.c"
#include "srlog2.h"
#include "srlog2-keygen-cli.h"

static int key_export(const struct key* key, str* s)
{
  return str_copys(s, key->cb->name)
    && str_catc(s, ':')
    && base64_encode_line(key->data, key->cb->size, s);
}

static void write_key(const char* filename, int mode, const char* keyline)
{
  obuf out;
  if (!obuf_open(&out, filename,
		 OBUF_CREATE|OBUF_TRUNCATE|OBUF_EXCLUSIVE, mode, 0))
    die3sys(1, "Could not open '", filename, "' for writing");
  if (!obuf_puts(&out, keyline) ||
      !obuf_putc(&out, LF) ||
      !obuf_close(&out))
    die3sys(1, "Could not write to '", filename, "'");
}

int cli_main(int argc, char* argv[])
{
  str path = {0,0,0};
  struct stat st;
  const struct key_cb* type;
  struct key public;
  struct key secret;
  str line = {0,0,0};

  if ((type = key_cb_lookup(opt_type)) == 0)
    dief(1, "{Unknown key type: }s", opt_type);
  brandom_init();
  key_generate(&secret, &public, type);
  
  wrap_str(str_copys(&path, argv[0]));
  if (stat(path.s, &st) == 0) {
    if (S_ISDIR(st.st_mode)) {
      wrap_str(str_catc(&path, '/'));
      wrap_str(str_cats(&path, type->name));
    }
    else
      dief(1, "{The file '}s{' already exists}", path.s);
  }
  else if (errno != ENOENT)
    die1sys(1, "stat failed");

  wrap_str(key_export(&secret, &line));
  write_key(path.s, 0400, line.s);

  line.len = 0;
  wrap_str(key_export(&public, &line));
  msg4("Public key for '", path.s, "' is ", line.s);
  wrap_str(str_cats(&path, ".pub"));
  write_key(path.s, 0444, line.s);

  return 0;
  (void)argc;
}

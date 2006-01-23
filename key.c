#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <base64/base64.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <msg/wrap.h>
#include <str/str.h>

#include "srlog.h"

static nistp224key BASEP224 = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";

static str keybuf;
static int load_key_line(ibuf* in, nistp224key key)
{
  char buf[40];
  if (!ibuf_gets(in, buf, sizeof buf, '\n')) return 0;
  if (!str_truncate(&keybuf, 0)) die1(1, "Out of memory");
  if (!base64_decode_line(buf, &keybuf)) return 0;
  if (keybuf.len != KEY_LENGTH) return 0;
  memcpy(key, keybuf.s, keybuf.len);
  return 1;
}

int load_key(const char* filename, nistp224key key)
{
  ibuf in;
  int result;
  if (!ibuf_open(&in, filename, 0)) return 0;
  result = load_key_line(&in, key);
  ibuf_close(&in);
  return result;
}

void brandom_key(nistp224key secret, nistp224key public)
{
  do {
    brandom_fill(secret, KEY_LENGTH);
    /* Constrain the first byte of the secret key to 8-135 inclusive,
       according to http://cr.yp.to/nistp224/library.html */
    secret[0] = (secret[0] % 128) + 8;
  } while (!nistp224(public, BASEP224, secret));
}

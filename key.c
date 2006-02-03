/* $Id$ */
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <base64/base64.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <msg/wrap.h>
#include <str/str.h>

#include "srlog2.h"

static struct key BASEP224 = { "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" };

static str keybuf;
static int load_key_line(ibuf* in, struct key* key)
{
  char buf[40];
  if (!ibuf_gets(in, buf, sizeof buf, '\n')) return 0;
  if (!str_truncate(&keybuf, 0)) die1(1, "Out of memory");
  if (!base64_decode_line(buf, &keybuf)) return 0;
  if (keybuf.len != KEY_LENGTH) return 0;
  memcpy(key->data, keybuf.s, keybuf.len);
  return 1;
}

int key_load(struct key* key, const char* prefix, const char* type, int public)
{
  ibuf in;
  int result;
  wrap_str(str_copy3s(&keybuf, prefix, type, public ? ".pub" : ""));
  if (!ibuf_open(&in, keybuf.s, 0)) return 0;
  result = load_key_line(&in, key);
  ibuf_close(&in);
  return result;
}

void key_generate(struct key* secret, struct key* public)
{
  do {
    brandom_fill(secret->data, KEY_LENGTH);
    /* Constrain the first byte of the secret key to 8-135 inclusive,
       according to http://cr.yp.to/nistp224/library.html */
    secret->data[0] = (secret->data[0] % 128) + 8;
  } while (!key_exchange(public, &BASEP224, secret));
}

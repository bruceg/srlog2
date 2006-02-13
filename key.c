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

static str keybuf;

int key_load_line(struct key* key, ibuf* in, const struct key_cb* cb)
{
  char buf[40];
  if (!ibuf_gets(in, buf, sizeof buf, '\n')) return 0;
  if (!str_truncate(&keybuf, 0)) die1(1, "Out of memory");
  if (!base64_decode_line(buf, &keybuf)) return 0;
  if (keybuf.len != cb->size) return 0;
  memcpy(key->data, keybuf.s, keybuf.len);
  key->cb = cb;
  return 1;
}

int key_load(struct key* key, const char* prefix, const struct key_cb* cb)
{
  ibuf in;
  int result;
  wrap_str(str_copy2s(&keybuf, prefix, cb->name));
  if (!ibuf_open(&in, keybuf.s, 0)) return 0;
  result = key_load_line(key, &in, cb);
  ibuf_close(&in);
  return result;
}

void key_generate(struct key* secret, struct key* public,
		  const struct key_cb* type)
{
  do {
    if (!type->generate(secret))
      continue;
  } while (!type->exchange(public, &type->public, secret));
}

int key_export(const struct key* key, str* s)
{
  return base64_encode_line(key->data, key->cb->size, s);
}

int key_exchange(struct key* shared,
		 const struct key* public,
		 const struct key* secret)
{
  // FIXME: make sure public and secret cbs match
  return public->cb->exchange(shared, public, secret);
}

const struct key_cb* key_cb_lookup(const char* name)
{
  if (strcasecmp(name, nistp224_cb.name) == 0)
    return &nistp224_cb;
#ifdef HASCURVE25519
  if (strcasecmp(name, curve25519_cb.name) == 0)
    return &curve25519_cb;
#endif
  return 0;
}

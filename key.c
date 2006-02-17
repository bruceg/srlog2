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

void key_generate(struct key* secret, struct key* public,
		  const struct key_cb* type)
{
  do {
    if (!type->generate(secret))
      continue;
  } while (!type->exchange(public, &type->public, secret));
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

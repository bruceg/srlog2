#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <bglibs/base64.h>
#include <bglibs/iobuf.h>
#include <bglibs/msg.h>
#include <bglibs/wrap.h>
#include <bglibs/str.h>

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
  if (strcasecmp(name, curve25519_cb.name) == 0)
    return &curve25519_cb;
  return 0;
}

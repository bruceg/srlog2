#include <nistp224.h>
#include "srlog2.h"

static int exchange(struct key* shared,
		    const struct key* public,
		    const struct key* secret)
{
  if (!nistp224(shared->data,
		(unsigned char*)public->data,
		(unsigned char*)secret->data))
    return 0;
  shared->cb = &nistp224_cb;
  return 1;
}

static int generate(struct key* secret)
{
  secret->cb = &nistp224_cb;
  brandom_fill(secret->data, 28);
  /* Constrain the first byte of the secret key to 8-135 inclusive,
     according to http://cr.yp.to/nistp224/library.html */
  secret->data[0] = (secret->data[0] % 128) + 8;
  return 1;
}

const struct key_cb nistp224_cb = {
  .name = "nistp224",
  .size = 28,
  .public = { &nistp224_cb, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" },
  .generate = generate,
  .exchange = exchange,
};

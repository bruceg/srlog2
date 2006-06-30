/* $Id$ */
#include "srlog2.h"
#ifdef HASCURVE25519

static int exchange(struct key* shared,
		    const struct key* public,
		    const struct key* secret)
{
  shared->cb = &curve25519_cb;
  curve25519(shared->data,
	     (unsigned char*)secret->data,
	     (unsigned char*)public->data);
  return 1;
}

static int generate(struct key* secret)
{
  unsigned char* data = secret->data;
  secret->cb = &curve25519_cb;
  brandom_fill(data, 32);
  /* See http://cr.yp.to/ecdh.html for details on the below. */
  data[0] &= 0xf8;
  data[31] &= 0x7f;
  data[31] |= 0x40;
  return 1;
}

const struct key_cb curve25519_cb = {
  .name = "curve25519",
  .size = 32,
  .public = { &curve25519_cb, {9,0} },
  .generate = generate,
  .exchange = exchange,
};

#endif

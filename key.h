#ifndef SRLOG__KEY__H__
#define SRLOG__KEY__H__

#include "curve25519.h"

struct ibuf;
struct key_cb;
struct str;

#define MAX_KEY_LENGTH 32

struct key
{
  const struct key_cb* cb;
  unsigned char data[MAX_KEY_LENGTH];
};

typedef int (*key_exchange_fn)(struct key* shared,
			       const struct key* public,
			       const struct key* secret);
typedef int (*key_generate_fn)(struct key* secret);

struct key_cb
{
  const char* name;
  unsigned int size;
  const struct key public;
  key_generate_fn generate;
  key_exchange_fn exchange;
};

extern const struct key_cb nistp224_cb;
#ifdef HASCURVE25519
extern const struct key_cb curve25519_cb;
#endif

extern const struct key_cb* key_cb_lookup(const char* name);

extern void key_generate(struct key* secret, struct key* public,
			 const struct key_cb* cb);
extern int key_export(const struct key* key, struct str* s);
extern int key_exchange(struct key* shared,
			const struct key* public,
			const struct key* secret);

#endif

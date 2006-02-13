#ifndef SRLOG2__KEYLIST__H
#define SRLOG2__KEYLIST__H

#include "key.h"

struct str;

#ifdef HASCURVE25519
#define ADD_CURVE25519 1
#else
#define ADD_CURVE25519 0
#endif

#define KEY_TYPE_COUNT (1+ADD_CURVE25519)

struct keylist
{
  struct key keys[KEY_TYPE_COUNT];
};

extern int keylist_set(struct keylist* list, const struct key* key);
extern struct key* keylist_get(struct keylist* list, const struct key_cb* cb);
extern int keylist_import(struct keylist* list, const struct str* text);
extern int keylist_load(struct keylist* list, const char* path);
extern int keylist_exchange(struct key* shared,
			    const struct key* public,
			    const struct keylist* secrets);
extern int keylist_exchange_list(struct keylist* shareds,
				 const struct keylist* publics,
				 const struct keylist* secrets);

#endif

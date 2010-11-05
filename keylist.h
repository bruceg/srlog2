#ifndef SRLOG2__KEYLIST__H
#define SRLOG2__KEYLIST__H

#include "key.h"

struct str;

#define KEY_TYPE_COUNT 2

struct keylist
{
  struct key keys[KEY_TYPE_COUNT];
};

extern int keylist_set(struct keylist* list, const struct key* key);
extern struct key* keylist_get(struct keylist* list, const struct key_cb* cb);
extern int keylist_load(struct keylist* list, const char* path);
extern int keylist_load_multi(struct keylist* list,
			      const char* prefix,
			      const char* suffix);
extern int keylist_exchange_key_list(struct key* shared,
				     const struct key* public,
				     const struct keylist* secrets);
extern int keylist_exchange_list_key(struct key* shared,
				     const struct keylist* publics,
				     const struct key* secret);
extern int keylist_exchange_all(struct keylist* shareds,
				const struct keylist* publics,
				const struct keylist* secrets);

#endif

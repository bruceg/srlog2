/* $Id$ */
#include <string.h>
#include "keylist.h"

static int keyindex(const char* name)
{
  if (strcmp(name, "nistp224") == 0)
    return 0;
#ifdef HASCURVE25519
  if (strcmp(name, "curve25519") == 0)
    return 1;
#endif
  return -1;
}

int keylist_set(struct keylist* list, const struct key* key)
{
  int i;
  if ((i = keyindex(key->cb->name)) < 0)
    return 0;
  list->keys[i].cb = key->cb;
  memcpy(&list->keys[i], key, sizeof *key);
  return 1;
}
  
struct key* keylist_get(struct keylist* list, const char* type)
{
  int i;
  return ((i = keyindex(type)) < 0)
    ? 0
    : (list->keys[i].cb == 0)
    ? 0
    : &list->keys[i];
}

int keylist_exchange(struct key* shared,
		     const struct key* public,
		     const struct keylist* secrets)
{
  int i;
  return ((i = keyindex(public->cb->name)) < 0)
    ? 0
    : (secrets->keys[i].cb == 0)
    ? 0
    : public->cb->exchange(shared, public, &secrets->keys[i]);
}

int keylist_exchange_list(struct keylist* shareds,
			  const struct keylist* publics,
			  const struct keylist* secrets)
{
  int count;
  int i;
  for (count = i = 0; i < KEY_TYPE_COUNT; ++i) {
    const struct key_cb* cb = publics->keys[i].cb;
    if (cb != 0 && secrets->keys[i].cb == cb)
      count += cb->exchange(&shareds->keys[i],
			    &publics->keys[i], &secrets->keys[i]);
    else
      shareds->keys[i].cb = 0;
  }
  return count;
}

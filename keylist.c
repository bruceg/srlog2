#include <string.h>
#include "keylist.h"

static int keyindex(const char* name)
{
  if (strcasecmp(name, nistp224_cb.name) == 0)
    return 0;
  if (strcasecmp(name, curve25519_cb.name) == 0)
    return 1;
  return -1;
}

int keylist_set(struct keylist* list, const struct key* key)
{
  int i;
  if ((i = keyindex(key->cb->name)) < 0)
    return 0;
  list->keys[i] = *key;
  return 1;
}
  
struct key* keylist_get(struct keylist* list, const struct key_cb* cb)
{
  int i;
  for (i = 0; i < KEY_TYPE_COUNT; ++i)
    if (list->keys[i].cb == cb)
      return &list->keys[i];
  return 0;
}

int keylist_exchange_key_list(struct key* shared,
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

int keylist_exchange_list_key(struct key* shared,
			      const struct keylist* publics,
			      const struct key* secret)
{
  int i;
  return ((i = keyindex(secret->cb->name)) < 0)
    ? 0
    : (publics->keys[i].cb == 0)
    ? 0
    : secret->cb->exchange(shared, &publics->keys[i], secret);
}

int keylist_exchange_all(struct keylist* shareds,
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

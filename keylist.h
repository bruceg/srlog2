#ifndef SRLOG2__KEYLIST__H
#define SRLOG2__KEYLIST__H

#include "key.h"

#ifdef HASCURVE25519
#define KEY_TYPE_COUNT 2
#else
#define KEY_TYPE_COUNT 1
#endif

struct keylist
{
  struct key keys[KEY_TYPE_COUNT];
};

extern int keylist_set(struct keylist* list, const struct key* key);
extern struct key* keylist_get(struct keylist* list, const char* type);

#endif

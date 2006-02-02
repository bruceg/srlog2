#ifndef SRLOG__KEY__H__
#define SRLOG__KEY__H__

#include <nistp224.h>

#define KEYEXCHANGE_NAME "nistp224"

#define KEY_LENGTH 28
struct key
{
  unsigned char data[KEY_LENGTH];
};

extern int key_load(struct key* key, const char* filename);
extern void key_generate(struct key* secret, struct key* public);
#define key_exchange(SHARED,PUBLIC,SECRET) \
	nistp224((SHARED)->data, (PUBLIC)->data, (SECRET)->data)

#endif

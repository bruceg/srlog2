#ifndef SRLOG__KEY__H__
#define SRLOG__KEY__H__

#include <nistp224.h>

#define KEY_LENGTH 28
typedef unsigned char nistp224key[KEY_LENGTH];

extern int load_key(const char* filename, nistp224key key);
extern void brandom_key(nistp224key secret, nistp224key public);

#endif

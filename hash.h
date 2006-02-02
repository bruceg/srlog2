#ifndef SRLOG__HASH__H__
#define SRLOG__HASH__H__

#include "key.h"

#define HASH_LENGTH 16
typedef struct { nistp224key secret; } HASH_CTX;

#define AUTHENTICATOR_NAME "HMAC-MD5"

extern void hash_start(HASH_CTX* ctx, const nistp224key key);
extern void hash_finish(const HASH_CTX* ctx, const void* data, long len,
			unsigned char digest[HASH_LENGTH]);

#endif

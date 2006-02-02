#ifndef SRLOG__AUTH__H__
#define SRLOG__AUTH__H__

#include "key.h"

#define AUTH_LENGTH 16
typedef struct { nistp224key secret; } AUTH_CTX;

#define AUTHENTICATOR_NAME "HMAC-MD5"

extern void auth_start(AUTH_CTX* ctx, const nistp224key key);
extern void auth_finish(const AUTH_CTX* ctx, const void* data, long len,
			unsigned char digest[AUTH_LENGTH]);

#endif

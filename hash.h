#ifndef SRLOG__HASH__H__
#define SRLOG__HASH__H__

#include <crypto/md5.h>
#define HASH_LENGTH 16
typedef struct md5_ctx HASH_CTX;

#include "key.h"

extern void hash_start(HASH_CTX* ctx, const nistp224key key);
extern void hash_finish(const HASH_CTX* ctx, const void* data, long len,
			unsigned char digest[HASH_LENGTH]);

#endif

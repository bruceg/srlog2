/* $Id$ */
#include "encr.h"
#include <crypto/sha512.h>

#define KEYSIZE 64
typedef uint8 keydata[KEYSIZE];

static void make_key(const char* data, unsigned datalen, keydata key)
{
  struct SHA512_ctx ctx;
  SHA512_init(&ctx);
  SHA512_update(&ctx, data, datalen);
  SHA512_final(&ctx, key);
}

void decr_init(DECR_CTX* context, const char* data, unsigned datalen)
{
  keydata key;
  make_key(data, datalen, key);
  rijndael_init(context, RIJNDAEL_DECRYPT, 32, key, RIJNDAEL_CBC, 0);
}

void encr_init(DECR_CTX* context, const char* data, unsigned datalen)
{
  keydata key;
  make_key(data, datalen, key);
  rijndael_init(context, RIJNDAEL_ENCRYPT, 32, key, RIJNDAEL_CBC, 0);
}

#if 0
void decr_blocks(DECR_CTX* context, char* data, unsigned len)
{
  rijndael_decrypt_blocks(context, data, len, data);
}

void encr_blocks(ENCR_CTX* context, char* data, unsigned len)
{
  rijndael_encrypt_blocks(context, data, len, data);
}
#endif

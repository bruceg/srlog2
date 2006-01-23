/* $Id$ */
#include "encr.h"

void decr_init(DECR_CTX* context, const char* key, unsigned keylen)
{
  keylen -= keylen % 8;
  rijndael_init(context, RIJNDAEL_DECRYPT, keylen, key, RIJNDAEL_CBC, 0);
}

void encr_init(DECR_CTX* context, const char* key, unsigned keylen)
{
  keylen -= keylen % 8;
  rijndael_init(context, RIJNDAEL_ENCRYPT, keylen, key, RIJNDAEL_CBC, 0);
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

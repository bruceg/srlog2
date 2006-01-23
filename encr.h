#ifndef SRLOG__ENCR__H__
#define SRLOG__ENCR__H__

#include "rijndael/rijndael.h"

typedef rijndael_cipher ENCR_CTX;
typedef rijndael_cipher DECR_CTX;

#define ENCR_BLOCK_SIZE 16

#define PADLEN(BYTES) (ENCR_BLOCK_SIZE - ((BYTES) % ENCR_BLOCK_SIZE))

extern void decr_init(DECR_CTX* context, const char* key, unsigned keylen);
extern void encr_init(DECR_CTX* context, const char* key, unsigned keylen);

#define decr_blocks(C,D,L) rijndael_decrypt_blocks(C,D,L,D)
#define encr_blocks(C,D,L) rijndael_encrypt_blocks(C,D,L,D)

#endif

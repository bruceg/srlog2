#ifndef SRLOG__ENCR__H__
#define SRLOG__ENCR__H__

#include "rijndael/rijndael.h"

typedef rijndael_cipher ENCR_CTX;
typedef rijndael_cipher DECR_CTX;

#define ENCR_BLOCK_SIZE 16

#define PADLEN(BYTES) (ENCR_BLOCK_SIZE - ((BYTES) % ENCR_BLOCK_SIZE))

extern void decr_init(DECR_CTX* context, const char* data, unsigned datalen);
extern void encr_init(DECR_CTX* context, const char* data, unsigned datalen);
extern void decr_blocks(DECR_CTX* context, char* data, unsigned len);
extern void encr_blocks(ENCR_CTX* context, char* data, unsigned len);

#endif

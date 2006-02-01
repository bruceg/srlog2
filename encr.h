#ifndef SRLOG__ENCR__H__
#define SRLOG__ENCR__H__

#include "rijndael/rijndael.h"

#define KEYHASH_NAME "SHA-512"
#define ENCRYPTOR_NAME "AES256-CBC-ESSIV"

struct ENCR_CTX
{
  rijndael_cipher encr;
  rijndael_cipher ivencr;
};
typedef struct ENCR_CTX ENCR_CTX;

struct DECR_CTX
{
  rijndael_cipher decr;
  rijndael_cipher ivencr;
};
typedef struct DECR_CTX DECR_CTX;

#define ENCR_BLOCK_SIZE 16

#define PADLEN(BYTES) (ENCR_BLOCK_SIZE - ((BYTES) % ENCR_BLOCK_SIZE))

extern void decr_init(DECR_CTX* context, const char* data, unsigned datalen);
extern void encr_init(ENCR_CTX* context, const char* data, unsigned datalen);
extern void decr_blocks(DECR_CTX* context, char* data, unsigned len,
			uint64 sequence);
extern void encr_blocks(ENCR_CTX* context, char* data, unsigned len,
			uint64 sequence);

#endif

#ifndef SRLOG__ENCR__H__
#define SRLOG__ENCR__H__

#include <tomcrypt.h>

#define KEYHASH_NAME "SHA512"
#define ENCRYPTOR_NAME "AES256-CBC-ESSIV"

struct key;

struct ENCR_CTX
{
  symmetric_CBC encr;
  symmetric_ECB ivencr;
};
typedef struct ENCR_CTX ENCR_CTX;
typedef struct ENCR_CTX DECR_CTX;

#define ENCR_BLOCK_SIZE 16

#define PADLEN(BYTES) (ENCR_BLOCK_SIZE - ((BYTES) % ENCR_BLOCK_SIZE))

extern void encr_start(void);
extern void encr_init(ENCR_CTX* context, struct key* key);
#define decr_init(C,K) encr_init(C,K)
extern void decr_blocks(DECR_CTX* context, char* data, unsigned len,
			uint64 sequence);
extern void encr_blocks(ENCR_CTX* context, char* data, unsigned len,
			uint64 sequence);

#endif

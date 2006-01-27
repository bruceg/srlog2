/* $Id$ */
#include "encr.h"
#include <crypto/sha512.h>
#include <uint64.h>
#include <string.h>

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
  rijndael_init(&context->decr, RIJNDAEL_DECRYPT, 32, key, RIJNDAEL_CBC, 0);
  make_key(key, sizeof key, key);
  rijndael_init(&context->ivencr, RIJNDAEL_ENCRYPT, 32, key, RIJNDAEL_ECB, 0);
}

void encr_init(ENCR_CTX* context, const char* data, unsigned datalen)
{
  keydata key;
  make_key(data, datalen, key);
  rijndael_init(&context->encr, RIJNDAEL_ENCRYPT, 32, key, RIJNDAEL_CBC, 0);
  make_key(key, sizeof key, key);
  rijndael_init(&context->ivencr, RIJNDAEL_ENCRYPT, 32, key, RIJNDAEL_ECB, 0);
}

static void setiv(uint8 IV[MAX_IV_SIZE], rijndael_cipher* encryptor,
		  uint64 sequence)
{
  unsigned char block[ENCR_BLOCK_SIZE];
  uint64_pack_lsb(sequence, block);
  memset(block + 8, 0, sizeof block - 8);
  rijndael_encrypt_blocks(encryptor, block, sizeof block, block);
  memcpy(IV, block, MAX_IV_SIZE);
}

void decr_blocks(DECR_CTX* context, char* data, unsigned len, uint64 sequence)
{
  rijndael_cipher copy = context->decr;
  setiv(copy.IV, &context->ivencr, sequence);
  rijndael_decrypt_blocks(&copy, data, len, data);
}

void encr_blocks(ENCR_CTX* context, char* data, unsigned len, uint64 sequence)
{
  rijndael_cipher copy = context->encr;
  setiv(copy.IV, &context->ivencr, sequence);
  rijndael_encrypt_blocks(&copy, data, len, data);
}

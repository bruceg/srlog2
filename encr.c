#include <crypto/sha256.h>
#include <uint64.h>
#include <string.h>

#include <msg/msg.h>

#include "encr.h"
#include "key.h"

#define KEYSIZE 32
typedef uint8 keydata[KEYSIZE];
static int aes = -1;

void encr_start(void)
{
  if ((aes = register_cipher(&aes_desc)) < 0)
    die1(1, "Could not register AES encryption");
}

static void make_key(const unsigned char* data, unsigned datalen, keydata key)
{
  SHA256_ctx ctx;
  SHA256_init(&ctx);
  SHA256_update(&ctx, data, datalen);
  SHA256_final(&ctx, key);
}

void encr_init(ENCR_CTX* context, struct key* key)
{
  uint8 IV[ENCR_BLOCK_SIZE];	/* The value is not actually used here. */
  keydata dkey;
  make_key(key->data, key->cb->size, dkey);
  cbc_start(aes, IV, dkey, 16, 0, &context->encr);
  make_key(dkey, sizeof dkey, dkey);
  ecb_start(aes, dkey, 16, 0, &context->ivencr);
}

static void setiv(ENCR_CTX* context, uint64 sequence)
{
  uint8 IV[ENCR_BLOCK_SIZE];
  uint64_pack_lsb(sequence, IV);
  memset(IV + 8, 0, sizeof IV - 8);
  ecb_encrypt(IV, IV, sizeof IV, &context->ivencr);
  cbc_setiv(IV, sizeof IV, &context->encr);
}

void decr_blocks(DECR_CTX* context, unsigned char* data, unsigned len,
		 uint64 sequence)
{
  setiv(context, sequence);
  cbc_encrypt(data, data, len, &context->encr);
}

void encr_blocks(ENCR_CTX* context, unsigned char* data, unsigned len,
		 uint64 sequence)
{
  setiv(context, sequence);
  cbc_decrypt(data, data, len, &context->encr);
}

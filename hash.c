/* $Id$ */
#include <string.h>
#include <crypto/hmac.h>
#include <crypto/md5.h>
#include <str/str.h>
#include "hash.h"

void hash_start(HASH_CTX* ctx, const nistp224key key)
{
  memcpy(ctx->secret, key, sizeof key);
}

void hash_finish(const HASH_CTX* ctx, const void* data, long len,
		 unsigned char digest[HASH_LENGTH])
{
  const str secret = { (char*)ctx->secret, sizeof *ctx, 0 };
  const str nonce = { (char*)data, len, 0 };
  hmac(&hmac_md5, &secret, &nonce, digest);
}

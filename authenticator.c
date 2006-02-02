/* $Id$ */
#include <string.h>
#include <crypto/hmac.h>
#include <crypto/md5.h>
#include <str/str.h>
#include "authenticator.h"

void auth_start(AUTH_CTX* ctx, const nistp224key key)
{
  memcpy(ctx->secret, key, sizeof key);
}

void auth_finish(const AUTH_CTX* ctx, const void* data, long len,
		 unsigned char digest[AUTH_LENGTH])
{
  const str secret = { (char*)ctx->secret, sizeof *ctx, 0 };
  const str nonce = { (char*)data, len, 0 };
  hmac(&hmac_md5, &secret, &nonce, digest);
}

#include <string.h>
#include <bglibs/hmac.h>
#include <bglibs/md5.h>
#include <bglibs/str.h>
#include "authenticator.h"

void auth_start(AUTH_CTX* ctx, const struct key* key)
{
  const str secret = { (char*)key->data, key->cb->size, 0 };
  hmac_prepare(&hmac_md5, ctx->context, &secret);
}

void auth_finish(const AUTH_CTX* ctx, const void* data, long len,
		 unsigned char digest[AUTH_LENGTH])
{
  const str nonce = { (char*)data, len, 0 };
  hmac_finish(&hmac_md5, ctx->context, &nonce, digest);
}

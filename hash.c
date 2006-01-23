/* $Id$ */
#include <string.h>
#include "hash.h"

void hash_start(struct md5_ctx* ctx, const nistp224key key)
{
  md5_init_ctx(ctx);
  md5_process_bytes(key, KEY_LENGTH, ctx);
}

void hash_finish(const struct md5_ctx* ctx, const void* data, long len,
		 unsigned char digest[HASH_LENGTH])
{
  static struct md5_ctx copy;
  memcpy(&copy, ctx, sizeof copy);
  md5_process_bytes(data, len, &copy);
  md5_finish_ctx(&copy, digest);
}

/* $Id$ */
#include <string.h>
#include <base64/base64.h>
#include <iobuf/ibuf.h>
#include <msg/wrap.h>
#include <str/str.h>
#include <str/iter.h>

#include "keylist.h"

int keylist_import_line(struct keylist* list,
			const char* line, unsigned long len)
{
  int i;
  int prefix;
  str tmp = {0,0,0};
  const struct key_cb* cb;
  if (memcmp(line, "nistp224:", 9) == 0)
    i = 0, prefix = 9, cb = &nistp224_cb;
#ifdef HASCURVE25519
  else if (memcmp(line, "curve25519:", 11) == 0)
    i = 1, prefix = 11, cb = &curve25519_cb;
#endif
  else
    return 0;
  line += prefix;
  len -= prefix;
  if (base64_decode_line(line, &tmp)
      && tmp.len == cb->size) {
    list->keys[i].cb = cb;
    memcpy(list->keys[i].data, tmp.s, tmp.len);
    str_free(&tmp);
    return 1;
  }
  str_free(&tmp);
  return 0;
}

int keylist_import(struct keylist* list, const struct str* text)
{
  striter i;
  striter_loop(&i, text, '\n') {
    if (!keylist_import_line(list, i.startptr, i.len))
      return 0;
  }
  return 1;
}

int keylist_load(struct keylist* list, const char* path)
{
  str buf = {0,0,0};
  int result;
  switch (ibuf_openreadclose(path, &buf)) {
  case 0:
  case -1:
    return 0;
  default:
    result = keylist_import(list, &buf);
  }
  str_free(&buf);
  return result;
}

int keylist_load_multi(struct keylist* list,
		       const char* prefix,
		       const char* suffix)
{
  str path = {0,0,0};
  int result = 0;
  if (suffix == 0)
    suffix = "";
  wrap_str(str_copy3s(&path, prefix, nistp224_cb.name, suffix));
  result += keylist_load(list, path.s);
#ifdef HASCURVE25519
  wrap_str(str_copy3s(&path, prefix, curve25519_cb.name, suffix));
  result += keylist_load(list, path.s);
#endif
  str_free(&path);
  return result;
}

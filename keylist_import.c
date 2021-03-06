#include <string.h>
#include <bglibs/base64.h>
#include <bglibs/ibuf.h>
#include <bglibs/msg.h>
#include <bglibs/wrap.h>
#include <bglibs/str.h>
#include <bglibs/striter.h>

#include "keylist.h"

static int keylist_import_line(struct keylist* list,
			       const char* line, unsigned long len)
{
  int i;
  int prefix;
  str tmp = {0,0,0};
  const struct key_cb* cb;
  if (memcmp(line, "nistp224:", 9) == 0)
    i = 0, prefix = 9, cb = &nistp224_cb;
  else if (memcmp(line, "curve25519:", 11) == 0)
    i = 1, prefix = 11, cb = &curve25519_cb;
  else {
    warn1("Unknown key type in keylist");
    return 1;
  }
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

static int keylist_import(struct keylist* list, const struct str* text)
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
  wrap_str(str_copy3s(&path, prefix, curve25519_cb.name, suffix));
  result += keylist_load(list, path.s);
  str_free(&path);
  return result;
}

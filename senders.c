/* $Id$ */
#include <sysdeps.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <adt/ghash.h>
#include <base64/base64.h>
#include <crc/crc32.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <msg/wrap.h>
#include <fmt/number.h>

#include "srlog2.h"
#include "srlog2d.h"
#include "srlog2d-cli.h"

struct ghash senders = {0,0,0,0,0,0,0,0,0,0,0};

static str tmp;

static uint32 sender_hash(str const* key)
{
  return crc32_block(key->s, key->len);
}

static int sender_datacopy(struct sender_data* a,
			   struct sender_data const* b)
{
  *a = *b;
  return 1;
}

GHASH_DEFN(senders, str, struct sender_data,
	   sender_hash, str_diff,
	   str_copy, sender_datacopy,
	   str_free, 0);

/* ------------------------------------------------------------------------- */
static struct senders_entry* add_sender(const char* sender)
{
  str k;
  struct sender_data d;
  struct senders_entry* s;
  
  memset(&k, 0, sizeof k);
  memset(&d, 0, sizeof d);
  wrap_str(str_copys(&k, sender));
  if ((s = senders_get(&senders, &k)) == 0) {
    wrap_alloc(s = senders_add(&senders, &k, &d));
    msgf("{Added sender: }s", sender);
  }
  return s;
}

static void update_sender(struct senders_entry* s, const struct key* key)
{
  const struct key* old;
  if ((old = keylist_get(&s->data.keys, key->cb)) == 0
      || memcmp(old->data, key->data, key->cb->size) != 0) {
    keylist_set(&s->data.keys, key);
    msgf("{Updated sender key: }s{ (}s{)}",
	 s->key.s, key->cb->name);
  }
}

static void parse_sender_line(void)
{
  int i;
  int j;
  struct key tmpkey;
  const struct key_cb* cb;
  struct senders_entry* s;

  tmp.len = 0;
  if ((i = str_findfirst(&line, ':')) == -1
      || (j = str_findnext(&line, ':', i+1)) == -1
      || !base64_decode_line(line.s + j+1, &tmp))
    warnf("{Invalid senders line, ignoring: }s", line.s);
  else {
    line.s[i++] = 0;
    line.s[j++] = 0;
    if ((cb = key_cb_lookup(line.s + i)) == 0)
      warnf("{Invalid key type, ignoring: }s", line.s);
    else if (tmp.len != cb->size)
      warnf("{Invalid key size, ignoring: }s", line.s);
    else if (keylist_get(&server_secrets, cb) == 0)
      warnf("{Key type does not match any server keys, ignoring: }s", line.s);
    else {
      s = add_sender(line.s);
      memset(&tmpkey, 0, sizeof tmpkey);
      tmpkey.cb = cb;
      memcpy(tmpkey.data, tmp.s, tmp.len);
      update_sender(s, &tmpkey);
    }
  }
}

static void read_senders(void)
{
  ibuf in;
  if (!ibuf_open(&in, opt_senders, 0))
    warnfsys("{Could not open '}s{', skipping}", opt_senders);
  else {
    while (ibuf_getstr(&in, &line, LF)) {
      str_strip(&line);
      if (line.len == 0 || line.s[0] == '#') continue;
      parse_sender_line();
    }
    ibuf_close(&in);
  }
}

void load_senders(int reload)
{
  if (reload)
    msg1("Reloading new senders");
  else {
    connections_init(&connections);
    senders_init(&senders);
    msg1("Loading senders");
  }
  read_senders();
}

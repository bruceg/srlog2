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

struct ghash senders = {0,0,0,0,0,0,0,0,0,0,0};

static str tmp;

static uint32 sender_hash(struct sender_key const* key)
{
  uint32 crc = crc32_update(CRC32INIT, key->sender.s, key->sender.len);
  return crc32_update(crc, key->service.s, key->service.len) & CRC32POST;
}

static int sender_cmp(struct sender_key const* a, struct sender_key const* b)
{ 
  int i;
  if ((i = str_diff(&a->sender, &b->sender)) == 0)
    i = str_diff(&a->service, &b->service);
  return i;
}

static int sender_keycopy(struct sender_key* a, struct sender_key const* b)
{
  *a = *b;
  return 1;
}

static int sender_datacopy(struct sender_data* a, struct sender_data const* b)
{
  *a = *b;
  return 1;
}

static void sender_keyfree(struct sender_key* addr)
{
  str_free(&addr->sender);
  str_free(&addr->service);
}

GHASH_DEFN(senders, struct sender_key, struct sender_data,
	   sender_hash, sender_cmp,
	   sender_keycopy, sender_datacopy, sender_keyfree, 0);

/* ------------------------------------------------------------------------- */
const char* format_sender(const struct senders_entry* c)
{
  if (!str_copy(&tmp, &c->key.sender)) return 0;
  if (!str_catc(&tmp, '/')) return 0;
  if (!str_cat(&tmp, &c->key.service)) return 0;
  if (!str_cats(&tmp, ": ")) return 0;
  return tmp.s;
}

/* ------------------------------------------------------------------------- */
struct senders_entry* find_sender(const char* sender, const char* service)
{
  static struct sender_key key;
  wrap_str(str_copys(&key.sender, sender));
  wrap_str(str_copys(&key.service, service));
  return senders_get(&senders, &key);
}

/* ------------------------------------------------------------------------- */
static struct senders_entry* add_sender(const char* sender,
					const char* service)
{
  struct sender_key a;
  struct sender_data d;
  struct senders_entry* s;
  
  memset(&a, 0, sizeof a);
  memset(&d, 0, sizeof d);
  wrap_str(str_copys(&a.sender, sender));
  wrap_str(str_copys(&a.service, service));
  if ((s = senders_get(&senders, &a)) == 0) {
    if (!senders_add(&senders, &a, &d))
      die_oom(1);
    s = senders_get(&senders, &a);
    msgf("{Added sender: }s{/}s", sender, service);
  }
  return s;
}

static void update_sender(struct senders_entry* s, const struct key* key)
{
  const struct key* old;
  if ((old = keylist_get(&s->data.keys, key->cb)) == 0
      || memcmp(old->data, key->data, key->cb->size) != 0) {
    keylist_set(&s->data.keys, key);
    msgf("{Updated sender key: }s{/}s{ (}s{)}",
	 s->key.sender.s, s->key.service.s, key->cb->name);
  }
}

static void parse_sender_line(void)
{
  int i;
  int j;
  int k;
  struct key tmpkey;
  const struct key_cb* cb;
  struct senders_entry* s;

  tmp.len = 0;
  if ((i = str_findfirst(&line, ':')) == -1
      || (j = str_findnext(&line, ':', i+1)) == -1
      || (k = str_findnext(&line, ':', j+1)) == -1
      || !base64_decode_line(line.s + k+1, &tmp))
    warnf("{Invalid senders line, ignoring: }s", line.s);
  else {
    line.s[i++] = 0;
    line.s[j++] = 0;
    line.s[k++] = 0;
    if ((cb = key_cb_lookup(line.s + j)) == 0)
      warnf("{Invalid key type, ignoring: }s", line.s);
    else if (tmp.len != cb->size)
      warnf("{Invalid key size, ignoring: }s", line.s);
    else if (keylist_get(&server_secrets, cb) == 0)
      warnf("{Key type does not match any server keys, ignoring: }s", line.s);
    else {
      s = add_sender(line.s, line.s + i);
      memset(&tmpkey, 0, sizeof tmpkey);
      tmpkey.cb = cb;
      memcpy(tmpkey.data, tmp.s, tmp.len);
      update_sender(s, &tmpkey);
    }
  }
}

static void read_senders(const char* filename)
{
  ibuf in;
  if (!ibuf_open(&in, filename, 0))
    die3sys(1, "Could not open '", filename, "'");
  while (ibuf_getstr(&in, &line, LF)) {
    str_strip(&line);
    if (line.len == 0 || line.s[0] == '#') continue;
    parse_sender_line();
  }
  ibuf_close(&in);
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
  read_senders("senders");
}

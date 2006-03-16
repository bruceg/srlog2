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

struct ghash services = {0,0,0,0,0,0,0,0,0,0,0};

static str tmp;

static uint32 service_hash(struct service_key const* key)
{
  uint32 crc = CRC32INIT;
  crc = crc32_update(crc, key->sender.s, key->sender.len);
  crc = crc32_update(crc, "", 1);
  crc = crc32_update(crc, key->service.s, key->service.len);
  return crc ^ CRC32POST;
}

static int service_cmp(struct service_key const* a,
		       struct service_key const* b)
{ 
  int i;
  if ((i = str_diff(&a->sender, &b->sender)) == 0)
    i = str_diff(&a->service, &b->service);
  return i;
}

static int service_keycopy(struct service_key* a,
			   struct service_key const* b)
{
  return str_copy(&a->sender, &b->sender)
    && str_copy(&a->service, &b->service);
}

static int service_datacopy(struct service_data* a,
			    struct service_data const* b)
{
  *a = *b;
  return 1;
}

static void service_keyfree(struct service_key* addr)
{
  str_free(&addr->sender);
  str_free(&addr->service);
}

GHASH_DEFN(services, struct service_key, struct service_data,
	   service_hash, service_cmp,
	   service_keycopy, service_datacopy,
	   service_keyfree, 0);

/* ------------------------------------------------------------------------- */
const char* format_service(const struct services_entry* c)
{
  if (!str_copy(&tmp, &c->key.sender)) return 0;
  if (!str_catc(&tmp, '/')) return 0;
  if (!str_cat(&tmp, &c->key.service)) return 0;
  if (!str_cats(&tmp, ": ")) return 0;
  return tmp.s;
}

/* ------------------------------------------------------------------------- */
struct services_entry* find_service(const char* sender, const char* service)
{
  static struct service_key key;
  struct services_entry* svc;
  struct senders_entry* snd;

  wrap_str(str_copys(&key.sender, sender));
  str_lower(&key.sender);
  wrap_str(str_copys(&key.service, service));
  if ((svc = services_get(&services, &key)) == 0) {
    /* If a corresponding sender entry can be found,
     * automatically add a service entry. */
    if ((snd = senders_get(&senders, &key.sender)) != 0) {
      struct service_data data;
      memset(&data, 0, sizeof data);
      data.sender = snd;
      wrap_alloc(svc = services_add(&services, &key, &data));
      msgf("{Automatically added service: }s{/}s", sender, service);
    }
  }
  return svc;
}

/* ------------------------------------------------------------------------- */
static struct services_entry* add_service(const char* sender,
					  const char* service)
{
  struct service_key a;
  struct service_data d;
  struct services_entry* s;
  
  memset(&a, 0, sizeof a);
  memset(&d, 0, sizeof d);
  wrap_str(str_copys(&a.sender, sender));
  str_lower(&a.sender);
  wrap_str(str_copys(&a.service, service));
  if ((s = services_get(&services, &a)) == 0) {
    wrap_alloc(s = services_add(&services, &a, &d));
    msgf("{Added service: }s{/}s", sender, service);
  }
  return s;
}

static void update_service(struct services_entry* s, const struct key* key)
{
  const struct key* old;
  if ((old = keylist_get(&s->data.keys, key->cb)) == 0
      || memcmp(old->data, key->data, key->cb->size) != 0) {
    keylist_set(&s->data.keys, key);
    msgf("{Updated service key: }s{/}s{ (}s{)}",
	 s->key.sender.s, s->key.service.s, key->cb->name);
  }
}

static void parse_service_line(void)
{
  int i;
  int j;
  int k;
  struct key tmpkey;
  const struct key_cb* cb;
  struct services_entry* s;

  tmp.len = 0;
  if ((i = str_findfirst(&line, ':')) == -1
      || (j = str_findnext(&line, ':', i+1)) == -1
      || (k = str_findnext(&line, ':', j+1)) == -1
      || !base64_decode_line(line.s + k+1, &tmp))
    warnf("{Invalid services line, ignoring: }s", line.s);
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
      s = add_service(line.s, line.s + i);
      memset(&tmpkey, 0, sizeof tmpkey);
      tmpkey.cb = cb;
      memcpy(tmpkey.data, tmp.s, tmp.len);
      update_service(s, &tmpkey);
    }
  }
}

static void read_services(void)
{
  ibuf in;
  if (!ibuf_open(&in, opt_services, 0))
    warnfsys("{Could not open '}s{', skipping}", opt_services);
  else {
    while (ibuf_getstr(&in, &line, LF)) {
      str_strip(&line);
      if (line.len == 0 || line.s[0] == '#') continue;
      parse_service_line();
    }
    ibuf_close(&in);
  }
}

void load_services(int reload)
{
  if (reload)
    msg1("Reloading new services");
  else {
    connections_init(&connections);
    services_init(&services);
    msg1("Loading services");
  }
  read_services();
}

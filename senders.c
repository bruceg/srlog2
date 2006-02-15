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

static str path;
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
static void add_sender(const char* sender, const char* service, 
		       const struct keylist* keys)
{
  struct sender_key a;
  struct sender_data d;

  msgf("{Loading sender: }s{/}s", sender, service);
  memset(&a, 0, sizeof a);
  memset(&d, 0, sizeof d);
  wrap_str(str_copys(&a.sender, sender));
  wrap_str(str_copys(&a.service, service));
  d.keys = *keys;
  if (!senders_add(&senders, &a, &d)) die_oom(1);
}

static void update_sender(struct senders_entry* s, const struct keylist* keys)
{
  if (memcmp(&s->data.keys, keys, sizeof *keys) != 0) {
    msgf("{Reloading sender: }s{/}s", s->key.sender.s, s->key.service.s);
    s->data.keys = *keys;
  }
}

static struct keylist* loadkeys(const char* host, const char* service,
				struct keylist* keys)
{
  wrap_str(str_copys(&tmp, host));
  if (service != 0)
    wrap_str(str_cat2s(&tmp, "/", service));
  wrap_str(str_cats(&tmp, "/.publics"));
  if (keylist_load(keys, tmp.s)
      && keylist_exchange_all(keys, keys, &server_secrets))
    return keys;
  else if (errno != ENOENT)
    diefsys(1, "{Error opening '}s{'}", tmp.s);
  return 0;
}
    
static void try_load_service(const char* host, const char* service,
			     const struct keylist* keys)
{
  struct stat st;
  struct keylist svckey;
  struct senders_entry* s;

  wrap_str(str_copy3s(&path, host, "/", service));
  if (stat(path.s, &st) != 0)
    warnfsys("{Could not stat '}s{', skipping}", path.s);
  else if (S_ISDIR(st.st_mode)) {
    if (loadkeys(host, service, &svckey))
      keys = &svckey;
    if (keys) {
      if ((s = find_sender(host, service)) == 0)
	add_sender(host, service, keys);
      else
	update_sender(s, keys);
    }
  }
}

static void load_hostdir(const char* hostname)
{
  DIR* dir;
  direntry* entry;
  struct keylist hostkey;
  const struct keylist* hostkeyptr;
  
  if ((dir = opendir(hostname)) == 0)
    warnfsys("{Could not open '}s{', skipping}", hostname);
  else {
    hostkeyptr = loadkeys(hostname, 0, &hostkey);
    while ((entry = readdir(dir)) != 0) {
      const char* service = entry->d_name;
      if (service[0] == '.')
	continue;
      try_load_service(hostname, service, hostkeyptr);
    }
    closedir(dir);
  }
}

static void load_dir(void)
{
  DIR* dir;
  direntry* entry;
  struct stat st;
  if ((dir = opendir(".")) == 0)
    die1sys(1, "Could not open current directory");
  while ((entry = readdir(dir)) != 0) {
    const char* hostname = entry->d_name;
    if (hostname[0] == '.')
      continue;
    if (stat(hostname, &st) != 0)
      warnfsys("{Could not stat '}s{', skipping}", hostname);
    else if (S_ISDIR(st.st_mode))
      load_hostdir(hostname);
  }
  closedir(dir);
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
  load_dir();
}

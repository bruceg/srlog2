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

extern struct key server_secret;

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

static void sender_datafree(struct sender_data* data)
{
  str_free(&data->dir);
}

GHASH_DEFN(senders, struct sender_key, struct sender_data,
	   sender_hash, sender_cmp,
	   sender_keycopy, sender_datacopy, sender_keyfree, sender_datafree);

/* ------------------------------------------------------------------------- */
static const char* format_sender(const struct senders_entry* c)
{
  if (!str_copy(&tmp, &c->key.sender)) return 0;
  if (!str_catc(&tmp, '/')) return 0;
  if (!str_cat(&tmp, &c->key.service)) return 0;
  return tmp.s;
}

void msg_sender(const struct senders_entry* c, const char* a, const char* b)
{
  msg4(format_sender(c), ": ", a, b);
}

void error_sender(const struct senders_entry* c, const char* s)
{
  msg3(format_sender(c), ": Error: ", s);
}

void error_sender3(const struct senders_entry* c, const char* s,
		   uint64 u1, uint64 u2)
{
  char num1[FMT_ULONG_LEN];
  char num2[FMT_ULONG_LEN];
  num1[fmt_ulldec(num1, u1)] = 0;
  num2[fmt_ulldec(num2, u2)] = 0;
  msg6(format_sender(c), ": Error: ", s, num1, " ", num2);
}

void warn_sender(const struct senders_entry* c, const char* s)
{
  msg3(format_sender(c), ": Warning: ", s);
}

void warn_sender3(const struct senders_entry* c, const char* s,
		  uint64 u1, uint64 u2)
{
  char num1[FMT_ULONG_LEN];
  char num2[FMT_ULONG_LEN];
  num1[fmt_ulldec(num1, u1)] = 0;
  num2[fmt_ulldec(num2, u2)] = 0;
  msg6(format_sender(c), ": Warning: ", s, num1, " ", num2);
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
		       const struct key* key, const char* dir)
{
  struct sender_key a;
  struct sender_data d;

  msg2("Loading sender: ", dir);
  memset(&a, 0, sizeof a);
  memset(&d, 0, sizeof d);
  wrap_str(str_copys(&a.sender, sender));
  wrap_str(str_copys(&a.service, service));
  wrap_str(str_copys(&d.dir, dir));
  d.key.cb = key->cb;
  memcpy(d.key.data, key->data, key->cb->size);
  auth_start(&d.ini_authenticator, key);
  if (!senders_add(&senders, &a, &d)) die_oom(1);
}

static void update_sender(struct senders_entry* s, const struct key* key)
{
  if (s->data.key.cb != key->cb
      || memcmp(s->data.key.data, key->data, key->cb->size) != 0) {
    msg2("Reloading sender: ", s->data.dir.s);
    s->data.key.cb = key->cb;
    memcpy(s->data.key.data, key->data, key->cb->size);
    auth_start(&s->data.ini_authenticator, key);
  }
}

static struct key* loadkey(const char* host, const char* service,
			   struct key* key)
{
  ibuf in;
  
  wrap_str(str_copys(&tmp, host));
  if (service != 0)
    wrap_str(str_cat2s(&tmp, "/", service));
  wrap_str(str_cats(&tmp, "/.nistp224.pub"));
  if (ibuf_open(&in, tmp.s, 0)) {
    if (key_load_line(key, &in, &nistp224_cb)) {
      key_exchange(key, key, &server_secret);
      ibuf_close(&in);
      return key;
    }
    ibuf_close(&in);
  }
  else if (errno != ENOENT)
    diefsys(1, "{Error opening '}s{'}", tmp.s);
  return 0;
}
    
static void try_load_service(const char* host, const char* service,
			     const struct key* key)
{
  struct stat st;
  struct key svckey;
  struct senders_entry* s;

  wrap_str(str_copy3s(&path, host, "/", service));
  if (stat(path.s, &st) != 0)
    warnfsys("{Could not stat '}s{', skipping}", path.s);
  else if (S_ISDIR(st.st_mode)) {
    if (loadkey(host, service, &svckey))
      key = &svckey;
    if ((s = find_sender(host, service)) == 0)
      add_sender(host, service, key, path.s);
    else
      update_sender(s, key);
  }
}

static void load_hostdir(const char* hostname)
{
  DIR* dir;
  direntry* entry;
  struct key hostkey;
  const struct key* hostkeyptr;
  
  if ((dir = opendir(hostname)) == 0)
    warnfsys("{Could not open '}s{', skipping}", hostname);
  else {
    hostkeyptr = loadkey(hostname, 0, &hostkey);
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

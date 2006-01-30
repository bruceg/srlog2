/* $Id$ */
#include <string.h>

#include <adt/ghash.h>
#include <base64/base64.h>
#include <crc/crc32.h>
#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <msg/wrap.h>
#include <fmt/number.h>

#include "srlog2.h"

struct ghash senders = {0,0,0,0,0,0,0,0,0,0,0};

static uint32 sender_hash(struct sender_addr const* key)
{
  return crc32_block((const unsigned char*)key, sizeof *key);
}

static int sender_cmp(struct sender_addr const* a, struct sender_addr const* b)
{ 
  return memcmp(a, b, sizeof *a);
}

static int sender_keycopy(struct sender_addr* a, struct sender_addr const* b)
{
  *a = *b;
  return 1;
}

static int sender_datacopy(struct sender_data* a, struct sender_data const* b)
{
  *a = *b;
  return 1;
}

static void sender_datafree(struct sender_data* data)
{
  str_free(&data->service);
  str_free(&data->dir);
}

GHASH_DEFN(senders, struct sender_addr, struct sender_data,
	   sender_hash, sender_cmp,
	   sender_keycopy, sender_datacopy, 0, sender_datafree);

/* ------------------------------------------------------------------------- */
static const char* format_sender(const struct senders_entry* c)
{
  static str s;
  if (!str_copys(&s, ipv4_format(&c->key.ip))) return 0;
  if (!str_catc(&s, '/')) return 0;
  if (!str_catu(&s, c->key.port)) return 0;
  if (!str_catc(&s, '/')) return 0;
  if (!str_cat(&s, &c->data.service)) return 0;
  return s.s;
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
static str line;
static str tmp_sender;
static str tmp_service;
static str tmp;

static inline int ipcmp(const ipv4addr* a, const ipv4addr* b)
{
  return *(uint32*)b - *(uint32*)a;
}

static int is_sender(struct senders_entry const* entry)
{
  return str_diff(&tmp_sender, &entry->data.sender) == 0
    && str_diff(&tmp_service, &entry->data.service) == 0;
}

struct senders_entry* find_sender(const char* sender, const char* service)
{
  wrap_str(str_copys(&tmp_sender, sender));
  wrap_str(str_copys(&tmp_service, service));
  return senders_search(&senders, is_sender);
}

/* ------------------------------------------------------------------------- */
extern nistp224key server_secret;

static void add_sender(const char* sender, const char* service, 
		       nistp224key key, const char* dir)
{
  struct sender_addr a;
  struct sender_data d;

  memset(&a, 0, sizeof a);
  memset(&d, 0, sizeof d);
  wrap_str(str_copys(&d.sender, sender));
  wrap_str(str_copys(&d.service, service));
  wrap_str(str_copys(&d.dir, dir));
  hash_start(&d.ini_authenticator, key);
  d.fd = -1;
  if (!senders_add(&senders, &a, &d)) die_oom(1);
  msg2("Loaded sender: ", dir);
}

static void parse_sender_line(void)
{
  int i;
  int j;
  int k;
  nistp224key tmpkey;
  if ((i = str_findfirst(&line, ':')) == -1 ||
      (j = str_findnext(&line, ':', i+1)) == -1 ||
      (k = str_findnext(&line, ':', j+1)) == -1 ||
      k-j != 41)
    warn3("Invalid senders line: '", line.s, "', ignoring");
  else {
    line.s[i++] = 0;
    line.s[j++] = 0;
    line.s[k++] = 0;
    if (find_sender(line.s, line.s+i))
      return;
    if (!str_truncate(&tmp, 0) ||
        !base64_decode_line(line.s+j, &tmp) ||
        tmp.len != KEY_LENGTH) {
      warn3("Invalid client key '", line.s+j, "', ignoring line");
      return;
    }
    nistp224(tmpkey, tmp.s, server_secret);
    add_sender(line.s, line.s+i, tmpkey, line.s+k);
  }
}

static void read_senders(const char* path)
{
  ibuf in;
  if (!ibuf_open(&in, path, 0))
    die3sys(1, "Could not open '", path, "'");
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
    senders_init(&senders);
    msg1("Loading senders");
  }
  read_senders("senders");
}

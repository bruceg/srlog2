#include <string.h>

#include <bglibs/ghash.h>
#include <bglibs/base64.h>
#include <bglibs/crc32.h>
#include <bglibs/iobuf.h>
#include <bglibs/msg.h>
#include <bglibs/wrap.h>
#include <bglibs/fmt.h>

#include "srlog2.h"
#include "srlog2d.h"

struct ghash connections = {0,0,0,0,0,0,0,0,0,0,0};

static uint32 connection_hash(struct connection_key const* key)
{
  return crc32_block((const char*)key, sizeof *key);
}

static int connection_cmp(struct connection_key const* a,
			  struct connection_key const* b)
{ 
  return memcmp(a, b, sizeof *a);
}

static int connection_keycopy(struct connection_key* a,
			      struct connection_key const* b)
{
  *a = *b;
  return 1;
}

static int connection_datacopy(struct connection_data* a,
			       struct connection_data const* b)
{
  *a = *b;
  return 1;
}

GHASH_DEFN(connections, struct connection_key, struct connection_data,
	   connection_hash, connection_cmp,
	   connection_keycopy, connection_datacopy,
	   0, 0);

/* ------------------------------------------------------------------------- */
const char* format_connection(const struct connections_entry* c)
{
  static str s;
  if (!str_copys(&s, ipv4_format(&c->key.ip))) return 0;
  if (!str_catc(&s, '/')) return 0;
  if (!str_catu(&s, c->key.port)) return 0;
  if (!str_catc(&s, '/')) return 0;
  if (!str_cat(&s, &c->data.service->key.sender)) return 0;
  if (!str_catc(&s, '/')) return 0;
  if (!str_cat(&s, &c->data.service->key.service)) return 0;
  if (!str_cats(&s, ": ")) return 0;
  return s.s;
}

void error_connection(const struct connections_entry* c, const char* s)
{
  msg3(format_connection(c), "Error: ", s);
}

void error_connection3(const struct connections_entry* c, const char* s,
		       uint64 u1, uint64 u2)
{
  char num1[FMT_ULONG_LEN];
  char num2[FMT_ULONG_LEN];
  num1[fmt_ulldec(num1, u1)] = 0;
  num2[fmt_ulldec(num2, u2)] = 0;
  msg6(format_connection(c), "Error: ", s, num1, " ", num2);
}

void warn_connection(const struct connections_entry* c, const char* s)
{
  msg3(format_connection(c), "Warning: ", s);
}

void warn_connection3(const struct connections_entry* c, const char* s,
		      uint64 u1, uint64 u2)
{
  char num1[FMT_ULONG_LEN];
  char num2[FMT_ULONG_LEN];
  num1[fmt_ulldec(num1, u1)] = 0;
  num2[fmt_ulldec(num2, u2)] = 0;
  msg6(format_connection(c), "Warning: ", s, num1, " ", num2);
}

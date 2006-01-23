/* $Id$ */
#include <string.h>

#include <str/str.h>

#include "srlog.h"
#include "hash.h"

static unsigned char digest[HASH_LENGTH];

int pkt_start(str* s, const char type[4])
{
  return str_copyb(s, "SRL2", 4) &&
    str_catb(s, type, 4);
}

int pkt_add_u1(str* s, unsigned u)
{
  if (u > 0xff) return 0;
  return str_catc(s, u & 0xff);
}

int pkt_add_u2(str* s, unsigned u)
{
  char b[2];
  if (u > 0xffff) return 0;
  b[0] = (u >> 8) & 0xff;
  b[1] = u & 0xff;
  return str_catb(s, b, 2);
}

int pkt_add_u4(str* s, uint32 u)
{
  char b[4];
  b[0] = (u >> 24) & 0xff;
  b[1] = (u >> 16) & 0xff;
  b[2] = (u >> 8) & 0xff;
  b[3] = u & 0xff;
  return str_catb(s, b, 4);
}

int pkt_add_u8(str* s, uint64 u)
{
  char b[8];
  b[0] = (u >> 56) & 0xff;
  b[1] = (u >> 48) & 0xff;
  b[2] = (u >> 40) & 0xff;
  b[3] = (u >> 32) & 0xff;
  b[4] = (u >> 24) & 0xff;
  b[5] = (u >> 16) & 0xff;
  b[6] = (u >> 8) & 0xff;
  b[7] = u & 0xff;
  return str_catb(s, b, 8);
}

int pkt_add_ts(str* s, const struct timestamp* ts)
{
  return pkt_add_u4(s, ts->sec) && pkt_add_u4(s, ts->nsec);
}

int pkt_add_s1(str* s, const str* l)
{
  return pkt_add_u1(s, l->len) &&
    str_catb(s, l->s, l->len);
}

int pkt_add_s2(str* s, const str* l)
{
  return pkt_add_u2(s, l->len) &&
    str_catb(s, l->s, l->len);
}

int pkt_add_key(str* s, const nistp224key k)
{
  return str_catb(s, k, KEY_LENGTH);
}

int pkt_add_cc(str* s, const HASH_CTX* ctx)
{
  hash_finish(ctx, s->s, s->len, digest);
  return str_catb(s, digest, HASH_LENGTH);
}

unsigned pkt_get_u1(const str* s, unsigned o, unsigned* u)
{
  if (o >= s->len) return 0;
  *u = (unsigned char)(s->s[o]);
  return o + 1;
}

unsigned pkt_get_u2(const str* s, unsigned o, unsigned* u)
{
  const unsigned char* p = s->s + o;
  o += 2;
  if (o > s->len) return 0;
  *u = p[0] << 8 | p[1];
  return o;
}

unsigned pkt_get_u4(const str* s, unsigned o, uint32* u)
{
  const unsigned char* p = s->s + o;
  o += 4;
  if (o > s->len) return 0;
  *u = (uint32)p[0] << 24 |
    (uint32)p[1] << 16 |
    (uint32)p[2] << 8 |
    (uint32)p[3];
  return o;
}

unsigned pkt_get_u8(const str* s, unsigned o, uint64* u)
{
  const unsigned char* p = s->s + o;
  o += 8;
  if (o > s->len) return 0;
  *u = (uint64)p[0] << 56 |
    (uint64)p[1] << 48 |
    (uint64)p[2] << 40 |
    (uint64)p[3] << 32 |
    (uint64)p[4] << 24 |
    (uint64)p[5] << 16 |
    (uint64)p[6] << 8 |
    (uint64)p[7];
  return o;
}

unsigned pkt_get_ts(const str* s, unsigned o, struct timestamp* ts)
{
  if ((o = pkt_get_u4(s, o, &ts->sec)) == 0) return 0;
  return pkt_get_u4(s, o, &ts->nsec);
}

unsigned pkt_get_b(const str* s, unsigned o, str* l, unsigned len)
{
  const char* p = s->s + o;
  o += len;
  if (o > s->len) return 0;
  if (!str_copyb(l, p, len)) return 0;
  return o;
}

unsigned pkt_get_s1(const str* s, unsigned o, str* l)
{
  unsigned len;
  if ((o = pkt_get_u1(s, o, &len)) == 0) return 0;
  return pkt_get_b(s, o, l, len);
}

unsigned pkt_get_s2(const str* s, unsigned o, str* l)
{
  unsigned len;
  if ((o = pkt_get_u2(s, o, &len)) == 0) return 0;
  return pkt_get_b(s, o, l, len);
}

unsigned pkt_get_key(const str* s, unsigned o, nistp224key k)
{
  const char* p = s->s + o;
  o += KEY_LENGTH;
  if (o > s->len) return 0;
  memcpy(k, p, KEY_LENGTH);
  return o;
}

int pkt_validate(str* s, const HASH_CTX* ctx)
{
  long slen = s->len - HASH_LENGTH;
  if (slen > 0) {
    hash_finish(ctx, s->s, slen, digest);
    if (memcmp(digest, s->s+slen, HASH_LENGTH) == 0) {
      s->len = slen;
      return 1;
    }
  }
  return 0;
}

#include <string.h>

#include <crc/crc32.h>
#include "srlog.h"

struct ghash addrname = {0,0,0,0,0,0,0,0,0,0,0};

static uint32 ipv4addr_hash(ipv4addr const* key)
{
  return crc32_block((const unsigned char*)key, sizeof *key);
}

static uint32 ipv4addr_cmp(ipv4addr const* a, ipv4addr const* b)
{
  return memcmp(a, b, sizeof *a);
}

static int ipv4addr_copy(ipv4addr* a, ipv4addr const* b)
{
  *a = *b;
  return 1;
}

static int charptr_copy(const char** a, const char* const* b)
{
  return (*a = strdup(*b)) != 0;
}

static void charptr_free(const char** a)
{
  free((char*)*a);
}

GHASH_DEFN(addrname, ipv4addr, const char*,
	   ipv4addr_hash, ipv4addr_cmp, ipv4addr_copy,
	   charptr_copy, 0, charptr_free);

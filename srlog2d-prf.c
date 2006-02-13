/* $Id$ */
#include <string.h>

#include <misc/misc.h>
#include <msg/msg.h>
#include <net/resolve.h>
#include <str/iter.h>

#include "srlog2.h"
#include "srlog2d.h"
#include "srlog2d-cli.h"

static int contains(const str* s, const char* key)
{
  striter i;
  striter_loop(&i, s, 0) {
    if (strcasecmp(i.startptr, key) == 0)
      return 1;
  }
  return 0;
}

static void send_prf(const char nonce[8])
{
  pkt_add_u4(&packet, SRL2);
  pkt_add_u4(&packet, PRF1);
  pkt_add_b(&packet, nonce, 8);
  pkt_add_s1c(&packet, AUTHENTICATOR_NAME);
#ifdef HASCURVE25519
  if (contains(&keyex_name, curve25519_cb.name))
    pkt_add_s1c(&packet, curve25519_cb.name);
  else
#endif
    pkt_add_s1c(&packet, nistp224_cb.name);
  pkt_add_s1c(&packet, KEYHASH_NAME);
  pkt_add_s1c(&packet, ENCRYPTOR_NAME);
  pkt_add_s1c(&packet, "null");
  send_packet();
}

void handle_prq(void)
{
  unsigned offset;
  if (pkt_get_b(&packet, 8, &line, 8) == 0
      || (offset = pkt_get_s1(&packet, 16, &auth_name)) == 0
      || (offset = pkt_get_s1(&packet, offset, &keyex_name)) == 0
      || (offset = pkt_get_s1(&packet, offset, &keyhash_name)) == 0
      || (offset = pkt_get_s1(&packet, offset, &encr_name)) == 0
      || (offset = pkt_get_s1(&packet, offset, &compr_name)) == 0)
    msg4(ipv4_format(&ip), "/", utoa(port),
	 ": Warning: PRQ packet is missing elements");
  else
    send_prf(line.s);
}

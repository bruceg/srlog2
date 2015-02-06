#include <string.h>

#include <bglibs/msg.h>
#include <bglibs/resolve.h>
#include <bglibs/striter.h>

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

static void send_prf(const unsigned char nonce[8])
{
  pkt_start(&packet, PRF1);
  pkt_add_b(&packet, nonce, 8);
  pkt_add_s1c(&packet, AUTHENTICATOR_NAME);
  if (contains(&keyex_name, curve25519_cb.name))
    pkt_add_s1c(&packet, curve25519_cb.name);
  else
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
    msgpkt2("Warning: PRQ packet is missing elements");
  else
    send_prf((unsigned char*)line.s);
}

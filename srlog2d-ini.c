/* $Id$ */
#include <sys/types.h>
#include <string.h>

#include <systime.h>
#include <adt/ghash.h>
#include <msg/msg.h>
#include <msg/wrap.h>

#include "srlog2.h"
#include "srlog2d.h"
#include "srlog2d-cli.h"

/* Time in seconds to pause between accepting INIs */
static double ini_throttle = 1.0 / 64;

static str sender;

static void send_cid(struct connections_entry* c, struct key* sp)
{
  pkt_start(&packet, CID1);
  pkt_add_key(&packet, sp);
  pkt_add_cc(&packet, &c->data.authenticator);
  send_packet();
}

static struct timeval last_ini;

void handle_ini(void)
{
  struct timeval now;
  unsigned offset;
  uint64 seq;
  struct timestamp ts;
  struct services_entry* s;
  struct connections_entry* ce;
  struct key csession_public;
  struct key ssession_public;
  struct key ssession_secret;
  struct key tmpkey;
  const struct key* key;
  const struct key_cb* cb;
  AUTH_CTX authenticator;
  unsigned i;

  if (recv(sock, &i, 4, MSG_PEEK|MSG_DONTWAIT) != -1 &&
      i != 0xffffffffUL) {
    msgpkt2("Warning: INI throttled: queued packets");
    ++ini_queued;
    return;
  }
  gettimeofday(&now, 0);
  if (((now.tv_sec - last_ini.tv_sec) +
       (now.tv_usec - last_ini.tv_usec) / 1000000.0) < ini_throttle) {
    msgpkt2("Warning: INI throttled: too many");
    ++ini_too_many;
    return;
  }

  if ((offset = pkt_get_u8(&packet, 8, &seq)) == 0 ||
      (offset = pkt_get_ts(&packet, offset, &ts)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &sender)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &line)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &auth_name)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &keyex_name)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &keyhash_name)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &encr_name)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &compr_name)) == 0) {
    msgpkt2("Error: INI has invalid format");
    ++ini_invalid;
    return;
  }

  if (str_diffs(&auth_name, AUTHENTICATOR_NAME) != 0
      || (cb = key_cb_lookup(keyex_name.s)) == 0
      || str_diffs(&keyhash_name, KEYHASH_NAME) != 0
      || str_diffs(&encr_name, ENCRYPTOR_NAME) != 0
      || str_diffs(&compr_name, "null") != 0) {
    msgpkt3("Error: INI has unknown parameter value");
    ++ini_unknown_parameter;
    return;
  }

  if ((offset = pkt_get_key(&packet, offset,
			    &csession_public, cb)) == 0 ||
      offset + AUTH_LENGTH != packet.len) {
    msgpkt3("Error: INI has invalid format");
    ++ini_invalid;
    return;
  }

  /* Only allow connections to services listed in our config */
  if ((s = find_service(sender.s, line.s)) == 0) {
    msgpkt3("Error: INI from unknown sender");
    ++ini_unknown_sender;
    return;
  }
  last_ini = now;

  if ((key = keylist_get(&s->data.keys, cb)) == 0) {
    msgpkt3("Error: Given key type is missing");
    ++ini_missing_key;
    return;
  }

  key_exchange(&tmpkey, key, keylist_get(&server_secrets, cb));
  auth_start(&authenticator, &tmpkey);
  if (!pkt_validate(&packet, &authenticator)) {
    msgpkt3("Error: INI failed authentication");
    ++ini_failed_auth;
    return;
  }
  ++ini_valid;

  ce = s->data.connection;
  msgf("ss{ (}s{/}s{/}s{/}s{/}s{)}", format_service(s),
       (ce != 0) ? "Reconnected" : "New connection",
       auth_name.s, keyex_name.s, keyhash_name.s, encr_name.s, compr_name.s);

  if (ce == 0) {
    struct connection_key ck = { port, ip };
    struct connection_data cd;
    memset(&cd, 0, sizeof cd);

    wrap_alloc(ce = connections_add(&connections, &ck, &cd));
    ce->data.service = s;
    s->data.connection = ce;
  }
  else {
    ce->key.port = port;
    ce->key.ip = ip;
    connections_rehash(&connections);
    ce = connections_get(&connections, &ce->key);

    if (seq > s->data.next_seq)
      warn_connection(ce, "Reset sequence number forwards");
    /* Special case: if the sent sequence number is the immediate
     * previous number (the just-received packet), accept the
     * sequence number but skip writing the next line.
     */
    else if (seq == s->data.last_seq) 
      seq = s->data.next_seq, ts = s->data.last_timestamp;
    else if (seq < s->data.next_seq)
      warn_connection(ce, "Reset sequence number backwards");
    if (tslt(&ts, &s->data.last_timestamp))
      warn_connection(ce, "Reset timestamp backwards");
  }
  s->data.next_seq = seq;
  s->data.last_timestamp = ts;
  s->data.last_count = 0;
  key_generate(&ssession_secret, &ssession_public, cb);
  keylist_exchange_key_list(&tmpkey, &csession_public, &server_secrets);
  auth_start(&ce->data.authenticator, &tmpkey);
  send_cid(ce, &ssession_public);
  key_exchange(&tmpkey, &csession_public, &ssession_secret);
  auth_start(&ce->data.authenticator, &tmpkey);
  decr_init(&ce->data.decryptor, &tmpkey);
}

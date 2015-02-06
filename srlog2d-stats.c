#include <bglibs/msg.h>
#include <bglibs/socket.h>

#include "srlog2.h"
#include "srlog2d.h"
#include "srlog2d-cli.h"

uint64 stats_next = STATS_INTERVAL;

uint64 packets_received = 0;
uint64 packets_sent = 0;
uint64 bytes_received = 0;
uint64 bytes_sent = 0;
uint64 msg_retransmits = 0;
uint64 msg_valid = 0;
uint64 ini_queued = 0;
uint64 ini_too_many = 0;
uint64 ini_invalid = 0;
uint64 ini_unknown_sender = 0;
uint64 ini_unknown_parameter = 0;
uint64 ini_failed_auth = 0;
uint64 ini_missing_key = 0;
uint64 ini_valid = 0;
uint64 lines_written = 0;
uint64 bytes_written = 0;

void show_stats(void)
{
  str_copys(&tmp, "R:"); str_catull(&tmp, packets_received);
  str_cats(&tmp, " S:"); str_catull(&tmp, packets_sent);
  str_cats(&tmp, " I:"); str_catull(&tmp, ini_valid);
  str_cats(&tmp, " M:"); str_catull(&tmp, msg_valid);
  str_cats(&tmp, " L:"); str_catull(&tmp, lines_written);
  msg2("stats: ", tmp.s);
}

static int str_catstat(str* s, const char* prefix, uint64 u)
{
  return
    str_cat2s(s, prefix, ": ") &&
    str_catull(s, u) &&
    str_catc(s, '\n');
}

static void send_srp(const unsigned char nonce[8])
{
  tmp.len = 0;
  str_catstat(&tmp, "Packets-Received", packets_received);
  str_catstat(&tmp, "Packets-Sent", packets_sent);
  str_catstat(&tmp, "Bytes-Received", bytes_received);
  str_catstat(&tmp, "Bytes-Sent", bytes_sent);
  str_catstat(&tmp, "Lines-Written", lines_written);
  str_catstat(&tmp, "Bytes-Written", bytes_written);
  str_catstat(&tmp, "INI-Dropped-Queued", ini_queued);
  str_catstat(&tmp, "INI-Dropped-Too-Many", ini_too_many);
  str_catstat(&tmp, "INI-Invalid-Format", ini_invalid);
  str_catstat(&tmp, "INI-Unknown-Sender", ini_unknown_sender);
  str_catstat(&tmp, "INI-Unknown-Parameter", ini_unknown_parameter);
  str_catstat(&tmp, "INI-Failed-Authentication", ini_failed_auth);
  str_catstat(&tmp, "INI-Missing-Key", ini_missing_key);
  str_catstat(&tmp, "INI-Valid", ini_valid);
  str_catstat(&tmp, "MSG-Retransmits", msg_retransmits);
  str_catstat(&tmp, "MSG-Valid", msg_valid);

  pkt_start(&packet, SRP1);
  pkt_add_b(&packet, nonce, 8);
  pkt_add_s2(&packet, &tmp);
  send_packet();
}

void handle_srq(void)
{
  if (pkt_get_b(&packet, 8, &line, 8) == 0)
    msgpkt2("Warning: SRQ packet is missing nonce");
  else
    send_srp((unsigned char*)line.s);
}

/* $Id$ */
#include <sys/types.h>
#include <unistd.h>

#include <crc/crc32.h>
#include <msg/msg.h>

#include "srlog2.h"
#include "srlog2d.h"
#include "srlog2d-cli.h"

static void send_ack(struct connections_entry* c, uint64 seq)
{
  packet.len = 0;
  pkt_add_u4(&packet, SRL2);
  pkt_add_u4(&packet, ACK1);
  pkt_add_u8(&packet, seq);
  pkt_add_cc(&packet, &c->data.authenticator);
  send_packet();
}

static int str_catuhex(str* s, uint32 u)
{
  static char bin2hex[16] = "0123456789abcdef";
  char hex[8];
  hex[0] = bin2hex[(u>>28) & 0xf];
  hex[1] = bin2hex[(u>>24) & 0xf];
  hex[2] = bin2hex[(u>>20) & 0xf];
  hex[3] = bin2hex[(u>>16) & 0xf];
  hex[4] = bin2hex[(u>>12) & 0xf];
  hex[5] = bin2hex[(u>>8) & 0xf];
  hex[6] = bin2hex[(u>>4) & 0xf];
  hex[7] = bin2hex[u & 0xf];
  return str_catb(s, hex, 8);
}

static void write_line(struct connections_entry* c,
		       const struct timestamp* ts, const str* l)
{
  /* Assumption: the timestamp is monotonically increasing */
  if (ts->sec >= c->data.rotate_at)
    reopen(c, ts);
  if (!str_copys(&tmp, "@40000000") ||
      !str_catuhex(&tmp, ts->sec) ||
      !str_catuhex(&tmp, ts->nsec) ||
      !str_catc(&tmp, ' ') ||
      !str_cat(&tmp, l) ||
      !str_catc(&tmp, '\n'))
    die1(1, "Out of memory");
  if (write(c->data.fd, tmp.s, tmp.len) != (long)tmp.len)
    die1sys(1, "Write to log file failed");
  lines_written++;
  bytes_written += tmp.len;
}

static int check_crc(const str* s, unsigned offset)
{
  uint32 crc;
  return pkt_get_u4(s, s->len-4, &crc) > 0 &&
    crc32_block(s->s+offset, s->len-offset-4) == crc;
}

void handle_msg(void)
{
  unsigned offset;
  struct timestamp ts;
  struct timestamp last_ts;
  struct connections_entry* c;
  const struct connection_key key = { port, ip };
  uint64 seq;
  unsigned count;
  unsigned i;

  if ((c = connections_get(&connections, &key)) == 0) {
    msgpkt2("Warning: MSG from unknown sender");
    return;
  }
  if (!pkt_validate(&packet, &c->data.authenticator)) {
    error_connection(c, "MSG failed authentication");
    return;
  }
  if ((packet.len - (8+8+1)) % ENCR_BLOCK_SIZE != 0) {
    error_connection(c, "MSG has invalid padding");
    return;
  }
  if (packet.len < 8 + 8 + 1 + 8 + 2+1 + 4) {
    error_connection(c, "MSG is too short");
    return;
  }
  
  pkt_get_u8(&packet, 8, &seq);
  pkt_get_u1(&packet, 8+8, &count);
  if (seq > c->data.next_seq) {
    error_connection3(c, "MSG has sequence number in future: ",
		      seq, c->data.next_seq);
    return;
  }

  decr_blocks(&c->data.decryptor, packet.s+(8+8+1), packet.len-(8+8+1), seq);

  if (!check_crc(&packet, 8+8+1)) {
    error_connection(c, "MSG has invalid CRC");
    //dump_packet(c, &packet);
    return;
  }

  ++msg_valid;

  if (seq == c->data.next_seq ||
      (seq == c->data.last_seq && count > c->data.last_count)) {
    /* Pass 1 -- validate the offsets and timestamps before writing anything */
    last_ts = c->data.last_timestamp;
    for (offset = 8+8+1, i = 0; i < count; ++i) {
      if ((offset = pkt_get_ts(&packet, offset, &ts)) == 0 ||
	  (offset = pkt_get_s2(&packet, offset, &line)) == 0) {
	error_connection(c, "MSG has invalid format");
	return;
      }
      if (tslt(&ts, &last_ts) &&
	  (i > 0 || seq == c->data.next_seq)) {
	error_connection(c, "MSG has timestamp going backwards");
	return;
      }
      last_ts = ts;
    }
    if (seq == c->data.last_seq) {
      warn_connection3(c, "MSG has retransmitted lines: ", seq, count);
      ++msg_retransmits;
    }
    /* Pass 2 -- write out the lines */
    c->data.last_seq = seq;
    for (offset = 8+8+1, i = 0; i < count; ++i, ++seq) {
      offset = pkt_get_ts(&packet, offset, &ts);
      offset = pkt_get_s2(&packet, offset, &line);
      /* Only write out lines we haven't already acknowledged yet. */
      if (seq >= c->data.next_seq)
	write_line(c, &ts, &line);
    }
    
    c->data.next_seq = seq;
    c->data.last_timestamp = ts;
    c->data.last_count = count;
    send_ack(c, seq - 1);
  }
  /* Since the sender waits for an ACK before sending the next MSG,
   * it will never resend anything except for the previous packet. */
  else if (seq == c->data.last_seq &&
	   count == c->data.last_count) {
    /* Ignore the contents of the message, just ACK it
     * since we've already seen it */
    send_ack(c, seq+count-1);
    ++msg_retransmits;
  }
  else
    error_connection(c, "MSG has invalid sequence number");
}

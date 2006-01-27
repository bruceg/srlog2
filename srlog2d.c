/* $Id$ */
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <systime.h>
#include <adt/ghash.h>
#include <base64/base64.h>
#include <crc/crc32.h>
#include <iobuf/iobuf.h>
#include <misc/misc.h>
#include <msg/msg.h>
#include <net/resolve.h>
#include <net/socket.h>
#include <unix/sig.h>

#include "srlog.h"

const char program[] = "srlogd";
const int msg_show_pid = 0;
int msg_debug_bits = 0;

/* Time in seconds to pause between accepting INIs */
static double ini_throttle = 1.0 / 64;

/* Set this to 1 when testing log rotation, and it will rotate logs
   every second instead of every hour */
#define ROLLOVER_SECOND 0

#define STATS_INTERVAL 10000
static uint64 stats_next = STATS_INTERVAL;

/* The maximum number of packets to receive before exiting. */
static uint32 maxpackets = 0;

static int sock;
static ipv4addr ip;
static ipv4port port;
static str packet;
static str line;
static str tmp;
static str path;

/* Stats Gathering --------------------------------------------------------- */
static uint64 packets_received;
static uint64 packets_sent;
static uint64 bytes_received;
static uint64 bytes_sent;
static uint64 msg_retransmits;
static uint64 msg_valid;
static uint64 ini_queued;
static uint64 ini_too_many;
static uint64 ini_invalid;
static uint64 ini_unknown_sender;
static uint64 ini_failed_auth;
static uint64 ini_valid;
static uint64 lines_written;
static uint64 bytes_written;

static void show_stats(void)
{
  str_copys(&tmp, "R:"); str_catull(&tmp, packets_received);
  str_cats(&tmp, " S:"); str_catull(&tmp, packets_sent);
  str_cats(&tmp, " I:"); str_catull(&tmp, ini_valid);
  str_cats(&tmp, " M:"); str_catull(&tmp, msg_valid);
  str_cats(&tmp, " L:"); str_catull(&tmp, lines_written);
  msg2("stats: ", tmp.s);
}

/* Key Handling ------------------------------------------------------------ */
nistp224key server_public;
nistp224key server_secret;

/* ------------------------------------------------------------------------- */
static void send_ack(struct senders_entry* c, uint64 seq)
{
  packet.len = 0;
  pkt_add_u4(&packet, PREFIX);
  pkt_add_u4(&packet, ACK);
  pkt_add_u8(&packet, seq);
  pkt_add_cc(&packet, &c->data.authenticator);
  if (!socket_send4(sock, packet.s, packet.len, &c->key.ip, c->key.port))
    die1sys(1, "Could not send ACK packet");
  packets_sent++;
  bytes_sent += packet.len;
}

static void send_cid(struct senders_entry* c, nistp224key sp)
{
  packet.len = 0;
  pkt_add_u4(&packet, PREFIX);
  pkt_add_u4(&packet, CID);
  pkt_add_key(&packet, sp);
  pkt_add_cc(&packet, &c->data.authenticator);
  if (!socket_send4(sock, packet.s, packet.len, &c->key.ip, c->key.port))
    die1sys(1, "Could not send CID packet");
  packets_sent++;
  bytes_sent += packet.len;
}

static int str_catstat(str* s, const char* prefix, uint64 u)
{
  return
    str_cat2s(s, prefix, ": ") &&
    str_catull(s, u) &&
    str_catc(s, '\n');
}

static void send_srp(void)
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
  str_catstat(&tmp, "INI-Failed-Authentication", ini_failed_auth);
  str_catstat(&tmp, "INI-Valid", ini_valid);
  str_catstat(&tmp, "MSG-Retransmits", msg_retransmits);
  str_catstat(&tmp, "MSG-Valid", msg_valid);
  packet.len = 0;
  pkt_add_u8(&packet, SRP);
  pkt_add_s2(&packet, &tmp);
  if (!socket_send4(sock, packet.s, packet.len, &ip, port))
    die1sys(1, "Could not send SRP packet");
  packets_sent++;
  bytes_sent += packet.len;
}

/* ------------------------------------------------------------------------- */
static void reopen(struct senders_entry* c, const struct timestamp* ts)
{
  time_t t;
  struct tm* lt;

  t = ts->sec;
  lt = localtime(&t);
  tmp.len = 0;
  str_catuw(&tmp, lt->tm_year+1900, 4, '0');
  str_catc(&tmp, '-');
  str_catuw(&tmp, lt->tm_mon+1, 2, '0');
  str_catc(&tmp, '-');
  str_catuw(&tmp, lt->tm_mday, 2, '0');
  str_catc(&tmp, '-');
  str_catuw(&tmp, lt->tm_hour, 2, '0');
#if ROLLOVER_SECOND
  str_catc(&tmp, ':');
  str_catuw(&tmp, lt->tm_min, 2, '0');
  str_catc(&tmp, ':');
  str_catuw(&tmp, lt->tm_sec, 2, '0');
#endif

  if (c->data.fd > 0) {
    fsync(c->data.fd);
    close(c->data.fd);
  }

  str_copy(&path, &c->data.dir);
  str_catc(&path, '/');
  str_cat(&path, &tmp);
  msg_sender(c, "Opening ", path.s);
  if ((c->data.fd = open(path.s, O_WRONLY|O_CREAT|O_APPEND, 0644)) == -1)
    die3sys(1, "Could not open '", path.s, "'"); /* FIXME: should not die */

  str_copy(&path, &c->data.dir);
  str_cats(&path, "/current");
  unlink(path.s);
  symlink(tmp.s, path.s);

#if ROLLOVER_SECOND
  ++lt->tm_sec;
#else
  ++lt->tm_hour;
  lt->tm_sec = 0;
  lt->tm_min = 0;
#endif
  c->data.rotate_at = mktime(lt);
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

static void write_line(struct senders_entry* c,
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
      !str_catc(&tmp, LF))
    die1(1, "Out of memory");
  if (write(c->data.fd, tmp.s, tmp.len) != (long)tmp.len)
    die1sys(1, "Write to log file failed");
  lines_written++;
  bytes_written += tmp.len;
}

/* ------------------------------------------------------------------------- */
static int tslt(const struct timestamp* a, const struct timestamp* b)
{
  return a->sec < b->sec ||
    (a->sec == b->sec && a->nsec < b->nsec);
}

static int check_crc(const str* s, unsigned offset)
{
  uint32 crc;
  return pkt_get_u4(s, s->len-4, &crc) > 0 &&
    crc32_block(s->s+offset, s->len-offset-4) == crc;
}

#if 0
static void dump_packet(struct senders_entry* c, const str* s)
{
  const unsigned char* p;
  unsigned i;
  unsigned j;
  obuf_puts(&outbuf, "len=");
  obuf_putu(&outbuf, s->len);
  obuf_putc(&outbuf, LF);
  for (i = 0, p = s->s; i < 64 && i < s->len; i += 16, p += 16) {
    obuf_putxw(&outbuf, i, 4, '0');
    for (j = 0; j < 16 && i+j < s->len; ++j) {
      obuf_putc(&outbuf, ' ');
      obuf_putxw(&outbuf, p[j], 2, '0');
    }
    obuf_putc(&outbuf, ' ');
    for (j = 0; j < 16 && i+j < s->len; ++j)
      obuf_putc(&outbuf, (p[j] >= 32 && p[j] <= 127) ? p[j] : '?');
    obuf_putc(&outbuf, LF);
  }
  obuf_flush(&outbuf);
}
#endif

static void handle_msg(void)
{
  unsigned offset;
  struct timestamp ts;
  struct timestamp last_ts;
  struct senders_entry* c;
  const struct sender_addr key = { port, ip };
  uint64 seq;
  unsigned count;
  unsigned i;

  if ((c = senders_get(&senders, &key)) == 0) {
    msg4(ipv4_format(&ip), "/", utoa(port),
	 ": MSG from unknown sender");
    return;
  }
  if (!pkt_validate(&packet, &c->data.authenticator)) {
    error_sender(c, "MSG failed authentication");
    return;
  }
  if ((packet.len - (8+8+1)) % ENCR_BLOCK_SIZE != 0) {
    error_sender(c, "MSG has invalid padding");
    return;
  }
  if (packet.len < 8 + 8 + 1 + 8 + 2+1 + 4) {
    error_sender(c, "MSG is too short");
    return;
  }
  
  pkt_get_u8(&packet, 8, &seq);
  pkt_get_u1(&packet, 8+8, &count);
  if (seq > c->data.next_seq) {
    error_sender3(c, "MSG has sequence number in future: ",
		  seq, c->data.next_seq);
    return;
  }

  decr_blocks(&c->data.decryptor, packet.s+(8+8+1), packet.len-(8+8+1), seq);

  if (!check_crc(&packet, 8+8+1)) {
    error_sender(c, "MSG has invalid CRC");
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
	error_sender(c, "MSG has invalid format");
	return;
      }
      if (tslt(&ts, &last_ts) &&
	  (i > 0 || seq == c->data.next_seq)) {
	error_sender(c, "MSG has timestamp going backwards");
	return;
      }
      last_ts = ts;
    }
    if (seq == c->data.last_seq) {
      warn_sender3(c, "MSG has retransmitted lines: ", seq, count);
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
    error_sender(c, "MSG has invalid sequence number");
}

static struct timeval last_ini;

static void handle_ini()
{
  struct timeval now;
  unsigned offset;
  uint64 seq;
  struct timestamp ts;
  struct senders_entry* c;
  nistp224key csession_public;
  nistp224key ssession_public;
  nistp224key ssession_secret;
  nistp224key tmpkey;
  unsigned i;

  if (recv(sock, &i, 4, MSG_PEEK|MSG_DONTWAIT) != -1 &&
      i != 0xffffffffUL) {
    msg4(ipv4_format(&ip), "/", utoa(port),
	 ": Warning: INI throttled: queued packets");
    ++ini_queued;
    return;
  }
  gettimeofday(&now, 0);
  if (((now.tv_sec - last_ini.tv_sec) +
       (now.tv_usec - last_ini.tv_usec) / 1000000.0) < ini_throttle) {
    msg4(ipv4_format(&ip), "/", utoa(port),
	 ": Warning: INI throttled: too many");
    ++ini_too_many;
    return;
  }

  if ((offset = pkt_get_u8(&packet, 8, &seq)) == 0 ||
      (offset = pkt_get_ts(&packet, offset, &ts)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &line)) == 0 ||
      (offset = pkt_get_key(&packet, offset, csession_public)) == 0 ||
      offset + HASH_LENGTH != packet.len) {
    msg4(ipv4_format(&ip), "/", utoa(port),
	 ": Error: INI has invalid format");
    ++ini_invalid;
    return;
  }

  /* Only allow connections to services listed in our config */
  if ((c = find_sender(&ip, line.s)) == 0) {
    msg6(ipv4_format(&ip), "/", utoa(port), "/", line.s,
	 ": Warning: INI from unknown sender");
    ++ini_unknown_sender;
    return;
  }
  last_ini = now;
  
  if (!pkt_validate(&packet, &c->data.ini_authenticator)) {
    error_sender(c, "INI failed authentication");
    ++ini_failed_auth;
    return;
  }
  ++ini_valid;
  c->key.port = port;
  senders_rehash(&senders);
  if (c->data.next_seq == 0) {
    msg_sender(c, "New connection", 0);
    c->data.next_seq = seq;
  }
  else {
    msg_sender(c, "Reconnected", 0);
    if (seq > c->data.next_seq)
      warn_sender(c, "Reset sequence number forwards");
    /* Special case: if the sent sequence number is the immediate
     * previous number (the just-received packet), accept the
     * sequence number but skip writing the next line.
     */
    else if (seq == c->data.last_seq) 
      seq = c->data.next_seq, ts = c->data.last_timestamp;
    else if (seq < c->data.next_seq)
      warn_sender(c, "Reset sequence number backwards");
    if (tslt(&ts, &c->data.last_timestamp))
      warn_sender(c, "Reset timestamp backwards");
    c->data.next_seq = seq;
    c->data.last_timestamp = ts;
    c->data.last_count = 0;
  }
  brandom_key(ssession_secret, ssession_public);
  nistp224(tmpkey, csession_public, server_secret);
  hash_start(&c->data.authenticator, tmpkey);
  reopen(c, &ts);
  send_cid(c, ssession_public);
  nistp224(tmpkey, csession_public, ssession_secret);
  hash_start(&c->data.authenticator, tmpkey);
  decr_init(&c->data.decryptor, tmpkey, 28);
}

static void handle_srq(void)
{
  send_srp();
}

/* ------------------------------------------------------------------------- */
static int exitasap;
static int reload;

static void sigfn(int ignored) { exitasap = 1; (void)ignored; }
static void sighup(int ignored) { reload = 1; (void)ignored; }

int main(void)
{
  int i;
  uint32 type;
  const char* env;

  msg_debug_init();
  if ((env = getenv("MAXPACKETS")) != 0)
    maxpackets = strtoul(env, 0, 10);
  if (!load_key("secret", server_secret) ||
      !load_key("public", server_public))
    die1(1, "Could not load keys");
  load_senders(0);
  brandom_init(28*senders.count, 1);

  if ((sock = socket_udp()) == -1)
    die1sys(1, "Could not create UDP socket");
  if (!socket_bind4(sock, &ip, 11006))
    die1sys(1, "Could not bind UDP socket");
  if (!str_ready(&packet, 65536) ||
      !str_ready(&line, 65536) ||
      !str_ready(&tmp, 65536))
    die1(1, "Out of memory");
  sig_all_catch(sigfn);
  sig_hup_catch(sighup);

  gettimeofday(&last_ini, 0);
  --last_ini.tv_sec;

  msg1("Starting");
  while (!exitasap) {
    if (reload) {
      reload = 0;
      load_senders(1);
      msg1("Continuing");
    }
    if ((i = socket_recv4(sock, packet.s, packet.size, &ip, &port)) == -1) {
      if (errno == EINTR) continue;
      die1sys(1, "Socket receive failed");
    }
    packet.len = i;
    if (!pkt_get_u4(&packet, 0, &type)
	|| type != PREFIX)
      msg4(ipv4_format(&ip), "/", utoa(port),
	   ": Warning: Packet is missing prefix");
    else {
      pkt_get_u4(&packet, 4, &type);
      if (type == INI)
	handle_ini();
      else if (type == MSG)
	handle_msg();
      else if (type == SRQ)
	handle_srq();
      else
	msg4(ipv4_format(&ip), "/", utoa(port),
	     ": Warning: Unknown packet type");
    }
    packets_received++;
    bytes_received += i;
    if (packets_received >= stats_next) {
      show_stats();
      stats_next += STATS_INTERVAL;
    }
    /* Profiling hook: */
    if (maxpackets > 0 && packets_received >= maxpackets) break;
  }

  msg1("Exiting");
  return 0;
}
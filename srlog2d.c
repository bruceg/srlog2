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
#include <str/iter.h>
#include <unix/sig.h>

#include "srlog2.h"
#include "srlog2d.h"
#include "srlog2d-cli.h"

/* Time in seconds to pause between accepting INIs */
static double ini_throttle = 1.0 / 64;

/* Set this to 1 when testing log rotation, and it will rotate logs
   every second instead of every hour */
#define ROLLOVER_SECOND 0

/* The maximum number of packets to receive before exiting. */
static uint32 maxpackets = 0;

static int sock;
ipv4addr ip;
ipv4port port;
str packet = {0,0,0};
str line = {0,0,0};
str tmp = {0,0,0};
str auth_name = {0,0,0};
str keyex_name = {0,0,0};
str keyhash_name = {0,0,0};
str encr_name = {0,0,0};
str compr_name = {0,0,0};

static str sender;
static str path;

struct keylist server_secrets;

/* ------------------------------------------------------------------------- */
void send_packet(void)
{
  if (!socket_send4(sock, packet.s, packet.len, &ip, port))
    die1sys(1, "Could not send packet");
  packets_sent++;
  bytes_sent += packet.len;
}

static void send_ack(struct connections_entry* c, uint64 seq)
{
  packet.len = 0;
  pkt_add_u4(&packet, SRL2);
  pkt_add_u4(&packet, ACK1);
  pkt_add_u8(&packet, seq);
  pkt_add_cc(&packet, &c->data.authenticator);
  send_packet();
}

static void send_cid(struct connections_entry* c, struct key* sp)
{
  packet.len = 0;
  pkt_add_u4(&packet, SRL2);
  pkt_add_u4(&packet, CID1);
  pkt_add_key(&packet, sp);
  pkt_add_cc(&packet, &c->data.authenticator);
  send_packet();
}

static int contains(const str* s, const char* key)
{
  striter i;
  striter_loop(&i, s, 0) {
    if (strcasecmp(i.startptr, key) == 0)
      return 1;
  }
  return 0;
}

/* ------------------------------------------------------------------------- */
static void reopen(struct connections_entry* c, const struct timestamp* ts)
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
  msg_connection(c, "Opening ", path.s);
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
static void dump_packet(struct connections_entry* c, const str* s)
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
  struct connections_entry* c;
  const struct connection_key key = { port, ip };
  uint64 seq;
  unsigned count;
  unsigned i;

  if ((c = connections_get(&connections, &key)) == 0) {
    msg4(ipv4_format(&ip), "/", utoa(port),
	 ": MSG from unknown sender");
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

static struct timeval last_ini;

static void handle_ini()
{
  struct timeval now;
  unsigned offset;
  uint64 seq;
  struct timestamp ts;
  struct senders_entry* s;
  struct connection_key* c;
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
      (offset = pkt_get_s1(&packet, offset, &sender)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &line)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &auth_name)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &keyex_name)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &keyhash_name)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &encr_name)) == 0 ||
      (offset = pkt_get_s1(&packet, offset, &compr_name)) == 0) {
    msg4(ipv4_format(&ip), "/", utoa(port),
	 ": Error: INI has invalid format");
    ++ini_invalid;
    return;
  }

  if (str_diffs(&auth_name, AUTHENTICATOR_NAME) != 0
      || (cb = key_cb_lookup(keyex_name.s)) == 0
      || str_diffs(&keyhash_name, KEYHASH_NAME) != 0
      || str_diffs(&encr_name, ENCRYPTOR_NAME) != 0
      || str_diffs(&compr_name, "null") != 0) {
    msg6(ipv4_format(&ip), "/", utoa(port), "/", line.s,
	 ": Warning: INI has unknown parameter value");
    ++ini_unknown_parameter;
    return;
  }

  if ((offset = pkt_get_key(&packet, offset,
			    &csession_public, cb)) == 0 ||
      offset + AUTH_LENGTH != packet.len) {
    msg4(ipv4_format(&ip), "/", utoa(port),
	 ": Error: INI has invalid format");
    ++ini_invalid;
    return;
  }

  /* Only allow connections to services listed in our config */
  if ((s = find_sender(sender.s, line.s)) == 0) {
    msg6(ipv4_format(&ip), "/", utoa(port), "/", line.s,
	 ": Warning: INI from unknown sender");
    ++ini_unknown_sender;
    return;
  }
  last_ini = now;

  if ((key = keylist_get(&s->data.keys, cb)) == 0) {
    error_sender(s, "Given key type is missing");
    ++ini_missing_key;
    return;
  }

  auth_start(&authenticator, key);
  if (!pkt_validate(&packet, &authenticator)) {
    error_sender(s, "INI failed authentication");
    ++ini_failed_auth;
    return;
  }
  ++ini_valid;

  if ((c = s->data.connection) == 0) {
    msg_sender(s, "New connection", 0);

    struct connection_key ck = { port, ip };
    struct connection_data cd;
    memset(&cd, 0, sizeof cd);
    str_copy(&cd.dir, &s->data.dir);

    if (!connections_add(&connections, &ck, &cd)) die_oom(1);
    ce = connections_get(&connections, &ck);
    s->data.connection = &ce->key;
  }
  else {
    msg_sender(s, "Reconnected", 0);

    c->port = port;
    c->ip = ip;
    connections_rehash(&connections);
    ce = connections_get(&connections, c);

    if (seq > ce->data.next_seq)
      warn_connection(ce, "Reset sequence number forwards");
    /* Special case: if the sent sequence number is the immediate
     * previous number (the just-received packet), accept the
     * sequence number but skip writing the next line.
     */
    else if (seq == ce->data.last_seq) 
      seq = ce->data.next_seq, ts = ce->data.last_timestamp;
    else if (seq < ce->data.next_seq)
      warn_connection(ce, "Reset sequence number backwards");
    if (tslt(&ts, &ce->data.last_timestamp))
      warn_connection(ce, "Reset timestamp backwards");
  }
  ce->data.next_seq = seq;
  ce->data.last_timestamp = ts;
  ce->data.last_count = 0;
  key_generate(&ssession_secret, &ssession_public, cb);
  keylist_exchange(&tmpkey, &csession_public, &server_secrets);
  auth_start(&ce->data.authenticator, &tmpkey);
  reopen(ce, &ts);
  send_cid(ce, &ssession_public);
  key_exchange(&tmpkey, &csession_public, &ssession_secret);
  auth_start(&ce->data.authenticator, &tmpkey);
  decr_init(&ce->data.decryptor, &tmpkey);
}

/* ------------------------------------------------------------------------- */
static int exitasap;
static int reload;

static void sigfn(int ignored) { exitasap = 1; (void)ignored; }
static void sighup(int ignored) { reload = 1; (void)ignored; }

int cli_main(int argc, char* argv[])
{
  int i;
  uint32 type;
  const char* env;

  msg_debug_init();
  if ((env = getenv("MAXPACKETS")) != 0)
    maxpackets = strtoul(env, 0, 10);
  if (!keylist_load(&server_secrets, "secrets"))
    die1(1, "Could not load server key");
  load_senders(0);
  brandom_init();

  if ((sock = socket_udp()) == -1)
    die1sys(1, "Could not create UDP socket");
  port = opt_port;
  if (!socket_bind4(sock, &ip, port))
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
	|| type != SRL2)
      msg4(ipv4_format(&ip), "/", utoa(port),
	   ": Warning: Packet is missing prefix");
    else {
      pkt_get_u4(&packet, 4, &type);
      if (type == INI1)
	handle_ini();
      else if (type == MSG1)
	handle_msg();
      else if (type == SRQ1)
	handle_srq();
      else if (type == PRQ1)
	handle_prq();
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
  (void)argc;
  (void)argv;
}

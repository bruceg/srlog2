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
#include <msg/msg.h>
#include <net/resolve.h>
#include <net/socket.h>
#include <str/iter.h>
#include <unix/sig.h>

#include "srlog2.h"
#include "srlog2d.h"
#include "srlog2d-cli.h"

/* The maximum number of packets to receive before exiting. */
static uint32 maxpackets = 0;

int sock;
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

static str path;

struct keylist server_secrets;

/* ------------------------------------------------------------------------- */
void msgpkt2(const char* msg)
{
  msgf("s{/}u{: }s", ipv4_format(&ip), port, msg);
}

void msgpkt3(const char* msg)
{
  msgf("s{/}u{/}s{: }s", ipv4_format(&ip), port, line.s, msg);
}

/* ------------------------------------------------------------------------- */
void send_packet(void)
{
  if (!socket_send4(sock, packet.s, packet.len, &ip, port))
    die1sys(1, "Could not send packet");
  packets_sent++;
  bytes_sent += packet.len;
}

/* ------------------------------------------------------------------------- */
void reopen(struct connections_entry* c, const struct timestamp* ts)
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

/* ------------------------------------------------------------------------- */
int tslt(const struct timestamp* a, const struct timestamp* b)
{
  return a->sec < b->sec ||
    (a->sec == b->sec && a->nsec < b->nsec);
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
      msgpkt2("Warning: Packet is missing prefix");
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
	msgpkt2("Warning: Unknown packet type");
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

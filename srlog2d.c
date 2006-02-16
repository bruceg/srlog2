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

int logger;
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

static int start_logger(int argc, char* argv[])
{
  pid_t pid;
  int fds[2];
  if (argc == 0)
    return 1;
  else {
    if (pipe(fds) == -1)
      die1sys(1, "Could not create pipe");
    if ((pid = fork()) == -1)
      die1sys(1, "Could not fork");
    if (pid == 0) {
      dup2(fds[0], 0);
      close(fds[0]);
      close(fds[1]);
      execvp(argv[0], argv);
      diefsys(1, "{Could not execute '}s{'}", argv[0]);
    }
    close(fds[0]);
    return fds[1];
  }
}

int cli_main(int argc, char* argv[])
{
  int i;
  uint32 type;

  msg_debug_init();
  if (!keylist_load(&server_secrets, opt_keylist))
    die1(1, "Could not load server keys");
  load_senders(0);
  load_services(0);
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
  logger = start_logger(argc, argv);
  
  while (!exitasap) {
    if (reload) {
      reload = 0;
      load_senders(1);
      load_services(1);
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
    if (opt_maxpackets > 0
	&& packets_received >= opt_maxpackets)
      break;
  }

  msg1("Exiting");
  return 0;
  (void)argc;
  (void)argv;
}

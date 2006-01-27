/* $Id$ */
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sysdeps.h>
#include <systime.h>
#include <crc/crc32.h>
#include <iobuf/iobuf.h>
#include <misc/misc.h>
#include <msg/msg.h>
#include <msg/wrap.h>
#include <net/resolve.h>
#include <net/socket.h>
#include <str/str.h>
#include <unix/sig.h>

#include "conf_etc.c"
#include "srlog.h"
#include "srlog2-cli.h"

static str service;
static ipv4addr ip;
static ipv4port port;
static int sock;
static unsigned long ack_timeout = 1000;
static unsigned long cid_timeout = 5*1000;
static unsigned long retransmits = 4;
static unsigned long readwait = 100;
static const char** patterns;

static int exitasap;

static str out_packet;
static str ack_packet;

static char num1[40];
static char num2[40];

/* Key/Encryption Handling ------------------------------------------------- */
static nistp224key server_public;
static HASH_CTX ini_authenticator;
static HASH_CTX msg_authenticator;
static HASH_CTX cid_authenticator;
static ENCR_CTX encryptor;

/* ------------------------------------------------------------------------- */
static struct line last_line;

static void gettimestamp(struct timestamp* ts)
{
  static struct timeval tv;
  gettimeofday(&tv, 0);
  ts->sec = tv.tv_sec;
  ts->nsec = tv.tv_usec * 1000 + 500;
}

static int read_line(void)
{
  const char** p;
  int matches;
  if (!ibuf_getstr(&inbuf, &last_line.line, LF)) {
    exitasap = 1;
    if (!ibuf_eof(&inbuf))
      error1sys("Could not read line from stdin");
    return 0;
  }
  if (patterns != 0) {
    matches = 1;
    for (p = patterns; *p != 0; ++p) {
      if (str_matchs(&last_line.line, (*p)+1))
	matches = **p == '+';
    }
    if (!matches) return 0;
  }
  gettimestamp(&last_line.timestamp);
  last_line.seq = seq_next++;
  save_seq();
  --last_line.line.len;		/* Strip off the trailing LF */
  buffer_push(&last_line);
  return 1;
}

static int read_lines(void)
{
  int count = 0;
  do {
    count += read_line();
  } while (inbuf.io.buflen > inbuf.io.bufstart);
  return count;
}

/* Polling ----------------------------------------------------------------- */
static int poll_timeout;
static struct timeval poll_timestamp;
static iopoll_fd io[2];
#define stdin_ready (io[0].revents)
#define sock_ready (io[1].revents)

static void poll_reset(int timeout)
{
  poll_timeout = timeout;
  poll_timestamp.tv_sec = 0;
  io[0].fd = 0;
  io[0].events = IOPOLL_READ;
  io[1].fd = sock;
  io[1].events = IOPOLL_READ;
}

static int poll_both(void)
{
  struct timeval timestamp;
  int ready;

  /* Sanity check to make sure no data is lost */
  if (inbuf.io.buflen > inbuf.io.bufstart) {
    stdin_ready = IOPOLL_READ;
    sock_ready = 0;
    return 1;
  }

  /* Calculate remaining timeout */
  gettimeofday(&timestamp, 0);
  if (poll_timestamp.tv_sec != 0) {
    poll_timeout -= (timestamp.tv_sec - poll_timestamp.tv_sec) * 1000 +
      (timestamp.tv_usec - poll_timestamp.tv_usec) / 1000;
    if (poll_timeout < 0) poll_timeout = 0;
  }
  poll_timestamp = timestamp;

  switch (ready = iopoll(io, 2, poll_timeout)) {
  case -1:
    if (errno == EAGAIN || errno == EINTR)
      exit(0);
    die1sys(1, "Poll failed!");
    return 0;
  case 0:
    poll_timeout = 0;
    return 0;
  default:
    return ready;
  }
}

/* Packet generation ------------------------------------------------------- */
static uint64 seq_last;
static uint64 seq_first;

static int add_msg(const struct line* l)
{
  if ((unsigned char)out_packet.s[8] == 0xff
      || out_packet.len + 8 + 2 + l->line.len + 4 + HASH_LENGTH >= MAX_PACKET
      || (seq_last > 0 && l->seq != seq_last + 1))
    return 0;
  debug2(DEBUG_MSG, "Adding line #", utoa(l->seq));
  ++out_packet.s[8+8];
  pkt_add_ts(&out_packet, &l->timestamp);
  pkt_add_s2(&out_packet, &l->line);
  seq_last = l->seq;
  return 1;
}

static void start_msg(const struct line* l)
{
  seq_first = l->seq;
  out_packet.len = 0;
  pkt_add_u4(&out_packet, SRL2);
  pkt_add_u4(&out_packet, MSG1);
  pkt_add_u8(&out_packet, l->seq);
  pkt_add_u1(&out_packet, 0);
  add_msg(l);
}

static void end_msg(void)
{
  // FIXME: pad with random data
  int i;
  for (i = ENCR_BLOCK_SIZE - (out_packet.len - 17 + 4) % ENCR_BLOCK_SIZE;
       i > 0;
       --i)
    pkt_add_u1(&out_packet, 0);
  pkt_add_u4(&out_packet, crc32_block(out_packet.s+17, out_packet.len-17));
  encr_blocks(&encryptor, out_packet.s+17, out_packet.len-17, seq_first);
  pkt_add_cc(&out_packet, &msg_authenticator);
}

static int make_msg(void)
{
  const struct line* line;
  if ((line = buffer_read()) == 0)
    return 0;
  start_msg(line);
  while ((line = buffer_peek()) != 0) {
    if (!add_msg(line))
      break;
    buffer_read();
  }
  end_msg();
  return 1;
}

static void make_ini(const nistp224key key, const struct line* line)
{
  const struct timestamp* ts;
  struct timestamp now;
  out_packet.len = 0;
  pkt_add_u4(&out_packet, SRL2);
  pkt_add_u4(&out_packet, INI1);
  pkt_add_u8(&out_packet, seq_send);
  if (line == 0) {
    gettimestamp(&now);
    ts = &now;
  }
  else
    ts = &line->timestamp;
  pkt_add_ts(&out_packet, ts);
  pkt_add_s1(&out_packet, &service);
  pkt_add_key(&out_packet, key);
  pkt_add_cc(&out_packet, &ini_authenticator);
}

/* Network I/O ------------------------------------------------------------- */
static void send_msg(unsigned scale)
{
  if (!socket_send4(sock, out_packet.s, out_packet.len, &ip, port)) {
    error1sys("Could not send packet to server");
    exitasap = 1;
  }
  else {
    utoa2(seq_send, num1);
    utoa2(seq_last, num2);
    debug4(DEBUG_PACKET, "Sent MSG packet ", num1, "-", num2);
    poll_reset(ack_timeout*scale);
  }
}

static int receive_ack(void)
{
  int i;
  uint64 seq;
  uint32 t;
  if ((i = socket_recv4(sock, ack_packet.s, ack_packet.size, &ip,&port)) == -1)
    return 0;
  if ((ack_packet.len = i) != 4+4+8 + HASH_LENGTH) return 0;
  pkt_get_u4(&ack_packet, 0, &t);
  if (t != SRL2) return 0;
  pkt_get_u4(&ack_packet, 4, &t);
  if (t != ACK1) return 0;
  pkt_get_u8(&ack_packet, 8, &seq);
  if (seq != seq_last) {
    utoa2(seq, num1);
    utoa2(seq_last, num2);
    debug4(DEBUG_PACKET, "Received wrong ACK sequence ", num1, " ", num2);
    return 0;
  }
  if (!pkt_validate(&ack_packet, &msg_authenticator)) {
    debug1(DEBUG_PACKET, "Received invalid ACK");
    return 0;
  }
  debug2(DEBUG_PACKET, "Received ACK packet ", utoa(seq));
  buffer_pop();
  seq_last = 0;
  return 1;
}

static void send_ini(void)
{
  if (!socket_send4(sock, out_packet.s, out_packet.len, &ip, port)) {
    error1sys("Could not send INI packet");
    exitasap = 1;
  }
  else {
    debug1(DEBUG_PACKET, "Sent INI packet");
    poll_reset(cid_timeout);
  }
}

static int receive_cid(nistp224key csession_secret)
{
  int i;
  uint32 t;
  nistp224key ssession_public;
  nistp224key tmpkey;
  if ((i = socket_recv4(sock, ack_packet.s, ack_packet.size, &ip,&port)) == -1)
    return 0;
  if ((ack_packet.len = i) != 8 + KEY_LENGTH + HASH_LENGTH) return 0;
  pkt_get_u4(&ack_packet, 0, &t);
  if (t != SRL2) return 0;
  pkt_get_u4(&ack_packet, 4, &t);
  if (t != CID1) return 0;
  if (!pkt_validate(&ack_packet, &cid_authenticator)) return 0;
  pkt_get_key(&ack_packet, 8, ssession_public);
  nistp224(tmpkey, ssession_public, csession_secret);
  hash_start(&msg_authenticator, tmpkey);
  encr_init(&encryptor, tmpkey, 28);
  debug1(DEBUG_PACKET, "Received CID packet");
  seq_last = 0;
  return 1;
}

/* States ------------------------------------------------------------------ */
#define STATE_DISCONNECTED 0
#define STATE_SENDING 1
#define STATE_CONNECTED 2
#define STATE_EXITING 3

static int do_disconnected(void)
{
  nistp224key csession_secret;
  nistp224key csession_public;
  nistp224key tmpkey;

  buffer_rewind();
  buffer_sync();
  brandom_init(32, 0);
  brandom_key(csession_secret, csession_public);
  make_ini(csession_public, buffer_peek());
  nistp224(tmpkey, server_public, csession_secret);
  hash_start(&cid_authenticator, tmpkey);

  while (!exitasap) {
    send_ini();
    while (!exitasap) {
      if (poll_both() == 0)
	break;
      if (stdin_ready)
	read_lines();
      if (sock_ready && receive_cid(csession_secret))
	return STATE_SENDING;
    }
  }
  return STATE_EXITING;
}

static int do_sending(void)
{
  unsigned i;
  if (!make_msg())
    return STATE_CONNECTED;
  /* Try to send the message packet multiple times. */
  for (i = 1; !exitasap && i <= retransmits; ++i) {
    send_msg(i);
    while (!exitasap) {
      if (poll_both() == 0) {
	debug1(DEBUG_STATE, "Timed out waiting for ACK");
	break;
      }
      if (stdin_ready)
	read_lines();
      if (sock_ready && receive_ack())
	return STATE_SENDING;
    }
  }
  return STATE_DISCONNECTED;
}

static int do_connected(void)
{
  while (!exitasap) {
    if (read_lines())
      break;
  }
  
  /* Keep capturing lines as long as there are lines ready to read. */
  while (!exitasap) {
    switch (iopoll(io, 1, readwait)) {
    case -1:
      return STATE_EXITING;
    case 1:
      read_lines();
      continue;
    case 0:
      break;
    }
    return STATE_SENDING;
  }
  return STATE_EXITING;
}

/* State Machine ----------------------------------------------------------- */
static void mainloop(void)
{
  int state = STATE_DISCONNECTED;
  while (!exitasap) {
    debug2(DEBUG_STATE, "Entering state ", utoa(state));
    switch (state) {
    case STATE_DISCONNECTED: state = do_disconnected(); break;
    case STATE_SENDING:      state = do_sending(); break;
    case STATE_CONNECTED:    state = do_connected(); break;
    case STATE_EXITING:      exitasap = 1; break;
    default: die1(1, "Illegal state");
    }
  }
}

/* Main Loop --------------------------------------------------------------- */
static void sigfn(int s) {
  warn2("Killed with signal ", utoa(s));
  exitasap = 1;
}

static void load_patterns(char** argv)
{
  patterns = (const char**)argv;
  while (*argv) {
    if (*argv[0] != '-' && *argv[0] != '+')
      usage(1, "Invalid pattern");
    ++argv;
  }
}

static void load_server_key(const char* hostname)
{
  str path = {0,0,0};
  wrap_str(str_copy3s(&path, conf_etc, "/servers/", hostname));
  if (!load_key(path.s, server_public) &&
      !load_key("server", server_public))
    die1sys(1, "Could not load server key");
  str_free(&path);
}

static void load_host_key(void)
{
  nistp224key client_secret;
  nistp224key tmpkey;
  str path = {0,0,0};
  if (!load_key("secret", client_secret)) {
    wrap_str(str_copy2s(&path, conf_etc, "/key/secret"));
    if (!load_key(path.s, client_secret))
      die1sys(1, "Could not load sender key");
    str_free(&path);
  }
  nistp224(tmpkey, server_public, client_secret);
  hash_start(&ini_authenticator, tmpkey);
}

static void getenvu(const char* name, unsigned long* dst)
{
  const char* env;
  char* end;
  if ((env = getenv(name)) != 0)
    if ((*dst = strtoul(env, &end, 10)) <= 0 || *end != 0)
      die5(1, "Invalid value for $", name, ": '", env, "'");
}

int cli_main(int argc, char* argv[])
{
  const char* tmp;
  char* end;
  const char* server_name = 0;

  msg_debug_init();
  if (!str_copys(&service, argv[0])) die_oom(1);
  if (argc > 1
      && argv[1][0] != '-'
      && argv[1][0] != '+') {
    server_name = argv[1];
    ++argv;
    --argc;
  }
  if (argc > 1)
    load_patterns(argv + 1);

  if (server_name == 0
      && (server_name = getenv("SERVER")) == 0)
    die1(1, "Server address not named on command line nor in $SERVER");
  if (!resolve_ipv4name(server_name, &ip))
    die3(1, "Could not resolve '", server_name, "'");

  load_server_key(server_name);
  load_host_key();

  if ((tmp = getenv("PORT")) == 0) tmp = "11006";
  if ((port = strtol(tmp, &end, 10)) == 0 || *end != 0)
    die3(1, "Could not parse port '", tmp, "'");

  if ((sock = socket_udp()) == -1)
    die1sys(1, "Could not create UDP socket");
  if (!socket_connect4(sock, &ip, port))
    die1sys(1, "Could not bind socket");
  if (!str_ready(&out_packet, 65535) ||
      !str_ready(&ack_packet, 65535))
    die1(1, "Out of memory");

  getenvu("ACK_TIMEOUT", &ack_timeout);
  getenvu("CID_TIMEOUT", &cid_timeout);
  getenvu("RETRANSMITS", &retransmits);
  getenvu("READWAIT", &readwait);

  buffer_init();
  atexit(buffer_sync);

  sig_all_catch(sigfn);
  exitasap = 0;

  mainloop();
  return 0;
}

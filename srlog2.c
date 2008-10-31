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
#include <msg/msg.h>
#include <msg/wrap.h>
#include <net/resolve.h>
#include <net/socket.h>
#include <str/str.h>
#include <unix/sig.h>

#include "conf_etc.c"
#include "srlog2.h"
#include "srlog2-cli.h"

#define REJECTf(FORMAT, ...) do { \
  debugf(DEBUG_PACKET, FORMAT, __VA_ARGS__); \
  return 0; \
} while (0)

#define REJECT1(STRING) do { \
  debug1(DEBUG_PACKET, STRING); \
  return 0; \
} while (0)

static const char* keydir = conf_etc;
static const char* sender;
static const char* service;
static ipv4addr ip;
static ipv4port port;
static int sock;
static unsigned long ack_timeout = 1000;
static unsigned long cid_timeout = 5*1000;
static unsigned long retransmits = 4;
static unsigned long readwait = 100;
static const char** patterns;
static str keyex_name;
static const struct key_cb* keyex;
static str tmpstr;
static unsigned char nonce[8];
static int exitoneof = 1;

static int exitasap;

static str packet;
static str rpacket;

static const struct line* (*buffer_peek)(void);
static const struct line* (*buffer_read)(void);
static void (*buffer_pop)(void);
static void (*buffer_push)(const struct line*);
static void (*buffer_rewind)(void);

/* Key/Encryption Handling ------------------------------------------------- */
static struct keylist shared_secrets;
static struct keylist server_publics;
static struct keylist client_secrets;
static AUTH_CTX ini_authenticator;
static AUTH_CTX msg_authenticator;
static AUTH_CTX cid_authenticator;
static ENCR_CTX encryptor;

/* ------------------------------------------------------------------------- */
static int stdin_eof = 0;
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
    exitasap = exitoneof;
    if (!ibuf_eof(&inbuf))
      error1sys("Could not read line from stdin");
    else
      stdin_eof = 1;
    return 0;
  }
  --last_line.line.len;		/* Strip off the trailing LF */
  if (patterns != 0) {
    matches = 1;
    for (p = patterns; *p != 0; ++p) {
      if (str_matchs(&last_line.line, (*p)+1))
	matches = **p == '+';
    }
    if (!matches) return 0;
  }
  gettimestamp(&last_line.timestamp);
  SET_SEQ(last_line.seq = seq_next++);
  if (last_line.line.len > MAX_LINE) {
    str_rcut(&last_line.line, last_line.line.len - MAX_LINE);
    memcpy(last_line.line.s + MAX_LINE - 17, "[...truncated...]", 17);
  }
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

  io[0].fd = 0;
  io[0].events = stdin_eof ? 0 : IOPOLL_READ;
  io[1].fd = sock;
  io[1].events = IOPOLL_READ;

  switch (ready = iopoll(io, 2, poll_timeout)) {
  case -1:
    if (errno == EAGAIN || errno == EINTR)
      exitasap = 1;
    else
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
static int saw_seq_gap = 0;

static int add_msg(const struct line* l)
{
  if ((unsigned char)packet.s[8+8] == 0xff
      || packet.len + 8 + 2 + l->line.len + 4 + AUTH_LENGTH >= MAX_PACKET)
    return 0;
  if (seq_last > 0 && l->seq != seq_last + 1) {
    saw_seq_gap = 1;
    return 0;
  }
  debugf(DEBUG_MSG, "{Adding line #}llu", l->seq);
  ++packet.s[8+8];
  pkt_add_ts(&packet, &l->timestamp);
  pkt_add_s2(&packet, &l->line);
  seq_last = l->seq;
  return 1;
}

static void start_msg(const struct line* l)
{
  seq_first = l->seq;
  pkt_start(&packet, MSG1);
  pkt_add_u8(&packet, l->seq);
  pkt_add_u1(&packet, 0);
  add_msg(l);
}

static void end_msg(void)
{
  unsigned char pad[ENCR_BLOCK_SIZE - (packet.len - 17 + 4) % ENCR_BLOCK_SIZE];
  brandom_fill(pad, sizeof pad);
  pkt_add_b(&packet, pad, sizeof pad);
  pkt_add_u4(&packet, crc32_block(packet.s+17, packet.len-17));
  encr_blocks(&encryptor,
	      (unsigned char*)packet.s+17, packet.len-17, seq_first);
  pkt_add_cc(&packet, &msg_authenticator);
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

static void make_prq(void)
{
  brandom_fill(nonce, sizeof nonce);
  pkt_start(&packet, PRQ1);
  pkt_add_b(&packet, nonce, sizeof nonce);
  pkt_add_s1c(&packet, AUTHENTICATOR_NAME);
  wrap_str(str_copys(&keyex_name, nistp224_cb.name));
#ifdef HASCURVE25519
  if (keylist_get(&shared_secrets, &curve25519_cb) != 0) {
    wrap_str(str_catc(&keyex_name, 0));
    wrap_str(str_cats(&keyex_name, curve25519_cb.name));
  }
#endif
  pkt_add_s1(&packet, &keyex_name);
  pkt_add_s1c(&packet, KEYHASH_NAME);
  pkt_add_s1c(&packet, ENCRYPTOR_NAME);
  pkt_add_s1c(&packet, "null");
}

static void make_ini(const struct key* key, const struct line* line)
{
  const struct timestamp* ts;
  struct timestamp now;
  pkt_start(&packet, INI1);
  pkt_add_u8(&packet, seq_send);
  if (line == 0) {
    gettimestamp(&now);
    ts = &now;
  }
  else
    ts = &line->timestamp;
  pkt_add_ts(&packet, ts);
  pkt_add_s1c(&packet, sender);
  pkt_add_s1c(&packet, service);
  pkt_add_s1c(&packet, AUTHENTICATOR_NAME);
  pkt_add_s1c(&packet, keyex->name);
  pkt_add_s1c(&packet, KEYHASH_NAME);
  pkt_add_s1c(&packet, ENCRYPTOR_NAME);
  pkt_add_s1c(&packet, "null");
  pkt_add_key(&packet, key);
  pkt_add_cc(&packet, &ini_authenticator);
}

/* Network I/O ------------------------------------------------------------- */
static void send_packet(const char* type, int timeout)
{
  if (!socket_send4(sock, packet.s, packet.len, &ip, port)) {
    errorfsys("{Could not send }s{ packet to server}", type);
    exitasap = 1;
  }
  else {
    debugf(DEBUG_PACKET, "{Sent }s{ packet}", type);
    poll_reset(timeout);
  }
}

static int receive_packet(uint32 type, int minlength, int maxlength)
{
  int i;
  uint32 t;
  if ((i = socket_recv4(sock, rpacket.s, rpacket.size, &ip,&port)) < 0)
    REJECT1("Socket receive failed");
  if (i < minlength)
    REJECT1("Received packet is too short");
  if (maxlength > 0
      && i > maxlength)
    REJECT1("Received packet is too long");
  rpacket.len = i;
  pkt_get_u4(&rpacket, 0, &t);
  if (t != SRL2)
    REJECT1("Received packet format was not SRL2");
  pkt_get_u4(&rpacket, 4, &t);
  if (t != type)
    REJECT1("Received incorrect packet type");
  return 1;
}

static int receive_prf(void)
{
  unsigned offset;
  struct key* key;

  if (!receive_packet(PRF1, 8+8+2+2+2+2+2, 8+8+256+256+256+256+256))
    return 0;
  if ((offset = pkt_get_b(&rpacket, 8, &tmpstr, sizeof nonce)) == 0
      || memcmp(tmpstr.s, nonce, sizeof nonce) != 0
      || (offset = pkt_get_s1(&rpacket, offset, &tmpstr)) == 0
      || strcasecmp(tmpstr.s, AUTHENTICATOR_NAME) != 0
      || (offset = pkt_get_s1(&rpacket, offset, &keyex_name)) == 0
      || (keyex = key_cb_lookup(keyex_name.s)) == 0
      || (offset = pkt_get_s1(&rpacket, offset, &tmpstr)) == 0
      || strcasecmp(tmpstr.s, KEYHASH_NAME) != 0
      || (offset = pkt_get_s1(&rpacket, offset, &tmpstr)) == 0
      || strcasecmp(tmpstr.s, ENCRYPTOR_NAME) != 0
      || (offset = pkt_get_s1(&rpacket, offset, &tmpstr)) == 0
      || strcasecmp(tmpstr.s, "null") != 0
      || offset != rpacket.len)
    REJECT1("Received PRF1 had invalid format or parameters");

  if ((keyex = key_cb_lookup(keyex_name.s)) == 0)
    REJECTf("{PRF response contained bad keyex name: }s", keyex_name.s);
  if ((key = keylist_get(&shared_secrets, keyex)) == 0)
    REJECTf("{PRF response referenced missing shared secret: }s", keyex_name.s);
  debug1(DEBUG_PACKET, "Received PRF packet");
  auth_start(&ini_authenticator, key);

  return 1;
}
  
static int receive_ack(void)
{
  uint64 seq;
  if (!receive_packet(ACK1, 8+8+AUTH_LENGTH, 8+8+AUTH_LENGTH))
    return 0;
  pkt_get_u8(&rpacket, 8, &seq);
  if (seq != seq_last) {
    debugf(DEBUG_PACKET, "{Received wrong ACK sequence #}llu{ sent #}llu",
	   seq, seq_last);
    return 0;
  }
  if (!pkt_validate(&rpacket, &msg_authenticator)) {
    debug1(DEBUG_PACKET, "Received ACK failed validation");
    return 0;
  }
  debugf(DEBUG_PACKET, "{Received ACK packet #}llu", seq);
  buffer_pop();
  seq_last = 0;
  return 1;
}

static int receive_cid(struct key* csession_secret)
{
  struct key ssession_public;
  struct key tmpkey;
  if (!receive_packet(CID1,
		      8 + keyex->size + AUTH_LENGTH,
		      8 + keyex->size + AUTH_LENGTH))
    return 0;
  if (!pkt_validate(&rpacket, &cid_authenticator)) {
    debug1(DEBUG_PACKET, "Received CID failed validation");
    return 0;
  }
  pkt_get_key(&rpacket, 8, &ssession_public, keyex);
  key_exchange(&tmpkey, &ssession_public, csession_secret);
  auth_start(&msg_authenticator, &tmpkey);
  encr_init(&encryptor, &tmpkey);
  debug1(DEBUG_PACKET, "Received CID packet");
  seq_last = 0;
  return 1;
}

/* States ------------------------------------------------------------------ */
#define STATE_DISCONNECTED 0
#define STATE_NEGOTIATED 1
#define STATE_SENDING 2
#define STATE_CONNECTED 3
#define STATE_EXITING 4

static int do_negotiating(void)
{
  make_prq();
  while (!exitasap) {
    send_packet("PRQ1", cid_timeout);
    while (!exitasap) {
      if (poll_both() == 0)
	break;
      if (stdin_ready)
	read_lines();
      if (sock_ready && receive_prf())
	return STATE_NEGOTIATED;
    }
  }
  return STATE_EXITING;
}

static int do_connecting(void)
{
  struct key csession_secret;
  struct key csession_public;
  struct key tmpkey;

  saw_seq_gap = 0;
  buffer_rewind();
  key_generate(&csession_secret, &csession_public, keyex);
  make_ini(&csession_public, buffer_peek());
  keylist_exchange_list_key(&tmpkey, &server_publics, &csession_secret);
  auth_start(&cid_authenticator, &tmpkey);

  while (!exitasap) {
    send_packet("INI1", cid_timeout);
    while (!exitasap) {
      if (poll_both() == 0)
	return STATE_DISCONNECTED;
      if (stdin_ready)
	read_lines();
      if (sock_ready && receive_cid(&csession_secret))
	return STATE_SENDING;
    }
  }
  return STATE_EXITING;
}

static int do_sending(void)
{
  unsigned i;
  if (!make_msg())
    return (stdin_eof && !exitoneof) ? STATE_EXITING : STATE_CONNECTED;
  /* Try to send the message packet multiple times. */
  for (i = 1; !exitasap && i <= retransmits; ++i) {
    debugf(DEBUG_PACKET, "{Sending seq #}llu{ to #}llu", seq_send, seq_last);
    send_packet("MSG1", ack_timeout * i);
    while (!exitasap) {
      if (poll_both() == 0) {
	debug1(DEBUG_STATE, "Timed out waiting for ACK");
	break;
      }
      if (stdin_ready)
	read_lines();
      if (sock_ready && receive_ack())
	return saw_seq_gap ? STATE_DISCONNECTED : STATE_SENDING;
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
    debugf(DEBUG_STATE, "{Entering state }u", state);
    switch (state) {
    case STATE_DISCONNECTED: state = do_negotiating(); break;
    case STATE_NEGOTIATED:   state = do_connecting(); break;
    case STATE_SENDING:      state = do_sending(); break;
    case STATE_CONNECTED:    state = do_connected(); break;
    case STATE_EXITING:      exitasap = 1; break;
    default: die1(1, "Illegal state");
    }
  }
}

/* Main Loop --------------------------------------------------------------- */
static void sigfn(int s) {
  warnf("{Killed with signal }u", s);
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

static void load_keys(const char* server)
{
  str path = {0,0,0};

  wrap_str(str_copy4s(&path, keydir, "/servers/", server, "."));
  if (!keylist_load_multi(&server_publics, path.s, 0) &&
      !keylist_load_multi(&server_publics, "server.", 0))
    die1sys(1, "Could not load server keys");

  if (!keylist_load_multi(&client_secrets, "", 0)) {
    wrap_str(str_copy2s(&path, keydir, "/"));
    if (!keylist_load_multi(&client_secrets, path.s, 0))
      die1sys(1, "Could not load sender keys");
  }

  if (!keylist_exchange_all(&shared_secrets, &server_publics, &client_secrets))
    die1(1, "No server keys matched any sender keys");
  
  str_free(&path);
}

static void getenvu(const char* name, unsigned long* dst)
{
  const char* env;
  char* end;
  if ((env = getenv(name)) != 0)
    if ((*dst = strtoul(env, &end, 10)) <= 0 || *end != 0)
      die5(1, "Invalid value for $", name, ": '", env, "'");
}

static void prep_sender(void)
{
  static char hostname[256];
  char* p;
  
  if ((sender = getenv("SENDER")) == 0) {
    if (gethostname(hostname, sizeof hostname) != 0)
      die1sys(1, "gethostname failed");
    hostname[sizeof hostname - 1] = 0;
    if ((p = strchr(hostname, '.')) != 0)
      *p = 0;
    sender = hostname;
  }
}

int cli_main(int argc, char* argv[])
{
  const char* server_name = 0;
  const char* env;

  msg_debug_init();
  encr_start();
  prep_sender();
  service = argv[0];
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

  brandom_init();
  if ((env = getenv("KEYDIR")) != 0)
    keydir = env;
  load_keys(server_name);

  if ((env = getenv("PORT")) != 0)
    port = strtoul(env, 0, 10);
  if (port == 0)
    port = 11014;
  if ((sock = socket_udp()) == -1)
    die1sys(1, "Could not create UDP socket");
  if (!socket_connect4(sock, &ip, port))
    die1sys(1, "Could not bind socket");
  if (!str_ready(&packet, 65535)
      || !str_ready(&rpacket, 4+4+8+256*5))
    die1(1, "Out of memory");

  getenvu("ACK_TIMEOUT", &ack_timeout);
  getenvu("CID_TIMEOUT", &cid_timeout);
  getenvu("RETRANSMITS", &retransmits);
  getenvu("READWAIT", &readwait);
  if ((env = getenv("EXITONEOF")) != 0)
    exitoneof = strtoul(env, 0, 0);

  if (getenv("NOFILE") == 0) {
    buffer_file_init();
    buffer_peek = buffer_file_peek;
    buffer_read = buffer_file_read;
    buffer_pop = buffer_file_pop;
    buffer_push = buffer_file_push;
    buffer_rewind = buffer_file_rewind;
  }
  else {
    buffer_peek = buffer_nofile_peek;
    buffer_read = buffer_nofile_read;
    buffer_pop = buffer_nofile_pop;
    buffer_push = buffer_nofile_push;
    buffer_rewind = buffer_nofile_rewind;
  }

  sig_all_catch(sigfn);
  exitasap = 0;

  mainloop();
  return 0;
}

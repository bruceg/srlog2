#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bglibs/sysdeps.h>
#include <bglibs/systime.h>
#include <bglibs/crc32.h>
#include <bglibs/iobuf.h>
#include <bglibs/misc.h>
#include <bglibs/msg.h>
#include <bglibs/resolve.h>
#include <bglibs/socket.h>
#include <bglibs/str.h>
#include <bglibs/sig.h>

#include "srlog2.h"
#include "srlog2q-cli.h"

static str pktin;
static str pktout;
static str data;

int cli_main(int argc, char* argv[])
{
  ipv4addr ip;
  ipv4port port = opt_port;
  int sock;
  unsigned try;
  unsigned tries = 5;
  iopoll_fd io;
  uint32 code;
  long len;
  unsigned char nonce[8];
  str noncecopy = {0,0,0};

  if (!resolve_ipv4name(argv[0], &ip))
    die3(1, "Could not resolve '", argv[0], "'");

  if ((sock = socket_udp()) == -1)
    die1sys(1, "Could not create UDP socket");
  if (!socket_connect4(sock, &ip, port))
    die1sys(1, "Could not bind socket");
  if (!str_ready(&pktin, 65535))
    die1(1, "Out of memory");

  brandom_init();
  brandom_fill(nonce, sizeof nonce);
  pkt_start(&pktout, SRQ1);
  pkt_add_b(&pktout, nonce, sizeof nonce);

  io.fd = sock;
  io.events = IOPOLL_READ;
  for (try = 0; try < tries; ++try) {
    if (!socket_send4(sock, pktout.s, pktout.len, &ip, port))
      die1sys(1, "Could not send packet to server");
    switch (iopoll_restart(&io, 1, opt_timeout)) {
    case -1:
      die1sys(1, "Poll failed");
    case 1:
      if ((len = socket_recv4(sock, pktin.s, pktin.size, &ip, &port)) == -1)
	die1sys(1, "Could not receive packet");
      pktin.len = len;
      if (pktin.len < pktout.len ||
	  pkt_get_u4(&pktin, 0, &code) != 4 ||
	  code != SRL2 ||
	  pkt_get_u4(&pktin, 4, &code) != 8 ||
	  code != SRP1 ||
	  pkt_get_b(&pktin, 8, &noncecopy, 8) != 16 ||
	  memcmp(noncecopy.s, nonce, 8) != 0 ||
	  pkt_get_s2(&pktin, 16, &data) <= 0)
	die1(1, "Invalid data from server");
      write(1, data.s, data.len);
      return 0;
    }
  }
  die1(1, "Timed out");
  return 1;
  (void)argc;
}

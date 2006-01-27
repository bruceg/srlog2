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
#include <net/resolve.h>
#include <net/socket.h>
#include <str/str.h>
#include <unix/sig.h>

#include "srlog.h"

const char program[] = "srlogq";
const int msg_show_pid = 0;

static void usage(void)
{
  die3(1, "usage: ", program, " server [port]");
}

static str pktin;
static str pktout;
static str data;

int main(int argc, char* argv[])
{
  ipv4addr ip;
  ipv4port port = 11006;
  int sock;
  unsigned timeout = 1000;
  const char* tmp;
  unsigned try;
  unsigned tries = 5;
  iopoll_fd io;
  uint64 code;

  if (argc < 2) usage();
  if (!resolve_ipv4name(argv[1], &ip))
    die3(1, "Could not resolve '", argv[1], "'");
  if (argc > 2)
    port = strtoul(argv[2], 0, 10);

  if ((sock = socket_udp()) == -1)
    die1sys(1, "Could not create UDP socket");
  if (!socket_connect4(sock, &ip, port))
    die1sys(1, "Could not bind socket");
  if (!str_ready(&pktin, 65535))
    die1(1, "Out of memory");

  if ((tmp = getenv("TIMEOUT")) != 0)
    if ((timeout = atoi(tmp)) <= 0)
      die3(1, "Invalid timeout value: '", tmp, "'");

  pkt_add_u8(&pktout, SRQ);
  io.fd = sock;
  io.events = IOPOLL_READ;
  for (try = 0; try < tries; ++try) {
    if (!socket_send4(sock, pktout.s, pktout.len, &ip, port))
      die1sys(1, "Could not send packet to server");
    switch (iopoll_restart(&io, 1, timeout)) {
    case -1:
      die1sys(1, "Poll failed");
    case 1:
      if ((pktin.len = socket_recv4(sock, pktin.s, pktin.size, &ip, &port)) == -1)
	die1sys(1, "Could not receive packet");
      if (pktin.len < pktout.len ||
	  pkt_get_u8(&pktin, 0, &code) != 8 ||
	  code != SRP ||
	  pkt_get_s2(&pktin, 8, &data) <= 0)
	die1(1, "Invalid data from server");
      write(1, data.s, data.len);
      return 0;
    }
  }
  die1(1, "Timed out");
  return 1;
}
